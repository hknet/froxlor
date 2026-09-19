<?php

use Froxlor\Api\Commands\Customers;
use Froxlor\Api\Commands\Domains;
use Froxlor\Database\Database;
use Froxlor\Settings;
use Froxlor\System\LogAcl;
use Froxlor\System\LogAclSynchronizer;
use PHPUnit\Framework\TestCase;

/**
 * End-to-end lifecycle matrix for customer logfile ACLs.
 *
 * Customers and domains are created through the regular API, logfiles are real
 * files, and reconciliation runs the real synchronizer against real setfacl.
 * Only the root check is injected, because the suite does not run as root.
 *
 * @group integration
 */
class LogAclLifecycleMatrixTest extends TestCase
{
	/** @var string */
	private $root = '';

	/** @var array<string,string> */
	private $originalSettings = [];

	protected function setUp(): void
	{
		if (LogAcl::findBinary('setfacl') === null || LogAcl::findBinary('getfacl') === null) {
			$this->markTestSkipped('setfacl/getfacl are unavailable');
		}
		$this->root = sys_get_temp_dir() . '/froxlor-acl-matrix-' . bin2hex(random_bytes(6));
		mkdir($this->root, 0755, true);
		if (!(new LogAcl())->isUsable($this->root)) {
			rmdir($this->root);
			$this->markTestSkipped('the temporary filesystem does not support POSIX ACLs');
		}
		foreach (['logfiles_directory', 'logfiles_acl_enabled'] as $name) {
			$this->originalSettings[$name] = (string)Settings::Get('system.' . $name);
		}
		Settings::Set('system.logfiles_directory', $this->root . '/', true);
	}

	protected function tearDown(): void
	{
		foreach ($this->originalSettings as $name => $value) {
			Settings::Set('system.' . $name, $value, true);
		}
		foreach ((array)glob($this->root . '/*') as $file) {
			@unlink($file);
		}
		@rmdir($this->root);
	}

	public function testGlobalAndPerCustomerTransitionsGrantAndRevokeCorrectly(): void
	{
		global $admin_userdata;

		Database::query('START TRANSACTION');
		try {
			$a = $this->createCustomerWithDomain('mtxa', 'mtxa.example.test');
			$b = $this->createCustomerWithDomain('mtxb', 'mtxb.example.test');
			$fileA = $this->createLogfile('mtxa-mtxa.example.test-access.log');
			$fileB = $this->createLogfile('mtxb-mtxb.example.test-access.log');
			$rotatedA = $this->createLogfile('mtxa-mtxa.example.test-access.log.1');

			// --- global off: nothing is granted -----------------------------
			$this->setGlobal('0');
			$this->assertTrue($this->reconcile(), 'reconcile with feature off');
			$this->assertFalse($this->hasGrant($fileA, $a['gid']), 'no grant while globally disabled');

			// --- global on, both customers eligible -------------------------
			$this->setGlobal('1');
			$this->assertTrue($this->reconcile(), 'reconcile with feature on');
			$this->assertTrue($this->hasGrant($fileA, $a['gid']), 'A reads its own log');
			$this->assertTrue($this->hasGrant($rotatedA, $a['gid']), 'A reads its rotated log');
			$this->assertTrue($this->hasGrant($fileB, $b['gid']), 'B reads its own log');
			$this->assertFalse($this->hasGrant($fileA, $b['gid']), 'B must not read A');
			$this->assertFalse($this->hasGrant($fileB, $a['gid']), 'A must not read B');
			$this->assertSame(0640, fileperms($fileA) & 07777, 'mode preserved');
			$this->assertSame(2, $this->countStates(), 'one state row per eligible customer');

			// --- per-customer off: only B loses access ----------------------
			$this->setCustomerLogview($b['customerid'], 0);
			$this->assertTrue($this->reconcile(), 'reconcile after per-customer disable');
			$this->assertFalse($this->hasGrant($fileB, $b['gid']), 'B revoked');
			$this->assertTrue($this->hasGrant($fileA, $a['gid']), 'A unaffected by B');
			$this->assertSame(1, $this->countStates(), 'B state row removed');

			// --- per-customer back on ---------------------------------------
			$this->setCustomerLogview($b['customerid'], 1);
			$this->assertTrue($this->reconcile(), 'reconcile after per-customer re-enable');
			$this->assertTrue($this->hasGrant($fileB, $b['gid']), 'B granted again');
			$this->assertSame(2, $this->countStates());

			// --- global off: everything revoked, state emptied --------------
			$this->setGlobal('0');
			$this->assertTrue($this->reconcile(), 'reconcile after global disable');
			$this->assertFalse($this->hasGrant($fileA, $a['gid']), 'A revoked by global disable');
			$this->assertFalse($this->hasGrant($rotatedA, $a['gid']), 'A rotated revoked too');
			$this->assertFalse($this->hasGrant($fileB, $b['gid']), 'B revoked by global disable');
			$this->assertSame(0, $this->countStates(), 'no managed state left');
			$this->assertSame(0640, fileperms($fileA) & 07777, 'mode still preserved after revoke');

			// --- global on again: re-granted --------------------------------
			$this->setGlobal('1');
			$this->assertTrue($this->reconcile(), 'reconcile after global re-enable');
			$this->assertTrue($this->hasGrant($fileA, $a['gid']), 'A granted again');
			$this->assertSame(2, $this->countStates());
		} finally {
			Database::query('ROLLBACK');
		}
	}

	public function testReconciliationCostScalesWithCustomersNotLogfiles(): void
	{
		// Guards the reworked grant/revoke paths: adding logfiles must not add
		// setfacl invocations, otherwise a busy installation cannot finish a run
		// inside its cron interval.
		$counts = [];
		foreach ([4, 40] as $filesPerCustomer) {
			$calls = 0;
			$acl = new LogAcl(
				static function () use (&$calls): int {
					$calls++;
					return 0;
				},
				'/usr/bin/setfacl',
				'/usr/bin/getfacl',
				static function (): array {
					return [0, []];
				}
			);
			$root = sys_get_temp_dir() . '/froxlor-acl-scale-' . bin2hex(random_bytes(6));
			mkdir($root, 0755, true);
			$desired = [];
			for ($c = 1; $c <= 5; $c++) {
				$basenames = [];
				for ($f = 1; $f <= $filesPerCustomer; $f++) {
					$name = 'sc' . $c . '-d' . $f . '-access.log';
					$basenames[] = $name;
					touch($root . '/' . $name);
					chmod($root . '/' . $name, 0640);
				}
				$desired[13000 + $c] = ['customerid' => $c, 'prefix' => 'sc' . $c . '-', 'basenames' => $basenames];
			}
			$sync = new LogAclSynchronizer(
				$acl,
				static function (): bool {
					return true;
				},
				static function () use ($root): ?string {
					return $root;
				},
				static function (): bool {
					return true;
				},
				static function () use ($desired): array {
					return $desired;
				},
				static function (): array {
					return [];
				},
				static function (): void {
				},
				static function (): void {
				}
			);
			$this->assertTrue($sync->sync());
			foreach ((array)glob($root . '/*') as $file) {
				@unlink($file);
			}
			@rmdir($root);
			$counts[$filesPerCustomer] = $calls;
		}

		// Ten times the logfiles must not mean ten times the work.
		$this->assertSame(
			$counts[4],
			$counts[40],
			'setfacl invocations changed with the number of logfiles: ' . json_encode($counts)
		);
	}

	private function reconcile(): bool
	{
		$sync = new LogAclSynchronizer(new LogAcl(), static function (): bool {
			return true; // the suite does not run as root
		});
		$ok = $sync->sync();
		if (!$ok) {
			$this->fail('reconciliation failed: ' . $sync->getLastError());
		}
		return $ok;
	}

	private function createCustomerWithDomain(string $loginname, string $domain): array
	{
		global $admin_userdata;

		$result = Customers::getLocal($admin_userdata, [
			'new_loginname' => $loginname,
			'email' => $loginname . '@example.invalid',
			'firstname' => 'Matrix',
			'name' => ucfirst($loginname),
			'new_customer_password' => 'Str0ng-ACL-Matrix!',
			'sendpassword' => 0,
			'createstdsubdomain' => 0,
			'logviewenabled' => 1
		])->add();
		$customer = json_decode($result, true)['data'];

		Domains::getLocal($admin_userdata, [
			'domain' => $domain,
			'customerid' => $customer['customerid'],
			'speciallogfile' => 1,
			'writeaccesslog' => 1,
			'writeerrorlog' => 1
		])->add();

		return ['customerid' => (int)$customer['customerid'], 'gid' => (int)$customer['guid']];
	}

	private function createLogfile(string $basename): string
	{
		$path = $this->root . '/' . $basename;
		touch($path);
		chmod($path, 0640);
		return $path;
	}

	private function setGlobal(string $value): void
	{
		Settings::Set('system.logfiles_acl_enabled', $value, true);
	}

	private function setCustomerLogview(int $customerid, int $enabled): void
	{
		$stmt = Database::prepare("UPDATE `" . TABLE_PANEL_CUSTOMERS . "`
			SET `logviewenabled` = :enabled WHERE `customerid` = :id");
		Database::pexecute($stmt, ['enabled' => $enabled, 'id' => $customerid]);
	}

	private function countStates(): int
	{
		$stmt = Database::query("SELECT COUNT(*) FROM `" . TABLE_PANEL_LOG_ACL_STATE . "`");
		return (int)$stmt->fetchColumn();
	}

	private function hasGrant(string $path, int $gid): bool
	{
		$output = [];
		exec('getfacl -n --absolute-names -- ' . escapeshellarg($path) . ' 2>/dev/null', $output);
		return in_array('group:' . $gid . ':r--', array_map('trim', $output), true);
	}
}
