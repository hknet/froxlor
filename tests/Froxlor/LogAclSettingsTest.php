<?php

use Froxlor\Cron\Http\Nginx;
use Froxlor\Database\Database;
use Froxlor\Settings;
use Froxlor\System\LogAcl;
use Froxlor\System\LogAclSynchronizer;
use Froxlor\Settings\Store;
use Froxlor\Validate\Check;
use PHPUnit\Framework\TestCase;

class LogAclSettingsTest extends TestCase
{
	public function testEnablingIsAcceptedWithoutAConfirmationQuestion(): void
	{
		$root = sys_get_temp_dir() . '/froxlor-log-acl-settings-' . bin2hex(random_bytes(6));
		$originalRoot = (string)Settings::Get('system.logfiles_directory');
		mkdir($root, 0755, true);
		Database::query('START TRANSACTION');
		try {
			Settings::Set('system.logfiles_directory', $root . '/', true);
			$this->insertCustomer('acl-active', 12001, 0);
			$this->insertCustomer('acl-disabled', 12002, 1);

			$result = Check::checkLogfilesAcl(
				'system_logfiles_acl_enabled',
				['value' => '0'],
				'1',
				[]
			);
			$this->assertSame([Check::FORMFIELDS_PLAUSIBILITY_CHECK_OK], $result);
		} finally {
			Database::query('ROLLBACK');
			Settings::Set('system.logfiles_directory', $originalRoot, true);
			rmdir($root);
		}
	}

	public function testNginxGeneratesSharedCustomerLogfileNames(): void
	{
		$root = sys_get_temp_dir() . '/froxlor-nginx-log-acl-' . bin2hex(random_bytes(6));
		mkdir($root, 0755, true);
		$settingNames = ['logfiles_directory', 'httpuser', 'httpgroup'];
		$original = [];
		foreach ($settingNames as $name) {
			$original[$name] = (string)Settings::Get('system.' . $name);
		}
		$user = posix_getpwuid(posix_geteuid());
		$group = posix_getgrgid(posix_getegid());
		try {
			Settings::Set('system.logfiles_directory', $root . '/', true);
			Settings::Set('system.httpuser', $user['name'], true);
			Settings::Set('system.httpgroup', $group['name'], true);
			$method = new ReflectionMethod(Nginx::class, 'getLogFiles');
			// PHP < 8.1 requires this explicitly for non-public methods.
			$method->setAccessible(true);
			$output = $method->invoke(new Nginx(), [
				'loginname' => 'customer1',
				'domain' => 'example.test',
				'speciallogfile' => '1',
				'writeerrorlog' => 1,
				'writeaccesslog' => 1,
				'parentdomainid' => 0
			]);
			$this->assertStringContainsString($root . '/customer1-example.test-access.log', $output);
			$this->assertStringContainsString($root . '/customer1-example.test-error.log', $output);
			$this->assertFileExists($root . '/customer1-example.test-access.log');
			$this->assertFileExists($root . '/customer1-example.test-error.log');
		} finally {
			foreach ($original as $name => $value) {
				Settings::Set('system.' . $name, $value, true);
			}
			@unlink($root . '/customer1-example.test-access.log');
			@unlink($root . '/customer1-example.test-error.log');
			@rmdir($root);
		}
	}

	public function testNginxGrantsCustomerAclWhenItCreatesTheLogfile(): void
	{
		if (LogAcl::findBinary('setfacl') === null || LogAcl::findBinary('getfacl') === null) {
			$this->markTestSkipped('setfacl/getfacl are unavailable');
		}
		$root = sys_get_temp_dir() . '/froxlor-nginx-acl-create-' . bin2hex(random_bytes(6));
		mkdir($root, 0755, true);
		$gid = posix_getegid();
		$user = posix_getpwuid(posix_geteuid());
		$group = posix_getgrgid($gid);
		$settingNames = ['logfiles_directory', 'httpuser', 'httpgroup', 'logfiles_acl_enabled'];
		$original = [];
		foreach ($settingNames as $name) {
			$original[$name] = (string)Settings::Get('system.' . $name);
		}
		$logfile = $root . '/aclcust-access.log';
		try {
			Settings::Set('system.logfiles_directory', $root . '/', true);
			Settings::Set('system.httpuser', $user['name'], true);
			Settings::Set('system.httpgroup', $group['name'], true);
			Settings::Set('system.logfiles_acl_enabled', '1', true);

			$method = new ReflectionMethod(Nginx::class, 'getLogFiles');
			$method->setAccessible(true);
			$method->invoke(new Nginx(), [
				'loginname' => 'aclcust',
				'domain' => 'example.test',
				'speciallogfile' => '0',
				'writeerrorlog' => 0,
				'writeaccesslog' => 1,
				'parentdomainid' => 0,
				'guid' => $gid,
				'logviewenabled' => 1,
				'customer_deactivated' => 0
			]);

			$this->assertFileExists($logfile);
			$acl = [];
			exec('getfacl -n --absolute-names -- ' . escapeshellarg($logfile) . ' 2>/dev/null', $acl);
			$this->assertContains('group:' . $gid . ':r--', array_map('trim', $acl));
			// The 0640 mode the webserver config sets must survive the ACL.
			$this->assertSame(0640, fileperms($logfile) & 07777);
		} finally {
			foreach ($original as $name => $value) {
				Settings::Set('system.' . $name, $value, true);
			}
			@unlink($logfile);
			@rmdir($root);
		}
	}

	public function testLogfilesDirectorySaveQueuesLogAclTask(): void
	{
		// A changed log root leaves managed ACL entries behind on the old
		// directory, so saving it must queue reconciliation just like the
		// global switch does.
		$webserver = file_get_contents(__DIR__ . '/../../actions/admin/settings/130.webserver.php');
		$this->assertIsString($webserver);
		$definition = substr($webserver, (int)strpos($webserver, "'system_logfiles_directory' => ["));
		$definition = substr($definition, 0, (int)strpos($definition, '],'));
		$this->assertStringContainsString("'save_method' => 'storeSettingFieldInsertLogAclTask'", $definition);

		$originalRoot = (string)Settings::Get('system.logfiles_directory');
		Database::query('START TRANSACTION');
		try {
			Database::query("DELETE FROM `" . TABLE_PANEL_TASKS . "` WHERE `type` = '15'");
			$this->assertNotFalse(Store::storeSettingFieldInsertLogAclTask(
				'system_logfiles_directory',
				[
					'settinggroup' => 'system',
					'varname' => 'logfiles_directory',
					'value' => $originalRoot
				],
				$originalRoot
			));
			$stmt = Database::query("SELECT COUNT(*) FROM `" . TABLE_PANEL_TASKS . "` WHERE `type` = '15'");
			$this->assertSame(1, (int)$stmt->fetchColumn());
		} finally {
			Database::query('ROLLBACK');
			Settings::Set('system.logfiles_directory', $originalRoot, true);
		}
	}

	public function testGlobalSettingSaveQueuesLogAclTask(): void
	{
		$originalSetting = (string)Settings::Get('system.logfiles_acl_enabled');
		Database::query('START TRANSACTION');
		try {
			Database::query("DELETE FROM `" . TABLE_PANEL_TASKS . "` WHERE `type` = '15'");
			$this->assertNotFalse(Store::storeSettingFieldInsertLogAclTask(
				'system_logfiles_acl_enabled',
				[
					'settinggroup' => 'system',
					'varname' => 'logfiles_acl_enabled',
					'value' => '0'
				],
				'1'
			));
			$stmt = Database::query("SELECT COUNT(*) FROM `" . TABLE_PANEL_TASKS . "` WHERE `type` = '15'");
			$this->assertSame(1, (int)$stmt->fetchColumn());
		} finally {
			Database::query('ROLLBACK');
			Settings::Set('system.logfiles_acl_enabled', $originalSetting, true);
		}
	}

	public function testTwoCustomersSharingOneGidRevokeInsteadOfGrant(): void
	{
		// Ambiguity the database can actually produce: two customers with the same
		// Unix GID. Nothing may be granted, and managed state must be cleaned up.
		$root = sys_get_temp_dir() . '/froxlor-acl-dupgid-' . bin2hex(random_bytes(6));
		mkdir($root, 0755, true);
		$originalRoot = (string)Settings::Get('system.logfiles_directory');
		$originalSetting = (string)Settings::Get('system.logfiles_acl_enabled');
		Database::query('START TRANSACTION');
		try {
			Settings::Set('system.logfiles_directory', $root . '/', true);
			Settings::Set('system.logfiles_acl_enabled', '1', true);
			// Managed state left by other tests points at directories that no
			// longer exist; its revocation failure would mask the error under test.
			Database::query("DELETE FROM `" . TABLE_PANEL_LOG_ACL_STATE . "`");
			$this->insertCustomer('dupa', 19001, 0);
			$this->insertCustomer('dupb', 19001, 0);
			$this->insertDomain('dupa', 'dupa.example.test');
			$this->insertDomain('dupb', 'dupb.example.test');

			$granted = [];
			$acl = new LogAcl(static function (string $command) use (&$granted): int {
				// Only customer grants matter here; the capability probe issues a
				// u: entry on its own throwaway file.
				if (strpos($command, "'-m'") !== false && strpos($command, "'g:") !== false) {
					$granted[] = $command;
				}
				return 0;
			}, '/usr/bin/setfacl', '/usr/bin/getfacl', static function (): array {
				return [0, []];
			});
			$sync = new LogAclSynchronizer($acl, static function (): bool {
				return true;
			});

			$this->assertFalse($sync->sync(), 'a shared GID must fail the run');
			$this->assertStringContainsString('GID', $sync->getLastError());
			$this->assertSame([], $granted, 'nothing may be granted while ownership is ambiguous');
		} finally {
			Database::query('ROLLBACK');
			Settings::Set('system.logfiles_directory', $originalRoot, true);
			Settings::Set('system.logfiles_acl_enabled', $originalSetting, true);
			@rmdir($root);
		}
	}

	private function insertDomain(string $loginname, string $domain): void
	{
		$stmt = Database::prepare("INSERT INTO `" . TABLE_PANEL_DOMAINS . "`
			(`domain`, `customerid`, `adminid`, `parentdomainid`, `speciallogfile`,
			 `writeaccesslog`, `writeerrorlog`, `email_only`)
			SELECT :domain, `customerid`, 1, 0, '0', '1', '1', '0'
			FROM `" . TABLE_PANEL_CUSTOMERS . "` WHERE `loginname` = :loginname");
		Database::pexecute($stmt, ['domain' => $domain, 'loginname' => $loginname]);
	}

	private function insertCustomer(string $loginname, int $gid, int $deactivated): void
	{
		$stmt = Database::prepare("INSERT INTO `" . TABLE_PANEL_CUSTOMERS . "`
			(`loginname`, `guid`, `deactivated`, `logviewenabled`, `allowed_phpconfigs`, `allowed_mysqlserver`)
			VALUES (:loginname, :gid, :deactivated, '1', '', '')");
		Database::pexecute($stmt, [
			'loginname' => $loginname,
			'gid' => $gid,
			'deactivated' => $deactivated
		]);
	}
}
