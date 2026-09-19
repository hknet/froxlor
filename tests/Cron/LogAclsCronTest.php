<?php

// phpcs:ignoreFile PSR1.Files.SideEffects -- load the test-only cron harness.
require_once __DIR__ . '/LogAclsCronHarness.php';

use Froxlor\Cron\FroxlorCron;
use Froxlor\Database\Database;
use Froxlor\FroxlorLogger;
use Froxlor\Settings;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Froxlor\Cron\System\LogAclsCron
 */
class LogAclsCronTest extends TestCase
{
	protected function setUp(): void
	{
		LogAclsCronHarness::$syncCalls = 0;
		LogAclsCronHarness::$syncResult = true;
		LogAclsCronHarness::$syncScopes = [];
		FroxlorCron::setCronlog(FroxlorLogger::getInstanceOf());
	}

	public function testDoesNothingWhenDisabledAndNoManagedStateRemains(): void
	{
		$original = (string)Settings::Get('system.logfiles_acl_enabled');
		Database::query('START TRANSACTION');
		try {
			Database::query("DELETE FROM `" . TABLE_PANEL_LOG_ACL_STATE . "`");
			Settings::Set('system.logfiles_acl_enabled', '0', true);
			LogAclsCronHarness::run();
			$this->assertSame(0, LogAclsCronHarness::$syncCalls, 'must not spawn ACL tooling with nothing to do');
		} finally {
			Database::query('ROLLBACK');
			Settings::Set('system.logfiles_acl_enabled', $original, true);
		}
	}

	public function testRunsWhenDisabledButManagedStateStillNeedsCleanup(): void
	{
		$original = (string)Settings::Get('system.logfiles_acl_enabled');
		Database::query('START TRANSACTION');
		try {
			Settings::Set('system.logfiles_acl_enabled', '0', true);
			$stmt = Database::prepare("INSERT INTO `" . TABLE_PANEL_LOG_ACL_STATE . "`
				(`customerid`, `gid`, `logroot`) VALUES (:cid, :gid, :root)");
			Database::pexecute($stmt, ['cid' => 4242, 'gid' => 14242, 'root' => '/var/customers/logs']);
			LogAclsCronHarness::run();
			$this->assertSame(1, LogAclsCronHarness::$syncCalls, 'leftover state must still be cleaned up');
		} finally {
			Database::query('ROLLBACK');
			Settings::Set('system.logfiles_acl_enabled', $original, true);
		}
	}

	public function testRunsWhenEnabled(): void
	{
		$original = (string)Settings::Get('system.logfiles_acl_enabled');
		Database::query('START TRANSACTION');
		try {
			Settings::Set('system.logfiles_acl_enabled', '1', true);
			LogAclsCronHarness::run();
			$this->assertSame(1, LogAclsCronHarness::$syncCalls);
			// The periodic job always converges everything; scoping is what task 15 is for.
			$this->assertSame([[]], LogAclsCronHarness::$syncScopes);
		} finally {
			Database::query('ROLLBACK');
			Settings::Set('system.logfiles_acl_enabled', $original, true);
		}
	}

	public function testFailureIsReportedAndDoesNotThrow(): void
	{
		$original = (string)Settings::Get('system.logfiles_acl_enabled');
		LogAclsCronHarness::$syncResult = false;
		Database::query('START TRANSACTION');
		try {
			Settings::Set('system.logfiles_acl_enabled', '1', true);
			LogAclsCronHarness::run();
			$this->assertSame(1, LogAclsCronHarness::$syncCalls);
		} finally {
			Database::query('ROLLBACK');
			Settings::Set('system.logfiles_acl_enabled', $original, true);
		}
	}
}
