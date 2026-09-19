<?php

use Froxlor\Froxlor;
use PHPUnit\Framework\TestCase;

class LogAclConfigurationTest extends TestCase
{
	public function testFreshInstallDatabaseVersionMatchesApplicationVersion(): void
	{
		$sql = require __DIR__ . '/../../install/froxlor.sql.php';
		$this->assertMatchesRegularExpression(
			"/\\('panel', 'db_version', '" . preg_quote(Froxlor::DBVERSION, '/') . "'\\);/",
			$sql
		);
	}

	public function testReconciliationIsRegisteredAsItsOwnCronjob(): void
	{
		// Reconciliation must not ride along with the 5-minute tasks cron; it gets
		// its own entry so the interval is visible and adjustable like any other
		// froxlor cronjob.
		$sql = require __DIR__ . '/../../install/froxlor.sql.php';
		$this->assertStringContainsString("'logfile_acls'", $sql);
		$this->assertStringContainsString('LogAclsCron', $sql);
		$this->assertStringContainsString("'1 DAY', '1', 'cron_logfile_acls'", $sql);

		$language = require __DIR__ . '/../../lng/en.lng.php';
		$this->assertArrayHasKey('cron_logfile_acls', $language['crondesc']);
	}

	public function testUpgradePathRegistersTheSameCronjobAsAFreshInstall(): void
	{
		// A fresh install and an upgraded install must end up with the same cron
		// entry, otherwise only one of the two ever reconciles.
		$update = file_get_contents(__DIR__ . '/../../install/updates/froxlor/update_2.3.inc.php');
		$this->assertIsString($update);
		foreach (["'logfile_acls'", 'LogAclsCron', "'1 DAY'", "'cron_logfile_acls'"] as $needle) {
			$this->assertStringContainsString($needle, $update);
		}
		// The new entry only takes effect once cron.d has been regenerated.
		$this->assertStringContainsString('TaskId::REBUILD_CRON', $update);
		// Re-running the update must not insert a duplicate row.
		$this->assertStringContainsString('WHERE NOT EXISTS', $update);
		$this->assertStringContainsString("Froxlor::updateToDbVersion('" . Froxlor::DBVERSION . "')", $update);
	}

	public function testSettingsImportQueuesAclReconciliation(): void
	{
		// An import can change logfiles_acl_enabled or logfiles_directory without
		// going through the settings form, so it must queue reconciliation itself.
		$source = (string)file_get_contents(__DIR__ . '/../../lib/Froxlor/Api/Commands/Froxlor.php');
		$importer = substr($source, (int)strpos($source, 'public function importSettings()'));
		$importer = substr($importer, 0, (int)strpos($importer, 'public function exportSettings()'));
		$this->assertStringContainsString('TaskId::REBUILD_LOG_ACLS', $importer);
	}

	public function testLogRootStateKeyUsesBinaryFilesystemSemantics(): void
	{
		$sql = require __DIR__ . '/../../install/froxlor.sql.php';
		$this->assertStringContainsString('`logroot` varbinary(255) NOT NULL', $sql);
	}

	public function testPendingTaskHasEnglishDescription(): void
	{
		$language = require __DIR__ . '/../../lng/en.lng.php';
		$this->assertSame('Reconciling customer logfile ACLs', $language['tasks']['REBUILD_LOG_ACLS'] ?? null);
	}

	public function testApacheAndNginxUseSharedLogfileBasenameBuilder(): void
	{
		foreach (['Apache.php', 'Nginx.php'] as $filename) {
			$source = file_get_contents(__DIR__ . '/../../lib/Froxlor/Cron/Http/' . $filename);
			$this->assertIsString($source);
			$this->assertStringContainsString('LogAcl::getLogfileBasename', $source);
			// The refactor removed the local $speciallogfile variable. Any remaining
			// use of it is an orphan that silently resolves to an empty string.
			$this->assertStringNotContainsString('$speciallogfile', $source);
		}
	}

	public function testGlobalAclControlIsLocatedInSecuritySettings(): void
	{
		$security = file_get_contents(__DIR__ . '/../../actions/admin/settings/210.security.php');
		$webserver = file_get_contents(__DIR__ . '/../../actions/admin/settings/130.webserver.php');
		$this->assertIsString($security);
		$this->assertIsString($webserver);
		$this->assertStringContainsString("'system_logfiles_acl_enabled' => [", $security);
		$this->assertStringNotContainsString("'system_logfiles_acl_enabled' => [", $webserver);
		$this->assertGreaterThan(
			strpos($security, "'system_froxlorusergroup' => ["),
			strpos($security, "'system_logfiles_acl_enabled' => [")
		);
		$language = require __DIR__ . '/../../lng/en.lng.php';
		$this->assertStringContainsString(
			'<strong class="text-danger">',
			$language['serversettings']['logfiles_acl_enabled']['description']
		);
	}
}
