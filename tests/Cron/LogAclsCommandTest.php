<?php

use Froxlor\Cli\LogAcls;
use Froxlor\Cli\MasterCron;
use Froxlor\Cron\TaskId;
use Froxlor\System\LogAclSynchronizer;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;

class LogAclsCommandTest extends TestCase
{
	public function testCommandRejectsNonRootExecution(): void
	{
		$command = new LogAcls(static function (): bool {
			return false;
		});
		$tester = new CommandTester($command);
		$this->assertSame(Command::FAILURE, $tester->execute([]));
		$this->assertStringContainsString('must run as root', $tester->getDisplay());
	}

	public function testMasterCronDocumentsRunTask15Option(): void
	{
		$definition = (new MasterCron())->getDefinition();
		$this->assertTrue($definition->hasOption('run-task'));
		$this->assertStringContainsString(
			'15 = reconcile logfile ACLs',
			$definition->getOption('run-task')->getDescription()
		);
		$this->assertSame(15, TaskId::REBUILD_LOG_ACLS);
	}

	public function testPeriodicReconciliationRunsOnlyFromItsOwnCronjob(): void
	{
		// Nothing outside TasksCron (task 15) and the dedicated LogAclsCron may
		// invoke ACL tooling, or unrelated cron jobs would spawn it and mail.
		$cronDirectory = __DIR__ . '/../../lib/Froxlor/Cron';
		$referencing = [];
		$files = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator($cronDirectory, RecursiveDirectoryIterator::SKIP_DOTS)
		);
		foreach ($files as $file) {
			if (!$file->isFile() || $file->getExtension() !== 'php') {
				continue;
			}
			if (strpos((string)file_get_contents($file->getPathname()), 'LogAclSynchronizer') !== false) {
				$referencing[] = $file->getFilename();
			}
		}
		sort($referencing);
		$this->assertSame(['LogAclsCron.php', 'TasksCron.php'], $referencing);
	}

	public function testCommandReportsSynchronizerFailure(): void
	{
		$synchronizer = new class extends LogAclSynchronizer {
			public function sync(array $customerids = []): bool
			{
				return false;
			}

			public function getLastError(): string
			{
				return 'test failure detail';
			}
		};
		$command = new LogAcls(
			static function (): bool {
				return true;
			},
			static function () use ($synchronizer): LogAclSynchronizer {
				return $synchronizer;
			}
		);
		$tester = new CommandTester($command);
		$this->assertSame(Command::FAILURE, $tester->execute([]));
		$this->assertStringContainsString('test failure detail', $tester->getDisplay());
	}
}
