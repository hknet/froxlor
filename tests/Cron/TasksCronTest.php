<?php

// phpcs:ignoreFile PSR1.Files.SideEffects -- load the test-only cron harness.
require_once __DIR__ . '/LogAclTasksCronHarness.php';

use Froxlor\Cron\FroxlorCron;
use Froxlor\Cron\System\TasksCron;
use Froxlor\Cron\TaskId;
use Froxlor\Database\Database;
use Froxlor\FroxlorLogger;
use Froxlor\System\Cronjob;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Froxlor\Cron\System\TasksCron
 */
class TasksCronTest extends TestCase
{
	public function testFailedLogAclTaskRemainsQueued(): void
	{
		LogAclTasksCronHarness::$syncResult = false;
		LogAclTasksCronHarness::$syncCalls = 0;
		Database::query('START TRANSACTION');
		try {
			$this->clearNonSystemTasks();
			$id = $this->queueLogAclTask();
			FroxlorCron::setCronlog(FroxlorLogger::getInstanceOf());
			LogAclTasksCronHarness::run();
			$this->assertSame(1, LogAclTasksCronHarness::$syncCalls);
			$this->assertTrue($this->taskExists($id));
		} finally {
			Database::query('ROLLBACK');
		}
	}

	public function testSuccessfulLogAclTaskIsRemoved(): void
	{
		LogAclTasksCronHarness::$syncResult = true;
		LogAclTasksCronHarness::$syncCalls = 0;
		Database::query('START TRANSACTION');
		try {
			$this->clearNonSystemTasks();
			$id = $this->queueLogAclTask();
			FroxlorCron::setCronlog(FroxlorLogger::getInstanceOf());
			LogAclTasksCronHarness::run();
			$this->assertSame(1, LogAclTasksCronHarness::$syncCalls);
			$this->assertFalse($this->taskExists($id));
		} finally {
			Database::query('ROLLBACK');
		}
	}

	public function testPerCustomerTaskLimitsReconciliationToThatCustomer(): void
	{
		LogAclTasksCronHarness::$syncResult = true;
		LogAclTasksCronHarness::$syncCalls = 0;
		LogAclTasksCronHarness::$syncScopes = [];
		Database::query('START TRANSACTION');
		try {
			$this->clearNonSystemTasks();
			Cronjob::inserttask(TaskId::REBUILD_LOG_ACLS, 4711);
			FroxlorCron::setCronlog(FroxlorLogger::getInstanceOf());
			LogAclTasksCronHarness::run();
			$this->assertSame(1, LogAclTasksCronHarness::$syncCalls);
			$this->assertSame([[4711]], LogAclTasksCronHarness::$syncScopes);
		} finally {
			Database::query('ROLLBACK');
		}
	}

	public function testGlobalTaskReconcilesEveryCustomer(): void
	{
		LogAclTasksCronHarness::$syncResult = true;
		LogAclTasksCronHarness::$syncCalls = 0;
		LogAclTasksCronHarness::$syncScopes = [];
		Database::query('START TRANSACTION');
		try {
			$this->clearNonSystemTasks();
			Cronjob::inserttask(TaskId::REBUILD_LOG_ACLS);
			FroxlorCron::setCronlog(FroxlorLogger::getInstanceOf());
			LogAclTasksCronHarness::run();
			$this->assertSame(1, LogAclTasksCronHarness::$syncCalls);
			// empty scope == converge everything
			$this->assertSame([[]], LogAclTasksCronHarness::$syncScopes);
		} finally {
			Database::query('ROLLBACK');
		}
	}

	public function testGlobalTaskSupersedesQueuedPerCustomerTasks(): void
	{
		Database::query('START TRANSACTION');
		try {
			$this->clearNonSystemTasks();
			Cronjob::inserttask(TaskId::REBUILD_LOG_ACLS, 1);
			Cronjob::inserttask(TaskId::REBUILD_LOG_ACLS, 2);
			$this->assertSame(2, $this->countLogAclTasks());
			Cronjob::inserttask(TaskId::REBUILD_LOG_ACLS);
			$this->assertSame(1, $this->countLogAclTasks());
		} finally {
			Database::query('ROLLBACK');
		}
	}

	public function testRepeatedChangesToOneCustomerCollapseToOneTask(): void
	{
		Database::query('START TRANSACTION');
		try {
			$this->clearNonSystemTasks();
			Cronjob::inserttask(TaskId::REBUILD_LOG_ACLS, 7);
			Cronjob::inserttask(TaskId::REBUILD_LOG_ACLS, 7);
			Cronjob::inserttask(TaskId::REBUILD_LOG_ACLS, 7);
			$this->assertSame(1, $this->countLogAclTasks());
			Cronjob::inserttask(TaskId::REBUILD_LOG_ACLS, 8);
			$this->assertSame(2, $this->countLogAclTasks());
		} finally {
			Database::query('ROLLBACK');
		}
	}

	private function countLogAclTasks(): int
	{
		$stmt = Database::prepare("SELECT COUNT(*) FROM `" . TABLE_PANEL_TASKS . "` WHERE `type` = :type");
		Database::pexecute($stmt, ['type' => TaskId::REBUILD_LOG_ACLS]);
		return (int)$stmt->fetchColumn();
	}

	public function testLogAclTaskInsertionIsDeduplicated(): void
	{
		Database::query('START TRANSACTION');
		try {
			$this->clearNonSystemTasks();
			Cronjob::inserttask(TaskId::REBUILD_LOG_ACLS);
			Cronjob::inserttask(TaskId::REBUILD_LOG_ACLS);
			$stmt = Database::prepare("SELECT COUNT(*) FROM `" . TABLE_PANEL_TASKS . "` WHERE `type` = :type");
			Database::pexecute($stmt, ['type' => TaskId::REBUILD_LOG_ACLS]);
			$this->assertSame(1, (int)$stmt->fetchColumn());
		} finally {
			Database::query('ROLLBACK');
		}
	}

	private function queueLogAclTask(): int
	{
		Cronjob::inserttask(TaskId::REBUILD_LOG_ACLS);
		$stmt = Database::prepare("SELECT `id` FROM `" . TABLE_PANEL_TASKS . "` WHERE `type` = :type");
		Database::pexecute($stmt, ['type' => TaskId::REBUILD_LOG_ACLS]);
		return (int)$stmt->fetchColumn();
	}

	private function taskExists(int $id): bool
	{
		$stmt = Database::prepare("SELECT `id` FROM `" . TABLE_PANEL_TASKS . "` WHERE `id` = :id");
		return Database::pexecute_first($stmt, ['id' => $id]) !== false;
	}

	private function clearNonSystemTasks(): void
	{
		Database::query("DELETE FROM `" . TABLE_PANEL_TASKS . "` WHERE `type` <> '99'");
	}
}
