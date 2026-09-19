<?php

use Froxlor\Api\Commands\Customers;
use Froxlor\Cron\TaskId;
use Froxlor\Database\Database;
use PHPUnit\Framework\TestCase;

class LogAclCustomerLifecycleTest extends TestCase
{
	public function testCustomerUpdateAndDeletionQueueReconciliation(): void
	{
		global $admin_userdata;

		Database::query('START TRANSACTION');
		try {
			$result = Customers::getLocal($admin_userdata, [
				'new_loginname' => 'aclqueue',
				'email' => 'aclqueue@example.invalid',
				'firstname' => 'ACL',
				'name' => 'Queue',
				'customernumber' => 987654,
				'new_customer_password' => 'Str0ng-ACL-Queue!',
				'sendpassword' => 0,
				'createstdsubdomain' => 0
			])->add();
			$customer = json_decode($result, true)['data'];

			$this->clearLogAclTasks();
			Customers::getLocal($admin_userdata, [
				'id' => $customer['customerid'],
				'logviewenabled' => 1
			])->update();
			$this->assertSame(1, $this->countLogAclTasks());

			$this->clearLogAclTasks();
			Customers::getLocal($admin_userdata, [
				'id' => $customer['customerid']
			])->delete();
			$this->assertSame(1, $this->countLogAclTasks());
		} finally {
			Database::query('ROLLBACK');
		}
	}

	private function clearLogAclTasks(): void
	{
		$stmt = Database::prepare("DELETE FROM `" . TABLE_PANEL_TASKS . "` WHERE `type` = :type");
		Database::pexecute($stmt, ['type' => TaskId::REBUILD_LOG_ACLS]);
	}

	private function countLogAclTasks(): int
	{
		$stmt = Database::prepare("SELECT COUNT(*) FROM `" . TABLE_PANEL_TASKS . "` WHERE `type` = :type");
		Database::pexecute($stmt, ['type' => TaskId::REBUILD_LOG_ACLS]);
		return (int)$stmt->fetchColumn();
	}
}
