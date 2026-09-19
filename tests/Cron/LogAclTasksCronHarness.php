<?php

use Froxlor\Cron\System\TasksCron;
use Froxlor\System\LogAclSynchronizer;

class LogAclTasksCronHarness extends TasksCron
{
	public static bool $syncResult = false;
	public static int $syncCalls = 0;
	/** @var array<int,int[]> */
	public static array $syncScopes = [];

	protected static function createLogAclSynchronizer(): LogAclSynchronizer
	{
		self::$syncCalls++;
		return new class (self::$syncResult) extends LogAclSynchronizer {
			private bool $result;

			public function __construct(bool $result)
			{
				$this->result = $result;
			}

			public function sync(array $customerids = []): bool
			{
				LogAclTasksCronHarness::$syncScopes[] = $customerids;
				return $this->result;
			}
		};
	}
}
