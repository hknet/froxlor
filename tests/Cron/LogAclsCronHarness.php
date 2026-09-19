<?php

use Froxlor\Cron\System\LogAclsCron;
use Froxlor\System\LogAclSynchronizer;

class LogAclsCronHarness extends LogAclsCron
{
	public static bool $syncResult = true;
	public static int $syncCalls = 0;
	/** @var array<int,int[]> */
	public static array $syncScopes = [];

	protected static function createSynchronizer(): LogAclSynchronizer
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
				LogAclsCronHarness::$syncScopes[] = $customerids;
				return $this->result;
			}

			public function getLastError(): string
			{
				return 'harness failure';
			}
		};
	}
}
