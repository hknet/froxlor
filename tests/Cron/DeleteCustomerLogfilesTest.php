<?php

use Froxlor\Cron\System\TasksCron;
use Froxlor\Database\Database;
use Froxlor\Settings;
use PHPUnit\Framework\TestCase;

/**
 * Deleting a customer must remove its logfiles including rotated and compressed
 * variants, and must not touch files another customer could own.
 *
 * @covers \Froxlor\Cron\System\TasksCron
 */
class DeleteCustomerLogfilesTest extends TestCase
{
	/** @var string */
	private $root = '';

	/** @var string */
	private $originalRoot = '';

	protected function setUp(): void
	{
		$this->root = sys_get_temp_dir() . '/froxlor-del-logs-' . bin2hex(random_bytes(6));
		mkdir($this->root, 0755, true);
		$this->originalRoot = (string)Settings::Get('system.logfiles_directory');
		Settings::Set('system.logfiles_directory', $this->root . '/', true);
	}

	protected function tearDown(): void
	{
		Settings::Set('system.logfiles_directory', $this->originalRoot, true);
		foreach ((array)glob($this->root . '/*') as $file) {
			@unlink($file);
		}
		@rmdir($this->root);
	}

	public function testRotatedAndCompressedLogfilesAreRemovedToo(): void
	{
		Database::query('START TRANSACTION');
		try {
			$this->createFiles([
				'delme-access.log',
				'delme-access.log.1',
				'delme-access.log.2.gz',
				'delme-error.log',
				'delme-error.log.7.bz2',
				'delme-sub.example.test-access.log',
				'delme-sub.example.test-access.log.3.xz'
			]);

			$this->deleteCustomerLogfiles('delme');

			$this->assertSame([], $this->remainingFiles(), 'every variant of the customer\'s logs must be gone');
		} finally {
			Database::query('ROLLBACK');
		}
	}

	public function testFilesOfAnotherCustomerAreLeftAlone(): void
	{
		Database::query('START TRANSACTION');
		try {
			// "delme-foo" is a loginname in its own right, so "delme-foo-*" files
			// belong to it and not to "delme", even though the prefix matches.
			$this->insertCustomer('delme-foo');
			$this->createFiles([
				'delme-access.log',
				'delme-access.log.1',
				'delme-foo-access.log',
				'delme-foo-access.log.1',
				'delme-foo-other.example.test-error.log',
				'unrelated-access.log'
			]);

			$this->deleteCustomerLogfiles('delme');

			$remaining = $this->remainingFiles();
			sort($remaining);
			$this->assertSame([
				'delme-foo-access.log',
				'delme-foo-access.log.1',
				'delme-foo-other.example.test-error.log',
				'unrelated-access.log'
			], $remaining);
		} finally {
			Database::query('ROLLBACK');
		}
	}

	public function testNonLogfilesAndSymlinksAreNeverRemoved(): void
	{
		Database::query('START TRANSACTION');
		try {
			$this->createFiles(['delme-access.log', 'delme-notes.txt', 'delme-access.log.keep']);
			$target = $this->root . '/delme-error.log';
			touch($target . '.real');
			symlink($target . '.real', $target);

			$this->deleteCustomerLogfiles('delme');

			$remaining = $this->remainingFiles();
			sort($remaining);
			$this->assertContains('delme-notes.txt', $remaining, 'a file that is not a logfile must survive');
			$this->assertContains('delme-error.log', $remaining, 'a symlink must never be followed or removed');
			$this->assertNotContains('delme-access.log', $remaining);
		} finally {
			Database::query('ROLLBACK');
		}
	}

	private function deleteCustomerLogfiles(string $loginname): void
	{
		$method = new ReflectionMethod(TasksCron::class, 'deleteCustomerLogfiles');
		// PHP < 8.1 requires this explicitly for non-public methods.
		$method->setAccessible(true);
		$method->invoke(null, $loginname);
	}

	/**
	 * @param string[] $names
	 */
	private function createFiles(array $names): void
	{
		foreach ($names as $name) {
			touch($this->root . '/' . $name);
		}
	}

	/**
	 * @return string[]
	 */
	private function remainingFiles(): array
	{
		$names = [];
		foreach ((array)scandir($this->root) as $entry) {
			if ($entry !== '.' && $entry !== '..') {
				$names[] = $entry;
			}
		}
		return $names;
	}

	private function insertCustomer(string $loginname): void
	{
		$stmt = Database::prepare("INSERT INTO `" . TABLE_PANEL_CUSTOMERS . "`
			(`loginname`, `guid`, `deactivated`, `logviewenabled`, `allowed_phpconfigs`, `allowed_mysqlserver`)
			VALUES (:loginname, 29001, '0', '1', '', '')");
		Database::pexecute($stmt, ['loginname' => $loginname]);
	}
}
