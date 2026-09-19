<?php

use Froxlor\System\LogAcl;
use Froxlor\System\LogAclSynchronizer;
use Froxlor\Validate\Check;
use PHPUnit\Framework\TestCase;

class LogAclTest extends TestCase
{
	public function testAllSupportedLogrotateTemplatesCallTheAclReconciler(): void
	{
		foreach (['focal', 'jammy', 'noble', 'bullseye', 'bookworm', 'trixie'] as $distribution) {
			$template = __DIR__ . '/../../lib/configfiles/' . $distribution . '.xml';
			$this->assertFileExists($template);
			$xml = simplexml_load_file($template);
			$this->assertNotFalse($xml);
			$daemons = $xml->xpath("//daemon[@name='logrotate']");
			$this->assertCount(1, $daemons);
			$content = (string)$daemons[0]->file->content;
			$this->assertMatchesRegularExpression('/postrotate.*froxlor:log-acls.*endscript/s', $content);
		}
	}

	public function testLogfileBasenamesForStandardDomain(): void
	{
		$basenames = LogAcl::getLogfileBasenames([
			'loginname' => 'customer1',
			'domain' => 'example.test',
			'speciallogfile' => '0',
			'parentdomainid' => '0',
			'writeerrorlog' => '1',
			'writeaccesslog' => '1'
		]);

		$this->assertSame([
			'customer1-error.log',
			'customer1-access.log'
		], $basenames);
	}

	public function testLogfileBasenameForSpecialRootDomain(): void
	{
		$basename = LogAcl::getLogfileBasename([
			'loginname' => 'customer1',
			'domain' => 'example.test',
			'speciallogfile' => '1',
			'parentdomainid' => '0'
		], 'access');

		$this->assertSame('customer1-example.test-access.log', $basename);
	}

	public function testLogfileBasenamesForSpecialSubdomain(): void
	{
		$basenames = LogAcl::getLogfileBasenames([
			'loginname' => 'customer1',
			'domain' => 'sub.example.test',
			'parentdomain' => 'example.test',
			'speciallogfile' => '1',
			'parentdomainid' => '12',
			'writeerrorlog' => '0',
			'writeaccesslog' => '1'
		]);

		$this->assertSame(['customer1-example.test-access.log'], $basenames);
	}

	public function testRotatedLogfileVariants(): void
	{
		$this->assertTrue(LogAcl::isLogfileVariant('customer1-access.log', 'customer1-access.log'));
		$this->assertTrue(LogAcl::isLogfileVariant('customer1-access.log', 'customer1-access.log.1'));
		$this->assertTrue(LogAcl::isLogfileVariant('customer1-access.log', 'customer1-access.log.2.gz'));
		$this->assertTrue(LogAcl::isLogfileVariant('customer1-access.log', 'customer1-access.log.2.bz2'));
		$this->assertTrue(LogAcl::isLogfileVariant('customer1-access.log', 'customer1-access.log.2.xz'));
		$this->assertTrue(LogAcl::isLogfileVariant('customer1-access.log', 'customer1-access.log.2.zst'));
		$this->assertFalse(LogAcl::isLogfileVariant('customer1-access.log', 'customer10-access.log'));
		$this->assertFalse(LogAcl::isLogfileVariant('customer1-access.log', 'customer1-access.log.backup'));
	}

	public function testMissingAclToolsFailClosed(): void
	{
		$acl = new LogAcl(static function (string $command): int {
			return 0;
		}, null, null, null, static function (string $name): ?string {
			return null;
		});

		$this->assertFalse($acl->isAvailable());
		$this->assertFalse($acl->isUsable());
		$this->assertSame(['setfacl', 'getfacl'], $acl->getMissingTools());
	}

	public function testUnsupportedFilesystemProbeFailsClosed(): void
	{
		$acl = new LogAcl(static function (string $command): int {
			return 1;
		}, '/bin/true', '/bin/true');

		$this->assertTrue($acl->isAvailable());
		$this->assertFalse($acl->isUsable());
	}

	public function testCapabilityProbeUsesRequestedFilesystem(): void
	{
		$root = $this->makeTempDirectory();
		$commands = [];
		try {
			$acl = new LogAcl(static function (string $command) use (&$commands): int {
				$commands[] = $command;
				return 0;
			}, '/bin/true', '/bin/true');

			$this->assertTrue($acl->isUsable($root));
			$this->assertNotEmpty($commands);
			foreach ($commands as $command) {
				$this->assertStringContainsString($root, $command);
			}
		} finally {
			$this->removeTempDirectory($root);
		}
	}

	public function testGlobalDisableRevokesEveryGidInOnePass(): void
	{
		// Fifty customers coming off the same directory must cost one walk, not
		// fifty: setfacl takes every entry in a single call.
		$root = $this->makeTempDirectory();
		$states = [];
		for ($i = 1; $i <= 50; $i++) {
			$states[] = ['customerid' => $i, 'gid' => 12000 + $i, 'logroot' => $root];
		}
		for ($f = 1; $f <= 20; $f++) {
			$path = $root . '/customer' . $f . '-access.log';
			touch($path);
			chmod($path, 0640);
		}
		$fileRemovals = [];
		try {
			$acl = new LogAcl(static function (string $command) use (&$fileRemovals): int {
				if (strpos($command, "'-x'") !== false && strpos($command, '-access.log') !== false) {
					$fileRemovals[] = $command;
				}
				return 0;
			}, '/usr/bin/setfacl', '/usr/bin/getfacl', static function (): array {
				return [0, ['group:12001:r--']];
			});
			$synchronizer = new LogAclSynchronizer(
				$acl,
				static function (): bool {
					return true;
				},
				static function () use ($root): ?string {
					return $root;
				},
				static function (): bool {
					return false; // feature disabled: revoke everything
				},
				static function (): array {
					return [];
				},
				static function () use ($states): array {
					return $states;
				},
				static function (): void {
				},
				static function (): void {
				}
			);

			$this->assertTrue($synchronizer->sync());
			$this->assertCount(1, $fileRemovals, 'all GIDs must come off the files in a single setfacl call');
			// That one call must name every GID.
			$this->assertStringContainsString('g:12001', $fileRemovals[0]);
			$this->assertStringContainsString('g:12050', $fileRemovals[0]);
		} finally {
			array_map('unlink', (array)glob($root . '/*'));
			$this->removeTempDirectory($root);
		}
	}

	public function testVanishedLogfileIsNotTreatedAsRevocationFailure(): void
	{
		// Rotation or customer cleanup can remove a file between the directory
		// scan and the call. A file that is gone carries no ACL.
		$acl = new LogAcl(static function (): int {
			return 0;
		}, '/usr/bin/setfacl', '/usr/bin/getfacl', static function (): array {
			return [0, []];
		});
		$this->assertTrue($acl->revokeMany(['/var/customers/logs/gone-access.log'], [12001]));
	}

	public function testUnreadableDesiredSetLeavesExistingAclsAlone(): void
	{
		// A failed query is absence of information, not ambiguity. The entries on
		// disk were correct as of the last successful run, so a database hiccup
		// must not revoke every customer's access.
		$root = $this->makeTempDirectory();
		$file = $root . '/customer1-access.log';
		touch($file);
		chmod($file, 0640);
		$commands = [];
		$deleted = [];
		try {
			$acl = new LogAcl(static function (string $command) use (&$commands): int {
				$commands[] = $command;
				return 0;
			}, '/bin/true', '/bin/true', static function (): array {
				return [0, []];
			});
			$synchronizer = new LogAclSynchronizer(
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
				static function (): array {
					throw new RuntimeException('database is unavailable');
				},
				static function () use ($root): array {
					return [['gid' => 12001, 'customerid' => 7, 'logroot' => $root]];
				},
				static function (): void {
				},
				static function (int $gid, string $logroot) use (&$deleted): void {
					$deleted[] = $gid;
				}
			);

			$this->assertFalse($synchronizer->sync(), 'the run must report failure');
			$this->assertSame([], $deleted, 'managed state must survive a failed query');
			$revokes = array_filter($commands, static function (string $command): bool {
				return strpos($command, "'-x'") !== false;
			});
			$this->assertSame([], $revokes, 'nothing may be revoked when the desired set is unknown');
		} finally {
			@unlink($file);
			$this->removeTempDirectory($root);
		}
	}

	public function testCapabilityProbeLeavesNothingBehindInTheLogDirectory(): void
	{
		$root = $this->makeTempDirectory();
		try {
			// Litter from a run that died before cleaning up.
			$stale = $root . '/' . LogAcl::PROBE_FILENAME;
			touch($stale);

			$acl = new LogAcl(static function (): int {
				return 0;
			}, '/bin/true', '/bin/true', static function (): array {
				return [0, ['user::rw-']];
			});
			$this->assertTrue($acl->isUsable($root));

			$this->assertFileDoesNotExist($stale, 'the probe must not be left behind in the customer log directory');
		} finally {
			$this->removeTempDirectory($root);
		}
	}

	public function testGetfaclUsesAbsoluteNamesToKeepSuccessfulCronRunsSilent(): void
	{
		$commands = [];
		$acl = new LogAcl(static function (string $command): int {
			return 0;
		}, '/bin/true', '/bin/true', static function (string $command) use (&$commands): array {
			$commands[] = $command;
			return [0, []];
		});

		$this->assertTrue($acl->revoke('/var/customers/logs/customer1-access.log', 12001));
		$this->assertStringContainsString("'--absolute-names'", $commands[0]);
	}

	public function testRevokeIsIdempotentWhenEntryIsAbsent(): void
	{
		$commands = [];
		$acl = new LogAcl(static function (string $command) use (&$commands): int {
			$commands[] = $command;
			return 0;
		}, '/bin/true', '/bin/true', static function (string $command): array {
			return [0, []];
		});

		$this->assertTrue($acl->revoke('/var/customers/logs/customer1-access.log', 12001));
		$this->assertSame([], $commands);
	}

	public function testAclGrantsFailClosedWhenModeMaskCannotCarryPermission(): void
	{
		$root = $this->makeTempDirectory();
		$file = $root . '/customer1-access.log';
		touch($file);
		chmod($root, 0700);
		chmod($file, 0600);
		$commands = [];
		try {
			$acl = new LogAcl(static function (string $command) use (&$commands): int {
				$commands[] = $command;
				return 0;
			}, '/bin/true', '/bin/true');

			$this->assertFalse($acl->grantDirectoryAccess($root, 12001));
			$this->assertFalse($acl->grantLogfileRead($file, 12001));
			$this->assertSame([], $commands);
		} finally {
			$this->removeTempDirectory($root);
		}
	}

	public function testCommandsUseNumericGidAndReadOnlyPermissions(): void
	{
		$commands = [];
		$executor = static function (string $command) use (&$commands): int {
			$commands[] = $command;
			return 0;
		};
		$acl = new LogAcl($executor, '/bin/true', '/bin/true');

		$this->assertTrue($acl->grantDirectoryAccess('/var/customers/logs', 12001));
		$this->assertTrue($acl->grantLogfileRead('/var/customers/logs/customer1-access.log', 12001));
		$this->assertTrue($acl->revoke('/var/customers/logs/customer1-access.log.1.gz', 12001));

		$this->assertStringContainsString("'g:12001:r-x'", $commands[0]);
		$this->assertStringContainsString("'g:12001:r--'", $commands[1]);
		$this->assertStringContainsString("'g:12001'", $commands[2]);
		$this->assertStringNotContainsString('0644', implode(' ', $commands));
	}

	public function testAclCommandFailureProvidesDiagnosticDetail(): void
	{
		$acl = new LogAcl(static function (string $command): int {
			return 23;
		}, '/bin/false', '/bin/false');

		$this->assertFalse($acl->grantLogfileRead('/var/customers/logs/customer1-access.log', 12001));
		$this->assertStringContainsString('exit status 23', $acl->getLastError());
		$this->assertStringContainsString('customer1-access.log', $acl->getLastError());
		$this->assertStringContainsString('g:12001:r--', $acl->getLastError());
	}

	public function testDisabledSettingDoesNotRequireAclTools(): void
	{
		$result = Check::checkLogfilesAcl('system_logfiles_acl_enabled', [], '0', []);
		$this->assertSame([Check::FORMFIELDS_PLAUSIBILITY_CHECK_OK], $result);
	}

	public function testInvalidGidAndPathAreRejected(): void
	{
		$acl = new LogAcl(static function (string $command): int {
			return 0;
		}, '/bin/true', '/bin/true');

		$this->expectException(InvalidArgumentException::class);
		$acl->grantLogfileRead('relative.log', 12001);
	}

	public function testSymlinkComponentsAreRejected(): void
	{
		$root = $this->makeTempDirectory();
		$target = $root . '/target';
		$link = $root . '/link';
		mkdir($target);
		symlink($target, $link);

		try {
			$acl = new LogAcl(static function (string $command): int {
				return 0;
			}, '/bin/true', '/bin/true');
			$this->expectException(InvalidArgumentException::class);
			$acl->grantLogfileRead($link . '/access.log', 12001);
		} finally {
			$this->removeTempDirectory($root);
		}
	}

	public function testSynchronizerRefusesOverlappingRun(): void
	{
		$lockDirectory = function_exists('posix_geteuid') && posix_geteuid() === 0 ? '/run/lock' : sys_get_temp_dir();
		$lock = fopen($lockDirectory . '/froxlor-log-acls.lock', 'c');
		$this->assertIsResource($lock);
		$this->assertTrue(flock($lock, LOCK_EX | LOCK_NB));
		$root = $this->makeTempDirectory();
		$states = [];
		try {
			$acl = new LogAcl(static function (string $command): int {
				return 0;
			}, '/bin/true', '/bin/true');
			$synchronizer = $this->makeSynchronizer($acl, $root, true, [], $states);
			$this->assertFalse($synchronizer->sync());
			$this->assertStringContainsString('another run may already be active', $synchronizer->getLastError());
		} finally {
			flock($lock, LOCK_UN);
			fclose($lock);
			$this->removeTempDirectory($root);
		}
	}

	public function testSynchronizerAppliesActiveAccessAndErrorLogs(): void
	{
		$root = $this->makeTempDirectory();
		touch($root . '/customer1-access.log');
		touch($root . '/customer1-error.log');
		$states = [];
		$commands = [];
		try {
			$acl = new LogAcl(static function (string $command) use (&$commands): int {
				if (strpos($command, "'g:12001:r--'") !== false) {
					$commands[] = $command;
				}
				return 0;
			}, '/bin/true', '/bin/true');
			$synchronizer = $this->makeSynchronizer($acl, $root, true, [
				12001 => [
					'customerid' => 7,
					'prefix' => 'customer1-',
					'basenames' => ['customer1-access.log', 'customer1-error.log']
				]
			], $states);

			$this->assertTrue($synchronizer->sync());
			// Grants are batched into as few setfacl calls as possible, so assert on
			// the granted paths rather than on the number of invocations.
			$granted = implode(' ', $commands);
			$this->assertStringContainsString("'" . $root . "/customer1-access.log'", $granted);
			$this->assertStringContainsString("'" . $root . "/customer1-error.log'", $granted);
		} finally {
			$this->removeTempDirectory($root);
		}
	}

	public function testSynchronizerUsesExactCustomerLogBasenames(): void
	{
		$root = $this->makeTempDirectory();
		touch($root . '/customer1-access.log');
		touch($root . '/customer1-access.log.1');
		touch($root . '/customer1-access.log.2.gz');
		touch($root . '/customer10-access.log');
		touch($root . '/customer1-access.log.backup');
		$states = [];
		$commands = [];
		try {
			$acl = new LogAcl(static function (string $command) use (&$commands): int {
				if (strpos($command, "'g:12001:r--'") !== false) {
					$commands[] = $command;
				}
				return 0;
			}, '/bin/true', '/bin/true');
			$synchronizer = $this->makeSynchronizer($acl, $root, true, [
				12001 => [
					'customerid' => 7,
					'prefix' => 'customer1-',
					'basenames' => ['customer1-access.log']
				]
			], $states);

			$this->assertTrue($synchronizer->sync());
			$granted = implode(' ', $commands);
			foreach (['customer1-access.log', 'customer1-access.log.1', 'customer1-access.log.2.gz'] as $expected) {
				$this->assertStringContainsString("'" . $root . '/' . $expected . "'", $granted);
			}
			$this->assertStringNotContainsString('customer10-access.log', $granted);
			$this->assertStringNotContainsString('.backup', $granted);
		} finally {
			$this->removeTempDirectory($root);
		}
	}

	public function testSynchronizerRetainsStateAfterPartialGrantFailure(): void
	{
		$root = $this->makeTempDirectory();
		touch($root . '/customer1-access.log');
		$states = [];
		try {
			$acl = new LogAcl(static function (string $command): int {
				return strpos($command, "'g:12001:r--'") !== false ? 1 : 0;
			}, '/bin/true', '/bin/true');
			$synchronizer = $this->makeSynchronizer($acl, $root, true, [
				12001 => [
					'customerid' => 7,
					'prefix' => 'customer1-',
					'basenames' => ['customer1-access.log']
				]
			], $states);

			$this->assertFalse($synchronizer->sync());
			$this->assertSame([12001 => ['customerid' => 7, 'gid' => 12001, 'logroot' => $root]], $states);
		} finally {
			$this->removeTempDirectory($root);
		}
	}

	public function testSynchronizerRevokesWhenTwoCustomersClaimTheSameLogfile(): void
	{
		// Ambiguity, not absence: the data is readable but does not say who owns
		// the file, so nothing may be granted and what we hold must come off.
		$root = $this->makeTempDirectory();
		$states = [[
			'customerid' => 7,
			'gid' => 12001,
			'logroot' => $root
		]];
		try {
			$acl = new LogAcl(static function (string $command): int {
				return 0;
			}, '/bin/true', '/bin/true');
			$synchronizer = new LogAclSynchronizer(
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
				static function (): array {
					// Same basename claimed by two different customers.
					return [
						12001 => ['customerid' => 7, 'prefix' => 'customer1-', 'basenames' => ['shared-access.log']],
						12002 => ['customerid' => 8, 'prefix' => 'customer2-', 'basenames' => ['shared-access.log']]
					];
				},
				static function () use (&$states): array {
					return $states;
				},
				static function (int $gid, int $customerid, string $logroot): void {
				},
				static function (int $gid, string $logroot) use (&$states): void {
					$states = [];
				}
			);

			$this->assertFalse($synchronizer->sync());
			$this->assertSame([], $states, 'ambiguous ownership must revoke managed state');
		} finally {
			$this->removeTempDirectory($root);
		}
	}

	public function testSynchronizerRejectsLogfileOwnershipCollision(): void
	{
		$root = $this->makeTempDirectory();
		touch($root . '/shared-access.log');
		$states = [];
		$commands = [];
		try {
			$acl = new LogAcl(static function (string $command) use (&$commands): int {
				$commands[] = $command;
				return 0;
			}, '/bin/true', '/bin/true');
			$synchronizer = $this->makeSynchronizer($acl, $root, true, [
				12001 => [
					'customerid' => 7,
					'prefix' => 'customer1-',
					'basenames' => ['shared-access.log']
				],
				12002 => [
					'customerid' => 8,
					'prefix' => 'customer2-',
					'basenames' => ['shared-access.log']
				]
			], $states);

			$this->assertFalse($synchronizer->sync());
			$this->assertSame([], $states);
			$this->assertStringNotContainsString("'g:12001:r--'", implode(' ', $commands));
			$this->assertStringNotContainsString("'g:12002:r--'", implode(' ', $commands));
		} finally {
			$this->removeTempDirectory($root);
		}
	}

	public function testSynchronizerCleansStateWhenDisabled(): void
	{
		$root = $this->makeTempDirectory();
		touch($root . '/customer1-access.log.1.gz');
		$states = [[
			'customerid' => 7,
			'gid' => 12001,
			'logroot' => $root
		]];
		try {
			$commands = [];
			$acl = new LogAcl(static function (string $command) use (&$commands): int {
				if (strpos($command, "'-x'") !== false) {
					$commands[] = $command;
				}
				return 0;
			}, '/bin/true', '/bin/true');
			$synchronizer = $this->makeSynchronizer($acl, $root, false, [], $states);

			$this->assertTrue($synchronizer->sync());
			$this->assertSame([], $states);
			$this->assertCount(2, $commands);
		} finally {
			$this->removeTempDirectory($root);
		}
	}

	public function testSynchronizerCleansOldStateWhenCurrentRootIsUnavailable(): void
	{
		$oldRoot = $this->makeTempDirectory();
		touch($oldRoot . '/customer1-access.log');
		$states = [[
			'customerid' => 7,
			'gid' => 12001,
			'logroot' => $oldRoot
		]];
		try {
			$acl = new LogAcl(static function (string $command): int {
				return 0;
			}, '/bin/true', '/bin/true');
			$synchronizer = new LogAclSynchronizer(
				$acl,
				static function (): bool {
					return true;
				},
				static function (): ?string {
					return null;
				},
				static function (): bool {
					return false;
				},
				static function (): array {
					throw new RuntimeException('Desired customers must not be loaded while disabled');
				},
				static function () use (&$states): array {
					return $states;
				},
				static function (int $gid, int $customerid, string $logroot): void {
				},
				static function (int $gid, string $logroot) use (&$states): void {
					$states = [];
				}
			);

			$this->assertTrue($synchronizer->sync());
			$this->assertSame([], $states);
		} finally {
			$this->removeTempDirectory($oldRoot);
		}
	}

	public function testSynchronizerRevokesBeforeGrantingReusedGid(): void
	{
		$root = $this->makeTempDirectory();
		touch($root . '/customer1-access.log');
		touch($root . '/customer2-access.log');
		$states = [[
			'customerid' => 7,
			'gid' => 12001,
			'logroot' => $root
		]];
		$commands = [];
		try {
			$acl = new LogAcl(static function (string $command) use (&$commands): int {
				if (strpos($command, "'-x'") !== false || strpos($command, "'g:12001:r--'") !== false) {
					$commands[] = $command;
				}
				return 0;
			}, '/bin/true', '/bin/true');
			$synchronizer = $this->makeSynchronizer($acl, $root, true, [
				12001 => [
					'customerid' => 8,
					'prefix' => 'customer2-',
					'basenames' => ['customer2-access.log']
				]
			], $states);

			$this->assertTrue($synchronizer->sync());
			$this->assertSame(8, $states[12001]['customerid']);
			$oldRevokes = array_filter($commands, static function (string $command): bool {
				return strpos($command, 'customer1-access.log') !== false && strpos($command, "'-x'") !== false;
			});
			$newGrants = array_filter($commands, static function (string $command): bool {
				return strpos($command, 'customer2-access.log') !== false && strpos($command, "'g:12001:r--'") !== false;
			});
			$this->assertNotEmpty($oldRevokes);
			$this->assertNotEmpty($newGrants);
		} finally {
			$this->removeTempDirectory($root);
		}
	}

	public function testSynchronizerCleansStaleStateWhenEnabledRootProbeFails(): void
	{
		$currentRoot = $this->makeTempDirectory();
		$oldRoot = $this->makeTempDirectory();
		touch($oldRoot . '/customer1-access.log');
		$states = [[
			'customerid' => 7,
			'gid' => 12001,
			'logroot' => $oldRoot
		]];
		try {
			$acl = new LogAcl(static function (string $command): int {
				return strpos($command, "'u:") !== false ? 1 : 0;
			}, '/bin/true', '/bin/true');
			$synchronizer = new LogAclSynchronizer(
				$acl,
				static function (): bool {
					return true;
				},
				static function () use ($currentRoot): ?string {
					return $currentRoot;
				},
				static function (): bool {
					return true;
				},
				static function (): array {
					throw new RuntimeException('Desired customers must not be loaded after a failed probe');
				},
				static function () use (&$states): array {
					return $states;
				},
				static function (int $gid, int $customerid, string $logroot): void {
				},
				static function (int $gid, string $logroot) use (&$states): void {
					$states = [];
				}
			);

			$this->assertFalse($synchronizer->sync());
			$this->assertSame([], $states);
		} finally {
			$this->removeTempDirectory($currentRoot);
			$this->removeTempDirectory($oldRoot);
		}
	}

	public function testSynchronizerRevokesOldRootWhenLogRootChanges(): void
	{
		$oldRoot = $this->makeTempDirectory();
		$newRoot = $this->makeTempDirectory();
		touch($oldRoot . '/customer1-access.log');
		touch($newRoot . '/customer1-access.log');
		$states = [[
			'customerid' => 7,
			'gid' => 12001,
			'logroot' => $oldRoot
		]];
		try {
			$commands = [];
			$acl = new LogAcl(static function (string $command) use (&$commands): int {
				if (strpos($command, "'-x'") !== false) {
					$commands[] = $command;
				}
				return 0;
			}, '/bin/true', '/bin/true');
			$synchronizer = $this->makeSynchronizer($acl, $newRoot, true, [
				12001 => [
					'customerid' => 7,
					'prefix' => 'customer1-',
					'basenames' => ['customer1-access.log']
				]
			], $states);

			$this->assertTrue($synchronizer->sync());
			$this->assertCount(1, $states);
			$this->assertSame($newRoot, $states[12001]['logroot']);
		} finally {
			$this->removeTempDirectory($oldRoot);
			$this->removeTempDirectory($newRoot);
		}
	}

	/**
	 * @param LogAcl $acl
	 * @param string $root
	 * @param bool $enabled
	 * @param array $desired
	 * @param array $states
	 * @return LogAclSynchronizer
	 */
	private function makeSynchronizer(LogAcl $acl, string $root, bool $enabled, array $desired, array &$states): LogAclSynchronizer
	{
		return new LogAclSynchronizer(
			$acl,
			static function (): bool {
				return true;
			},
			static function () use ($root): ?string {
				return $root;
			},
			static function () use ($enabled): bool {
				return $enabled;
			},
			static function () use ($desired): array {
				return $desired;
			},
			static function () use (&$states): array {
				return $states;
			},
			static function (int $gid, int $customerid, string $logroot) use (&$states): void {
				$states[$gid] = ['customerid' => $customerid, 'gid' => $gid, 'logroot' => $logroot];
			},
			static function (int $gid, string $logroot) use (&$states): void {
				foreach ($states as $key => $state) {
					if ((int)$state['gid'] === $gid && $state['logroot'] === $logroot) {
						unset($states[$key]);
					}
				}
			}
		);
	}

	private function makeTempDirectory(): string
	{
		$directory = sys_get_temp_dir() . '/froxlor-log-acl-' . bin2hex(random_bytes(6));
		mkdir($directory, 0750, true);
		return $directory;
	}

	private function removeTempDirectory(string $directory): void
	{
		if (!is_dir($directory) || is_link($directory)) {
			return;
		}
		foreach (scandir($directory) ?: [] as $entry) {
			if ($entry === '.' || $entry === '..') {
				continue;
			}
			$path = $directory . '/' . $entry;
			if (is_dir($path) && !is_link($path)) {
				$this->removeTempDirectory($path);
			} else {
				unlink($path);
			}
		}
		rmdir($directory);
	}
}
