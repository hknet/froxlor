<?php

use Froxlor\System\LogAcl;
use PHPUnit\Framework\TestCase;

/**
 * @group integration
 */
class LogAclIntegrationTest extends TestCase
{
	public function testRealAclGrantAndRevokePreservesMode(): void
	{
		$acl = new LogAcl();
		if (!$acl->isUsable()) {
			$this->markTestSkipped('setfacl/getfacl or filesystem ACL support is unavailable');
		}

		$setfacl = LogAcl::findBinary('setfacl');
		$getfacl = LogAcl::findBinary('getfacl');
		if ($setfacl === null || $getfacl === null) {
			$this->markTestSkipped('setfacl/getfacl are unavailable');
		}

		$directory = sys_get_temp_dir() . '/froxlor-log-acl-integration-' . bin2hex(random_bytes(6));
		mkdir($directory, 0750, true);
		$file = $directory . '/customer1-access.log';
		touch($file);
		chmod($file, 0640);
		$mode = fileperms($file) & 07777;
		$directoryMode = fileperms($directory) & 07777;
		$gid = function_exists('posix_getegid') ? posix_getegid() + 1 : filegroup($file) + 1;

		try {
			$this->assertTrue($acl->grantDirectoryAccess($directory, (int)$gid));
			$this->assertTrue($acl->grantLogfileRead($file, (int)$gid));
			$this->assertSame($mode, fileperms($file) & 07777);
			$this->assertSame($directoryMode, fileperms($directory) & 07777);

			$output = [];
			$status = 1;
			exec(escapeshellarg($getfacl) . ' --absolute-names -- ' . escapeshellarg($file), $output, $status);
			$this->assertSame(0, $status);
			$this->assertStringContainsString('group:' . (int)$gid . ':r--', implode("\n", $output));
			$directoryOutput = [];
			$directoryStatus = 1;
			exec(escapeshellarg($getfacl) . ' --absolute-names -- ' . escapeshellarg($directory), $directoryOutput, $directoryStatus);
			$this->assertSame(0, $directoryStatus);
			$this->assertStringContainsString('group:' . (int)$gid . ':r-x', implode("\n", $directoryOutput));

			$this->assertTrue($acl->revoke($file, (int)$gid));
			$this->assertTrue($acl->revoke($directory, (int)$gid));
			$this->assertSame($mode, fileperms($file) & 07777);
			$this->assertSame($directoryMode, fileperms($directory) & 07777);
		} finally {
			@unlink($file);
			@rmdir($directory);
		}
	}
}
