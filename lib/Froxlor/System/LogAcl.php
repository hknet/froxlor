<?php

/**
 * This file is part of the froxlor project.
 * Copyright (c) 2010 the froxlor Team (see authors).
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, you can also view it online at
 * https://files.froxlor.org/misc/COPYING.txt
 *
 * @copyright  the authors
 * @author     froxlor team <team@froxlor.org>
 * @license    https://files.froxlor.org/misc/COPYING.txt GPLv2
 */

namespace Froxlor\System;

use InvalidArgumentException;

class LogAcl
{
	/**
	 * Maximum number of paths handed to a single setfacl call.
	 */
	public const SETFACL_BATCH_SIZE = 256;

	/**
	 * Filename of the transient ACL capability probe.
	 */
	public const PROBE_FILENAME = '.froxlor-acl-probe';

	/**
	 * @var string|null
	 */
	private $setfacl;

	/**
	 * @var string|null
	 */
	private $getfacl;

	/**
	 * @var callable
	 */
	private $executor;

	/**
	 * @var callable|null
	 */
	private $aclReader;

	/** @var string */
	private $lastError = '';

	/**
	 * @param callable|null $executor receives a command and returns its exit status
	 * @param string|null $setfacl path to setfacl
	 * @param string|null $getfacl path to getfacl
	 * @param callable|null $aclReader receives a getfacl command and returns [status, output]
	 * @param callable|null $binaryFinder receives a binary name and returns its path or null
	 */
	public function __construct(
		?callable $executor = null,
		?string $setfacl = null,
		?string $getfacl = null,
		?callable $aclReader = null,
		?callable $binaryFinder = null
	) {
		$this->executor = $executor ?? static function (string $command): int {
			$output = [];
			$status = 1;
			exec($command, $output, $status);
			return $status;
		};
		$this->aclReader = $aclReader;
		if ($this->aclReader === null && $executor === null) {
			$this->aclReader = static function (string $command): array {
				$output = [];
				$status = 1;
				exec($command, $output, $status);
				return [$status, $output];
			};
		}
		$binaryFinder = $binaryFinder ?? static function (string $name): ?string {
			return self::findBinary($name);
		};
		$this->setfacl = $setfacl !== null ? $setfacl : $binaryFinder('setfacl');
		$this->getfacl = $getfacl !== null ? $getfacl : $binaryFinder('getfacl');
	}

	/**
	 * Return the first executable ACL utility found in standard system paths.
	 *
	 * @param string $name
	 * @return string|null
	 */
	public static function findBinary(string $name): ?string
	{
		foreach (['/usr/bin', '/bin', '/usr/sbin', '/sbin'] as $directory) {
			$path = $directory . '/' . $name;
			if (is_executable($path)) {
				return $path;
			}
		}
		return null;
	}

	/**
	 * @return bool
	 */
	public function isAvailable(): bool
	{
		return $this->setfacl !== null && $this->getfacl !== null;
	}

	/**
	 * Probe both ACL utilities against a temporary file on the target filesystem.
	 *
	 * @param string|null $probeDirectory existing directory to probe beneath
	 * @return bool
	 */
	public function isUsable(?string $probeDirectory = null): bool
	{
		if (!$this->isAvailable()) {
			$this->lastError = 'Required ACL tools are unavailable: ' . implode(', ', $this->getMissingTools());
			return false;
		}

		$base = rtrim(sys_get_temp_dir(), '/');
		if ($probeDirectory !== null) {
			if ($probeDirectory === '' || $probeDirectory[0] !== '/' || is_link(rtrim($probeDirectory, '/'))) {
				return false;
			}
			$realBase = realpath($probeDirectory);
			if ($realBase === false || !is_dir($realBase) || $realBase === '/') {
				return false;
			}
			$base = rtrim($realBase, '/');
		}
		// A single fixed file keeps the footprint minimal: reconciliation holds an
		// exclusive lock, so two probes can never exist at once, and only root can
		// write here. Anything left over belongs to a run that died, so remove it
		// rather than let it linger in a directory customers can list.
		$file = $base . '/' . self::PROBE_FILENAME;
		if (is_link($file) || (file_exists($file) && !is_file($file))) {
			$this->lastError = 'The ACL probe path is not a regular file: ' . $file;
			return false;
		}
		@unlink($file);
		// Suppress the PHP warning: a failed probe is reported through lastError,
		// and cron would otherwise mail the raw warning on top of the logged error.
		if (@touch($file) === false) {
			$this->lastError = 'Unable to create an ACL probe file below: ' . $base;
			return false;
		}
		@chmod($file, 0600);
		$uid = function_exists('posix_geteuid') ? posix_geteuid() : fileowner($file);
		$success = $this->runSetfacl(['-m', 'u:' . (int)$uid . ':r--', '--', $file])
			&& $this->runGetfacl($file);
		if (!$success && $this->lastError === '') {
			$this->lastError = 'Unable to apply or inspect an ACL below: ' . $base;
		}
		@unlink($file);
		return $success;
	}

	public function getLastError(): string
	{
		return $this->lastError;
	}

	/**
	 * @return string[]
	 */
	public function getMissingTools(): array
	{
		$missing = [];
		if ($this->setfacl === null) {
			$missing[] = 'setfacl';
		}
		if ($this->getfacl === null) {
			$missing[] = 'getfacl';
		}
		return $missing;
	}

	/**
	 * Grant a customer GID read and traversal access to the logfile directory.
	 *
	 * @param string $directory
	 * @param int $gid
	 * @return bool
	 */
	public function grantDirectoryAccess(string $directory, int $gid): bool
	{
		$this->assertGid($gid);
		$this->assertPath($directory);
		$mode = @fileperms($directory);
		if ($mode !== false && (($mode & 0050) !== 0050)) {
			// Preserving the existing mode would leave the ACL mask without r or x,
			// making the named entry ineffective.
			$this->lastError = 'The directory group mode cannot carry read and traversal permission: ' . $directory;
			return false;
		}
		// r-x rather than --x: a named entry replaces the "other" class for a
		// matching process, so traversal-only would stop customers listing the
		// directory at all and leave them unable to discover their own logfiles.
		return $this->runSetfaclPreservingMode(['-m', 'g:' . $gid . ':r-x', '--', $directory], $directory);
	}

	/**
	 * Grant read-only access to a logfile.
	 *
	 * @param string $logfile
	 * @param int $gid
	 * @return bool
	 */
	public function grantLogfileRead(string $logfile, int $gid): bool
	{
		$this->assertGid($gid);
		$this->assertPath($logfile);
		$mode = @fileperms($logfile);
		if ($mode !== false && (($mode & 0040) === 0)) {
			// Preserving the existing mode would leave the ACL mask without r,
			// making the named read entry ineffective.
			$this->lastError = 'The logfile group mode cannot carry read permission: ' . $logfile;
			return false;
		}
		return $this->runSetfaclPreservingMode(['-m', 'g:' . $gid . ':r--', '--', $logfile], $logfile);
	}

	/**
	 * Grant read-only access to many logfiles using as few setfacl calls as
	 * possible. Reconciliation uses this so its cost scales with the number of
	 * customers instead of the number of logfiles.
	 *
	 * @param string[] $logfiles
	 * @param int $gid
	 * @return bool
	 */
	public function grantLogfileReadMany(array $logfiles, int $gid): bool
	{
		$this->assertGid($gid);
		$success = true;
		$batch = [];
		foreach ($logfiles as $logfile) {
			$this->assertPath($logfile);
			$mode = @fileperms($logfile);
			if ($mode !== false && (($mode & 0040) === 0)) {
				$this->lastError = 'The logfile group mode cannot carry read permission: ' . $logfile;
				$success = false;
				continue;
			}
			$batch[] = $logfile;
		}

		// setfacl accepts many paths per call; chunk so the argument list stays
		// well inside ARG_MAX even with long customer and domain names.
		foreach (array_chunk($batch, self::SETFACL_BATCH_SIZE) as $chunk) {
			$modes = [];
			foreach ($chunk as $path) {
				$modes[$path] = @fileperms($path);
			}
			if (!$this->runSetfacl(array_merge(['-m', 'g:' . $gid . ':r--', '--'], $chunk))) {
				$success = false;
			}
			if (!$this->restoreModes($modes)) {
				$success = false;
			}
		}
		return $success;
	}

	/**
	 * Remove the managed customer GID entry from many paths using as few setfacl
	 * calls as possible.
	 *
	 * Unlike revoke(), this does not inspect each path first: setfacl -x succeeds
	 * and leaves the mode untouched when the entry is already absent, so the extra
	 * getfacl per file bought nothing and dominated the cost of disabling the
	 * feature on installations with many logfiles.
	 *
	 * @param string[] $paths
	 * @param int[] $gids
	 * @return bool
	 */
	public function revokeMany(array $paths, array $gids): bool
	{
		$entries = [];
		foreach ($gids as $gid) {
			$this->assertGid((int)$gid);
			$entries[] = 'g:' . (int)$gid;
		}
		if (empty($entries)) {
			return true;
		}

		$success = true;
		$batch = [];
		foreach ($paths as $path) {
			$this->assertPath($path);
			// A logfile that disappeared between the directory scan and this call,
			// through rotation or deletion, carries no ACL and needs no revocation.
			if (!file_exists($path)) {
				continue;
			}
			$batch[] = $path;
		}

		// setfacl removes several entries in one call, so every managed GID comes
		// off a file in a single invocation rather than one pass per GID.
		$removal = implode(',', $entries);
		foreach (array_chunk($batch, self::SETFACL_BATCH_SIZE) as $chunk) {
			$modes = [];
			foreach ($chunk as $path) {
				$modes[$path] = @fileperms($path);
			}
			if (!$this->runSetfacl(array_merge(['-x', $removal, '--'], $chunk))) {
				$success = false;
			}
			if (!$this->restoreModes($modes)) {
				$success = false;
			}
		}
		return $success;
	}

	/**
	 * Remove a customer GID ACL entry from a path.
	 *
	 * @param string $path
	 * @param int $gid
	 * @return bool
	 */
	public function revoke(string $path, int $gid): bool
	{
		$this->assertGid($gid);
		$this->assertPath($path);
		$entry = $this->hasGroupEntry($path, $gid);
		if ($entry === false) {
			return true;
		}
		if ($entry === null) {
			$this->lastError = 'Unable to inspect the ACL before revocation: ' . $path;
			return false;
		}
		return $this->runSetfaclPreservingMode(['-x', 'g:' . $gid, '--', $path], $path);
	}

	/**
	 * Return the canonical logfile basename shared by Apache, Nginx, and ACL
	 * reconciliation. Centralizing this security boundary prevents the ACL
	 * target from drifting from the file used by the webserver and preserves
	 * Froxlor's existing speciallogfile root/parent-domain naming behavior.
	 *
	 * @param array $domain
	 * @param string $type access or error
	 * @return string
	 */
	public static function getLogfileBasename(array $domain, string $type): string
	{
		if (!in_array($type, ['access', 'error'], true)) {
			throw new InvalidArgumentException('Unknown logfile type');
		}
		$components = [(string)($domain['loginname'] ?? ''), (string)($domain['domain'] ?? '')];
		if (isset($domain['parentdomain'])) {
			$components[] = (string)$domain['parentdomain'];
		}
		if ($components[0] === '' || $components[1] === '' || strpbrk(implode('', $components), "/\0\r\n") !== false) {
			throw new InvalidArgumentException('A logfile domain contains an unsafe path component');
		}

		$special = '';
		if ((string)($domain['speciallogfile'] ?? '0') === '1') {
			if ((int)($domain['parentdomainid'] ?? 0) === 0) {
				$special = '-' . $domain['domain'];
			} elseif (array_key_exists('parentdomain', $domain)) {
				$special = '-' . $domain['parentdomain'];
			}
		}
		return $domain['loginname'] . $special . '-' . $type . '.log';
	}

	/**
	 * Return only the active logfile basenames enabled for a vhost row. The
	 * synchronizer expands these exact names to supported rotation variants.
	 *
	 * @param array $domain
	 * @return string[]
	 */
	public static function getLogfileBasenames(array $domain): array
	{
		if (empty($domain['loginname']) || empty($domain['domain'])) {
			throw new InvalidArgumentException('A logfile domain requires loginname and domain');
		}
		$basenames = [];
		if ((string)($domain['writeerrorlog'] ?? '0') === '1') {
			$basenames[] = self::getLogfileBasename($domain, 'error');
		}
		if ((string)($domain['writeaccesslog'] ?? '0') === '1') {
			$basenames[] = self::getLogfileBasename($domain, 'access');
		}
		return $basenames;
	}

	/**
	 * Check whether a candidate is the base logfile or a supported logrotate variant.
	 *
	 * @param string $basename
	 * @param string $candidate
	 * @return bool
	 */
	public static function isLogfileVariant(string $basename, string $candidate): bool
	{
		$pattern = '/^' . preg_quote($basename, '/') . '(?:\.[0-9]+(?:\.(?:gz|bz2|xz|zst))?)?$/D';
		return preg_match($pattern, $candidate) === 1;
	}

	/**
	 * Return whether a filename has a Froxlor/logrotate logfile suffix.
	 *
	 * @param string $candidate
	 * @return bool
	 */
	public static function isLogfileCandidate(string $candidate): bool
	{
		return preg_match('/\.log(?:\.[0-9]+(?:\.(?:gz|bz2|xz|zst))?)?$/D', $candidate) === 1;
	}

	/**
	 * Map a logfile or one of its rotated variants back to the active basename,
	 * or null when the name is not a Froxlor logfile at all. This lets callers
	 * index a directory by basename in a single pass.
	 *
	 * @param string $candidate
	 * @return string|null
	 */
	public static function getActiveLogfileBasename(string $candidate): ?string
	{
		$matches = [];
		if (preg_match('/^(.*\.log)(?:\.[0-9]+(?:\.(?:gz|bz2|xz|zst))?)?$/D', $candidate, $matches) !== 1) {
			return null;
		}
		return $matches[1];
	}

	/**
	 * @param int $gid
	 * @return void
	 */
	private function assertGid(int $gid): void
	{
		if ($gid < 1) {
			throw new InvalidArgumentException('A customer GID must be greater than zero');
		}
	}

	/**
	 * @param string $path
	 * @return void
	 */
	private function assertPath(string $path): void
	{
		if ($path === '' || $path[0] !== '/' || strpbrk($path, "\0\r\n") !== false) {
			throw new InvalidArgumentException('An ACL path must be an absolute path without control characters');
		}

		$current = '';
		foreach (explode('/', ltrim($path, '/')) as $component) {
			if ($component === '') {
				continue;
			}
			$current .= '/' . $component;
			if (is_link($current)) {
				throw new InvalidArgumentException('ACL paths must not contain symlink components');
			}
		}
	}

	/**
	 * Return whether getfacl reports the managed numeric group entry.
	 *
	 * @param string $path
	 * @param int $gid
	 * @return bool|null null when the ACL cannot be inspected
	 */
	private function hasGroupEntry(string $path, int $gid): ?bool
	{
		if ($this->aclReader === null || $this->getfacl === null) {
			return true;
		}
		$reader = $this->aclReader;
		// --absolute-names suppresses getfacl's informational stderr message about
		// stripping the leading slash, which would otherwise be mailed by cron.
		$result = $reader(implode(' ', array_map('escapeshellarg', [$this->getfacl, '--absolute-names', '--', $path])));
		if (!is_array($result) || count($result) !== 2 || (int)$result[0] !== 0 || !is_array($result[1])) {
			return null;
		}
		$groupName = '';
		if (function_exists('posix_getgrgid')) {
			$group = posix_getgrgid($gid);
			$groupName = is_array($group) ? (string)$group['name'] : '';
		}
		foreach ($result[1] as $line) {
			if (preg_match('/^group:(?:' . preg_quote((string)$gid, '/') . ($groupName !== '' ? '|' . preg_quote($groupName, '/') : '') . '):/', trim((string)$line)) === 1) {
				return true;
			}
		}
		return false;
	}

	private function runSetfacl(array $arguments): bool
	{
		if ($this->setfacl === null) {
			$this->lastError = 'setfacl is unavailable';
			return false;
		}
		return $this->run(array_merge([$this->setfacl], $arguments));
	}

	/**
	 * Run setfacl while restoring the original Unix mode bits if the ACL mask
	 * changes them.
	 *
	 * @param string[] $arguments
	 * @param string $path
	 * @return bool
	 */
	private function runSetfaclPreservingMode(array $arguments, string $path): bool
	{
		$originalMode = @fileperms($path);
		$success = $this->runSetfacl($arguments);
		return $this->restoreModes([$path => $originalMode]) && $success;
	}

	/**
	 * Restore Unix mode bits that a recalculated ACL mask may have changed.
	 *
	 * @param array<string,int|false> $modes path => mode before the setfacl call
	 * @return bool
	 */
	private function restoreModes(array $modes): bool
	{
		$success = true;
		foreach ($modes as $path => $originalMode) {
			if ($originalMode === false) {
				continue;
			}
			$mode = $originalMode & 07777;
			$currentMode = @fileperms($path);
			if ($currentMode !== false && (($currentMode & 07777) !== $mode) && !@chmod($path, $mode)) {
				$this->lastError = 'Unable to restore the original Unix mode: ' . $path;
				$success = false;
			}
		}
		return $success;
	}

	/**
	 * @param string $path
	 * @return bool
	 */
	private function runGetfacl(string $path): bool
	{
		if ($this->getfacl === null) {
			$this->lastError = 'getfacl is unavailable';
			return false;
		}
		// Keep successful probes silent on stderr; root cron treats any output as
		// mail-worthy even though getfacl's leading-slash message is not an error.
		return $this->run([$this->getfacl, '--absolute-names', '--', $path]);
	}

	/**
	 * @param string[] $arguments
	 * @return bool
	 */
	private function run(array $arguments): bool
	{
		$command = implode(' ', array_map('escapeshellarg', $arguments));
		$executor = $this->executor;
		$status = $executor($command);
		if ($status !== 0) {
			$this->lastError = 'ACL command failed with exit status ' . (int)$status . ': ' . $command;
			return false;
		}
		return true;
	}
}
