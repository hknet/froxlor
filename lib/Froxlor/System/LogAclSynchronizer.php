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

use Exception;
use Froxlor\Database\Database;
use Froxlor\FileDir;
use Froxlor\Settings;
use PDO;

class LogAclSynchronizer
{
	/**
	 * Root-owned runtime directory holding the reconciliation lock.
	 */
	public const RUNTIME_DIRECTORY = '/run/froxlor';

	private LogAcl $acl;

	private string $lastError = '';

	/**
	 * Set when the desired set is readable but does not unambiguously say which
	 * customer owns which logfile.
	 */
	private bool $desiredAmbiguous = false;

	/** @var callable */
	private $rootChecker;

	/** @var callable */
	private $rootResolver;

	/** @var callable */
	private $enabledReader;

	/** @var callable */
	private $desiredProvider;

	/** @var callable */
	private $statesProvider;

	/** @var callable */
	private $stateStore;

	/** @var callable */
	private $stateDelete;

	/**
	 * @param LogAcl|null $acl
	 * @param callable|null $rootChecker
	 * @param callable|null $rootResolver
	 * @param callable|null $enabledReader
	 * @param callable|null $desiredProvider
	 * @param callable|null $statesProvider
	 * @param callable|null $stateStore
	 * @param callable|null $stateDelete
	 */
	public function __construct(
		?LogAcl $acl = null,
		?callable $rootChecker = null,
		?callable $rootResolver = null,
		?callable $enabledReader = null,
		?callable $desiredProvider = null,
		?callable $statesProvider = null,
		?callable $stateStore = null,
		?callable $stateDelete = null
	) {
		$this->acl = $acl ?? new LogAcl();
		$this->rootChecker = $rootChecker ?? static function (): bool {
			return function_exists('posix_geteuid') && posix_geteuid() === 0;
		};
		$this->rootResolver = $rootResolver ?? function (): ?string {
			return $this->getLogRoot();
		};
		$this->enabledReader = $enabledReader ?? static function (): bool {
			return (string)Settings::Get('system.logfiles_acl_enabled') === '1';
		};
		$this->desiredProvider = $desiredProvider ?? function (): array {
			return $this->getDesiredCustomers();
		};
		$this->statesProvider = $statesProvider ?? function (): array {
			return $this->getStates();
		};
		$this->stateStore = $stateStore ?? function (int $gid, int $customerid, string $root): void {
			$this->storeState($gid, $customerid, $root);
		};
		$this->stateDelete = $stateDelete ?? function (int $gid, string $root): void {
			$this->deleteState($gid, $root);
		};
	}

	/**
	 * Reconcile all Froxlor-managed customer logfile ACLs.
	 *
	 * This method is intentionally root-only. Web requests must enqueue or wait
	 * for the root cron rather than attempting to mutate logfile ACLs directly.
	 *
	 * @return bool true when all discovered operations succeeded
	 */
	/**
	 * @param int[] $customerids limit convergence to these customers; empty means all
	 */
	public function sync(array $customerids = []): bool
	{
		$this->lastError = '';
		$this->desiredAmbiguous = false;
		$rootChecker = $this->rootChecker;
		if (!$rootChecker()) {
			$this->lastError = 'Logfile ACL reconciliation must run as root';
			return false;
		}

		$lock = $this->acquireLock();
		if ($lock === null) {
			$this->lastError = 'Unable to acquire the logfile ACL reconciliation lock; another run may already be active';
			return false;
		}
		try {
			return $this->syncUnlocked(array_values(array_unique(array_map('intval', $customerids))));
		} finally {
			flock($lock, LOCK_UN);
			fclose($lock);
		}
	}

	public function getLastError(): string
	{
		return $this->lastError;
	}

	/**
	 * Compute desired grants and converge persisted state plus filesystem ACLs.
	 * Stale grants are always revoked before new grants, which is essential when
	 * a numeric customer GID has been reused.
	 */
	/**
	 * @param int[] $customerids
	 */
	private function syncUnlocked(array $customerids = []): bool
	{
		$scoped = !empty($customerids);
		$statesProvider = $this->statesProvider;
		$states = $statesProvider();
		$rootResolver = $this->rootResolver;
		$root = $rootResolver();
		$enabledReader = $this->enabledReader;
		$enabled = $enabledReader();
		$canGrant = false;
		if ($root !== null && $enabled) {
			// Probe the actual logfile filesystem before granting any ACLs.
			try {
				$canGrant = $this->acl->isUsable($root);
			} catch (Exception $e) {
				$canGrant = false;
			}
		} elseif (!$this->acl->isAvailable()) {
			// A disabled installation may still need to revoke state from an old
			// root, so binary availability is sufficient for cleanup attempts.
			$this->lastError = 'Required ACL tools are unavailable: ' . implode(', ', $this->acl->getMissingTools());
			return false;
		}

		$desired = [];
		$desiredLoadFailed = false;
		$desiredUnknown = false;
		if ($canGrant) {
			try {
				$desiredProvider = $this->desiredProvider;
				$desired = $desiredProvider();
				if ($this->desiredAmbiguous) {
					$desired = [];
					$desiredLoadFailed = true;
					$this->lastError = 'Two customers share one Unix GID';
				} elseif ($this->hasLogfileOwnershipCollision($desired)) {
					// Ambiguous ownership: the data is there but it does not say who
					// may read which file, so grant nothing and revoke what we hold.
					$desired = [];
					$desiredLoadFailed = true;
					$this->lastError = 'Multiple customers resolve to the same logfile basename';
				}
			} catch (Exception $e) {
				// The desired set could not be read at all. That is absence of
				// information, not ambiguity: the ACLs on disk were correct as of
				// the last successful run, so leave them untouched and retry rather
				// than revoke every customer because one query failed.
				$desiredLoadFailed = true;
				$desiredUnknown = true;
				$this->lastError = 'Unable to load desired logfile ACLs: ' . $e->getMessage();
			}
		}
		if ($desiredUnknown) {
			return false;
		}
		if ($scoped) {
			// Narrow to the requested customers only after the collision guard has
			// seen the complete desired set, or a clash with an unscoped customer
			// would go unnoticed.
			$desired = array_filter($desired, static function (array $customer) use ($customerids): bool {
				return in_array((int)$customer['customerid'], $customerids, true);
			});
		}
		$logfiles = [];
		$logfilesLoaded = true;
		if ($canGrant) {
			$logfiles = $this->getLogfiles($root);
			$logfilesLoaded = $logfiles !== null;
			if (!$logfilesLoaded) {
				$this->lastError = 'Unable to scan the configured logfile directory: ' . $root;
			}
		} elseif ($enabled && $this->lastError === '') {
			$this->lastError = 'The configured logfile directory failed the ACL capability probe';
		}
		$success = !$enabled || ($canGrant && !$desiredLoadFailed && $logfilesLoaded);
		$stateDelete = $this->stateDelete;
		$blocked = [];

		// Revoke stale roots and GID/customer combinations before applying new
		// grants. This prevents a reused GID from retaining access to old logs.
		// Group the stale states by logfile root so each root is walked once for
		// every GID that has to come off it, instead of once per GID.
		$stale = [];
		foreach ($states as $state) {
			if ($scoped && !in_array((int)$state['customerid'], $customerids, true)) {
				// Another customer's managed state is not this run's business.
				continue;
			}
			$gid = (int)$state['gid'];
			$stateRoot = $state['logroot'];
			$desiredCustomer = ($root !== null && $stateRoot === $root) ? ($desired[$gid] ?? null) : null;
			if (is_array($desiredCustomer) && (int)$desiredCustomer['customerid'] === (int)$state['customerid']) {
				continue;
			}
			$stale[$stateRoot][] = $gid;
		}

		foreach ($stale as $stateRoot => $gids) {
			$gids = array_values(array_unique($gids));
			try {
				$revoked = $this->revokeStates($gids, (string)$stateRoot);
			} catch (Exception $e) {
				$revoked = false;
				$this->lastError = 'Unable to revoke logfile ACLs below ' . $stateRoot . ': ' . $e->getMessage();
			}
			foreach ($gids as $gid) {
				if ($revoked) {
					$stateDelete($gid, (string)$stateRoot);
				} else {
					// The failure is not attributable to one GID, so every state row
					// in this batch is kept and retried on the next run.
					$blocked[$this->stateKey($gid, (string)$stateRoot)] = true;
					$success = false;
				}
			}
		}

		if ($canGrant && $logfilesLoaded) {
			$stateStore = $this->stateStore;
			foreach ($desired as $gid => $customer) {
				$key = $this->stateKey((int)$gid, $root);
				if (isset($blocked[$key])) {
					continue;
				}
				try {
					// Retain state before mutating the filesystem so a partial grant
					// remains discoverable for a later cleanup pass.
					$stateStore((int)$gid, (int)$customer['customerid'], $root);
					if (!$this->applyCustomer($root, (int)$gid, $customer['basenames'], $customer['prefix'] ?? null, $logfiles)) {
						$success = false;
					}
				} catch (Exception $e) {
					$success = false;
					$this->lastError = 'Unable to apply logfile ACLs for GID ' . (int)$gid . ': ' . $e->getMessage();
				}
			}
		}

		if (!$success && $this->lastError === '' && $this->acl->getLastError() !== '') {
			$this->lastError = $this->acl->getLastError();
		}
		return $success;
	}

	/**
	 * @return string|null canonical log root without a trailing slash
	 */
	private function getLogRoot(): ?string
	{
		try {
			$configured = FileDir::makeCorrectDir((string)Settings::Get('system.logfiles_directory'));
		} catch (Exception $e) {
			return null;
		}

		$configured = rtrim($configured, '/');
		if ($configured === '' || is_link($configured)) {
			return null;
		}
		$real = realpath($configured);
		if ($real === false || !is_dir($real) || is_link($real) || $real === '/') {
			return null;
		}
		return rtrim($real, '/');
	}

	/**
	 * @return array<int,array{customerid:int,prefix:string,basenames:string[]}>
	 */
	private function getDesiredCustomers(): array
	{
		if ((string)Settings::Get('system.logfiles_acl_enabled') !== '1') {
			return [];
		}

		$stmt = Database::query("SELECT `d`.*, `pd`.`domain` AS `parentdomain`,
				`c`.`customerid`, `c`.`loginname`, `c`.`guid`,
				`c`.`deactivated` AS `customer_deactivated`,
				`c`.`logviewenabled`
			FROM `" . TABLE_PANEL_DOMAINS . "` `d`
			LEFT JOIN `" . TABLE_PANEL_CUSTOMERS . "` `c` USING (`customerid`)
			LEFT JOIN `" . TABLE_PANEL_DOMAINS . "` `pd` ON (`pd`.`id` = `d`.`parentdomainid`)
			WHERE `d`.`aliasdomain` IS NULL AND `d`.`email_only` <> '1'
			ORDER BY `d`.`parentdomainid` DESC, `d`.`domain` ASC");

		$customers = [];
		while ($domain = $stmt->fetch(PDO::FETCH_ASSOC)) {
			if ((string)$domain['logviewenabled'] !== '1' || (string)$domain['customer_deactivated'] === '1') {
				continue;
			}

			$gid = (int)$domain['guid'];
			if ($gid < 1 || (int)$domain['customerid'] < 1) {
				continue;
			}
			$basenames = LogAcl::getLogfileBasenames($domain);
			if (empty($basenames)) {
				continue;
			}

			if (!isset($customers[$gid])) {
				$customers[$gid] = [
					'customerid' => (int)$domain['customerid'],
					'prefix' => (string)$domain['loginname'] . '-',
					'basenames' => []
				];
			}
			if ($customers[$gid]['customerid'] !== (int)$domain['customerid']) {
				// Two customers share one Unix GID. The data is present but says
				// nothing about who may read which file, so report ambiguity
				// rather than throwing: an exception from here must only ever mean
				// that the desired set could not be read at all.
				$this->desiredAmbiguous = true;
				return [];
			}
			$customers[$gid]['basenames'] = array_merge($customers[$gid]['basenames'], $basenames);
		}

		foreach ($customers as &$customer) {
			$customer['basenames'] = array_values(array_unique($customer['basenames']));
		}
		unset($customer);
		return $customers;
	}

	/**
	 * @param string $root
	 * @param int $gid
	 * @param string[] $basenames
	 * @param string|null $prefix
	 * @param array<string,string[]> $logfiles active basename => all its paths
	 * @return bool
	 */
	private function applyCustomer(string $root, int $gid, array $basenames, ?string $prefix, array $logfiles): bool
	{
		// The managed entry allows traversal and listing, so a customer can find
		// its own logfiles from a shell. Listing exposes every customer's logfile
		// names; the per-file entries keep the contents protected.
		$success = $this->acl->grantDirectoryAccess($root, $gid);

		// $logfiles is indexed by active basename, so a customer's files are found
		// by direct lookup. Nothing here walks the whole directory per customer.
		$grant = [];
		foreach ($basenames as $basename) {
			foreach ($logfiles[$basename] ?? [] as $path) {
				$grant[$path] = $path;
			}
		}
		if (!$this->acl->grantLogfileReadMany(array_values($grant), $gid)) {
			$success = false;
		}

		// Files that carry this customer's prefix but are no longer one of its
		// active logfiles must lose the managed entry again.
		if ($prefix !== null) {
			$stale = [];
			foreach ($logfiles as $basename => $paths) {
				if (strpos($basename, $prefix) !== 0 || in_array($basename, $basenames, true)) {
					continue;
				}
				foreach ($paths as $path) {
					$stale[] = $path;
				}
			}
			if (!empty($stale) && !$this->acl->revokeMany($stale, [$gid])) {
				$success = false;
			}
		}
		return $success;
	}

	/**
	 * @param string $root
	 * @return array<string,string[]>|null active basename => all its paths
	 */
	private function getLogfiles(string $root): ?array
	{
		// Scan once per reconciliation and reuse the map for every customer. This
		// avoids a full directory walk per customer on installations with many logs.
		try {
			$iterator = new \DirectoryIterator($root);
		} catch (\UnexpectedValueException $e) {
			return null;
		}
		$logfiles = [];
		foreach ($iterator as $entry) {
			if ($entry->isDot() || $entry->isLink() || !$entry->isFile()) {
				continue;
			}
			$name = $entry->getFilename();
			$basename = LogAcl::getActiveLogfileBasename($name);
			if ($basename !== null) {
				// Group every rotated variant under its active basename so each
				// customer can look its files up directly instead of scanning.
				$logfiles[$basename][] = $entry->getPathname();
			}
		}
		return $logfiles;
	}

	/**
	 * @param int $gid
	 * @param string $root
	 * @return bool
	 */
	/**
	 * Remove the managed entries of every given GID from one logfile root.
	 *
	 * The directory is walked once for the whole set: setfacl accepts several
	 * entries per call, so revoking fifty customers costs one pass rather than
	 * fifty. No realistic failure here is attributable to a single GID, so the
	 * caller keeps every involved state row and retries.
	 *
	 * @param int[] $gids
	 */
	private function revokeStates(array $gids, string $root): bool
	{
		if (empty($gids)) {
			return true;
		}
		if ($root === '' || $root[0] !== '/' || strpbrk($root, "\0\r\n") !== false) {
			return false;
		}
		if (!is_dir($root) || is_link($root)) {
			// The managed root cannot be inspected right now, for example because it
			// is a separate mount that is not available yet. Keep the state rows so a
			// later run can still revoke; dropping them here would strand the ACLs.
			$this->lastError = 'Unable to inspect the managed logfile directory for revocation: ' . $root;
			return false;
		}

		$success = true;
		foreach ($gids as $gid) {
			if (!$this->acl->revoke($root, (int)$gid)) {
				$success = false;
			}
		}

		try {
			$iterator = new \DirectoryIterator($root);
		} catch (\UnexpectedValueException $e) {
			return false;
		}

		$paths = [];
		foreach ($iterator as $entry) {
			if ($entry->isDot() || $entry->isLink() || !$entry->isFile()) {
				continue;
			}
			if (!LogAcl::isLogfileCandidate($entry->getFilename())) {
				continue;
			}
			$paths[] = $entry->getPathname();
		}
		return $this->acl->revokeMany($paths, $gids) && $success;
	}

	/**
	 * @return array<int,array{customerid:int,gid:int,logroot:string}>
	 */
	private function getStates(): array
	{
		$stmt = Database::query("SELECT `customerid`, `gid`, `logroot` FROM `" . TABLE_PANEL_LOG_ACL_STATE . "`");
		$states = [];
		while ($state = $stmt->fetch(PDO::FETCH_ASSOC)) {
			$states[] = [
				'customerid' => (int)$state['customerid'],
				'gid' => (int)$state['gid'],
				'logroot' => $state['logroot']
			];
		}
		return $states;
	}

	private function storeState(int $gid, int $customerid, string $root): void
	{
		$stmt = Database::prepare("INSERT INTO `" . TABLE_PANEL_LOG_ACL_STATE . "`
			(`customerid`, `gid`, `logroot`) VALUES (:customerid, :gid, :logroot)
			ON DUPLICATE KEY UPDATE `customerid` = VALUES(`customerid`)");
		Database::pexecute($stmt, [
			'customerid' => $customerid,
			'gid' => $gid,
			'logroot' => $root
		]);
	}

	private function deleteState(int $gid, string $root): void
	{
		$stmt = Database::prepare("DELETE FROM `" . TABLE_PANEL_LOG_ACL_STATE . "`
			WHERE `gid` = :gid AND `logroot` = :logroot");
		Database::pexecute($stmt, [
			'gid' => $gid,
			'logroot' => $root
		]);
	}

	/**
	 * @return resource|null
	 */
	private function acquireLock()
	{
		// Cron and logrotate may invoke reconciliation concurrently. A non-blocking
		// process lock prevents interleaved grant/revoke operations; callers retry.
		//
		// The lock must live where only root can create it. This lock gates
		// revocation, so any local user able to hold it could keep their own log
		// access after an administrator has taken it away. /run/lock is mode 1777
		// and therefore unusable for that purpose.
		$lockDirectory = sys_get_temp_dir();
		if (function_exists('posix_geteuid') && posix_geteuid() === 0) {
			$lockDirectory = self::RUNTIME_DIRECTORY;
			if ((!is_dir($lockDirectory) && !@mkdir($lockDirectory, 0700, true))
				|| is_link($lockDirectory)
				|| !is_dir($lockDirectory)
				|| fileowner($lockDirectory) !== 0
			) {
				$this->lastError = 'Unable to use a root-owned runtime directory for the ACL lock: ' . $lockDirectory;
				return null;
			}
		}
		$lock = @fopen($lockDirectory . '/froxlor-log-acls.lock', 'c');
		if ($lock === false || !flock($lock, LOCK_EX | LOCK_NB)) {
			if (is_resource($lock)) {
				fclose($lock);
			}
			return null;
		}
		return $lock;
	}

	/**
	 * Return whether the desired set would grant one physical logfile to
	 * different customers.
	 *
	 * @param array<int,array{customerid:int,basenames:string[]}> $desired
	 * @return bool
	 */
	private function hasLogfileOwnershipCollision(array $desired): bool
	{
		$owners = [];
		foreach ($desired as $customer) {
			foreach ($customer['basenames'] as $basename) {
				if (isset($owners[$basename]) && $owners[$basename] !== (int)$customer['customerid']) {
					return true;
				}
				$owners[$basename] = (int)$customer['customerid'];
			}
		}
		return false;
	}

	private function stateKey(int $gid, string $root): string
	{
		return $gid . ':' . $root;
	}
}
