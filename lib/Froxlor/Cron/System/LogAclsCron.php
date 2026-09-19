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

namespace Froxlor\Cron\System;

use Froxlor\Cron\FroxlorCron;
use Froxlor\Database\Database;
use Froxlor\FroxlorLogger;
use Froxlor\Settings;
use Froxlor\System\LogAclSynchronizer;
use Throwable;

/**
 * Periodic convergence for customer logfile ACLs.
 *
 * Grants and revocations normally happen straight away: the webserver cron
 * grants when it creates a logfile, eligibility changes queue task 15, and
 * logrotate calls froxlor:log-acls after it creates a new active file. This
 * job exists only to repair drift caused outside Froxlor, such as an
 * administrator editing ACLs by hand, which nothing can detect immediately.
 * It therefore runs on its own, much longer interval rather than with every
 * tasks run.
 */
class LogAclsCron extends FroxlorCron
{
	protected static function createSynchronizer(): LogAclSynchronizer
	{
		return new LogAclSynchronizer();
	}

	public static function run()
	{
		if (!self::hasWorkToDo()) {
			return;
		}

		self::$cronlog->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, 'Reconciling customer logfile ACLs');
		try {
			$synchronizer = static::createSynchronizer();
			if (!$synchronizer->sync()) {
				$detail = $synchronizer->getLastError();
				self::$cronlog->logAction(FroxlorLogger::CRON_ACTION, LOG_WARNING, 'Customer logfile ACL reconciliation did not complete successfully' . ($detail !== '' ? ': ' . $detail : ''));
			}
		} catch (Throwable $e) {
			self::$cronlog->logAction(FroxlorLogger::CRON_ACTION, LOG_ERR, 'Customer logfile ACL reconciliation failed: ' . $e->getMessage());
		}
	}

	/**
	 * Reconciliation is pointless when the feature is off and nothing is left
	 * to clean up, so avoid spawning ACL tooling in that case.
	 */
	private static function hasWorkToDo(): bool
	{
		if ((string)Settings::Get('system.logfiles_acl_enabled') === '1') {
			return true;
		}
		try {
			$stmt = Database::query("SELECT COUNT(*) FROM `" . TABLE_PANEL_LOG_ACL_STATE . "`");
			return (int)$stmt->fetchColumn() > 0;
		} catch (Throwable $e) {
			return false;
		}
	}
}
