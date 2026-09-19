<?php

/**
 * This file is part of the froxlor project.
 * Copyright (c) 2010 the froxlor Team (see authors).
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 */

namespace Froxlor\Cli;

use Froxlor\System\LogAclSynchronizer;
use Symfony\Component\Console\Formatter\OutputFormatter;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

final class LogAcls extends CliCommand
{
	/** @var callable */
	private $rootChecker;

	/** @var callable */
	private $synchronizerFactory;

	public function __construct(?callable $rootChecker = null, ?callable $synchronizerFactory = null)
	{
		$this->rootChecker = $rootChecker ?? static function (): bool {
			return function_exists('posix_geteuid') && posix_geteuid() === 0;
		};
		$this->synchronizerFactory = $synchronizerFactory ?? static function (): LogAclSynchronizer {
			return new LogAclSynchronizer();
		};
		parent::__construct();
	}

	protected function configure()
	{
		// This dedicated root command is used by generated logrotate hooks and is
		// also available to administrators for explicit reconciliation.
		$this->setName('froxlor:log-acls');
		$this->setDescription('Reconcile SSH access ACLs for customer web logs');
	}

	protected function execute(InputInterface $input, OutputInterface $output): int
	{
		$result = $this->validateRequirements($output);
		if ($result !== self::SUCCESS) {
			return $result;
		}

		$rootChecker = $this->rootChecker;
		if (!$rootChecker()) {
			$output->writeln('<error>The logfile ACL reconciler must run as root.</>');
			return self::FAILURE;
		}

		try {
			$synchronizerFactory = $this->synchronizerFactory;
			$synchronizer = $synchronizerFactory();
			if (!$synchronizer->sync()) {
				$detail = OutputFormatter::escape($synchronizer->getLastError());
				$output->writeln('<error>Customer logfile ACL reconciliation did not complete successfully.' . ($detail !== '' ? ' ' . $detail : '') . '</>');
				return self::FAILURE;
			}
		} catch (\Throwable $e) {
			$output->writeln('<error>Customer logfile ACL reconciliation failed: ' . OutputFormatter::escape($e->getMessage()) . '</>');
			return self::FAILURE;
		}

		$output->writeln('<info>Customer logfile ACL reconciliation completed.</>');
		return self::SUCCESS;
	}
}
