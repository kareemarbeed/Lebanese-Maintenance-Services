<?php
declare(strict_types=1);

/*
 * Start/resume session safely for consistent session availability.
 */
if (session_status() === PHP_SESSION_NONE) {
	session_start();
}

/*
 * Shared admin authentication configuration.
 */
const ADMIN_EMAIL = 'admin@gmail.com';
const ADMIN_PASSWORD_HASH = '$2y$10$niPIDXMSgTjnqlhkhvmk7Ol3cc9F5BipSg6fChd/4B6kwq1U91pCK';
