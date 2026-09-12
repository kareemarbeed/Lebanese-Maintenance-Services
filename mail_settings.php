<?php
declare(strict_types=1);

/*
 * Start/resume session safely for consistent session availability.
 */
if (session_status() === PHP_SESSION_NONE) {
	session_start();
}

/*
 * Mail transport configuration for password reset emails.
 * Use SMTP with authentication by setting MAIL_TRANSPORT to 'smtp'
 * and filling in the SMTP_* values.
 */
const MAIL_TRANSPORT = 'smtp';
const SMTP_HOST = 'smtp.gmail.com';
const SMTP_PORT = 587;
const SMTP_USERNAME = 'lebanesemaintenaceservices@gmail.com';
const SMTP_PASSWORD = 'kcvj czat cnyn oqrh';
const SMTP_ENCRYPTION = 'tls';
const SMTP_FROM_EMAIL = 'lebanesemaintenaceservices@gmail.com';
const SMTP_FROM_NAME = 'Lebanese Maintenance';
