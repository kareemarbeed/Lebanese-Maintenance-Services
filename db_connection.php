<?php
declare(strict_types=1);

/*
 * Start/resume session safely for consistent session availability.
 */
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

/*
 * Connection credentials for the local XAMPP MySQL instance.
 * Update these values when moving from local development to staging/production.
 */
$dbHost = '127.0.0.1';
$dbName = 'seniort';
$dbUser = 'root';
$dbPass = '';

$dbCharset = 'utf8mb4';

/*
 * DSN (Data Source Name) selects the MySQL driver, target database,
 * and character set so multilingual input (including Arabic) is stored safely.
 */
$dsn = "mysql:host={$dbHost};dbname={$dbName};charset={$dbCharset}";

/*
 * PDO hardening options:
 * - ERRMODE_EXCEPTION: query/connect errors throw exceptions for centralized handling.
 * - FETCH_ASSOC: rows are returned as associative arrays by column name.
 * - EMULATE_PREPARES=false: forces native prepared statements for safer SQL execution.
 */
$options = [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES => false,
];

/*
 * Create a reusable PDO object in $pdo.
 * Authentication pages include this file and run prepared statements through that handle.
 */
try {
    $pdo = new PDO($dsn, $dbUser, $dbPass, $options);
} catch (PDOException $exception) {
    // Return a generic failure response; do not expose DB credentials/host details.
    http_response_code(500);
    die('Database connection failed. Check db_connection.php settings.');
}