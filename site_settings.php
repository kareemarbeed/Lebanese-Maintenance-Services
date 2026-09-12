<?php
declare(strict_types=1);

/*
 * Start/resume session safely for consistent session availability.
 */
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

/*
 * Ensure the site settings table exists for admin-managed content.
 */
function ensureSiteSettingsTable(PDO $pdo): void
{
    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS site_settings (
            setting_key VARCHAR(100) PRIMARY KEY,
            setting_value TEXT NOT NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
    );
}

/*
 * Load site settings from the database and merge with defaults.
 */
function loadSiteSettings(PDO $pdo, array $defaults): array
{
    $statement = $pdo->prepare('SELECT setting_key, setting_value FROM site_settings');
    $statement->execute();

    $settings = $defaults;
    while ($row = $statement->fetch()) {
        $key = (string) ($row['setting_key'] ?? '');
        if ($key === '') {
            continue;
        }
        $settings[$key] = (string) ($row['setting_value'] ?? '');
    }

    return $settings;
}

/*
 * Persist site settings using an upsert for each key/value pair.
 */
function saveSiteSettings(PDO $pdo, array $settings): void
{
    $statement = $pdo->prepare(
        'INSERT INTO site_settings (setting_key, setting_value)
         VALUES (:setting_key, :setting_value)
         ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)'
    );

    foreach ($settings as $key => $value) {
        $statement->execute([
            'setting_key' => (string) $key,
            'setting_value' => (string) $value,
        ]);
    }
}

/*
 * Safely fetch the configured site favicon path.
 */
function resolveSiteFavicon(PDO $pdo): string
{
    try {
        ensureSiteSettingsTable($pdo);

        $statement = $pdo->prepare(
            'SELECT setting_value
             FROM site_settings
             WHERE setting_key = :setting_key
             LIMIT 1'
        );
        $statement->execute(['setting_key' => 'site_favicon']);

        return trim((string) ($statement->fetchColumn() ?? ''));
    } catch (PDOException $exception) {
        return '';
    }
}
