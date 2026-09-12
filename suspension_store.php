<?php
declare(strict_types=1);

/*
 * Start/resume session safely for consistent session availability.
 */
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

/*
 * Store suspended account IDs in a JSON file so admin actions persist
 * without requiring database schema changes.
 */
const SUSPENSION_STORE_PATH = __DIR__ . '/data/suspended_accounts.json';

/*
 * Normalize raw ID input into a unique, sorted list of positive integers.
 */
function normalizeSuspendedIds(array $ids): array
{
    $normalized = [];

    foreach ($ids as $id) {
        $id = (int) $id;
        if ($id > 0) {
            $normalized[$id] = true;
        }
    }

    $finalIds = array_keys($normalized);
    sort($finalIds, SORT_NUMERIC);

    return $finalIds;
}

/*
 * Normalize the suspended-account payload to ensure required keys exist.
 */
function normalizeSuspensionPayload(array $payload): array
{
    $customerIds = normalizeSuspendedIds((array) ($payload['customers'] ?? []));
    $providerIds = normalizeSuspendedIds((array) ($payload['providers'] ?? []));

    return [
        'customers' => $customerIds,
        'providers' => $providerIds,
    ];
}

/*
 * Load suspended account IDs from the JSON store.
 * Returns empty lists when the file is missing or invalid.
 */
function loadSuspendedAccountIds(): array
{
    if (!is_file(SUSPENSION_STORE_PATH)) {
        return [
            'customers' => [],
            'providers' => [],
        ];
    }

    $rawJson = file_get_contents(SUSPENSION_STORE_PATH);
    if ($rawJson === false || trim($rawJson) === '') {
        return [
            'customers' => [],
            'providers' => [],
        ];
    }

    $decoded = json_decode($rawJson, true);
    if (!is_array($decoded)) {
        return [
            'customers' => [],
            'providers' => [],
        ];
    }

    return normalizeSuspensionPayload($decoded);
}

/*
 * Persist suspended account IDs to the JSON store.
 */
function saveSuspendedAccountIds(array $payload): bool
{
    $normalized = normalizeSuspensionPayload($payload);
    $directory = dirname(SUSPENSION_STORE_PATH);

    if (!is_dir($directory)) {
        if (!mkdir($directory, 0755, true) && !is_dir($directory)) {
            return false;
        }
    }

    $jsonPayload = json_encode($normalized, JSON_PRETTY_PRINT);
    if ($jsonPayload === false) {
        return false;
    }

    return file_put_contents(SUSPENSION_STORE_PATH, $jsonPayload . PHP_EOL, LOCK_EX) !== false;
}

/*
 * Build a fast lookup map from a list of suspended IDs.
 */
function buildSuspendedLookup(array $ids): array
{
    $lookup = [];

    foreach ($ids as $id) {
        $id = (int) $id;
        if ($id > 0) {
            $lookup[$id] = true;
        }
    }

    return $lookup;
}
