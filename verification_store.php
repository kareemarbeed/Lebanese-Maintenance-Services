<?php
declare(strict_types=1);

/*
 * Start/resume session safely for consistent session availability.
 */
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

/*
 * Store verified service provider IDs in a JSON file so admin actions persist
 * without requiring schema changes.
 */
const VERIFICATION_STORE_PATH = __DIR__ . '/data/verified_providers.json';

/*
 * Normalize raw ID input into a unique, sorted list of positive integers.
 */
function normalizeVerifiedProviderIds(array $ids): array
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
 * Load verified provider IDs from the JSON store.
 * Returns an empty array when the file is missing or invalid.
 */
function loadVerifiedProviderIds(): array
{
    if (!is_file(VERIFICATION_STORE_PATH)) {
        return [];
    }

    $rawJson = file_get_contents(VERIFICATION_STORE_PATH);
    if ($rawJson === false || trim($rawJson) === '') {
        return [];
    }

    $decoded = json_decode($rawJson, true);
    if (!is_array($decoded)) {
        return [];
    }

    return normalizeVerifiedProviderIds($decoded);
}

/*
 * Persist verified provider IDs to the JSON store.
 */
function saveVerifiedProviderIds(array $ids): bool
{
    $normalized = normalizeVerifiedProviderIds($ids);
    $directory = dirname(VERIFICATION_STORE_PATH);

    if (!is_dir($directory)) {
        if (!mkdir($directory, 0755, true) && !is_dir($directory)) {
            return false;
        }
    }

    $payload = json_encode($normalized, JSON_PRETTY_PRINT);
    if ($payload === false) {
        return false;
    }

    return file_put_contents(VERIFICATION_STORE_PATH, $payload . PHP_EOL, LOCK_EX) !== false;
}

/*
 * Build a fast lookup map from a list of verified IDs.
 */
function buildVerifiedProviderLookup(array $ids): array
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
