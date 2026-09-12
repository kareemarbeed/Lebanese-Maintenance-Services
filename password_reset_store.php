<?php
declare(strict_types=1);

/*
 * Start/resume session safely for consistent session availability.
 */
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

/*
 * Ensure the password reset table exists for email-based reset links.
 */
function ensurePasswordResetTable(PDO $pdo): void
{
    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS password_reset (
            reset_id INT AUTO_INCREMENT PRIMARY KEY,
            user_email VARCHAR(255) NOT NULL,
            user_type VARCHAR(30) NOT NULL,
            token_hash CHAR(64) NOT NULL,
            expires_at DATETIME NOT NULL,
            used_at DATETIME DEFAULT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_email (user_email),
            INDEX idx_token (token_hash),
            INDEX idx_expires (expires_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
    );
}

/*
 * Create a new password reset entry and return the raw token.
 */
function createPasswordReset(PDO $pdo, string $email, string $userType, string $tokenHash, string $expiresAt): void
{
    $invalidate = $pdo->prepare(
        'UPDATE password_reset
         SET used_at = NOW()
         WHERE user_email = :email
           AND user_type = :user_type
           AND used_at IS NULL'
    );
    $invalidate->execute([
        'email' => $email,
        'user_type' => $userType,
    ]);

    $insert = $pdo->prepare(
        'INSERT INTO password_reset (user_email, user_type, token_hash, expires_at)
         VALUES (:email, :user_type, :token_hash, :expires_at)'
    );
    $insert->execute([
        'email' => $email,
        'user_type' => $userType,
        'token_hash' => $tokenHash,
        'expires_at' => $expiresAt,
    ]);
}

/*
 * Lookup a valid password reset row by token hash.
 */
function findPasswordReset(PDO $pdo, string $tokenHash): ?array
{
    $statement = $pdo->prepare(
        'SELECT reset_id, user_email, user_type, expires_at, used_at
         FROM password_reset
         WHERE token_hash = :token_hash
         LIMIT 1'
    );
    $statement->execute(['token_hash' => $tokenHash]);

    $row = $statement->fetch();
    if ($row === false) {
        return null;
    }

    return [
        'reset_id' => (int) $row['reset_id'],
        'user_email' => (string) $row['user_email'],
        'user_type' => (string) $row['user_type'],
        'expires_at' => (string) $row['expires_at'],
        'used_at' => $row['used_at'],
    ];
}

/*
 * Mark a reset token as used after successful password update.
 */
function markPasswordResetUsed(PDO $pdo, int $resetId): void
{
    $statement = $pdo->prepare(
        'UPDATE password_reset
         SET used_at = NOW()
         WHERE reset_id = :reset_id'
    );
    $statement->execute(['reset_id' => $resetId]);
}
