<?php
declare(strict_types=1);

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

function ensureEmailVerificationTable(PDO $pdo): void
{
    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS email_verification (
            verification_id INT AUTO_INCREMENT PRIMARY KEY,
            user_email      VARCHAR(255) NOT NULL,
            user_type       ENUM('customer','service_provider') NOT NULL,
            code            CHAR(6) NOT NULL,
            expires_at      DATETIME NOT NULL,
            used_at         DATETIME DEFAULT NULL,
            created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_ev_email_type (user_email, user_type)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
    );

    // Add is_verified to customer — existing rows default to 1 (already verified)
    try {
        $col = $pdo->query("SHOW COLUMNS FROM `customer` LIKE 'is_verified'");
        if ($col !== false && $col->rowCount() === 0) {
            $pdo->exec("ALTER TABLE `customer` ADD COLUMN `is_verified` TINYINT(1) NOT NULL DEFAULT 1");
        }
    } catch (PDOException) {}

    // Add is_verified to serviceprovider — existing rows default to 1
    try {
        $col = $pdo->query("SHOW COLUMNS FROM `serviceprovider` LIKE 'is_verified'");
        if ($col !== false && $col->rowCount() === 0) {
            $pdo->exec("ALTER TABLE `serviceprovider` ADD COLUMN `is_verified` TINYINT(1) NOT NULL DEFAULT 1");
        }
    } catch (PDOException) {}
}

function createVerificationCode(PDO $pdo, string $email, string $userType): string
{
    // Invalidate all prior active codes for this email/type before issuing a new one
    $pdo->prepare(
        'UPDATE email_verification
         SET used_at = NOW()
         WHERE user_email = :email AND user_type = :type AND used_at IS NULL'
    )->execute(['email' => $email, 'type' => $userType]);

    $code      = str_pad((string) random_int(0, 999999), 6, '0', STR_PAD_LEFT);
    $expiresAt = (new DateTime('+10 minutes'))->format('Y-m-d H:i:s');

    $pdo->prepare(
        'INSERT INTO email_verification (user_email, user_type, code, expires_at)
         VALUES (:email, :type, :code, :expires_at)'
    )->execute([
        'email'      => $email,
        'type'       => $userType,
        'code'       => $code,
        'expires_at' => $expiresAt,
    ]);

    return $code;
}

/*
 * Returns 'ok', 'expired', or 'invalid'.
 * Marks the row as used on success so each code can only be consumed once.
 */
function verifyEmailCode(PDO $pdo, string $email, string $userType, string $code): string
{
    if (!preg_match('/^\d{6}$/', $code)) {
        return 'invalid';
    }

    $stmt = $pdo->prepare(
        'SELECT verification_id, expires_at
         FROM email_verification
         WHERE user_email = :email
           AND user_type  = :type
           AND code       = :code
           AND used_at IS NULL
         ORDER BY verification_id DESC
         LIMIT 1'
    );
    $stmt->execute(['email' => $email, 'type' => $userType, 'code' => $code]);
    $row = $stmt->fetch();

    if (!$row) {
        return 'invalid';
    }

    if (new DateTime() > new DateTime((string) $row['expires_at'])) {
        return 'expired';
    }

    $pdo->prepare(
        'UPDATE email_verification SET used_at = NOW() WHERE verification_id = :id'
    )->execute(['id' => (int) $row['verification_id']]);

    return 'ok';
}
