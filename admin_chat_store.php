<?php
declare(strict_types=1);

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

function ensureAdminChatTable(PDO $pdo): void
{
    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS admin_direct_chat (
            message_id   INT AUTO_INCREMENT PRIMARY KEY,
            user_role    VARCHAR(20)  NOT NULL,
            user_id      INT          NOT NULL,
            sender       VARCHAR(10)  NOT NULL,
            message      TEXT         NOT NULL DEFAULT \'\',
            is_read_by_admin TINYINT(1) NOT NULL DEFAULT 0,
            is_read_by_user  TINYINT(1) NOT NULL DEFAULT 0,
            created_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_user    (user_role, user_id),
            INDEX idx_unread  (is_read_by_admin, created_at),
            INDEX idx_conv    (user_role, user_id, message_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
    );
}

function fetchAdminChatMessages(PDO $pdo, string $userRole, int $userId, int $sinceId, int $limit): array
{
    $stmt = $pdo->prepare(
        'SELECT message_id, sender, message, is_read_by_admin, is_read_by_user, created_at
         FROM admin_direct_chat
         WHERE user_role = :role AND user_id = :uid AND message_id > :since
         ORDER BY message_id ASC
         LIMIT :lim'
    );
    $stmt->bindValue(':role', $userRole);
    $stmt->bindValue(':uid', $userId, PDO::PARAM_INT);
    $stmt->bindValue(':since', $sinceId, PDO::PARAM_INT);
    $stmt->bindValue(':lim', $limit, PDO::PARAM_INT);
    $stmt->execute();

    $rows = [];
    while ($row = $stmt->fetch()) {
        $rows[] = [
            'message_id'       => (int) $row['message_id'],
            'sender'           => (string) $row['sender'],
            'message'          => (string) $row['message'],
            'is_read_by_admin' => (bool) $row['is_read_by_admin'],
            'is_read_by_user'  => (bool) $row['is_read_by_user'],
            'created_at'       => (string) $row['created_at'],
        ];
    }

    return $rows;
}

function insertAdminChatMessage(PDO $pdo, string $userRole, int $userId, string $sender, string $message): int
{
    $isReadByAdmin = $sender === 'admin' ? 1 : 0;
    $isReadByUser  = $sender === 'user'  ? 1 : 0;

    $stmt = $pdo->prepare(
        'INSERT INTO admin_direct_chat (user_role, user_id, sender, message, is_read_by_admin, is_read_by_user)
         VALUES (:role, :uid, :sender, :message, :read_admin, :read_user)'
    );
    $stmt->execute([
        'role'       => $userRole,
        'uid'        => $userId,
        'sender'     => $sender,
        'message'    => $message,
        'read_admin' => $isReadByAdmin,
        'read_user'  => $isReadByUser,
    ]);

    return (int) $pdo->lastInsertId();
}

function markAdminChatReadByAdmin(PDO $pdo, string $userRole, int $userId): void
{
    $stmt = $pdo->prepare(
        'UPDATE admin_direct_chat
         SET is_read_by_admin = 1
         WHERE user_role = :role AND user_id = :uid AND sender = \'user\' AND is_read_by_admin = 0'
    );
    $stmt->execute(['role' => $userRole, 'uid' => $userId]);
}

function markAdminChatReadByUser(PDO $pdo, string $userRole, int $userId): void
{
    $stmt = $pdo->prepare(
        'UPDATE admin_direct_chat
         SET is_read_by_user = 1
         WHERE user_role = :role AND user_id = :uid AND sender = \'admin\' AND is_read_by_user = 0'
    );
    $stmt->execute(['role' => $userRole, 'uid' => $userId]);
}

function countAdminUnreadFromUsers(PDO $pdo): int
{
    $stmt = $pdo->query(
        'SELECT COUNT(*) FROM admin_direct_chat WHERE sender = \'user\' AND is_read_by_admin = 0'
    );

    return (int) ($stmt ? $stmt->fetchColumn() : 0);
}

function getAdminChatConversations(PDO $pdo): array
{
    $stmt = $pdo->query(
        'SELECT adc.user_role,
                adc.user_id,
                MAX(adc.message_id) AS last_message_id,
                MAX(adc.created_at) AS last_at,
                SUM(CASE WHEN adc.sender = \'user\' AND adc.is_read_by_admin = 0 THEN 1 ELSE 0 END) AS unread_count,
                (SELECT m2.message FROM admin_direct_chat m2
                 WHERE m2.user_role = adc.user_role AND m2.user_id = adc.user_id
                 ORDER BY m2.message_id DESC LIMIT 1) AS last_message,
                COALESCE(c.name, sp.name, \'Unknown\') AS user_name
         FROM admin_direct_chat adc
         LEFT JOIN customer c ON adc.user_role = \'customer\' AND c.customer_id = adc.user_id
         LEFT JOIN serviceprovider sp ON adc.user_role = \'service_provider\' AND sp.provider_id = adc.user_id
         GROUP BY adc.user_role, adc.user_id
         ORDER BY last_at DESC'
    );

    $rows = [];
    if ($stmt) {
        while ($row = $stmt->fetch()) {
            $rows[] = [
                'user_role'   => (string) $row['user_role'],
                'user_id'     => (int) $row['user_id'],
                'user_name'   => (string) $row['user_name'],
                'last_message'=> (string) $row['last_message'],
                'last_at'     => (string) $row['last_at'],
                'unread_count'=> (int) $row['unread_count'],
            ];
        }
    }

    return $rows;
}

function countUserUnreadFromAdmin(PDO $pdo, string $userRole, int $userId): int
{
    $stmt = $pdo->prepare(
        'SELECT COUNT(*) FROM admin_direct_chat
         WHERE user_role = :role AND user_id = :uid
           AND sender = \'admin\' AND is_read_by_user = 0'
    );
    $stmt->execute(['role' => $userRole, 'uid' => $userId]);

    return (int) ($stmt->fetchColumn() ?: 0);
}
