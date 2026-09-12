<?php
declare(strict_types=1);

/*
 * Start/resume session safely for consistent session availability.
 */
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

/*
 * Ensure the chat table exists for request-level messaging.
 */
function ensureChatTable(PDO $pdo): void
{
    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS request_chat_message (
            message_id INT AUTO_INCREMENT PRIMARY KEY,
            request_id INT NOT NULL,
            sender_role VARCHAR(20) NOT NULL,
            sender_id INT NOT NULL,
            message TEXT NOT NULL DEFAULT \'\',
            image_path VARCHAR(500) NULL DEFAULT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_request (request_id),
            INDEX idx_request_message (request_id, message_id),
            INDEX idx_sender (sender_role, sender_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
    );

    try {
        $pdo->exec("ALTER TABLE `request_chat_message` ADD COLUMN `image_path` VARCHAR(500) NULL DEFAULT NULL");
    } catch (PDOException $e) {
        // column already exists — ignore
    }
}

/*
 * Fetch chat messages for a specific request.
 */
function fetchChatMessages(PDO $pdo, int $requestId, int $sinceId, int $limit): array
{
    $statement = $pdo->prepare(
        'SELECT message_id, sender_role, sender_id, message, image_path, created_at
         FROM request_chat_message
         WHERE request_id = :request_id
           AND message_id > :since_id
         ORDER BY message_id ASC
         LIMIT :limit'
    );
    $statement->bindValue(':request_id', $requestId, PDO::PARAM_INT);
    $statement->bindValue(':since_id', $sinceId, PDO::PARAM_INT);
    $statement->bindValue(':limit', $limit, PDO::PARAM_INT);
    $statement->execute();

    $messages = [];
    while ($row = $statement->fetch()) {
        $messages[] = [
            'message_id' => (int) $row['message_id'],
            'sender_role' => (string) $row['sender_role'],
            'sender_id' => (int) $row['sender_id'],
            'message' => (string) $row['message'],
            'image_path' => isset($row['image_path']) ? (string) $row['image_path'] : '',
            'created_at' => (string) $row['created_at'],
        ];
    }

    return $messages;
}

/*
 * Store a new chat message for a request.
 */
function insertChatMessage(PDO $pdo, int $requestId, string $senderRole, int $senderId, string $message, string $imagePath = ''): int
{
    $statement = $pdo->prepare(
        'INSERT INTO request_chat_message (request_id, sender_role, sender_id, message, image_path)
         VALUES (:request_id, :sender_role, :sender_id, :message, :image_path)'
    );
    $statement->execute([
        'request_id' => $requestId,
        'sender_role' => $senderRole,
        'sender_id' => $senderId,
        'message' => $message,
        'image_path' => $imagePath !== '' ? $imagePath : null,
    ]);

    return (int) $pdo->lastInsertId();
}
