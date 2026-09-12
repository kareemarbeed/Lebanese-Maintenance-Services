<?php
declare(strict_types=1);

/*
 * JSON API for request chat messages.
 */
header('Content-Type: application/json; charset=UTF-8');

/*
 * Start session for authentication and CSRF validation.
 */
session_start();

require_once __DIR__ . '/db_connection.php';
require_once __DIR__ . '/chat_store.php';

/*
 * Helper to emit JSON responses consistently.
 */
function sendChatResponse(int $statusCode, array $payload): void
{
    http_response_code($statusCode);
    echo json_encode($payload);
    exit;
}

ensureChatTable($pdo);

$action = strtolower(trim((string) ($_GET['action'] ?? $_POST['action'] ?? '')));
$requestId = (int) ($_GET['request_id'] ?? $_POST['request_id'] ?? 0);
$tabAccessToken = trim((string) ($_GET['tab'] ?? $_POST['tab'] ?? ''));

if (!in_array($action, ['fetch', 'send', 'send_image'], true)) {
    sendChatResponse(400, ['ok' => false, 'error' => 'Invalid action.']);
}

if ($requestId <= 0) {
    sendChatResponse(400, ['ok' => false, 'error' => 'Invalid request id.']);
}

/*
 * Resolve the current user role and ID for ownership checks.
 */
$userRole = '';
$userId = 0;

if ($tabAccessToken !== '' && preg_match('/^[a-f0-9]{64}$/', $tabAccessToken)) {
    if (isset($_SESSION['customer_tab_tokens']) && is_array($_SESSION['customer_tab_tokens'])) {
        $tokenPayload = $_SESSION['customer_tab_tokens'][$tabAccessToken] ?? null;
        if (is_array($tokenPayload)) {
            $userRole = 'customer';
            $userId = (int) ($tokenPayload['user_id'] ?? 0);
        }
    }
}

if ($userRole === '' && isset($_SESSION['user_type']) && (string) $_SESSION['user_type'] === 'service_provider') {
    $userRole = 'service_provider';
    $userId = (int) ($_SESSION['user_id'] ?? 0);
}

$isAdmin = isset($_SESSION['user_type']) && (string) $_SESSION['user_type'] === 'admin';
if ($userRole === '' && !$isAdmin) {
    sendChatResponse(401, ['ok' => false, 'error' => 'Unauthorized.']);
}

if ($isAdmin && $action !== 'fetch') {
    sendChatResponse(403, ['ok' => false, 'error' => 'Admin may only fetch messages.']);
}

if ($isAdmin) {
    $ownershipCheck = $pdo->prepare('SELECT request_id FROM servicerequest WHERE request_id = :request_id LIMIT 1');
    $ownershipCheck->execute(['request_id' => $requestId]);
    if ($ownershipCheck->fetchColumn() === false) {
        sendChatResponse(404, ['ok' => false, 'error' => 'Request not found.']);
    }
    $sinceId  = (int) ($_GET['since_id'] ?? 0);
    $messages = fetchChatMessages($pdo, $requestId, max($sinceId, 0), 200);
    sendChatResponse(200, ['ok' => true, 'messages' => $messages, 'last_id' => array_reduce($messages, fn($c, $m) => max($c, (int)$m['message_id']), 0)]);
}

/*
 * Confirm the request belongs to the current user.
 */
if ($userRole === '' || $userId <= 0) {
    sendChatResponse(401, ['ok' => false, 'error' => 'Unauthorized.']);
}

if ($userRole === 'customer') {
    $ownershipCheck = $pdo->prepare(
        'SELECT sr.request_id
         FROM servicerequest sr
         WHERE sr.request_id = :request_id
           AND sr.customer_id = :customer_id
         LIMIT 1'
    );
    $ownershipCheck->execute([
        'request_id' => $requestId,
        'customer_id' => $userId,
    ]);
} else {
    $ownershipCheck = $pdo->prepare(
        'SELECT sr.request_id
         FROM servicerequest sr
         INNER JOIN appointmentslot asl
            ON sr.slot_id = asl.slot_id
         WHERE sr.request_id = :request_id
           AND asl.serviceprovider_id = :provider_id
         LIMIT 1'
    );
    $ownershipCheck->execute([
        'request_id' => $requestId,
        'provider_id' => $userId,
    ]);
}

if ($ownershipCheck->fetchColumn() === false) {
    sendChatResponse(403, ['ok' => false, 'error' => 'Access denied.']);
}

if ($action === 'fetch') {
    $sinceId = (int) ($_GET['since_id'] ?? 0);
    $messages = fetchChatMessages($pdo, $requestId, max($sinceId, 0), 80);

    $lastId = $sinceId;
    foreach ($messages as $message) {
        $lastId = max($lastId, (int) $message['message_id']);
    }

    foreach ($messages as $index => $message) {
        $messages[$index]['is_self'] = $message['sender_role'] === $userRole && (int) $message['sender_id'] === $userId;
    }

    sendChatResponse(200, [
        'ok' => true,
        'messages' => $messages,
        'last_id' => $lastId,
    ]);
}

/*
 * Send a new chat message for the request (text or image).
 */
$postedCsrfToken = (string) ($_POST['csrf_token'] ?? '');
$expectedToken = $userRole === 'customer'
    ? (string) ($_SESSION['customer_chat_csrf'] ?? '')
    : (string) ($_SESSION['provider_chat_csrf'] ?? '');

if ($expectedToken === '' || !hash_equals($expectedToken, $postedCsrfToken)) {
    sendChatResponse(400, ['ok' => false, 'error' => 'Invalid request token.']);
}

/*
 * Image upload handler — saves file, stores path, inserts message row.
 */
$imagePath = '';
if ($action === 'send_image') {
    $uploadedFile = $_FILES['image'] ?? null;
    if (!is_array($uploadedFile) || ($uploadedFile['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
        sendChatResponse(400, ['ok' => false, 'error' => 'No valid image file received.']);
    }

    $allowedMimeTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    $detectedMime = mime_content_type((string) $uploadedFile['tmp_name']);
    if (!in_array($detectedMime, $allowedMimeTypes, true)) {
        sendChatResponse(400, ['ok' => false, 'error' => 'Only JPEG, PNG, GIF, and WebP images are allowed.']);
    }

    if ((int) $uploadedFile['size'] > 5 * 1024 * 1024) {
        sendChatResponse(400, ['ok' => false, 'error' => 'Image must be 5 MB or smaller.']);
    }

    $extensionMap = [
        'image/jpeg' => 'jpg',
        'image/png'  => 'png',
        'image/gif'  => 'gif',
        'image/webp' => 'webp',
    ];
    $ext = $extensionMap[$detectedMime] ?? 'jpg';
    $uploadDir = __DIR__ . '/uploads/chat_images/';
    $filename = 'chat_' . $requestId . '_' . date('Ymd_His') . '_' . bin2hex(random_bytes(6)) . '.' . $ext;
    $fullPath = $uploadDir . $filename;

    if (!is_dir($uploadDir)) {
        mkdir($uploadDir, 0755, true);
    }

    if (!move_uploaded_file((string) $uploadedFile['tmp_name'], $fullPath)) {
        sendChatResponse(500, ['ok' => false, 'error' => 'Failed to save image. Please try again.']);
    }

    $imagePath = 'uploads/chat_images/' . $filename;
}

$messageText = trim((string) ($_POST['message'] ?? ''));

if ($action === 'send' && $messageText === '') {
    sendChatResponse(400, ['ok' => false, 'error' => 'Message cannot be empty.']);
}

if ($action === 'send' && mb_strlen($messageText) > 1000) {
    sendChatResponse(400, ['ok' => false, 'error' => 'Message must be 1000 characters or fewer.']);
}

$insertedId = insertChatMessage($pdo, $requestId, $userRole, $userId, $messageText, $imagePath);
$messages = fetchChatMessages($pdo, $requestId, max($insertedId - 1, 0), 1);
$insertedMessage = $messages[0] ?? [
    'message_id' => $insertedId,
    'sender_role' => $userRole,
    'sender_id' => $userId,
    'message' => $messageText,
    'image_path' => $imagePath,
    'created_at' => date('Y-m-d H:i:s'),
    'is_self' => true,
];

if (!isset($insertedMessage['is_self'])) {
    $insertedMessage['is_self'] = true;
}

sendChatResponse(200, [
    'ok' => true,
    'message' => $insertedMessage,
]);
