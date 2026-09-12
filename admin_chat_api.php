<?php
declare(strict_types=1);

header('Content-Type: application/json; charset=UTF-8');
session_start();

require_once __DIR__ . '/db_connection.php';
require_once __DIR__ . '/admin_chat_store.php';

function sendJson(int $code, array $payload): void
{
    http_response_code($code);
    echo json_encode($payload);
    exit;
}

ensureAdminChatTable($pdo);

$action        = strtolower(trim((string) ($_GET['action'] ?? $_POST['action'] ?? '')));
$tabToken      = trim((string) ($_GET['tab'] ?? $_POST['tab'] ?? ''));

/*
 * Resolve caller identity: customer (tab token), service provider, or admin.
 */
$callerRole = '';
$callerId   = 0;
$isAdmin    = false;

if (isset($_SESSION['user_type']) && (string) $_SESSION['user_type'] === 'admin') {
    $isAdmin    = true;
    $callerRole = 'admin';
}

if (!$isAdmin) {
    if ($tabToken !== '' && preg_match('/^[a-f0-9]{64}$/', $tabToken)) {
        $tokens = $_SESSION['customer_tab_tokens'] ?? [];
        if (is_array($tokens) && isset($tokens[$tabToken]) && is_array($tokens[$tabToken])) {
            $callerRole = 'customer';
            $callerId   = (int) ($tokens[$tabToken]['user_id'] ?? 0);
        }
    }

    if ($callerRole === '' && isset($_SESSION['user_type']) && (string) $_SESSION['user_type'] === 'service_provider') {
        $callerRole = 'service_provider';
        $callerId   = (int) ($_SESSION['user_id'] ?? 0);
    }
}

if (!$isAdmin && ($callerRole === '' || $callerId <= 0)) {
    sendJson(401, ['ok' => false, 'error' => 'Unauthorized.']);
}

/*
 * ── ACTION: fetch ────────────────────────────────────────────────────────────
 * Returns messages for the conversation. Admin must pass user_role + user_id.
 */
if ($action === 'fetch') {
    if ($isAdmin) {
        $targetRole = trim((string) ($_GET['user_role'] ?? ''));
        $targetId   = (int) ($_GET['user_id'] ?? 0);
        if (!in_array($targetRole, ['customer', 'service_provider'], true) || $targetId <= 0) {
            sendJson(400, ['ok' => false, 'error' => 'Missing user_role or user_id.']);
        }
        markAdminChatReadByAdmin($pdo, $targetRole, $targetId);
    } else {
        $targetRole = $callerRole;
        $targetId   = $callerId;
        markAdminChatReadByUser($pdo, $targetRole, $targetId);
    }

    $sinceId  = (int) ($_GET['since_id'] ?? 0);
    $messages = fetchAdminChatMessages($pdo, $targetRole, $targetId, $sinceId, 100);
    $lastId   = $sinceId;
    foreach ($messages as $msg) {
        $lastId = max($lastId, $msg['message_id']);
    }

    foreach ($messages as $i => $msg) {
        $messages[$i]['is_self'] = $isAdmin
            ? $msg['sender'] === 'admin'
            : $msg['sender'] === 'user';
    }

    sendJson(200, ['ok' => true, 'messages' => $messages, 'last_id' => $lastId]);
}

/*
 * ── ACTION: send ─────────────────────────────────────────────────────────────
 */
if ($action === 'send') {
    $csrfPosted = (string) ($_POST['csrf_token'] ?? '');

    if ($isAdmin) {
        $expected = (string) ($_SESSION['admin_chat_csrf'] ?? '');
    } else {
        $expected = $callerRole === 'customer'
            ? (string) ($_SESSION['customer_admin_chat_csrf'] ?? '')
            : (string) ($_SESSION['provider_admin_chat_csrf'] ?? '');
    }

    if ($expected === '' || !hash_equals($expected, $csrfPosted)) {
        sendJson(400, ['ok' => false, 'error' => 'Invalid request token.']);
    }

    $messageText = trim((string) ($_POST['message'] ?? ''));
    if ($messageText === '') {
        sendJson(400, ['ok' => false, 'error' => 'Message cannot be empty.']);
    }
    if (mb_strlen($messageText) > 1000) {
        sendJson(400, ['ok' => false, 'error' => 'Message must be 1000 characters or fewer.']);
    }

    if ($isAdmin) {
        $targetRole = trim((string) ($_POST['user_role'] ?? ''));
        $targetId   = (int) ($_POST['user_id'] ?? 0);
        if (!in_array($targetRole, ['customer', 'service_provider'], true) || $targetId <= 0) {
            sendJson(400, ['ok' => false, 'error' => 'Missing user_role or user_id.']);
        }
        $sender = 'admin';
    } else {
        $targetRole = $callerRole;
        $targetId   = $callerId;
        $sender     = 'user';
    }

    $insertedId = insertAdminChatMessage($pdo, $targetRole, $targetId, $sender, $messageText);
    $msgs = fetchAdminChatMessages($pdo, $targetRole, $targetId, $insertedId - 1, 1);
    $msg  = $msgs[0] ?? [
        'message_id' => $insertedId,
        'sender'     => $sender,
        'message'    => $messageText,
        'created_at' => date('Y-m-d H:i:s'),
    ];
    $msg['is_self'] = true;

    sendJson(200, ['ok' => true, 'message' => $msg]);
}

/*
 * ── ACTION: conversations (admin only) ───────────────────────────────────────
 */
if ($action === 'conversations') {
    if (!$isAdmin) {
        sendJson(403, ['ok' => false, 'error' => 'Admin only.']);
    }
    $convs = getAdminChatConversations($pdo);
    sendJson(200, ['ok' => true, 'conversations' => $convs]);
}

/*
 * ── ACTION: unread_count (user-facing badge) ──────────────────────────────────
 */
if ($action === 'unread_count') {
    if ($isAdmin) {
        $count = countAdminUnreadFromUsers($pdo);
    } else {
        $count = countUserUnreadFromAdmin($pdo, $callerRole, $callerId);
    }
    sendJson(200, ['ok' => true, 'count' => $count]);
}

sendJson(400, ['ok' => false, 'error' => 'Invalid action.']);
