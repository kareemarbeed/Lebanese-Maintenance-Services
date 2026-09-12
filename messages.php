<?php
declare(strict_types=1);

/*
 * Messaging interface for customers and service providers.
 * Displays conversations linked to service requests after acceptance.
 */
session_start();

require_once __DIR__ . '/db_connection.php';
require_once __DIR__ . '/chat_store.php';
require_once __DIR__ . '/site_settings.php';
require_once __DIR__ . '/lang.php';

ensureSiteSettingsTable($pdo);
$siteFavicon = resolveSiteFavicon($pdo);

function msgLocalizedShortDate(string $isoDate): string {
    static $arMonths = ['January'=>'يناير','February'=>'فبراير','March'=>'مارس','April'=>'أبريل',
        'May'=>'مايو','June'=>'يونيو','July'=>'يوليو','August'=>'أغسطس',
        'September'=>'سبتمبر','October'=>'أكتوبر','November'=>'نوفمبر','December'=>'ديسمبر'];
    $ts = strtotime($isoDate);
    if (getLang() !== 'ar') return date('M j', $ts);
    $month = $arMonths[date('F', $ts)] ?? date('F', $ts);
    return $month . ' ' . toArabicNumerals(date('j', $ts));
}

function msgLocalizedStatus(string $status): string {
    $map = ['Pending' => 'req_status_pending', 'Confirmed' => 'req_status_confirmed',
            'Completed' => 'req_status_completed', 'Cancelled' => 'req_status_cancelled'];
    $key = $map[$status] ?? null;
    return $key !== null ? t($key) : $status;
}

/*
 * Verify authentication.
 * Customers use tab tokens, service providers use session variables.
 */
$userRole = '';
$userId = 0;
$userEmail = '';
$userName = '';
$tabAccessToken = '';

$tabAccessToken = trim((string) ($_GET['tab'] ?? ''));

if ($tabAccessToken !== '' && preg_match('/^[a-f0-9]{64}$/', $tabAccessToken)) {
    if (isset($_SESSION['customer_tab_tokens']) && is_array($_SESSION['customer_tab_tokens'])) {
        $tokenPayload = $_SESSION['customer_tab_tokens'][$tabAccessToken] ?? null;
        if (is_array($tokenPayload)) {
            $userRole = 'customer';
            $userId = (int) ($tokenPayload['user_id'] ?? 0);
            $userEmail = (string) ($tokenPayload['user_email'] ?? '');
        }
    }
}

if ($userRole === '' && isset($_SESSION['user_type']) && (string) $_SESSION['user_type'] === 'service_provider') {
    $userRole = 'service_provider';
    $userId = (int) ($_SESSION['user_id'] ?? 0);
    $userEmail = (string) ($_SESSION['user_email'] ?? '');
}

if ($userRole === '' || $userId <= 0) {
    header('Location: login.php');
    exit;
}

/*
 * Ensure chat CSRF tokens are available for API-based messaging.
 */
if ($userRole === 'customer') {
    if (!isset($_SESSION['customer_chat_csrf']) || !is_string($_SESSION['customer_chat_csrf'])) {
        $_SESSION['customer_chat_csrf'] = bin2hex(random_bytes(32));
    }
} elseif ($userRole === 'service_provider') {
    if (!isset($_SESSION['provider_chat_csrf']) || !is_string($_SESSION['provider_chat_csrf'])) {
        $_SESSION['provider_chat_csrf'] = bin2hex(random_bytes(32));
    }
}

ensureChatTable($pdo);

/*
 * Notification badge count for customer sidebar.
 */
$customerNotifCount = 0;
if ($userRole === 'customer' && $userId > 0) {
    try {
        if (!isset($_SESSION['customer_notif_seen'])) {
            try {
                $seenStmt = $pdo->prepare(
                    'SELECT last_msg_id, last_status_id
                     FROM customer_notification_seen
                     WHERE customer_id = :cid LIMIT 1'
                );
                $seenStmt->execute([':cid' => $userId]);
                $seenRow = $seenStmt->fetch();
                $_SESSION['customer_notif_seen'] = is_array($seenRow)
                    ? ['msg_id' => (int) $seenRow['last_msg_id'], 'status_id' => (int) $seenRow['last_status_id']]
                    : ['msg_id' => 0, 'status_id' => 0];
            } catch (PDOException) {
                $_SESSION['customer_notif_seen'] = ['msg_id' => 0, 'status_id' => 0];
            }
        }
        $seenData     = (array) ($_SESSION['customer_notif_seen'] ?? []);
        $seenMsgId    = (int) ($seenData['msg_id'] ?? 0);
        $seenStatusId = (int) ($seenData['status_id'] ?? 0);

        $notifCountStmt = $pdo->prepare(
            'SELECT
                 (SELECT COUNT(*) FROM request_chat_message rcm
                  INNER JOIN servicerequest sr  ON rcm.request_id = sr.request_id
                  WHERE sr.customer_id = :cid1
                    AND rcm.sender_role = \'service_provider\'
                    AND rcm.message_id > :msg_id) +
                 (SELECT COUNT(*) FROM servicerequest sr2
                  WHERE sr2.customer_id = :cid2
                    AND sr2.status IN (\'Confirmed\',\'Completed\',\'Cancelled\')
                    AND sr2.request_id > :status_id) AS total_unread'
        );
        $notifCountStmt->execute([
            ':cid1'      => $userId,
            ':msg_id'    => $seenMsgId,
            ':cid2'      => $userId,
            ':status_id' => $seenStatusId,
        ]);
        $countRow = $notifCountStmt->fetch();
        $customerNotifCount = (int) ($countRow['total_unread'] ?? 0);
    } catch (PDOException) {}
}

/*
 * All POST requests for sending and fetching messages are handled via chat_api.php.
 * This page (messages.php) is a GET-only UI renderer.
 */

/*
 * Fetch all accepted requests for the current user.
 */
try {
    if ($userRole === 'customer') {
                $requestsQuery = $pdo->prepare(
                        'SELECT sr.request_id, sr.status,
                                        asl.serviceprovider_id, sp.name as provider_name, sp.email as provider_email,
                                        COALESCE(sc.name, \'Service\') as service_name,
                                        asl.date AS appointment_date, asl.slot AS appointment_time,
                                        (SELECT MAX(message_id) FROM request_chat_message WHERE request_id = sr.request_id) as last_message_id
                         FROM servicerequest sr
                         INNER JOIN appointmentslot asl ON sr.slot_id = asl.slot_id
                         INNER JOIN serviceprovider sp ON asl.serviceprovider_id = sp.provider_id
                         LEFT JOIN servicecategory sc ON sr.category_id = sc.category_id
                         WHERE sr.customer_id = :customer_id
                             AND sr.status IN (\'Confirmed\', \'Completed\')
                         ORDER BY sr.request_id DESC'
                );
        $requestsQuery->execute(['customer_id' => $userId]);
    } else {
        $requestsQuery = $pdo->prepare(
                        'SELECT sr.request_id, sr.status,
                                        sr.customer_id, c.name as customer_name, c.email as customer_email,
                                        COALESCE(sc.name, \'Service\') as service_name,
                                        asl.date AS appointment_date, asl.slot AS appointment_time,
                                        (SELECT MAX(message_id) FROM request_chat_message WHERE request_id = sr.request_id) as last_message_id
                         FROM servicerequest sr
                         INNER JOIN customer c ON sr.customer_id = c.customer_id
                         INNER JOIN appointmentslot asl ON sr.slot_id = asl.slot_id
                         LEFT JOIN servicecategory sc ON sr.category_id = sc.category_id
                         WHERE asl.serviceprovider_id = :provider_id
                             AND sr.status IN (\'Confirmed\', \'Completed\')
                         ORDER BY sr.request_id DESC'
                );
        $requestsQuery->execute(['provider_id' => $userId]);
    }

    $requests = $requestsQuery->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    $requests = [];
}

$selectedRequestId = 0;
$selectedRequest = null;
$messages = [];

$requestIdParam = (int) ($_GET['request_id'] ?? 0);

if ($requestIdParam > 0) {
    foreach ($requests as $req) {
        if ((int) $req['request_id'] === $requestIdParam) {
            $selectedRequestId = $requestIdParam;
            $selectedRequest = $req;
            break;
        }
    }

    if ($selectedRequest) {
        $messages = fetchChatMessages($pdo, $selectedRequestId, 0, 1000);
        foreach ($messages as $index => $message) {
            $messages[$index]['is_self'] = $message['sender_role'] === $userRole
                && (int) $message['sender_id'] === $userId;
        }
    }
}
?>
<!DOCTYPE html>
<html lang="<?php echo getLang(); ?>" dir="<?php echo t('dir'); ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <?php if ($siteFavicon !== ''): ?>
        <link rel="icon" href="<?php echo htmlspecialchars($siteFavicon, ENT_QUOTES, 'UTF-8'); ?>">
    <?php endif; ?>
    <title><?php echo htmlspecialchars(t('msg_title'), ENT_QUOTES, 'UTF-8'); ?> - <?php echo htmlspecialchars(t('site_name'), ENT_QUOTES, 'UTF-8'); ?></title>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <?php if (isRtl()): ?>
    <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <?php endif; ?>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        /*
         * Global reset and viewport guards.
         */
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        html, body {
            width: 100%;
            height: 100%;
            overflow: hidden;
        }

        body {
            --brand: #0f766e;
            --brand-deep: #115e59;
            --accent: #f97316;
            --surface: #f8fafc;
            font-family: 'Plus Jakarta Sans', sans-serif;
            background:
                radial-gradient(circle at 5% 0%, rgba(20, 184, 166, 0.14), transparent 32%),
                radial-gradient(circle at 95% 5%, rgba(249, 115, 22, 0.14), transparent 30%),
                linear-gradient(135deg, #ecfeff, #f8fafc 50%, #fff7ed);
            display: flex;
            flex-direction: row;
        }

        .messages-pane {
            flex: 1;
            min-width: 0;
            display: flex;
            flex-direction: column;
            height: 100vh;
            overflow: hidden;
        }

        /*
         * Header/top bar
         */
        .messages-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 14px 24px;
            border-bottom: 1px solid rgba(15, 118, 110, 0.12);
            background: rgba(255, 255, 255, 0.92);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            box-shadow: 0 2px 12px rgba(15, 23, 42, 0.06);
            z-index: 10;
        }

        .messages-header h1 {
            font-size: 1.25rem;
            font-weight: 800;
            color: #042f2e;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .messages-header h1 i {
            color: var(--brand);
        }

        .header-actions {
            display: flex;
            gap: 12px;
            align-items: center;
        }

        .btn-back {
            padding: 9px 16px;
            border: 1px solid #dbe2ea;
            border-radius: 999px;
            background: #fff;
            color: #334155;
            cursor: pointer;
            font-weight: 700;
            font-size: 0.85rem;
            transition: background 0.2s ease, box-shadow 0.2s ease, transform 0.2s ease;
            display: flex;
            align-items: center;
            gap: 7px;
            text-decoration: none;
        }

        .btn-back:hover {
            background: #f1f5f9;
            box-shadow: 0 4px 12px rgba(15, 23, 42, 0.08);
            transform: translateY(-1px);
        }

        /*
         * Main container with two-column layout
         */
        .messages-container {
            display: flex;
            flex: 1;
            min-height: 0;
            overflow: hidden;
        }

        /*
         * Left sidebar - list of conversations
         */
        .messages-list {
            width: 300px;
            border-right: 1px solid rgba(15, 118, 110, 0.1);
            overflow-y: auto;
            background: rgba(255, 255, 255, 0.7);
            backdrop-filter: blur(8px);
            -webkit-backdrop-filter: blur(8px);
        }

        .conversation-item {
            padding: 13px 14px;
            border-bottom: 1px solid rgba(219, 226, 234, 0.7);
            cursor: pointer;
            transition: background 0.18s ease;
            display: block;
            text-decoration: none;
            color: inherit;
        }

        .conversation-item:hover {
            background: rgba(15, 118, 110, 0.05);
        }

        .conversation-item.active {
            background: linear-gradient(160deg, rgba(15, 118, 110, 0.12), rgba(15, 118, 110, 0.04));
            border-left: 3px solid var(--brand);
            padding-left: 11px;
        }

        .conversation-item-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 6px;
        }

        .conversation-item-name {
            font-weight: 700;
            color: #0f172a;
            font-size: 0.95rem;
        }

        .conversation-item-service {
            font-size: 0.8rem;
            color: #64748b;
            margin-bottom: 3px;
        }

        .conversation-item-slot {
            font-size: 0.76rem;
            color: #94a3b8;
            display: flex;
            align-items: center;
            gap: 5px;
        }

        .conversation-item-slot i {
            color: var(--brand);
            font-size: 0.72rem;
        }

        .conversation-item-status {
            font-size: 0.75rem;
            padding: 3px 6px;
            border-radius: 4px;
            font-weight: 700;
        }

        .conversation-item-status.accepted,
        .conversation-item-status.confirmed {
            background: rgba(34, 197, 94, 0.12);
            color: #15803d;
        }

        .conversation-item-status.in_progress {
            background: rgba(59, 130, 246, 0.12);
            color: #1e40af;
        }

        .conversation-item-status.completed {
            background: rgba(15, 118, 110, 0.12);
            color: #0f766e;
        }

        /*
         * Right side - chat area
         */
        .messages-chat {
            flex: 1;
            display: flex;
            flex-direction: column;
            background: rgba(255, 255, 255, 0.85);
            backdrop-filter: blur(8px);
            -webkit-backdrop-filter: blur(8px);
        }

        .chat-empty {
            flex: 1;
            display: flex;
            align-items: center;
            justify-content: center;
            flex-direction: column;
            color: #94a3b8;
            gap: 12px;
        }

        .chat-empty i {
            font-size: 3rem;
            opacity: 0.5;
        }

        .chat-header-info {
            padding: 14px 24px;
            border-bottom: 1px solid rgba(219, 226, 234, 0.7);
            background: rgba(248, 250, 252, 0.8);
        }

        .chat-contact-name {
            font-weight: 800;
            color: #0f172a;
            font-size: 1.05rem;
            margin-bottom: 4px;
        }

        .chat-contact-email {
            font-size: 0.85rem;
            color: #64748b;
        }

        /*
         * Messages display area
         */
        .chat-messages {
            flex: 1;
            overflow-y: auto;
            padding: 20px 24px;
            display: flex;
            flex-direction: column;
            gap: 10px;
            background: transparent;
        }

        .message-group {
            display: flex;
            gap: 8px;
            margin-bottom: 8px;
        }

        .message-group.self {
            justify-content: flex-end;
        }

        .message-bubble {
            max-width: 70%;
            padding: 10px 14px;
            border-radius: 16px;
            border-bottom-left-radius: 4px;
            font-size: 0.93rem;
            line-height: 1.45;
            background: rgba(241, 245, 249, 0.9);
            color: #0f172a;
            box-shadow: 0 1px 4px rgba(15, 23, 42, 0.06);
        }

        .message-group.self .message-bubble {
            background: linear-gradient(145deg, var(--brand), var(--brand-deep));
            color: #fff;
            border-bottom-left-radius: 16px;
            border-bottom-right-radius: 4px;
            box-shadow: 0 4px 12px rgba(15, 118, 110, 0.25);
        }

        .message-time {
            font-size: 0.75rem;
            color: #94a3b8;
            margin-top: 4px;
        }

        .message-group.self .message-time {
            text-align: right;
            color: #64748b;
        }

        /*
         * Message input area
         */
        .chat-input-area {
            padding: 14px 24px;
            border-top: 1px solid rgba(219, 226, 234, 0.7);
            background: rgba(248, 250, 252, 0.85);
        }

        .chat-form {
            display: flex;
            gap: 12px;
            align-items: flex-end;
        }

        .chat-form input {
            flex: 1;
            min-height: 44px;
            border: 1px solid #d1d5db;
            border-radius: 10px;
            padding: 10px 14px;
            font-family: inherit;
            font-size: 0.95rem;
            transition: border-color 0.2s ease;
        }

        .chat-form input:focus {
            outline: none;
            border-color: var(--brand);
            box-shadow: 0 0 0 3px rgba(15, 118, 110, 0.12);
        }

        .chat-form button {
            min-height: 44px;
            min-width: 44px;
            border: none;
            border-radius: 10px;
            background: linear-gradient(145deg, var(--brand), var(--brand-deep));
            color: #fff;
            cursor: pointer;
            font-weight: 800;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: transform 0.2s ease;
        }

        .chat-form button:hover {
            transform: translateY(-2px);
        }

        .chat-form button:active {
            transform: translateY(0);
        }

        .attach-btn {
            min-height: 44px;
            min-width: 44px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 10px;
            background: #f1f5f9;
            border: 1px solid #d1d5db;
            color: #64748b;
            cursor: pointer;
            font-size: 1.1rem;
            transition: background 0.2s ease, color 0.2s ease;
            flex-shrink: 0;
        }

        .attach-btn:hover {
            background: rgba(15, 118, 110, 0.1);
            color: var(--brand);
            border-color: var(--brand);
        }

        .image-preview-bar {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 8px 14px;
            background: rgba(15, 118, 110, 0.06);
            border: 1px solid rgba(15, 118, 110, 0.2);
            border-radius: 10px;
            margin-bottom: 10px;
        }

        .image-preview-thumb {
            width: 48px;
            height: 48px;
            object-fit: cover;
            border-radius: 8px;
            border: 1px solid rgba(15, 118, 110, 0.25);
        }

        .image-preview-name {
            flex: 1;
            font-size: 0.83rem;
            color: #475569;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .image-preview-remove {
            width: 28px;
            height: 28px;
            border-radius: 50%;
            border: none;
            background: #fee2e2;
            color: #b91c1c;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.8rem;
            flex-shrink: 0;
        }

        .message-bubble-image {
            padding: 6px;
            background: transparent;
            box-shadow: none;
        }

        .message-group.self .message-bubble-image {
            background: transparent;
            box-shadow: none;
        }

        .chat-image {
            max-width: 260px;
            max-height: 260px;
            border-radius: 12px;
            display: block;
            cursor: zoom-in;
            box-shadow: 0 2px 10px rgba(15, 23, 42, 0.12);
        }

        .chat-image-caption {
            padding: 6px 10px 4px;
            font-size: 0.88rem;
            color: #334155;
        }

        .message-group.self .chat-image-caption {
            color: rgba(255,255,255,0.9);
        }

        .image-overlay {
            display: none;
            position: fixed;
            inset: 0;
            background: rgba(0,0,0,0.82);
            z-index: 1000;
            align-items: center;
            justify-content: center;
            cursor: zoom-out;
        }

        .image-overlay.open {
            display: flex;
        }

        .image-overlay img {
            max-width: 92vw;
            max-height: 88vh;
            border-radius: 10px;
            box-shadow: 0 8px 40px rgba(0,0,0,0.5);
        }

        /*
         * Responsive design
         */
        @media (max-width: 768px) {
            html, body {
                overflow: auto;
            }

            .messages-container {
                flex-direction: column;
                height: auto;
                flex: 1;
            }

            .messages-list {
                width: 100%;
                max-height: 180px;
                border-right: none;
                border-bottom: 1px solid rgba(219, 226, 234, 0.7);
                flex-shrink: 0;
            }

            .messages-chat {
                min-height: 0;
                flex: 1;
            }

            .message-bubble {
                max-width: 85%;
            }

            .chat-messages {
                padding: 14px 14px;
            }

            .chat-input-area {
                padding: 10px 14px;
            }

            .messages-header {
                padding: 10px 14px;
            }

            .messages-header h1 {
                font-size: 1.05rem;
            }

            .btn-back {
                padding: 7px 12px;
                font-size: 0.8rem;
            }

            .chat-header-info {
                padding: 10px 14px;
            }
        }

        @media (max-width: 480px) {
            .messages-list {
                max-height: 140px;
            }

            .conversation-item {
                padding: 10px 12px;
            }

            .conversation-item-name {
                font-size: 0.88rem;
            }

            .chat-image {
                max-width: 200px;
                max-height: 200px;
            }

            .chat-form {
                gap: 8px;
            }

            .chat-form input {
                font-size: 0.88rem;
            }

            .attach-btn {
                min-width: 38px;
                min-height: 38px;
            }

            .chat-form button {
                min-width: 38px;
                min-height: 38px;
            }
        }

        @media (max-width: 380px) {
            .message-bubble {
                max-width: 92%;
                font-size: 0.88rem;
            }

            .chat-image {
                max-width: 160px;
                max-height: 160px;
            }

            .messages-list {
                max-height: 120px;
            }
        }

        /* ── Sidebar navigation ── */
        .sidebar-toggle {
            display: none;
            position: fixed;
            top: 16px;
            left: 16px;
            z-index: 120;
            width: 46px;
            height: 46px;
            border-radius: 14px;
            border: 1px solid rgba(15, 23, 42, 0.12);
            background: #fff;
            color: #0f172a;
            box-shadow: 0 12px 26px rgba(15, 23, 42, 0.14);
            align-items: center;
            justify-content: center;
            cursor: pointer;
        }

        .sidebar-backdrop {
            display: none;
            position: fixed;
            inset: 0;
            background: rgba(15, 23, 42, 0.45);
            opacity: 0;
            pointer-events: none;
            transition: opacity 0.2s ease;
            z-index: 90;
        }

        .sidebar {
            width: 220px;
            flex-shrink: 0;
            background: linear-gradient(180deg, rgba(15, 118, 110, 0.98), rgba(17, 94, 89, 0.98));
            backdrop-filter: blur(16px);
            border-right: 1px solid rgba(255, 255, 255, 0.1);
            z-index: 100;
            box-shadow: 4px 0 24px rgba(15, 23, 42, 0.25);
            display: flex;
            flex-direction: column;
            padding-top: 20px;
            padding-bottom: 20px;
            overflow-x: hidden;
            overflow-y: hidden;
            box-sizing: border-box;
        }

        @media (max-width: 900px) {
            .sidebar {
                position: fixed;
                left: 0;
                top: 0;
                width: min(82vw, 320px);
                height: 100vh;
                transform: translateX(-100%);
                transition: transform 0.25s ease;
            }

            .sidebar.open { transform: translateX(0); }

            .sidebar-toggle { display: inline-flex; }

            .sidebar-backdrop { display: block; }

            body.sidebar-open .sidebar-backdrop {
                opacity: 1;
                pointer-events: auto;
            }

            .messages-pane .messages-header { padding-left: 64px; }

            [dir="rtl"] .sidebar {
                left: auto;
                right: 0;
                transform: translateX(100%);
            }

            [dir="rtl"] .sidebar.open {
                transform: translateX(0);
            }

            [dir="rtl"] .sidebar-toggle {
                left: auto;
                right: 16px;
            }

            [dir="rtl"] .messages-pane .messages-header {
                padding-left: 0;
                padding-right: 64px;
            }
        }

        body.sidebar-open { overflow: hidden; }

        .sidebar-header {
            padding: 0 16px 20px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.15);
            margin-bottom: 10px;
        }

        .sidebar-header h2 {
            color: #fff;
            font-size: 1.1rem;
            font-weight: 800;
            letter-spacing: -0.3px;
        }

        .sidebar-user-info {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 12px 16px;
            margin-bottom: 12px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.15);
        }

        .sidebar-user-badge {
            width: 48px;
            height: 48px;
            border-radius: 12px;
            background: rgba(255, 255, 255, 0.15);
            display: flex;
            align-items: center;
            justify-content: center;
            color: #fff;
            font-size: 1.45rem;
            flex-shrink: 0;
        }

        .sidebar-user-details { flex: 1; min-width: 0; }

        .sidebar-user-id {
            font-size: 0.85rem;
            font-weight: 700;
            color: rgba(255, 255, 255, 0.9);
            white-space: nowrap;
        }

        .sidebar-user-email {
            font-size: 0.75rem;
            color: rgba(255, 255, 255, 0.7);
            word-break: break-word;
            margin-top: 2px;
        }

        .sidebar-menu {
            flex: 1;
            overflow-y: auto;
            min-height: 0;
            padding: 8px 0;
        }

        .sidebar-menu-item {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 12px 16px;
            color: rgba(255, 255, 255, 0.85);
            text-decoration: none;
            font-size: 0.95rem;
            font-weight: 600;
            border: none;
            background: none;
            width: 100%;
            text-align: left;
            transition: all 0.2s ease;
            border-left: 3px solid transparent;
        }

        .sidebar-menu-item:hover,
        .sidebar-menu-item.active {
            background: rgba(255, 255, 255, 0.12);
            border-left-color: #22d3ee;
            color: #fff;
            padding-left: 14px;
            margin-left: 2px;
        }

        .sidebar-menu-item.active {
            background: rgba(255, 255, 255, 0.18);
            border-left-color: #f97316;
        }

        .sidebar-menu-item i { min-width: 20px; text-align: center; font-size: 1rem; }

        .sidebar-menu-item { position: relative; }

        .menu-badge {
            position: absolute;
            top: 8px;
            right: 14px;
            min-width: 18px;
            height: 18px;
            padding: 0 5px;
            border-radius: 999px;
            background: #f97316;
            color: #fff;
            font-size: 0.68rem;
            font-weight: 800;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            line-height: 1;
        }

        .sidebar-footer {
            padding: 16px;
            border-top: 1px solid rgba(255, 255, 255, 0.15);
            margin-top: auto;
            flex-shrink: 0;
        }
        [dir="rtl"] body { font-family: 'Cairo', sans-serif; }
        [dir="rtl"] .sidebar { right: 0; left: auto; border-right: none; border-left: 1px solid rgba(255,255,255,.15); }
        [dir="rtl"] input, [dir="rtl"] textarea { text-align: right; }
    </style>
</head>
<body class="<?php echo htmlspecialchars(getLangBodyClass(), ENT_QUOTES, 'UTF-8'); ?>">
    <button class="sidebar-toggle" type="button" id="sidebarToggle" aria-label="Open navigation menu" aria-controls="sidebar" aria-expanded="false">
        <i class="fas fa-bars" aria-hidden="true"></i>
    </button>

    <div class="sidebar-backdrop" id="sidebarBackdrop" aria-hidden="true"></div>

    <aside class="sidebar" id="sidebar" aria-label="Navigation menu">
        <div class="sidebar-header">
            <h2><?php echo htmlspecialchars(t('sidebar_menu'), ENT_QUOTES, 'UTF-8'); ?></h2>
        </div>

        <div class="sidebar-user-info">
            <div class="sidebar-user-badge">
                <i class="fas fa-<?php echo $userRole === 'service_provider' ? 'user-gear' : 'user-circle'; ?>"></i>
            </div>
            <div class="sidebar-user-details">
                <div class="sidebar-user-id"><?php echo htmlspecialchars($userRole === 'service_provider' ? t('sidebar_provider_label') : t('sidebar_customer_label'), ENT_QUOTES, 'UTF-8'); ?> #<?php echo htmlspecialchars((string) $userId, ENT_QUOTES, 'UTF-8'); ?></div>
                <div class="sidebar-user-email no-ar-numerals" dir="ltr"><?php echo htmlspecialchars($userEmail !== '' ? $userEmail : t('sidebar_no_email'), ENT_QUOTES, 'UTF-8'); ?></div>
            </div>
        </div>

        <nav class="sidebar-menu">
            <?php if ($userRole === 'customer'): ?>
                <a href="customer_dashboard.php?tab=<?php echo urlencode($tabAccessToken); ?>" class="sidebar-menu-item">
                    <i class="fas fa-chart-line"></i>
                    <?php echo htmlspecialchars(t('sidebar_dashboard'), ENT_QUOTES, 'UTF-8'); ?>
                </a>
                <a href="customer_requests.php?tab=<?php echo urlencode($tabAccessToken); ?>" class="sidebar-menu-item">
                    <i class="fas fa-list-check"></i>
                    <?php echo htmlspecialchars(t('sidebar_my_requests'), ENT_QUOTES, 'UTF-8'); ?>
                </a>
                <a href="customer_dashboard.php?tab=<?php echo urlencode($tabAccessToken); ?>#notifications" class="sidebar-menu-item">
                    <i class="fas fa-bell"></i>
                    <?php echo htmlspecialchars(t('sidebar_notifications'), ENT_QUOTES, 'UTF-8'); ?>
                    <?php if ($customerNotifCount > 0): ?>
                        <span class="menu-badge"><?php echo htmlspecialchars((string) $customerNotifCount, ENT_QUOTES, 'UTF-8'); ?></span>
                    <?php endif; ?>
                </a>
                <a href="messages.php?tab=<?php echo urlencode($tabAccessToken); ?>" class="sidebar-menu-item active">
                    <i class="fas fa-comments"></i>
                    <?php echo htmlspecialchars(t('sidebar_messages'), ENT_QUOTES, 'UTF-8'); ?>
                </a>
                <a href="change_password.php?tab=<?php echo urlencode($tabAccessToken); ?>" class="sidebar-menu-item">
                    <i class="fas fa-key"></i>
                    <?php echo htmlspecialchars(t('sidebar_change_password'), ENT_QUOTES, 'UTF-8'); ?>
                </a>
                <a href="customer_dashboard.php?tab=<?php echo urlencode($tabAccessToken); ?>#profile-edit" class="sidebar-menu-item">
                    <i class="fas fa-user-circle"></i>
                    <?php echo htmlspecialchars(t('sidebar_my_profile'), ENT_QUOTES, 'UTF-8'); ?>
                </a>
            <?php else: ?>
                <a href="service_provider_dashboard.php" class="sidebar-menu-item">
                    <i class="fas fa-chart-line"></i>
                    <?php echo htmlspecialchars(t('sidebar_dashboard'), ENT_QUOTES, 'UTF-8'); ?>
                </a>
                <a href="service_provider_dashboard.php#profile-editor" class="sidebar-menu-item">
                    <i class="fas fa-user-edit"></i>
                    <?php echo htmlspecialchars(t('sidebar_edit_profile'), ENT_QUOTES, 'UTF-8'); ?>
                </a>
                <a href="service_provider_dashboard.php#service-categories" class="sidebar-menu-item">
                    <i class="fas fa-layer-group"></i>
                    <?php echo htmlspecialchars(t('sidebar_services'), ENT_QUOTES, 'UTF-8'); ?>
                </a>
                <a href="service_provider_dashboard.php#upcoming-slots" class="sidebar-menu-item">
                    <i class="fas fa-clock"></i>
                    <?php echo htmlspecialchars(t('sidebar_slots'), ENT_QUOTES, 'UTF-8'); ?>
                </a>
                <a href="service_provider_dashboard.php#requests" class="sidebar-menu-item">
                    <i class="fas fa-list-check"></i>
                    <?php echo htmlspecialchars(t('sidebar_requests'), ENT_QUOTES, 'UTF-8'); ?>
                </a>
                <a href="service_provider_dashboard.php#notifications" class="sidebar-menu-item">
                    <i class="fas fa-bell"></i>
                    <?php echo htmlspecialchars(t('sidebar_notifications'), ENT_QUOTES, 'UTF-8'); ?>
                </a>
                <a href="messages.php" class="sidebar-menu-item active">
                    <i class="fas fa-comments"></i>
                    <?php echo htmlspecialchars(t('sidebar_messages'), ENT_QUOTES, 'UTF-8'); ?>
                </a>
                <a href="change_password.php" class="sidebar-menu-item">
                    <i class="fas fa-key"></i>
                    <?php echo htmlspecialchars(t('sidebar_change_password'), ENT_QUOTES, 'UTF-8'); ?>
                </a>
            <?php endif; ?>
        </nav>

        <div class="sidebar-footer">
            <a href="logout.php" class="sidebar-menu-item">
                <i class="fas fa-right-from-bracket"></i>
                <?php echo htmlspecialchars(t('sidebar_sign_out'), ENT_QUOTES, 'UTF-8'); ?>
            </a>
        </div>
    </aside>

    <div class="messages-pane">
    <div class="messages-header">
        <h1><i class="fas fa-comments"></i> <?php echo htmlspecialchars(t('msg_title'), ENT_QUOTES, 'UTF-8'); ?></h1>
        <div class="header-actions">
            <?php
                $dashUrl = $userRole === 'customer'
                    ? 'customer_dashboard.php?tab=' . urlencode($tabAccessToken)
                    : 'service_provider_dashboard.php';
            ?>
            <a class="btn-back" href="<?php echo htmlspecialchars($dashUrl, ENT_QUOTES, 'UTF-8'); ?>">
                <i class="fas fa-<?php echo isRtl() ? 'arrow-right' : 'arrow-left'; ?>" aria-hidden="true"></i>
                <?php echo htmlspecialchars(t('sidebar_dashboard'), ENT_QUOTES, 'UTF-8'); ?>
            </a>
        </div>
    </div>

    <div class="messages-container">
        <!-- Conversations list -->
        <div class="messages-list">
            <?php if (empty($requests)): ?>
                <div style="padding: 20px; text-align: center; color: #94a3b8;">
                    <p><?php echo htmlspecialchars(t('msg_no_confirmed'), ENT_QUOTES, 'UTF-8'); ?></p>
                </div>
            <?php else: ?>
                <?php foreach ($requests as $req): ?>
                    <a href="messages.php?request_id=<?php echo (int) $req['request_id']; ?><?php if ($userRole === 'customer') echo '&tab=' . urlencode($tabAccessToken); ?>" 
                       class="conversation-item <?php echo $selectedRequestId === (int) $req['request_id'] ? 'active' : ''; ?>">
                        <div class="conversation-item-header">
                            <span class="conversation-item-name">
                                <?php 
                                    if ($userRole === 'customer') {
                                        echo htmlspecialchars((string) $req['provider_name'], ENT_QUOTES, 'UTF-8');
                                    } else {
                                        echo htmlspecialchars((string) $req['customer_name'], ENT_QUOTES, 'UTF-8');
                                    }
                                ?>
                            </span>
                            <span class="conversation-item-status <?php echo htmlspecialchars(strtolower(str_replace(' ', '_', (string) $req['status'])), ENT_QUOTES, 'UTF-8'); ?>">
                                <?php echo htmlspecialchars(msgLocalizedStatus((string) $req['status']), ENT_QUOTES, 'UTF-8'); ?>
                            </span>
                        </div>
                        <div class="conversation-item-service">
                            <?php echo htmlspecialchars((string) $req['service_name'], ENT_QUOTES, 'UTF-8'); ?>
                        </div>
                        <?php if (!empty($req['appointment_date'])): ?>
                        <div class="conversation-item-slot">
                            <i class="fas fa-calendar-alt"></i>
                            <?php
                                $slotDate = msgLocalizedShortDate((string) $req['appointment_date']);
                                $slotTime = !empty($req['appointment_time']) ? ' · ' . substr((string) $req['appointment_time'], 0, 5) : '';
                                echo htmlspecialchars($slotDate . $slotTime, ENT_QUOTES, 'UTF-8');
                            ?>
                        </div>
                        <?php endif; ?>
                    </a>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>

        <!-- Chat area -->
        <div class="messages-chat">
            <?php if ($selectedRequest === null): ?>
                <div class="chat-empty">
                    <i class="fas fa-comment-dots"></i>
                    <p><?php echo htmlspecialchars(t('msg_select_convo'), ENT_QUOTES, 'UTF-8'); ?></p>
                </div>
            <?php else: ?>
                <div class="chat-header-info">
                    <div class="chat-contact-name">
                        <?php 
                            if ($userRole === 'customer') {
                                echo htmlspecialchars((string) $selectedRequest['provider_name'], ENT_QUOTES, 'UTF-8');
                            } else {
                                echo htmlspecialchars((string) $selectedRequest['customer_name'], ENT_QUOTES, 'UTF-8');
                            }
                        ?>
                    </div>
                    <div class="chat-contact-email">
                        <?php 
                            if ($userRole === 'customer') {
                                echo htmlspecialchars((string) $selectedRequest['provider_email'], ENT_QUOTES, 'UTF-8');
                            } else {
                                echo htmlspecialchars((string) $selectedRequest['customer_email'], ENT_QUOTES, 'UTF-8');
                            }
                        ?>
                    </div>
                </div>

                <div class="chat-messages" id="chatMessages">
                    <?php foreach ($messages as $msg): ?>
                        <div class="message-group <?php echo !empty($msg['is_self']) ? 'self' : ''; ?>">
                            <div>
                                <?php if (!empty($msg['image_path'])): ?>
                                    <div class="message-bubble message-bubble-image">
                                        <img src="<?php echo htmlspecialchars((string) $msg['image_path'], ENT_QUOTES, 'UTF-8'); ?>"
                                             alt="Shared image"
                                             class="chat-image"
                                             onclick="openImagePreview(this.src)">
                                        <?php if (trim((string) $msg['message']) !== ''): ?>
                                            <div class="chat-image-caption"><?php echo htmlspecialchars((string) $msg['message'], ENT_QUOTES, 'UTF-8'); ?></div>
                                        <?php endif; ?>
                                    </div>
                                <?php else: ?>
                                    <div class="message-bubble">
                                        <?php echo htmlspecialchars((string) $msg['message'], ENT_QUOTES, 'UTF-8'); ?>
                                    </div>
                                <?php endif; ?>
                                <div class="message-time">
                                    <?php echo date('H:i', strtotime((string) $msg['created_at'])); ?>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>

                <div class="chat-input-area">
                    <div id="imagePreviewBar" class="image-preview-bar" style="display:none;">
                        <img id="imagePreviewThumb" src="" alt="Preview" class="image-preview-thumb">
                        <span id="imagePreviewName" class="image-preview-name"></span>
                        <button type="button" class="image-preview-remove" onclick="removeImageAttachment()" title="Remove image">
                            <i class="fas fa-times"></i>
                        </button>
                    </div>
                    <form class="chat-form" onsubmit="sendMessage(event)">
                        <label class="attach-btn" title="Attach image">
                            <i class="fas fa-image"></i>
                            <input type="file" id="imageInput" accept="image/jpeg,image/png,image/gif,image/webp" style="display:none;" onchange="handleImageSelect(this)">
                        </label>
                        <input type="text" id="messageInput" placeholder="<?php echo htmlspecialchars(t('msg_placeholder'), ENT_QUOTES, 'UTF-8'); ?>" autocomplete="off">
                        <button type="submit">
                            <i class="fas fa-paper-plane"></i>
                        </button>
                    </form>
                </div>

                <!-- Fullscreen image preview overlay -->
                <div id="imageOverlay" class="image-overlay" onclick="closeImagePreview()">
                    <img id="imageOverlayImg" src="" alt="Full size image">
                </div>
            <?php endif; ?>
        </div>
    </div>

    <script>
        var selectedRequestId = <?php echo (int) $selectedRequestId; ?>;
        var userRole = <?php echo json_encode($userRole); ?>;
        var tabAccessToken = <?php echo json_encode($userRole === 'customer' ? $tabAccessToken : ''); ?>;
        var chatCsrfToken = <?php echo json_encode($userRole === 'customer'
            ? (string) ($_SESSION['customer_chat_csrf'] ?? '')
            : (string) ($_SESSION['provider_chat_csrf'] ?? '')); ?>;
        var pollInterval = 3000;
        var lastMessageId = <?php echo !empty($messages) ? (int) end($messages)['message_id'] : 0; ?>;
        var isSending = false;
        var pendingImageFile = null;

        function formatChatTime(rawDatetime) {
            var normalized = (rawDatetime || '').replace(' ', 'T');
            var d = new Date(normalized);
            if (isNaN(d.getTime())) {
                return rawDatetime || '';
            }
            return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        }

        function setSendingState(sending) {
            isSending = sending;
            var btn = document.querySelector('.chat-form button[type="submit"]');
            var input = document.getElementById('messageInput');
            var attachBtn = document.querySelector('.attach-btn');
            if (btn) {
                btn.disabled = sending;
                btn.innerHTML = sending
                    ? '<i class="fas fa-spinner fa-spin"></i>'
                    : '<i class="fas fa-paper-plane"></i>';
            }
            if (input) input.disabled = sending;
            if (attachBtn) attachBtn.style.pointerEvents = sending ? 'none' : '';
        }

        function handleImageSelect(input) {
            var file = input.files[0];
            if (!file) return;

            var allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
            if (!allowedTypes.includes(file.type)) {
                alert('Only JPEG, PNG, GIF, and WebP images are supported.');
                input.value = '';
                return;
            }
            if (file.size > 5 * 1024 * 1024) {
                alert('Image must be 5 MB or smaller.');
                input.value = '';
                return;
            }

            pendingImageFile = file;
            var previewBar = document.getElementById('imagePreviewBar');
            var thumb = document.getElementById('imagePreviewThumb');
            var nameEl = document.getElementById('imagePreviewName');
            if (previewBar && thumb && nameEl) {
                thumb.src = URL.createObjectURL(file);
                nameEl.textContent = file.name;
                previewBar.style.display = 'flex';
            }
        }

        function removeImageAttachment() {
            pendingImageFile = null;
            var input = document.getElementById('imageInput');
            if (input) input.value = '';
            var previewBar = document.getElementById('imagePreviewBar');
            if (previewBar) previewBar.style.display = 'none';
        }

        function openImagePreview(src) {
            var overlay = document.getElementById('imageOverlay');
            var img = document.getElementById('imageOverlayImg');
            if (overlay && img) {
                img.src = src;
                overlay.classList.add('open');
            }
        }

        function closeImagePreview() {
            var overlay = document.getElementById('imageOverlay');
            if (overlay) overlay.classList.remove('open');
        }

        document.addEventListener('keydown', function (e) {
            if (e.key === 'Escape') closeImagePreview();
        });

        function sendMessage(event) {
            event.preventDefault();
            if (isSending) return;

            var messageInput = document.getElementById('messageInput');
            var messageText = (messageInput ? messageInput.value || '' : '').trim();

            if (!pendingImageFile && messageText === '') return;

            setSendingState(true);

            if (pendingImageFile) {
                var formData = new FormData();
                formData.append('action', 'send_image');
                formData.append('request_id', String(selectedRequestId));
                formData.append('message', messageText);
                formData.append('csrf_token', chatCsrfToken || '');
                formData.append('image', pendingImageFile);
                if (userRole === 'customer') {
                    formData.append('tab', tabAccessToken || '');
                }

                fetch('chat_api.php', { method: 'POST', body: formData })
                    .then(function (r) { return r.json(); })
                    .then(function (payload) {
                        setSendingState(false);
                        if (!payload || !payload.ok) return;
                        if (messageInput) messageInput.value = '';
                        removeImageAttachment();
                        lastMessageId = payload.message.message_id;
                        appendMessage(payload.message);
                        if (messageInput) messageInput.focus();
                    })
                    .catch(function () { setSendingState(false); });
                return;
            }

            var body = new URLSearchParams();
            body.append('action', 'send');
            body.append('request_id', String(selectedRequestId));
            body.append('message', messageText);
            body.append('csrf_token', chatCsrfToken || '');
            if (userRole === 'customer') {
                body.append('tab', tabAccessToken || '');
            }

            fetch('chat_api.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: body.toString(),
            })
                .then(function (response) { return response.json(); })
                .then(function (payload) {
                    setSendingState(false);
                    if (!payload || !payload.ok) {
                        if (messageInput) messageInput.focus();
                        return;
                    }
                    if (messageInput) messageInput.value = '';
                    var message = payload.message;
                    lastMessageId = message.message_id;
                    appendMessage(message);
                    if (messageInput) messageInput.focus();
                })
                .catch(function () {
                    setSendingState(false);
                    if (messageInput) messageInput.focus();
                });
        }

        function appendMessage(message) {
            var chatMessages = document.getElementById('chatMessages');
            if (!chatMessages) return;

            var isSelf = typeof message.is_self === 'boolean'
                ? message.is_self
                : (message.sender_role === userRole && parseInt(message.sender_id, 10) === <?php echo (int) $userId; ?>);

            var messageGroup = document.createElement('div');
            messageGroup.className = 'message-group' + (isSelf ? ' self' : '');

            var messageDiv = document.createElement('div');

            if (message.image_path) {
                var bubble = document.createElement('div');
                bubble.className = 'message-bubble message-bubble-image';

                var img = document.createElement('img');
                img.src = message.image_path;
                img.alt = 'Shared image';
                img.className = 'chat-image';
                img.addEventListener('click', function () { openImagePreview(img.src); });
                bubble.appendChild(img);

                if (message.message && message.message.trim()) {
                    var caption = document.createElement('div');
                    caption.className = 'chat-image-caption';
                    caption.textContent = message.message;
                    bubble.appendChild(caption);
                }

                messageDiv.appendChild(bubble);
            } else {
                var bubble = document.createElement('div');
                bubble.className = 'message-bubble';
                bubble.textContent = message.message;
                messageDiv.appendChild(bubble);
            }

            var time = document.createElement('div');
            time.className = 'message-time';
            time.textContent = formatChatTime(message.created_at);

            messageDiv.appendChild(time);
            messageGroup.appendChild(messageDiv);
            chatMessages.appendChild(messageGroup);
            chatMessages.scrollTop = chatMessages.scrollHeight;
        }

        (function () {
            var chatMessages = document.getElementById('chatMessages');
            if (chatMessages) chatMessages.scrollTop = chatMessages.scrollHeight;
        })();

        (function () {
            var input = document.getElementById('messageInput');
            if (input) input.focus();
        })();

        if (selectedRequestId > 0) {
            setInterval(function () {
                var url = 'chat_api.php?action=fetch&request_id=' + selectedRequestId + '&since_id=' + lastMessageId;
                if (userRole === 'customer') {
                    url += '&tab=' + encodeURIComponent(tabAccessToken);
                }

                fetch(url)
                    .then(function (response) { return response.json(); })
                    .then(function (payload) {
                        if (!payload || !payload.ok || !payload.messages) return;
                        (payload.messages || []).forEach(function (message) {
                            if (message.message_id > lastMessageId) {
                                lastMessageId = message.message_id;
                                appendMessage(message);
                            }
                        });
                    })
                    .catch(function () { return; });
            }, pollInterval);
        }

        /* Sidebar toggle for mobile */
        (function () {
            var sidebar = document.getElementById('sidebar');
            var toggleButton = document.getElementById('sidebarToggle');
            var backdrop = document.getElementById('sidebarBackdrop');
            if (!sidebar || !toggleButton || !backdrop) return;

            function setSidebarState(isOpen) {
                sidebar.classList.toggle('open', isOpen);
                document.body.classList.toggle('sidebar-open', isOpen);
                toggleButton.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
                toggleButton.setAttribute('aria-label', isOpen ? 'Close navigation menu' : 'Open navigation menu');
            }

            toggleButton.addEventListener('click', function () {
                setSidebarState(!sidebar.classList.contains('open'));
            });

            backdrop.addEventListener('click', function () { setSidebarState(false); });

            document.querySelectorAll('.sidebar-menu a, .sidebar-footer a').forEach(function (link) {
                link.addEventListener('click', function () {
                    if (window.innerWidth <= 900) setSidebarState(false);
                });
            });

            window.addEventListener('resize', function () {
                if (window.innerWidth > 900) setSidebarState(false);
            });

            document.addEventListener('keydown', function (e) {
                if (e.key === 'Escape' && sidebar.classList.contains('open')) setSidebarState(false);
            });
        })();
    </script>
    </div><!-- /.messages-pane -->
</body>
</html>
