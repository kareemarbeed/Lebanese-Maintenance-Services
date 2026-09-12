<?php
declare(strict_types=1);

/*
 * Start/resume session so service provider authentication and actions can be enforced.
 */
session_start();

/*
 * Shared PDO connection for service provider dashboard reads and status updates.
 */
require_once __DIR__ . '/db_connection.php';

/*
 * Service category helpers for provider service selection.
 */
require_once __DIR__ . '/service_categories.php';

/*
 * Chat storage helpers for provider notifications.
 */
require_once __DIR__ . '/chat_store.php';
require_once __DIR__ . '/admin_chat_store.php';
require_once __DIR__ . '/lang.php';

/*
 * Site settings helpers for favicon.
 */
require_once __DIR__ . '/site_settings.php';

function provLocalizedDate(string $isoDate, bool $includeDay = true): string {
    static $arDays = ['Sunday'=>'الأحد','Monday'=>'الاثنين','Tuesday'=>'الثلاثاء',
        'Wednesday'=>'الأربعاء','Thursday'=>'الخميس','Friday'=>'الجمعة','Saturday'=>'السبت'];
    static $arMonths = ['January'=>'يناير','February'=>'فبراير','March'=>'مارس','April'=>'أبريل',
        'May'=>'مايو','June'=>'يونيو','July'=>'يوليو','August'=>'أغسطس',
        'September'=>'سبتمبر','October'=>'أكتوبر','November'=>'نوفمبر','December'=>'ديسمبر'];
    $ts = strtotime($isoDate);
    if (getLang() !== 'ar') {
        return $includeDay ? date('D, M j, Y', $ts) : date('M j, Y', $ts);
    }
    $day    = $arDays[date('l', $ts)]   ?? date('l', $ts);
    $month  = $arMonths[date('F', $ts)] ?? date('F', $ts);
    $dayNum = toArabicNumerals(date('j', $ts));
    $year   = toArabicNumerals(date('Y', $ts));
    return $includeDay
        ? $day . '، ' . $dayNum . ' ' . $month . ' ' . $year
        : $dayNum . ' ' . $month . ' ' . $year;
}

/*
 * Load site settings for favicon.
 */
ensureSiteSettingsTable($pdo);
$siteSettings = loadSiteSettings($pdo, ['site_favicon' => '']);
$siteFavicon = trim((string) ($siteSettings['site_favicon'] ?? ''));

/*
 * Restrict this page to authenticated service provider accounts only.
 * Non-service provider or unauthenticated sessions are redirected to login.
 */
if (!isset($_SESSION['user_id'], $_SESSION['user_type']) || (string) $_SESSION['user_type'] !== 'service_provider') {
    header('Location: login.php');
    exit;
}

/*
 * Service Provider identity values used by dashboard queries and header display.
 */
$providerId = (int) $_SESSION['user_id'];
$providerEmail = (string) ($_SESSION['user_email'] ?? '');

/*
 * CSRF token dedicated to request status updates from this page.
 */
if (!isset($_SESSION['service_provider_status_csrf']) || !is_string($_SESSION['service_provider_status_csrf'])) {
    $_SESSION['service_provider_status_csrf'] = bin2hex(random_bytes(32));
}

/*
 * CSRF token dedicated to profile updates from this page.
 */
if (!isset($_SESSION['service_provider_profile_csrf']) || !is_string($_SESSION['service_provider_profile_csrf'])) {
    $_SESSION['service_provider_profile_csrf'] = bin2hex(random_bytes(32));
}

/*
 * CSRF token dedicated to service category updates from this page.
 */
if (!isset($_SESSION['service_provider_services_csrf']) || !is_string($_SESSION['service_provider_services_csrf'])) {
    $_SESSION['service_provider_services_csrf'] = bin2hex(random_bytes(32));
}

/*
 * CSRF token dedicated to appointment slot creation from this page.
 */
if (!isset($_SESSION['service_provider_slot_csrf']) || !is_string($_SESSION['service_provider_slot_csrf'])) {
    $_SESSION['service_provider_slot_csrf'] = bin2hex(random_bytes(32));
}

/*
 * CSRF token dedicated to service provider chat messages.
 */
if (!isset($_SESSION['provider_chat_csrf']) || !is_string($_SESSION['provider_chat_csrf'])) {
    $_SESSION['provider_chat_csrf'] = bin2hex(random_bytes(32));
}

/*
 * CSRF token for admin direct chat messages sent from this dashboard.
 */
if (!isset($_SESSION['provider_admin_chat_csrf']) || !is_string($_SESSION['provider_admin_chat_csrf'])) {
    $_SESSION['provider_admin_chat_csrf'] = bin2hex(random_bytes(32));
}
$adminChatCsrf = $_SESSION['provider_admin_chat_csrf'];

ensureAdminChatTable($pdo);

/*
 * Ensure the chat table exists for notifications and messaging.
 */
ensureChatTable($pdo);

/*
 * Ensure persistent notification read-state table exists.
 * This allows seen IDs to survive logout/login cycles.
 */
try {
    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS provider_notification_seen (
            provider_id   INT NOT NULL PRIMARY KEY,
            last_msg_id       INT NOT NULL DEFAULT 0,
            last_pending_id   INT NOT NULL DEFAULT 0,
            last_cancelled_id INT NOT NULL DEFAULT 0,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                ON UPDATE CURRENT_TIMESTAMP
        )'
    );
} catch (PDOException) {}

/*
 * On a fresh session (right after login) load the provider's last-seen IDs
 * from the DB so previously-read notifications stay marked as read.
 */
if (!isset($_SESSION['provider_notif_seen'])) {
    try {
        $seenLoadStmt = $pdo->prepare(
            'SELECT last_msg_id, last_pending_id, last_cancelled_id
             FROM provider_notification_seen
             WHERE provider_id = :pid LIMIT 1'
        );
        $seenLoadStmt->execute([':pid' => $providerId]);
        $dbSeenRow = $seenLoadStmt->fetch(PDO::FETCH_ASSOC);
        if (is_array($dbSeenRow)) {
            $_SESSION['provider_notif_seen'] = [
                'msg_id'       => (int) $dbSeenRow['last_msg_id'],
                'pending_id'   => (int) $dbSeenRow['last_pending_id'],
                'cancelled_id' => (int) $dbSeenRow['last_cancelled_id'],
            ];
        }
    } catch (PDOException) {}
}

/*
 * Schema migrations for location change approval system.
 */
try {
    $locationColumnCheck = $pdo->query("SHOW COLUMNS FROM serviceprovider LIKE 'location'");
    if ($locationColumnCheck !== false && $locationColumnCheck->rowCount() === 0) {
        $pdo->exec("ALTER TABLE serviceprovider ADD COLUMN location VARCHAR(255) NOT NULL DEFAULT ''");
    }
} catch (PDOException $e) {}

try {
    $pendingLocCheck = $pdo->query("SHOW COLUMNS FROM serviceprovider LIKE 'pending_location'");
    if ($pendingLocCheck !== false && $pendingLocCheck->rowCount() === 0) {
        $pdo->exec("ALTER TABLE serviceprovider ADD COLUMN pending_location VARCHAR(255) NOT NULL DEFAULT ''");
    }
} catch (PDOException $e) {}

try {
    $locStatusCheck = $pdo->query("SHOW COLUMNS FROM serviceprovider LIKE 'location_change_status'");
    if ($locStatusCheck !== false && $locStatusCheck->rowCount() === 0) {
        $pdo->exec("ALTER TABLE serviceprovider ADD COLUMN location_change_status ENUM('none','pending') NOT NULL DEFAULT 'none'");
    }
} catch (PDOException $e) {}

try {
    $cancelReasonCheck = $pdo->query("SHOW COLUMNS FROM servicerequest LIKE 'cancellation_reason'");
    if ($cancelReasonCheck !== false && $cancelReasonCheck->rowCount() === 0) {
        $pdo->exec("ALTER TABLE servicerequest ADD COLUMN cancellation_reason TEXT NULL");
    }
} catch (PDOException $e) {}
try {
    $cancelRequestedCheck = $pdo->query("SHOW COLUMNS FROM servicerequest LIKE 'cancellation_requested'");
    if ($cancelRequestedCheck !== false && $cancelRequestedCheck->rowCount() === 0) {
        $pdo->exec("ALTER TABLE servicerequest ADD COLUMN cancellation_requested TINYINT(1) NOT NULL DEFAULT 0");
    }
} catch (PDOException $e) {}

try {
    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS provider_location_requests (
            id INT AUTO_INCREMENT PRIMARY KEY,
            provider_id INT NOT NULL,
            current_location VARCHAR(255) NOT NULL DEFAULT '',
            requested_location VARCHAR(255) NOT NULL,
            status ENUM('pending','approved','rejected') NOT NULL DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
    );
} catch (PDOException $e) {}

/*
 * Upload policy for service provider profile photos.
 */
const PROVIDER_PHOTO_UPLOAD_DIRECTORY = __DIR__ . '/uploads/provider_photos';
const PROVIDER_PHOTO_UPLOAD_WEB_PATH = 'uploads/provider_photos';
const PROVIDER_PHOTO_MAX_IMAGE_BYTES = 2_097_152; // 2 MB

/*
 * View-state and data containers for render cycle.
 */
$errorMessage = '';
$successMessage = '';
$providerProfile = null;
$profileFormSubmitted = false;
$profileNameValue = '';
$profileBioValue = '';
$profileLocationValue = '';
$profilePhoneValue = '';
$profileEmailValue = '';
$serviceFormSubmitted = false;
$slotFormSubmitted = false;
$slotDateValue = '';
$slotTimeValue = '';
$serviceCategories = [];
$serviceCategoryLookup = [];
$serviceCategorySelections = [];
$servicePriceValues = [];
$providerServices = [];
$requests = [];
$upcomingSlots = [];
$requestStats = [
    'Pending' => 0,
    'Confirmed' => 0,
    'Completed' => 0,
    'Cancelled' => 0,
];
$averageRating = null;
$ratingCount = 0;

/*
 * Notification feeds for recent customer messages and cancellations.
 */
$notificationLimit = 5;
$recentCustomerMessages = [];
$recentCancelledRequests = [];
$recentPendingRequests = [];

/*
 * Early-exit AJAX handler — dismiss a single notification permanently for this session.
 */
if (strtolower(trim((string) ($_GET['ajax'] ?? ''))) === 'dismiss_notification') {
    $dismissType = trim((string) ($_POST['type'] ?? ''));
    $dismissId   = (int) ($_POST['id'] ?? 0);

    if ($dismissId > 0 && in_array($dismissType, ['message', 'pending', 'cancelled'], true)) {
        $dismissStore = (array) ($_SESSION['provider_dismissed_notifs'] ?? []);
        if (!isset($dismissStore[$dismissType])) {
            $dismissStore[$dismissType] = [];
        }
        $dismissStore[$dismissType][$dismissId] = true;
        // Cap per type to avoid unbounded session growth
        if (count($dismissStore[$dismissType]) > 200) {
            $dismissStore[$dismissType] = array_slice($dismissStore[$dismissType], -100, null, true);
        }
        $_SESSION['provider_dismissed_notifs'] = $dismissStore;
    }

    header('Content-Type: application/json; charset=UTF-8');
    echo json_encode(['ok' => true]);
    exit;
}

/*
 * Early-exit AJAX handler — mark notifications as read (clears badge).
 */
if (strtolower(trim((string) ($_GET['ajax'] ?? ''))) === 'mark_notifications_read') {
    $seen = (array) ($_SESSION['provider_notif_seen'] ?? []);
    $seen['msg_id']       = max((int) ($seen['msg_id'] ?? 0),       (int) ($_POST['last_msg_id'] ?? 0));
    $seen['pending_id']   = max((int) ($seen['pending_id'] ?? 0),   (int) ($_POST['last_pending_id'] ?? 0));
    $seen['cancelled_id'] = max((int) ($seen['cancelled_id'] ?? 0), (int) ($_POST['last_cancelled_id'] ?? 0));
    $_SESSION['provider_notif_seen'] = $seen;

    /* Persist to DB so read state survives logout/login. */
    try {
        $persistStmt = $pdo->prepare(
            'INSERT INTO provider_notification_seen
                 (provider_id, last_msg_id, last_pending_id, last_cancelled_id)
             VALUES (:pid, :msg, :pend, :canc)
             ON DUPLICATE KEY UPDATE
                 last_msg_id       = GREATEST(last_msg_id,       VALUES(last_msg_id)),
                 last_pending_id   = GREATEST(last_pending_id,   VALUES(last_pending_id)),
                 last_cancelled_id = GREATEST(last_cancelled_id, VALUES(last_cancelled_id))'
        );
        $persistStmt->execute([
            ':pid'  => $providerId,
            ':msg'  => $seen['msg_id'],
            ':pend' => $seen['pending_id'],
            ':canc' => $seen['cancelled_id'],
        ]);
    } catch (PDOException) {}

    header('Content-Type: application/json; charset=UTF-8');
    echo json_encode(['ok' => true]);
    exit;
}

/*
 * Early-exit AJAX handler for notification polling — runs before all heavy queries.
 */
if (strtolower(trim((string) ($_GET['ajax'] ?? ''))) === 'notifications') {
    $notifSeen = (array) ($_SESSION['provider_notif_seen'] ?? []);
    $lastSeenMsgId       = (int) ($notifSeen['msg_id'] ?? 0);
    $lastSeenPendingId   = (int) ($notifSeen['pending_id'] ?? 0);
    $lastSeenCancelledId = (int) ($notifSeen['cancelled_id'] ?? 0);

    $dismissedStore   = (array) ($_SESSION['provider_dismissed_notifs'] ?? []);
    $dismissedMsgIds  = array_keys((array) ($dismissedStore['message']   ?? []));
    $dismissedPendIds = array_keys((array) ($dismissedStore['pending']   ?? []));
    $dismissedCanIds  = array_keys((array) ($dismissedStore['cancelled'] ?? []));

    try {
        $dismissedMsgSql = count($dismissedMsgIds) > 0
            ? ' AND rcm.message_id NOT IN (' . implode(',', array_map('intval', $dismissedMsgIds)) . ')'
            : '';
        $ajaxMsgStmt = $pdo->prepare(
            'SELECT rcm.message_id, rcm.request_id, rcm.message, rcm.created_at,
                    c.name AS customer_name
             FROM request_chat_message rcm
             INNER JOIN servicerequest sr ON rcm.request_id = sr.request_id
             INNER JOIN appointmentslot asl ON sr.slot_id = asl.slot_id
             LEFT JOIN customer c ON sr.customer_id = c.customer_id
             WHERE asl.serviceprovider_id = :pid
               AND rcm.sender_role = \'customer\'' . $dismissedMsgSql . '
             ORDER BY rcm.created_at DESC
             LIMIT ' . (int) $notificationLimit
        );
        $ajaxMsgStmt->bindValue(':pid', $providerId, PDO::PARAM_INT);
        $ajaxMsgStmt->execute();
        while ($r = $ajaxMsgStmt->fetch()) {
            $recentCustomerMessages[] = [
                'message_id'    => (int) $r['message_id'],
                'request_id'    => (int) $r['request_id'],
                'message'       => (string) ($r['message'] ?? ''),
                'created_at'    => (string) ($r['created_at'] ?? ''),
                'customer_name' => (string) ($r['customer_name'] ?? t('notif_customer')),
                'is_unread'     => (int) $r['message_id'] > $lastSeenMsgId,
            ];
        }

        $dismissedCanSql = count($dismissedCanIds) > 0
            ? ' AND sr.request_id NOT IN (' . implode(',', array_map('intval', $dismissedCanIds)) . ')'
            : '';
        $ajaxCancelStmt = $pdo->prepare(
            'SELECT sr.request_id,
                    IFNULL(sr.cancellation_reason, \'\') AS cancellation_reason,
                    c.name AS customer_name,
                    asl.date AS appointment_date,
                    asl.slot AS appointment_time
             FROM servicerequest sr
             INNER JOIN appointmentslot asl ON sr.slot_id = asl.slot_id
             LEFT JOIN customer c ON sr.customer_id = c.customer_id
             WHERE asl.serviceprovider_id = :pid
               AND sr.status = \'Cancelled\'' . $dismissedCanSql . '
             ORDER BY sr.request_id DESC
             LIMIT ' . (int) $notificationLimit
        );
        $ajaxCancelStmt->bindValue(':pid', $providerId, PDO::PARAM_INT);
        $ajaxCancelStmt->execute();
        while ($r = $ajaxCancelStmt->fetch()) {
            $recentCancelledRequests[] = [
                'request_id'          => (int) $r['request_id'],
                'customer_name'       => (string) ($r['customer_name'] ?? 'Customer'),
                'appointment_date'    => (string) ($r['appointment_date'] ?? ''),
                'appointment_time'    => (string) ($r['appointment_time'] ?? ''),
                'cancellation_reason' => (string) ($r['cancellation_reason'] ?? ''),
                'is_unread'           => (int) $r['request_id'] > $lastSeenCancelledId,
            ];
        }

        $dismissedPendSql = count($dismissedPendIds) > 0
            ? ' AND sr.request_id NOT IN (' . implode(',', array_map('intval', $dismissedPendIds)) . ')'
            : '';
        $ajaxPendingStmt = $pdo->prepare(
            'SELECT sr.request_id,
                    c.name AS customer_name,
                    sc.name AS category_name,
                    asl.date AS appointment_date,
                    asl.slot AS appointment_time
             FROM servicerequest sr
             INNER JOIN appointmentslot asl ON sr.slot_id = asl.slot_id
             LEFT JOIN customer c ON sr.customer_id = c.customer_id
             LEFT JOIN servicecategory sc ON sr.category_id = sc.category_id
             WHERE asl.serviceprovider_id = :pid
               AND sr.status = \'Pending\'' . $dismissedPendSql . '
             ORDER BY sr.request_id DESC
             LIMIT ' . (int) $notificationLimit
        );
        $ajaxPendingStmt->bindValue(':pid', $providerId, PDO::PARAM_INT);
        $ajaxPendingStmt->execute();
        while ($r = $ajaxPendingStmt->fetch()) {
            $recentPendingRequests[] = [
                'request_id'       => (int) $r['request_id'],
                'customer_name'    => (string) ($r['customer_name'] ?? 'Customer'),
                'category_name'    => (string) ($r['category_name'] ?? t('prov_general_service')),
                'appointment_date' => (string) ($r['appointment_date'] ?? ''),
                'appointment_time' => (string) ($r['appointment_time'] ?? ''),
                'is_unread'        => (int) $r['request_id'] > $lastSeenPendingId,
            ];
        }
    } catch (PDOException $ajaxNotifException) {
        // Return empty arrays on DB error — client handles gracefully
    }

    $unreadCount = count(array_filter($recentCustomerMessages, static fn($m) => $m['is_unread']))
                 + count(array_filter($recentPendingRequests,   static fn($r) => $r['is_unread']))
                 + count(array_filter($recentCancelledRequests, static fn($r) => $r['is_unread']));

    header('Content-Type: application/json; charset=UTF-8');
    echo json_encode([
        'ok'                       => true,
        'unread_count'             => $unreadCount,
        'notification_count'       => count($recentCustomerMessages) + count($recentCancelledRequests) + count($recentPendingRequests),
        'recent_customer_messages' => $recentCustomerMessages,
        'recent_pending_requests'  => $recentPendingRequests,
        'recent_cancelled_requests'=> $recentCancelledRequests,
    ]);
    exit;
}

/*
 * Read one-time flash success message from previous PRG redirect.
 */
if (isset($_SESSION['service_provider_dashboard_flash_success']) && is_string($_SESSION['service_provider_dashboard_flash_success'])) {
    $successMessage = $_SESSION['service_provider_dashboard_flash_success'];
    unset($_SESSION['service_provider_dashboard_flash_success']);
}

/*
 * Load global service categories for service selection updates.
 */
try {
    $serviceCategories = ensureServiceCategories($pdo);
} catch (PDOException $exception) {
    $serviceCategories = [];
}

foreach ($serviceCategories as $category) {
    $serviceCategoryLookup[(int) $category['category_id']] = $category;
}

/*
 * Load this provider's category requests for display in the dashboard.
 */
$categoryRequests = [];
try {
    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS category_requests (
            request_id INT AUTO_INCREMENT PRIMARY KEY,
            provider_id INT NOT NULL,
            category_name VARCHAR(200) NOT NULL,
            category_info TEXT,
            status ENUM('pending','approved','rejected') NOT NULL DEFAULT 'pending',
            admin_notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
    );

    $catReqStmt = $pdo->prepare(
        'SELECT request_id, category_name, category_info, status, admin_notes, created_at
         FROM category_requests
         WHERE provider_id = :provider_id
         ORDER BY created_at DESC'
    );
    $catReqStmt->execute(['provider_id' => $providerId]);
    while ($catReqRow = $catReqStmt->fetch()) {
        $categoryRequests[] = [
            'request_id'    => (int) $catReqRow['request_id'],
            'category_name' => (string) $catReqRow['category_name'],
            'category_info' => (string) ($catReqRow['category_info'] ?? ''),
            'status'        => (string) $catReqRow['status'],
            'admin_notes'   => (string) ($catReqRow['admin_notes'] ?? ''),
            'created_at'    => (string) $catReqRow['created_at'],
        ];
    }
} catch (PDOException $exception) {
    // Non-fatal: table may not exist yet if never submitted
}

/*
 * Validate the optional profile photo upload and return normalized metadata.
 */
function validateProviderPhotoUpload(?array $filePayload): ?array
{
    if ($filePayload === null || !is_array($filePayload)) {
        return null;
    }

    $uploadError = (int) ($filePayload['error'] ?? UPLOAD_ERR_NO_FILE);
    if ($uploadError === UPLOAD_ERR_NO_FILE) {
        return null;
    }

    if ($uploadError !== UPLOAD_ERR_OK) {
        throw new RuntimeException(t('prov_err_photo_upload'));
    }

    $temporaryPath = (string) ($filePayload['tmp_name'] ?? '');
    if ($temporaryPath === '' || !is_uploaded_file($temporaryPath)) {
        throw new RuntimeException(t('prov_err_photo_verify'));
    }

    $fileSize = (int) ($filePayload['size'] ?? 0);
    if ($fileSize <= 0 || $fileSize > PROVIDER_PHOTO_MAX_IMAGE_BYTES) {
        throw new RuntimeException(t('prov_err_photo_size'));
    }

    $allowedMimeMap = [
        'image/jpeg' => 'jpg',
        'image/png' => 'png',
        'image/webp' => 'webp',
    ];

    $finfoResource = finfo_open(FILEINFO_MIME_TYPE);
    if ($finfoResource === false) {
        throw new RuntimeException(t('prov_err_photo_validate'));
    }

    try {
        $mimeType = finfo_file($finfoResource, $temporaryPath);
        if (!is_string($mimeType) || !array_key_exists($mimeType, $allowedMimeMap)) {
            throw new RuntimeException(t('prov_err_photo_type'));
        }
    } finally {
        finfo_close($finfoResource);
    }

    return [
        'tmp_name' => $temporaryPath,
        'extension' => $allowedMimeMap[$mimeType],
    ];
}

/*
 * Persist a validated profile photo to disk and return the web + absolute paths.
 */
function storeProviderPhoto(array $photoInfo, int $providerId): array
{
    if (!is_dir(PROVIDER_PHOTO_UPLOAD_DIRECTORY)) {
        $created = mkdir(PROVIDER_PHOTO_UPLOAD_DIRECTORY, 0755, true);
        if (!$created && !is_dir(PROVIDER_PHOTO_UPLOAD_DIRECTORY)) {
            throw new RuntimeException(t('prov_err_photo_storage'));
        }
    }

    $fileExtension = (string) ($photoInfo['extension'] ?? '');
    $tmpName = (string) ($photoInfo['tmp_name'] ?? '');
    $generatedName = 'provider_' . $providerId . '_' . date('Ymd_His') . '_' . bin2hex(random_bytes(8)) . '.' . $fileExtension;
    $absoluteDestination = PROVIDER_PHOTO_UPLOAD_DIRECTORY . DIRECTORY_SEPARATOR . $generatedName;

    if (!move_uploaded_file($tmpName, $absoluteDestination)) {
        throw new RuntimeException(t('prov_err_photo_save'));
    }

    return [
        'web_path' => PROVIDER_PHOTO_UPLOAD_WEB_PATH . '/' . $generatedName,
        'absolute_path' => $absoluteDestination,
    ];
}

/*
 * Safely remove an existing profile photo within the upload directory.
 */
function deleteProviderPhoto(string $photoPath): void
{
    $photoPath = trim($photoPath);
    if ($photoPath === '') {
        return;
    }

    $baseDirectory = realpath(PROVIDER_PHOTO_UPLOAD_DIRECTORY);
    if ($baseDirectory === false) {
        return;
    }

    $normalized = str_replace('\\', '/', $photoPath);
    if (strpos($normalized, '..') !== false) {
        return;
    }

    $absolutePath = realpath(__DIR__ . '/' . $normalized);
    if ($absolutePath === false) {
        $absolutePath = __DIR__ . '/' . $normalized;
    }

    if (strpos($absolutePath, $baseDirectory) !== 0) {
        return;
    }

    if (is_file($absolutePath)) {
        @unlink($absolutePath);
    }
}

/*
 * Fetch the current profile photo path for the active provider.
 */
function loadProviderPhotoPath(PDO $pdo, int $providerId): string
{
    $statement = $pdo->prepare('SELECT photo FROM serviceprovider WHERE provider_id = :provider_id LIMIT 1');
    $statement->execute(['provider_id' => $providerId]);

    return (string) ($statement->fetchColumn() ?? '');
}

/*
 * Handle profile updates, service category updates, slot creation,
 * and request status changes from this dashboard.
 */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $formAction = trim((string) ($_POST['form_action'] ?? ''));

    if ($formAction === 'update_status') {
        $postedCsrfToken = (string) ($_POST['csrf_token'] ?? '');
        $requestId = (int) ($_POST['request_id'] ?? 0);
        $newStatus = trim((string) ($_POST['status'] ?? ''));

        /*
         * Validation gate for CSRF, request selection, and allowed status values.
         */
        if (!hash_equals($_SESSION['service_provider_status_csrf'], $postedCsrfToken)) {
            $errorMessage = t('prov_err_csrf');
        } elseif ($requestId <= 0) {
            $errorMessage = t('prov_err_invalid_request');
        } elseif (!in_array($newStatus, ['Pending', 'Confirmed', 'Completed', 'Cancelled'], true)) {
            $errorMessage = t('prov_err_invalid_status');
        } else {
            try {
                /*
                 * Ensure the targeted request belongs to this service provider.
                 */
                $ownershipStatement = $pdo->prepare(
                    'SELECT
                        sr.request_id,
                        sr.status,
                        sr.customer_id,
                        sr.category_id,
                        sr.image1,
                        sr.image2,
                        sr.image3
                     FROM servicerequest sr
                     INNER JOIN appointmentslot asl
                        ON sr.slot_id = asl.slot_id
                     WHERE sr.request_id = :request_id
                       AND asl.serviceprovider_id = :provider_id
                     LIMIT 1'
                );
                $ownershipStatement->execute([
                    'request_id' => $requestId,
                    'provider_id' => $providerId,
                ]);

                $requestContext = $ownershipStatement->fetch();

                if ($requestContext === false) {
                    $errorMessage = t('prov_err_req_not_found');
                } else {
                    $currentStatus = (string) ($requestContext['status'] ?? 'Pending');

                    /*
                     * Providers cannot cancel once a request is confirmed.
                     * Cancelled requests are treated as final and cannot be updated.
                     */
                    if ($currentStatus === 'Cancelled') {
                        $errorMessage = t('prov_err_already_cancelled');
                    } elseif (in_array($currentStatus, ['Confirmed', 'Completed'], true) && $newStatus === 'Cancelled') {
                        $errorMessage = t('prov_err_cancel_by_cust');
                    }
                }

                if ($errorMessage === '') {
                    /*
                     * Collect optional price values when the status implies pricing.
                     * Confirmed → estimated_price   |   Completed → final_price
                     */
                    $priceSetClause = '';
                    $priceBindings  = [];
                    if ($newStatus === 'Confirmed') {
                        $rawEstimated = trim((string) ($_POST['estimated_price'] ?? ''));
                        if ($rawEstimated !== '' && is_numeric($rawEstimated) && (float) $rawEstimated >= 0) {
                            $priceSetClause = ', sr.estimated_price = :estimated_price';
                            $priceBindings['estimated_price'] = round((float) $rawEstimated, 2);
                        }
                    } elseif ($newStatus === 'Completed') {
                        $rawFinal = trim((string) ($_POST['final_price'] ?? ''));
                        if ($rawFinal !== '' && is_numeric($rawFinal) && (float) $rawFinal >= 0) {
                            $priceSetClause = ', sr.final_price = :final_price';
                            $priceBindings['final_price'] = round((float) $rawFinal, 2);
                        }
                    }

                    /*
                     * Update status for the target request and cancel
                     * other pending options from the same customer submission.
                     */
                    $pdo->beginTransaction();

                    $updateStatement = $pdo->prepare(
                        'UPDATE servicerequest sr
                         INNER JOIN appointmentslot asl
                            ON sr.slot_id = asl.slot_id
                         SET sr.status = :status' . $priceSetClause . '
                         WHERE sr.request_id = :request_id
                           AND asl.serviceprovider_id = :provider_id'
                    );
                    $updateStatement->execute(array_merge([
                        'status'     => $newStatus,
                        'request_id' => $requestId,
                        'provider_id'=> $providerId,
                    ], $priceBindings));

                    if (in_array($newStatus, ['Confirmed', 'Completed'], true)) {
                        /*
                         * Requests submitted with multiple slot options share the same images.
                         * Cancel all other pending options in that group once one is confirmed.
                         */
                        $cancelStatement = $pdo->prepare(
                            'UPDATE servicerequest sr
                             INNER JOIN appointmentslot asl
                                ON sr.slot_id = asl.slot_id
                             SET sr.status = "Cancelled"
                             WHERE sr.request_id <> :request_id
                               AND sr.status = "Pending"
                               AND sr.customer_id = :customer_id
                               AND sr.category_id = :category_id
                               AND sr.image1 = :image1
                               AND (sr.image2 <=> :image2)
                               AND (sr.image3 <=> :image3)
                               AND asl.serviceprovider_id = :provider_id'
                        );
                        $cancelStatement->execute([
                            'request_id' => $requestId,
                            'customer_id' => (int) $requestContext['customer_id'],
                            'category_id' => (int) $requestContext['category_id'],
                            'image1' => (string) ($requestContext['image1'] ?? ''),
                            'image2' => $requestContext['image2'],
                            'image3' => $requestContext['image3'],
                            'provider_id' => $providerId,
                        ]);
                    }

                    $pdo->commit();

                    $_SESSION['service_provider_dashboard_flash_success'] = t('prov_ok_status');
                    header('Location: service_provider_dashboard.php#requests');
                    exit;
                }
            } catch (PDOException $exception) {
                if ($pdo->inTransaction()) {
                    $pdo->rollBack();
                }
                $errorMessage = t('prov_err_status_fail');
            }
        }
    } elseif ($formAction === 'update_profile') {
        $profileFormSubmitted = true;
        $postedCsrfToken = (string) ($_POST['csrf_token'] ?? '');
        $profileNameValue = trim((string) ($_POST['profile_name'] ?? ''));
        $profileBioValue = trim((string) ($_POST['profile_bio'] ?? ''));
        $profilePhoneValue = trim((string) ($_POST['profile_phone'] ?? ''));

        if (!hash_equals($_SESSION['service_provider_profile_csrf'], $postedCsrfToken)) {
            $errorMessage = t('prov_err_csrf');
        } elseif ($profileNameValue === '') {
            $errorMessage = t('prov_err_enter_name');
        } elseif (mb_strlen($profileNameValue) > 100) {
            $errorMessage = t('prov_err_name_too_long');
        } elseif ($profileBioValue === '') {
            $errorMessage = t('prov_err_enter_bio');
        } elseif (mb_strlen($profileBioValue) > 2000) {
            $errorMessage = t('prov_err_bio_too_long');
        } else {
            $storedPhotoPath = '';
            $newPhotoAbsolutePath = '';

            try {
                $storedPhotoPath = loadProviderPhotoPath($pdo, $providerId);
                $photoUpload = validateProviderPhotoUpload($_FILES['profile_photo'] ?? null);
                $newPhotoPath = $storedPhotoPath;

                if ($photoUpload !== null) {
                    $storedPhotoInfo = storeProviderPhoto($photoUpload, $providerId);
                    $newPhotoPath = (string) ($storedPhotoInfo['web_path'] ?? '');
                    $newPhotoAbsolutePath = (string) ($storedPhotoInfo['absolute_path'] ?? '');
                }

                $updateFields = 'name = :name, bio = :bio, photo = :photo';
                $updateParams = [
                    'name'        => $profileNameValue,
                    'bio'         => $profileBioValue,
                    'photo'       => $newPhotoPath,
                    'provider_id' => $providerId,
                ];

                if ($profilePhoneValue !== '') {
                    $updateFields .= ', phone = :phone';
                    $updateParams['phone'] = $profilePhoneValue;
                }

                $updateStatement = $pdo->prepare(
                    'UPDATE serviceprovider SET ' . $updateFields . ' WHERE provider_id = :provider_id'
                );
                $updateStatement->execute($updateParams);

                if ($photoUpload !== null && $storedPhotoPath !== '' && $storedPhotoPath !== $newPhotoPath) {
                    deleteProviderPhoto($storedPhotoPath);
                }

                $_SESSION['service_provider_dashboard_flash_success'] = t('prov_ok_profile');
                header('Location: service_provider_dashboard.php#profile-editor');
                exit;
            } catch (RuntimeException $exception) {
                if ($newPhotoAbsolutePath !== '' && is_file($newPhotoAbsolutePath)) {
                    @unlink($newPhotoAbsolutePath);
                }
                $errorMessage = $exception->getMessage();
            } catch (PDOException $exception) {
                if ($newPhotoAbsolutePath !== '' && is_file($newPhotoAbsolutePath)) {
                    @unlink($newPhotoAbsolutePath);
                }
                $errorMessage = t('prov_err_profile_fail');
            }
        }
    } elseif ($formAction === 'request_location_change') {
        $postedCsrfToken = (string) ($_POST['csrf_token'] ?? '');
        $requestedLocation = trim((string) ($_POST['new_location'] ?? ''));

        if (!hash_equals($_SESSION['service_provider_profile_csrf'], $postedCsrfToken)) {
            $errorMessage = t('prov_err_csrf');
        } elseif ($requestedLocation === '') {
            $errorMessage = t('prov_location_change_err_empty');
        } elseif (mb_strlen($requestedLocation) > 255) {
            $errorMessage = t('prov_location_change_err_long');
        } else {
            try {
                // Load current location and pending status
                $curLocStmt = $pdo->prepare(
                    'SELECT IFNULL(location,\'\') AS location,
                            IFNULL(location_change_status,\'none\') AS location_change_status
                     FROM serviceprovider WHERE provider_id = :id LIMIT 1'
                );
                $curLocStmt->execute(['id' => $providerId]);
                $curLocRow = $curLocStmt->fetch();
                $currentLocation      = (string) ($curLocRow['location'] ?? '');
                $currentChangeStatus  = (string) ($curLocRow['location_change_status'] ?? 'none');

                if ($currentChangeStatus === 'pending') {
                    $errorMessage = t('prov_location_change_err_pending');
                } elseif ($requestedLocation === $currentLocation) {
                    $errorMessage = t('prov_location_change_err_same');
                } else {
                    // Insert pending request record
                    $pdo->prepare(
                        'INSERT INTO provider_location_requests
                            (provider_id, current_location, requested_location, status)
                         VALUES (:pid, :current, :requested, \'pending\')'
                    )->execute([
                        'pid'       => $providerId,
                        'current'   => $currentLocation,
                        'requested' => $requestedLocation,
                    ]);

                    // Mark provider as having a pending location change
                    $pdo->prepare(
                        'UPDATE serviceprovider
                         SET pending_location = :pending, location_change_status = \'pending\'
                         WHERE provider_id = :id'
                    )->execute(['pending' => $requestedLocation, 'id' => $providerId]);

                    $_SESSION['service_provider_dashboard_flash_success'] = t('prov_location_change_ok');
                    header('Location: service_provider_dashboard.php#profile-editor');
                    exit;
                }
            } catch (PDOException $exception) {
                $errorMessage = t('prov_err_profile_fail');
            }
        }
    } elseif ($formAction === 'create_slot') {
        $slotFormSubmitted = true;
        $postedCsrfToken = (string) ($_POST['csrf_token'] ?? '');
        $slotDateValue = trim((string) ($_POST['slot_date'] ?? ''));
        $slotTimeValue = trim((string) ($_POST['slot_time'] ?? ''));
        $normalizedTime = '';

        /*
         * Validation gate for CSRF, slot date, and slot time.
         */
        if (!hash_equals($_SESSION['service_provider_slot_csrf'], $postedCsrfToken)) {
            $errorMessage = t('prov_err_csrf');
        } elseif ($slotDateValue === '' || $slotTimeValue === '') {
            $errorMessage = t('prov_err_choose_slot');
        } else {
            $dateObject = DateTime::createFromFormat('Y-m-d', $slotDateValue);
            $timeObject = DateTime::createFromFormat('H:i', $slotTimeValue);

            if ($dateObject === false || $dateObject->format('Y-m-d') !== $slotDateValue) {
                $errorMessage = t('prov_err_invalid_date');
            } elseif ($timeObject === false) {
                $errorMessage = t('prov_err_invalid_time');
            } else {
                $normalizedDate = $dateObject->format('Y-m-d');
                $normalizedTime = $timeObject->format('H:i:s');

                $slotDateValue = $normalizedDate;
                $slotTimeValue = $timeObject->format('H:i');

                $today = new DateTime('today');
                if ($dateObject < $today) {
                    $errorMessage = t('prov_err_past_date');
                }
            }
        }

        if ($errorMessage === '') {
            try {
                /*
                 * Prevent duplicate slots for the same provider/date/time.
                 */
                $duplicateCheck = $pdo->prepare(
                    'SELECT slot_id
                     FROM appointmentslot
                     WHERE serviceprovider_id = :provider_id
                       AND date = :slot_date
                       AND slot = :slot_time
                     LIMIT 1'
                );
                $duplicateCheck->execute([
                    'provider_id' => $providerId,
                    'slot_date' => $slotDateValue,
                    'slot_time' => $normalizedTime,
                ]);

                if ($duplicateCheck->fetch() !== false) {
                    $errorMessage = t('prov_err_slot_exists');
                }
            } catch (PDOException $exception) {
                $errorMessage = t('prov_err_slot_check');
            }
        }

        if ($errorMessage === '') {
            try {
                /*
                 * Insert the new appointment slot for this provider.
                 */
                $insertSlot = $pdo->prepare(
                    'INSERT INTO appointmentslot (serviceprovider_id, date, slot)
                     VALUES (:provider_id, :slot_date, :slot_time)'
                );
                $insertSlot->execute([
                    'provider_id' => $providerId,
                    'slot_date' => $slotDateValue,
                    'slot_time' => $normalizedTime,
                ]);

                $_SESSION['service_provider_dashboard_flash_success'] = t('prov_ok_slot');
                header('Location: service_provider_dashboard.php#upcoming-slots');
                exit;
            } catch (PDOException $exception) {
                $errorMessage = t('prov_err_slot_fail');
            }
        }
    } elseif ($formAction === 'delete_slot') {
        $postedCsrfToken = (string) ($_POST['csrf_token'] ?? '');
        $deleteSlotId    = (int) ($_POST['slot_id'] ?? 0);

        if (!hash_equals($_SESSION['service_provider_slot_csrf'], $postedCsrfToken)) {
            $errorMessage = t('prov_err_csrf');
        } elseif ($deleteSlotId <= 0) {
            $errorMessage = t('prov_err_invalid_request');
        } else {
            try {
                $slotOwnerCheck = $pdo->prepare(
                    'SELECT asl.slot_id
                     FROM appointmentslot asl
                     LEFT JOIN servicerequest sr
                         ON sr.slot_id = asl.slot_id
                         AND sr.status IN (\'Pending\', \'Confirmed\', \'Completed\')
                     WHERE asl.slot_id            = :slot_id
                       AND asl.serviceprovider_id = :provider_id
                       AND sr.request_id IS NULL
                     LIMIT 1'
                );
                $slotOwnerCheck->execute([
                    'slot_id'     => $deleteSlotId,
                    'provider_id' => $providerId,
                ]);
                if ($slotOwnerCheck->fetch() === false) {
                    $errorMessage = t('prov_err_slot_not_found_or_booked');
                } else {
                    $pdo->prepare(
                        'DELETE FROM appointmentslot
                         WHERE slot_id            = :slot_id
                           AND serviceprovider_id = :provider_id'
                    )->execute([
                        'slot_id'     => $deleteSlotId,
                        'provider_id' => $providerId,
                    ]);
                    $_SESSION['service_provider_dashboard_flash_success'] = t('prov_ok_slot_deleted');
                    header('Location: service_provider_dashboard.php#upcoming-slots');
                    exit;
                }
            } catch (PDOException $exception) {
                $errorMessage = t('prov_err_slot_fail');
            }
        }
    } elseif ($formAction === 'update_services') {
        $serviceFormSubmitted = true;
        $postedCsrfToken = (string) ($_POST['csrf_token'] ?? '');
        $selectedCategoryIds = $_POST['category_ids'] ?? [];
        $postedPrices = $_POST['category_prices'] ?? [];
        $validatedServices = [];

        /*
         * Validation gate for CSRF, category availability, and visit prices.
         */
        if (!hash_equals($_SESSION['service_provider_services_csrf'], $postedCsrfToken)) {
            $errorMessage = t('prov_err_csrf');
        } elseif (count($serviceCategoryLookup) === 0) {
            $errorMessage = t('prov_err_no_categories');
        } else {
            $normalizedCategoryIds = [];

            foreach ((array) $selectedCategoryIds as $categoryId) {
                $categoryId = (int) $categoryId;
                if ($categoryId > 0) {
                    $normalizedCategoryIds[$categoryId] = $categoryId;
                }
            }

            $serviceCategorySelections = array_values($normalizedCategoryIds);

            if (count($serviceCategorySelections) === 0) {
                $errorMessage = t('prov_err_choose_category');
            } else {
                foreach ($serviceCategorySelections as $categoryId) {
                    if (!isset($serviceCategoryLookup[$categoryId])) {
                        $errorMessage = t('prov_err_invalid_cat');
                        break;
                    }

                    $rawPrice = fromArabicNumerals(trim((string) ($postedPrices[$categoryId] ?? '')));
                    $servicePriceValues[$categoryId] = $rawPrice;

                    if ($rawPrice === '' || !is_numeric($rawPrice)) {
                        $errorMessage = t('prov_err_enter_price');
                        break;
                    }

                    $priceValue = (float) $rawPrice;
                    if ($priceValue <= 0 || $priceValue > 100000) {
                        $errorMessage = t('prov_err_price_range');
                        break;
                    }

                    $validatedServices[$categoryId] = round($priceValue, 2);
                }
            }
        }

        if ($errorMessage === '') {
            try {
                /*
                 * Replace provider service categories with the submitted selection.
                 */
                $pdo->beginTransaction();

                $deleteStatement = $pdo->prepare('DELETE FROM providedservices WHERE provider_id = :provider_id');
                $deleteStatement->execute(['provider_id' => $providerId]);

                $insertStatement = $pdo->prepare(
                    'INSERT INTO providedservices (category_id, provider_id, visit_price)
                     VALUES (:category_id, :provider_id, :visit_price)'
                );

                foreach ($validatedServices as $categoryId => $priceValue) {
                    $insertStatement->execute([
                        'category_id' => $categoryId,
                        'provider_id' => $providerId,
                        'visit_price' => $priceValue,
                    ]);
                }

                $pdo->commit();

                $_SESSION['service_provider_dashboard_flash_success'] = t('prov_ok_services');
                header('Location: service_provider_dashboard.php#service-categories');
                exit;
            } catch (PDOException $exception) {
                if ($pdo->inTransaction()) {
                    $pdo->rollBack();
                }
                $errorMessage = t('prov_err_services_fail');
            }
        }
    } elseif ($formAction === 'request_category') {
        $catReqName = trim((string) ($_POST['cat_req_name'] ?? ''));
        $catReqInfo = trim((string) ($_POST['cat_req_info'] ?? ''));

        if ($catReqName === '') {
            $errorMessage = t('cat_req_err_name_empty');
        } elseif (mb_strlen($catReqName) > 200) {
            $errorMessage = t('cat_req_err_name_long');
        } elseif (mb_strlen($catReqInfo) > 1000) {
            $errorMessage = t('cat_req_err_info_long');
        } else {
            try {
                $pdo->exec(
                    "CREATE TABLE IF NOT EXISTS category_requests (
                        request_id INT AUTO_INCREMENT PRIMARY KEY,
                        provider_id INT NOT NULL,
                        category_name VARCHAR(200) NOT NULL,
                        category_info TEXT,
                        status ENUM('pending','approved','rejected') NOT NULL DEFAULT 'pending',
                        admin_notes TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
                );

                $insertCatReq = $pdo->prepare(
                    'INSERT INTO category_requests (provider_id, category_name, category_info, status)
                     VALUES (:provider_id, :category_name, :category_info, \'pending\')'
                );
                $insertCatReq->execute([
                    'provider_id'   => $providerId,
                    'category_name' => $catReqName,
                    'category_info' => $catReqInfo,
                ]);

                $_SESSION['service_provider_dashboard_flash_success'] = t('cat_req_ok');
                header('Location: service_provider_dashboard.php#cat-requests');
                exit;
            } catch (PDOException $exception) {
                $errorMessage = t('cat_req_err_db');
            }
        }
    } elseif ($formAction === 'confirm_cancellation') {
        $postedCsrfToken = (string) ($_POST['csrf_token'] ?? '');
        $requestId       = (int) ($_POST['request_id'] ?? 0);

        if (!hash_equals($_SESSION['service_provider_status_csrf'], $postedCsrfToken)) {
            $errorMessage = t('prov_err_csrf');
        } elseif ($requestId <= 0) {
            $errorMessage = t('prov_err_invalid_request');
        } else {
            try {
                $cancelOwnerCheck = $pdo->prepare(
                    'SELECT sr.request_id,
                            sr.status,
                            IFNULL(sr.cancellation_requested, 0) AS cancellation_requested
                     FROM servicerequest sr
                     INNER JOIN appointmentslot asl ON sr.slot_id = asl.slot_id
                     WHERE sr.request_id          = :request_id
                       AND asl.serviceprovider_id = :provider_id
                     LIMIT 1'
                );
                $cancelOwnerCheck->execute([
                    'request_id'  => $requestId,
                    'provider_id' => $providerId,
                ]);
                $cancelReqRow = $cancelOwnerCheck->fetch();

                if ($cancelReqRow === false) {
                    $errorMessage = t('prov_err_req_not_found');
                } elseif ((int) ($cancelReqRow['cancellation_requested'] ?? 0) !== 1) {
                    $errorMessage = t('prov_err_cancel_not_requested');
                } else {
                    $pdo->prepare(
                        'UPDATE servicerequest sr
                         INNER JOIN appointmentslot asl ON sr.slot_id = asl.slot_id
                         SET sr.status                = "Cancelled",
                             sr.cancellation_requested = 0
                         WHERE sr.request_id          = :request_id
                           AND asl.serviceprovider_id = :provider_id'
                    )->execute([
                        'request_id'  => $requestId,
                        'provider_id' => $providerId,
                    ]);
                    $_SESSION['service_provider_dashboard_flash_success'] = t('prov_ok_cancel_confirmed');
                    header('Location: service_provider_dashboard.php#requests');
                    exit;
                }
            } catch (PDOException $exception) {
                $errorMessage = t('prov_err_cancel_confirm_fail');
            }
        }
    } else {
        $errorMessage = t('prov_err_unknown_action');
    }
}

try {
    /*
     * Load service provider profile details and aggregate rating metrics.
     */
    $profileStatement = $pdo->prepare(
        'SELECT
            sp.provider_id,
            sp.name,
            sp.phone,
            sp.email,
            sp.bio,
            sp.photo,
            IFNULL(sp.location, \'\') AS location,
            IFNULL(sp.pending_location, \'\') AS pending_location,
            IFNULL(sp.location_change_status, \'none\') AS location_change_status,
            AVG(sr.rating) AS average_rating,
            COUNT(sr.rating) AS rating_count
         FROM serviceprovider sp
         LEFT JOIN appointmentslot asl
            ON sp.provider_id = asl.serviceprovider_id
         LEFT JOIN servicerequest sr
            ON asl.slot_id = sr.slot_id
            AND sr.rating IS NOT NULL
         WHERE sp.provider_id = :provider_id
         GROUP BY sp.provider_id, sp.name, sp.phone, sp.email, sp.bio, sp.photo,
                  sp.location, sp.pending_location, sp.location_change_status
         LIMIT 1'
    );
    $profileStatement->execute(['provider_id' => $providerId]);
    $profileRow = $profileStatement->fetch();

    if ($profileRow === false) {
        $errorMessage = t('prov_err_load_profile');
    } else {
        $providerProfile = [
            'provider_id'            => (int) $profileRow['provider_id'],
            'name'                   => (string) $profileRow['name'],
            'phone'                  => (string) ($profileRow['phone'] ?? ''),
            'email'                  => (string) ($profileRow['email'] ?? ''),
            'bio'                    => trim((string) ($profileRow['bio'] ?? '')),
            'photo'                  => (string) ($profileRow['photo'] ?? ''),
            'location'               => trim((string) ($profileRow['location'] ?? '')),
            'pending_location'       => trim((string) ($profileRow['pending_location'] ?? '')),
            'location_change_status' => (string) ($profileRow['location_change_status'] ?? 'none'),
        ];

        $ratingCount = (int) ($profileRow['rating_count'] ?? 0);
        $averageRating = $ratingCount > 0 ? (float) ($profileRow['average_rating'] ?? 0) : null;
    }

    /*
     * Load category list and visit pricing configured for this service provider.
     */
    $servicesStatement = $pdo->prepare(
        'SELECT
            ps.category_id,
            ps.visit_price,
            sc.name AS category_name,
            sc.description AS category_description,
            IFNULL(sc.name_ar, \'\') AS name_ar,
            IFNULL(sc.description_ar, \'\') AS description_ar
         FROM providedservices ps
         INNER JOIN servicecategory sc
            ON ps.category_id = sc.category_id
         WHERE ps.provider_id = :provider_id
         ORDER BY sc.name ASC'
    );
    $servicesStatement->execute(['provider_id' => $providerId]);

    while ($serviceRow = $servicesStatement->fetch()) {
        $providerServices[] = [
            'category_id'        => (int) $serviceRow['category_id'],
            'visit_price'        => (float) $serviceRow['visit_price'],
            'category_name'      => (string) $serviceRow['category_name'],
            'category_description' => trim((string) ($serviceRow['category_description'] ?? '')),
            'name'               => (string) $serviceRow['category_name'],
            'description'        => trim((string) ($serviceRow['category_description'] ?? '')),
            'name_ar'            => (string) ($serviceRow['name_ar'] ?? ''),
            'description_ar'     => trim((string) ($serviceRow['description_ar'] ?? '')),
        ];
    }

    /*
     * Load all requests mapped to this service provider through appointment slots.
     */
    $requestsStatement = $pdo->prepare(
        'SELECT
            sr.request_id,
            sr.status,
            sr.review,
            sr.rating,
            sr.estimated_price,
            sr.final_price,
            sr.image1,
            sr.image2,
            sr.image3,
            IFNULL(sr.cancellation_reason, \'\')    AS cancellation_reason,
            IFNULL(sr.cancellation_requested, 0)    AS cancellation_requested,
            c.name AS customer_name,
            c.email AS customer_email,
            c.phone AS customer_phone,
            c.latitude  AS customer_latitude,
            c.longitude AS customer_longitude,
            sc.name AS category_name,
            asl.date AS appointment_date,
            asl.slot AS appointment_time
         FROM servicerequest sr
         INNER JOIN appointmentslot asl
            ON sr.slot_id = asl.slot_id
         LEFT JOIN customer c
            ON sr.customer_id = c.customer_id
         LEFT JOIN servicecategory sc
            ON sr.category_id = sc.category_id
         WHERE asl.serviceprovider_id = :provider_id
         ORDER BY
            CASE sr.status
                WHEN \'Pending\' THEN 1
                WHEN \'Confirmed\' THEN 2
                WHEN \'Completed\' THEN 3
                WHEN \'Cancelled\' THEN 4
                ELSE 5
            END,
            asl.date DESC,
            asl.slot DESC,
            sr.request_id DESC'
    );
    $requestsStatement->execute(['provider_id' => $providerId]);

    while ($requestRow = $requestsStatement->fetch()) {
        $statusValue = (string) ($requestRow['status'] ?? 'Pending');
        if (isset($requestStats[$statusValue])) {
            $requestStats[$statusValue] += 1;
        }

        $imagePaths = [];
        foreach (['image1', 'image2', 'image3'] as $imageColumnName) {
            $imagePath = trim((string) ($requestRow[$imageColumnName] ?? ''));
            if ($imagePath !== '') {
                $imagePaths[] = $imagePath;
            }
        }

        $ratingRaw = $requestRow['rating'] ?? null;
        $ratingValue = $ratingRaw !== null ? (int) $ratingRaw : null;

        $custLatRaw = $requestRow['customer_latitude']  ?? null;
        $custLngRaw = $requestRow['customer_longitude'] ?? null;

        $requests[] = [
            'request_id' => (int) $requestRow['request_id'],
            'status' => $statusValue,
            'review' => trim((string) ($requestRow['review'] ?? '')),
            'rating' => $ratingValue,
            'estimated_price' => $requestRow['estimated_price'] !== null ? (float) $requestRow['estimated_price'] : null,
            'final_price' => $requestRow['final_price'] !== null ? (float) $requestRow['final_price'] : null,
            'customer_name' => (string) ($requestRow['customer_name'] ?? t('prov_unknown_customer')),
            'customer_email' => (string) ($requestRow['customer_email'] ?? ''),
            'customer_phone' => (string) ($requestRow['customer_phone'] ?? ''),
            'customer_latitude'  => $custLatRaw  !== null ? (float) $custLatRaw  : null,
            'customer_longitude' => $custLngRaw !== null ? (float) $custLngRaw : null,
            'category_name' => (string) ($requestRow['category_name'] ?? t('prov_general_service')),
            'appointment_date' => (string) ($requestRow['appointment_date'] ?? ''),
            'appointment_time' => (string) ($requestRow['appointment_time'] ?? ''),
            'images'                 => $imagePaths,
            'cancellation_reason'    => (string) ($requestRow['cancellation_reason'] ?? ''),
            'cancellation_requested' => (int) ($requestRow['cancellation_requested'] ?? 0) === 1,
            'can_provider_cancel'    => $statusValue === 'Pending',
        ];
    }

    /*
     * Load future slots and derive booking state from active request occupancy.
     */
    $slotsStatement = $pdo->prepare(
        "SELECT
            asl.slot_id,
            asl.date,
            asl.slot,
            CASE
                WHEN sr.request_id IS NULL THEN 0
                ELSE 1
                END AS is_booked,
                sr.request_id,
                sr.customer_id,
                c.name AS customer_name,
                c.email AS customer_email,
                c.phone AS customer_phone,
                c.address AS customer_address
         FROM appointmentslot asl
         LEFT JOIN servicerequest sr
            ON sr.slot_id = asl.slot_id
            AND sr.status IN ('Pending', 'Confirmed', 'Completed')
            LEFT JOIN customer c
                ON sr.customer_id = c.customer_id
         WHERE asl.serviceprovider_id = :provider_id
           AND asl.date >= CURDATE()
         ORDER BY asl.date ASC, asl.slot ASC
         LIMIT 40"
    );
    $slotsStatement->execute(['provider_id' => $providerId]);

    while ($slotRow = $slotsStatement->fetch()) {
        $upcomingSlots[] = [
            'slot_id' => (int) $slotRow['slot_id'],
            'date' => (string) $slotRow['date'],
            'slot' => (string) $slotRow['slot'],
            'is_booked' => (int) ($slotRow['is_booked'] ?? 0) === 1,
            'request_id' => (int) ($slotRow['request_id'] ?? 0),
            'customer_id' => (int) ($slotRow['customer_id'] ?? 0),
            'customer_name' => (string) ($slotRow['customer_name'] ?? ''),
            'customer_email' => (string) ($slotRow['customer_email'] ?? ''),
            'customer_phone' => (string) ($slotRow['customer_phone'] ?? ''),
            'customer_address' => (string) ($slotRow['customer_address'] ?? ''),
        ];
    }
} catch (PDOException $exception) {
    if ($errorMessage === '') {
        $errorMessage = t('prov_err_load_dashboard');
    }
}

/*
 * Load lightweight notification data for recent messages and cancellations.
 */
try {
    $messageStatement = $pdo->prepare(
        'SELECT rcm.message_id, rcm.request_id, rcm.message, rcm.created_at,
                c.name AS customer_name
         FROM request_chat_message rcm
         INNER JOIN servicerequest sr ON rcm.request_id = sr.request_id
         INNER JOIN appointmentslot asl ON sr.slot_id = asl.slot_id
         LEFT JOIN customer c ON sr.customer_id = c.customer_id
         WHERE asl.serviceprovider_id = :provider_id
           AND rcm.sender_role = "customer"
         ORDER BY rcm.created_at DESC
                 LIMIT ' . (int) $notificationLimit
    );
    $messageStatement->bindValue(':provider_id', $providerId, PDO::PARAM_INT);
    $messageStatement->execute();

    while ($messageRow = $messageStatement->fetch()) {
        $recentCustomerMessages[] = [
            'message_id'    => (int) $messageRow['message_id'],
            'request_id'    => (int) $messageRow['request_id'],
            'message'       => (string) ($messageRow['message'] ?? ''),
            'created_at'    => (string) ($messageRow['created_at'] ?? ''),
            'customer_name' => (string) ($messageRow['customer_name'] ?? t('notif_customer')),
            'is_unread'     => false,
        ];
    }

    $cancelStatement = $pdo->prepare(
        'SELECT sr.request_id,
                c.name AS customer_name,
                asl.date AS appointment_date,
                asl.slot AS appointment_time
         FROM servicerequest sr
         INNER JOIN appointmentslot asl ON sr.slot_id = asl.slot_id
         LEFT JOIN customer c ON sr.customer_id = c.customer_id
         WHERE asl.serviceprovider_id = :provider_id
           AND sr.status = \'Cancelled\'
         ORDER BY sr.request_id DESC
                 LIMIT ' . (int) $notificationLimit
    );
    $cancelStatement->bindValue(':provider_id', $providerId, PDO::PARAM_INT);
    $cancelStatement->execute();

    while ($cancelRow = $cancelStatement->fetch()) {
        $recentCancelledRequests[] = [
            'request_id'       => (int) $cancelRow['request_id'],
            'customer_name'    => (string) ($cancelRow['customer_name'] ?? t('notif_customer')),
            'appointment_date' => (string) ($cancelRow['appointment_date'] ?? ''),
            'appointment_time' => (string) ($cancelRow['appointment_time'] ?? ''),
            'is_unread'        => false,
        ];
    }

    $pendingStatement = $pdo->prepare(
        'SELECT sr.request_id,
                c.name AS customer_name,
                sc.name AS category_name,
                asl.date AS appointment_date,
                asl.slot AS appointment_time
         FROM servicerequest sr
         INNER JOIN appointmentslot asl ON sr.slot_id = asl.slot_id
         LEFT JOIN customer c ON sr.customer_id = c.customer_id
         LEFT JOIN servicecategory sc ON sr.category_id = sc.category_id
         WHERE asl.serviceprovider_id = :provider_id
           AND sr.status = \'Pending\'
         ORDER BY sr.request_id DESC
                 LIMIT ' . (int) $notificationLimit
    );
    $pendingStatement->bindValue(':provider_id', $providerId, PDO::PARAM_INT);
    $pendingStatement->execute();

    while ($pendingRow = $pendingStatement->fetch()) {
        $recentPendingRequests[] = [
            'request_id'       => (int) $pendingRow['request_id'],
            'customer_name'    => (string) ($pendingRow['customer_name'] ?? 'Customer'),
            'category_name'    => (string) ($pendingRow['category_name'] ?? 'Service'),
            'appointment_date' => (string) ($pendingRow['appointment_date'] ?? ''),
            'appointment_time' => (string) ($pendingRow['appointment_time'] ?? ''),
            'is_unread'        => false,
        ];
    }
} catch (PDOException $exception) {
    $recentCustomerMessages = [];
    $recentCancelledRequests = [];
    $recentPendingRequests = [];
}

/*
 * Notification badge count — only unread items (newer than session-stored seen IDs).
 */
$pageLoadSeen = (array) ($_SESSION['provider_notif_seen'] ?? []);
$pageLoadSeenMsgId       = (int) ($pageLoadSeen['msg_id'] ?? 0);
$pageLoadSeenPendingId   = (int) ($pageLoadSeen['pending_id'] ?? 0);
$pageLoadSeenCancelledId = (int) ($pageLoadSeen['cancelled_id'] ?? 0);

$notificationCount = 0;
foreach ($recentCustomerMessages as &$msg) {
    $msg['is_unread'] = $msg['message_id'] > $pageLoadSeenMsgId;
    if ($msg['is_unread']) $notificationCount++;
}
unset($msg);
foreach ($recentPendingRequests as &$req) {
    $req['is_unread'] = $req['request_id'] > $pageLoadSeenPendingId;
    if ($req['is_unread']) $notificationCount++;
}
unset($req);
foreach ($recentCancelledRequests as &$can) {
    $can['is_unread'] = $can['request_id'] > $pageLoadSeenCancelledId;
    if ($can['is_unread']) $notificationCount++;
}
unset($can);

/*
 * Default profile edit fields to current profile data when no submission occurred.
 */
$profilePendingLocation = '';
$profileLocationChangeStatus = 'none';

if (!$profileFormSubmitted && $providerProfile !== null) {
    $profileNameValue              = $providerProfile['name'];
    $profileBioValue               = $providerProfile['bio'];
    $profileLocationValue          = $providerProfile['location'];
    $profilePhoneValue             = $providerProfile['phone'];
    $profileEmailValue             = $providerProfile['email'];
    $profilePendingLocation        = $providerProfile['pending_location'];
    $profileLocationChangeStatus   = $providerProfile['location_change_status'];
}

/*
 * Default service category selections to current provider services when untouched.
 */
if (!$serviceFormSubmitted) {
    foreach ($providerServices as $service) {
        $categoryId = (int) $service['category_id'];
        $serviceCategorySelections[] = $categoryId;
        $servicePriceValues[$categoryId] = number_format((float) $service['visit_price'], 2, '.', '');
    }
}

/*
 * Default slot form fields for first load.
 */
if (!$slotFormSubmitted) {
    $slotDateValue = date('Y-m-d');
    $slotTimeValue = '09:00';
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
    <title><?php echo htmlspecialchars(t('prov_dash_title'), ENT_QUOTES, 'UTF-8'); ?> - <?php echo htmlspecialchars(t('site_name'), ENT_QUOTES, 'UTF-8'); ?></title>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <?php if (isRtl()): ?>
    <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <?php endif; ?>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <!-- Leaflet CSS — served locally -->
    <link rel="stylesheet" href="vendor/leaflet/leaflet.css">
    <style>
        /*
         * Global reset and shared visual tokens for consistent styling.
         */
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root {
            --ink: #0f172a;
            --muted: #475569;
            --line: #dbe2ea;
            --brand: #0f766e;
            --brand-deep: #115e59;
            --success-bg: #ecfdf5;
            --success-text: #166534;
            --success-border: #86efac;
            --warning-bg: #fff7ed;
            --warning-text: #9a3412;
            --warning-border: #fdba74;
            --danger-bg: #fff1f2;
            --danger-text: #be123c;
            --danger-border: #fecdd3;
            --neutral-bg: #f8fafc;
            --neutral-text: #334155;
            --neutral-border: #cbd5e1;
            --info-bg: #eff6ff;
            --info-text: #1d4ed8;
            --info-border: #bfdbfe;
        }

        html,
        body {
            width: 100%;
            overflow-x: hidden;
            height: 100%;
        }

        body {
            min-height: 100vh;
            font-family: 'Plus Jakarta Sans', sans-serif;
            color: var(--ink);
            background:
                radial-gradient(circle at 12% 0%, rgba(20, 184, 166, 0.17), transparent 35%),
                radial-gradient(circle at 92% 8%, rgba(249, 115, 22, 0.2), transparent 34%),
                linear-gradient(130deg, #ecfeff, #f8fafc 45%, #fff7ed);
            display: flex;
            flex-direction: row;
        }

        /*
         * Main page shell that constrains max width for readability.
         * Adjusted for sidebar layout - sidebar takes 15%, main content takes 85%.
         */
        .shell {
            width: 85%;
            max-width: none;
            margin: 0;
            display: flex;
            flex-direction: column;
            gap: 14px;
            padding: 24px 16px 34px;
            overflow-y: auto;
        }

        /*
         * Header card with profile summary and primary actions.
         */
        .topbar {
            background: rgba(255, 255, 255, 0.9);
            border: 1px solid rgba(255, 255, 255, 0.9);
            border-radius: 22px;
            box-shadow: 0 14px 34px rgba(15, 23, 42, 0.09);
            padding: 16px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 10px;
            flex-wrap: wrap;
        }

        .header-profile {
            display: flex;
            align-items: center;
            gap: 12px;
            flex-wrap: wrap;
        }

        .avatar {
            width: 64px;
            height: 64px;
            border-radius: 18px;
            overflow: hidden;
            border: 1px solid #dbe2ea;
            background: linear-gradient(135deg, #dbeafe, #e2e8f0);
            display: flex;
            align-items: center;
            justify-content: center;
            color: #0f172a;
            font-size: 1.35rem;
        }

        .avatar img {
            width: 100%;
            height: 100%;
            object-fit: cover;
            display: block;
        }

        .header-profile h1 {
            font-size: 1.28rem;
            font-weight: 800;
            color: #042f2e;
            margin-bottom: 3px;
        }

        .header-profile p {
            font-size: 0.84rem;
            color: var(--muted);
            line-height: 1.35;
        }

        .topbar-actions {
            display: flex;
            align-items: center;
            gap: 8px;
            flex-wrap: wrap;
        }

        .pill {
            min-height: 40px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 7px;
            padding: 8px 14px;
            border-radius: 999px;
            border: 1px solid var(--line);
            background: #ffffff;
            color: #0f172a;
            font-size: 0.84rem;
            font-weight: 700;
            text-decoration: none;
        }

        .pill.logout {
            border: none;
            color: #ffffff;
            background: linear-gradient(145deg, var(--brand), var(--brand-deep));
        }

        /*
         * Reusable panel shell for summaries and content groups.
         * Panels are hidden by default and shown when targeted.
         */
        .panel {
            display: none;
            background: rgba(255, 255, 255, 0.94);
            border: 1px solid rgba(255, 255, 255, 0.92);
            border-radius: 20px;
            box-shadow: 0 12px 28px rgba(15, 23, 42, 0.08);
            padding: 14px;
        }

        .panel.dashboard-summary {
            display: block;
        }

        .panel:target {
            display: block;
        }

        .panel h2 {
            font-size: 1.1rem;
            color: #042f2e;
            font-weight: 800;
            margin-bottom: 8px;
        }

        .panel p.lead {
            font-size: 0.86rem;
            color: var(--muted);
            margin-bottom: 10px;
            line-height: 1.4;
        }

        /*
         * Feedback banners for request update outcomes.
         */
        .feedback {
            border-radius: 14px;
            border: 1px solid;
            padding: 12px 14px;
            font-size: 0.9rem;
            font-weight: 700;
        }

        .feedback.error {
            background: var(--danger-bg);
            color: var(--danger-text);
            border-color: var(--danger-border);
        }

        .feedback.success {
            background: var(--success-bg);
            color: var(--success-text);
            border-color: var(--success-border);
        }

        /*
         * Summary cards visualizing provider ratings at a glance.
         */
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 10px;
        }

        .summary-card {
            border: 1px solid rgba(219, 226, 234, 0.8);
            border-radius: 16px;
            background: rgba(255, 255, 255, 0.92);
            padding: 14px 12px;
            box-shadow: 0 4px 14px rgba(15, 23, 42, 0.04);
            transition: box-shadow 0.2s ease, transform 0.2s ease;
        }

        .summary-card:hover {
            box-shadow: 0 8px 22px rgba(15, 23, 42, 0.09);
            transform: translateY(-2px);
        }

        .summary-card .label {
            font-size: 0.78rem;
            color: #64748b;
            margin-bottom: 4px;
        }

        .summary-card .value {
            font-size: 1.12rem;
            font-weight: 800;
            color: #0f172a;
        }

        /*
         * Notification panel styling for recent updates.
         */
        .notification-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 12px;
        }

        .notification-card {
            border: 1px solid rgba(219, 226, 234, 0.8);
            border-radius: 16px;
            background: rgba(255, 255, 255, 0.92);
            padding: 14px;
            display: grid;
            gap: 10px;
            box-shadow: 0 4px 14px rgba(15, 23, 42, 0.05);
            transition: box-shadow 0.2s ease;
        }

        .notification-card:hover {
            box-shadow: 0 8px 24px rgba(15, 23, 42, 0.09);
        }

        .notification-card h3 {
            font-size: 0.93rem;
            font-weight: 800;
            color: #0f172a;
            display: flex;
            align-items: center;
            gap: 7px;
        }

        .notification-card h3::before {
            content: '';
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: linear-gradient(135deg, var(--brand), var(--brand-deep));
            display: inline-block;
            flex-shrink: 0;
        }

        .notification-list {
            display: grid;
            gap: 7px;
        }

        .notification-item {
            border: 1px solid rgba(226, 232, 240, 0.8);
            border-radius: 12px;
            padding: 10px 12px;
            background: rgba(248, 250, 252, 0.8);
            display: grid;
            gap: 5px;
            transition: background 0.18s ease, border-color 0.18s ease;
        }

        .notification-item:hover {
            background: rgba(236, 253, 245, 0.5);
            border-color: rgba(15, 118, 110, 0.2);
        }

        .notification-item.is-unread {
            background: rgba(15, 118, 110, 0.06);
            border-color: rgba(15, 118, 110, 0.3);
        }

        .notification-item {
            position: relative; /* needed for absolute dismiss btn positioning */
        }

        .notif-dismiss-btn {
            position: absolute;
            top: 6px;
            right: 6px;
            width: 22px;
            height: 22px;
            border-radius: 50%;
            border: none;
            background: rgba(100, 116, 139, 0.12);
            color: #64748b;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.65rem;
            transition: background 0.15s ease, color 0.15s ease;
            opacity: 0;
            z-index: 2;
        }

        .notification-item:hover .notif-dismiss-btn {
            opacity: 1;
        }

        .notification-item .notif-dismiss-btn:hover {
            background: #fee2e2;
            color: #b91c1c;
        }

        /* Flash highlight for scrolled-to request cards */
        @keyframes requestHighlight {
            0%   { box-shadow: 0 0 0 3px rgba(15, 118, 110, 0.6), 0 8px 24px rgba(15, 23, 42, 0.12); }
            70%  { box-shadow: 0 0 0 3px rgba(15, 118, 110, 0.2), 0 8px 24px rgba(15, 23, 42, 0.08); }
            100% { box-shadow: none; }
        }

        .request-card.highlighted {
            animation: requestHighlight 2.2s ease forwards;
        }

        .notif-dot {
            display: inline-block;
            width: 8px;
            height: 8px;
            background: var(--brand, #0f766e);
            border-radius: 50%;
            margin-right: 6px;
            vertical-align: middle;
            flex-shrink: 0;
        }

        .notification-title {
            font-size: 0.83rem;
            font-weight: 700;
            color: #0f172a;
            display: flex;
            align-items: center;
        }

        .notification-text {
            font-size: 0.81rem;
            color: #334155;
            line-height: 1.4;
        }

        .notification-meta {
            font-size: 0.73rem;
            color: var(--muted);
            display: flex;
            justify-content: space-between;
            gap: 8px;
            flex-wrap: wrap;
            margin-top: 2px;
        }

        .notification-link {
            font-size: 0.73rem;
            font-weight: 700;
            color: var(--brand);
            text-decoration: none;
            transition: color 0.15s ease;
        }

        .notification-link:hover {
            color: var(--brand-deep);
        }

        /*
         * Profile edit form layout and field styling.
         */
        .profile-form {
            display: flex;
            flex-direction: column;
            gap: 12px;
        }

        .profile-grid {
            display: grid;
            grid-template-columns: minmax(220px, 0.6fr) 1fr;
            gap: 12px;
        }

        .profile-photo-panel {
            border: 1px solid #dbe2ea;
            border-radius: 14px;
            padding: 12px;
            background: #ffffff;
            display: grid;
            gap: 10px;
        }

        .profile-avatar {
            width: 88px;
            height: 88px;
            border-radius: 22px;
        }

        .profile-fields {
            display: grid;
            gap: 12px;
        }

        .profile-field label,
        .profile-photo-panel label {
            font-size: 0.84rem;
            font-weight: 700;
            color: #0f172a;
        }

        .profile-field input[type="text"],
        .profile-field textarea,
        .profile-photo-panel input[type="file"] {
            width: 100%;
            border: 2px solid #d9e2ec;
            border-radius: 12px;
            padding: 10px 12px;
            font-family: inherit;
            font-size: 0.86rem;
            color: #0f172a;
            background: #ffffff;
        }

        .profile-field textarea {
            min-height: 140px;
            resize: vertical;
        }

        .profile-field input:focus,
        .profile-field textarea:focus,
        .profile-photo-panel input[type="file"]:focus {
            outline: none;
            border-color: var(--brand);
            box-shadow: 0 0 0 4px rgba(15, 118, 110, 0.12);
        }

        .field-hint {
            font-size: 0.78rem;
            color: var(--muted);
        }

        .profile-submit {
            align-self: flex-start;
            min-height: 42px;
            border: none;
            border-radius: 12px;
            padding: 10px 14px;
            font-family: inherit;
            font-size: 0.85rem;
            font-weight: 800;
            color: #fff;
            background: linear-gradient(145deg, var(--brand), var(--brand-deep));
            cursor: pointer;
        }

        /*
         * Service category configuration form layout.
         */
        /* ── Services panel: stats bar ────────────────────────────────── */
        .svc-stats-bar {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 12px;
            margin-bottom: 22px;
        }
        .svc-stat-card {
            border-radius: 16px;
            padding: 14px 16px;
            display: flex;
            align-items: center;
            gap: 12px;
            transition: transform .15s;
        }
        .svc-stat-card:hover { transform: translateY(-2px); }
        .svc-stat-card.teal   { background: linear-gradient(135deg,#f0fdfa,#e8fdf8); border: 1px solid #99f6e4; }
        .svc-stat-card.indigo { background: linear-gradient(135deg,#eef2ff,#e9ecff); border: 1px solid #a5b4fc; }
        .svc-stat-card.amber  { background: linear-gradient(135deg,#fffbeb,#fef9e2); border: 1px solid #fde68a; }
        .svc-stat-icon {
            width: 42px; height: 42px; border-radius: 12px; flex-shrink: 0;
            display: flex; align-items: center; justify-content: center; font-size: 1.05rem;
        }
        .svc-stat-icon.teal   { background: linear-gradient(145deg,#0f766e,#115e59); color: #fff; }
        .svc-stat-icon.indigo { background: linear-gradient(145deg,#4f46e5,#4338ca); color: #fff; }
        .svc-stat-icon.amber  { background: linear-gradient(145deg,#d97706,#b45309); color: #fff; }
        .svc-stat-value { font-size: 1.5rem; font-weight: 800; color: #0f172a; line-height: 1; }
        .svc-stat-label { font-size: .7rem; font-weight: 600; color: #64748b; margin-top: 3px; text-transform: uppercase; letter-spacing: .3px; }

        /* ── Search bar ─────────────────────────────────────────────── */
        .svc-search-wrap { position: relative; margin-bottom: 14px; }
        .svc-search-icon {
            position: absolute; top: 50%; transform: translateY(-50%);
            left: 14px; color: #94a3b8; font-size: .88rem; pointer-events: none;
        }
        [dir="rtl"] .svc-search-icon { left: auto; right: 14px; }
        .svc-search-input {
            width: 100%; min-height: 44px;
            border: 2px solid #e2e8f0; border-radius: 12px;
            padding: 9px 12px 9px 40px;
            font-family: inherit; font-size: .9rem; color: #0f172a; background: #fff;
            transition: border-color .2s, box-shadow .2s;
        }
        [dir="rtl"] .svc-search-input { padding: 9px 40px 9px 12px; }
        .svc-search-input:focus {
            outline: none; border-color: #0f766e;
            box-shadow: 0 0 0 4px rgba(15,118,110,.1);
        }
        .svc-no-results {
            display: none; align-items: center; justify-content: center; flex-direction: column;
            gap: 8px; padding: 28px 16px; color: #94a3b8; font-size: .88rem;
            border: 2px dashed #e2e8f0; border-radius: 14px; text-align: center;
        }

        /* ── Service selection form ─────────────────────────────────── */
        .service-form { display: grid; gap: 12px; }
        .service-category-list { display: grid; gap: 8px; }
        .service-category-row {
            border: 2px solid #e2e8f0; border-radius: 16px;
            padding: 14px 16px; background: #fff;
            display: grid;
            grid-template-columns: 1fr minmax(160px, 0.38fr);
            gap: 10px; align-items: center;
            transition: border-color .2s, background .2s, box-shadow .2s;
        }
        .service-category-row:hover {
            border-color: #99f6e4;
            box-shadow: 0 2px 8px rgba(15,118,110,.07);
        }
        .service-category-row.is-selected {
            border-color: #0f766e;
            background: linear-gradient(135deg,#f0fdfa 0%,#f8fffd 100%);
            box-shadow: 0 2px 12px rgba(15,118,110,.1);
        }
        .service-category-row.is-disabled { opacity: .72; }
        .service-category-label {
            display: flex; align-items: flex-start; gap: 12px;
            cursor: pointer; user-select: none;
        }
        .service-category-label input[type="checkbox"] {
            width: 20px; height: 20px; flex-shrink: 0; margin-top: 2px;
            accent-color: #0f766e; cursor: pointer;
        }
        .svc-cat-name { font-size: .9rem; font-weight: 700; color: #0f172a; }
        .svc-cat-desc { font-size: .76rem; color: #64748b; margin-top: 3px; line-height: 1.4; }
        .service-category-description { display: none; }
        .service-category-price { display: grid; gap: 4px; }
        .service-category-price label { font-size: .74rem; font-weight: 700; color: #0f172a; }
        .svc-price-input-wrap { position: relative; }
        .svc-currency-sym {
            position: absolute; left: 10px; top: 50%; transform: translateY(-50%);
            font-size: .84rem; font-weight: 700; color: #64748b; pointer-events: none;
        }
        [dir="rtl"] .svc-currency-sym { left: auto; right: 10px; }
        .service-category-price input {
            min-height: 40px; width: 100%;
            border: 2px solid #d9e2ec; border-radius: 10px;
            padding: 8px 10px 8px 26px;
            font-family: inherit; font-size: .84rem; color: #0f172a; background: #fff;
            transition: border-color .2s;
        }
        [dir="rtl"] .service-category-price input { padding: 8px 26px 8px 10px; }
        .service-category-price input:focus {
            outline: none; border-color: var(--brand);
            box-shadow: 0 0 0 4px rgba(15,118,110,.12);
        }
        .service-category-price input:disabled { background: #f8fafc; color: #94a3b8; }
        .service-form-actions { display: flex; align-items: center; justify-content: flex-start; padding-top: 4px; }
        .service-divider { height: 2px; background: linear-gradient(90deg,#e2e8f0,transparent); margin: 24px 0; border: none; }

        /* ── Active services display ────────────────────────────────── */
        .svc-section-head {
            display: flex; align-items: center; justify-content: space-between;
            margin-bottom: 14px; gap: 10px;
        }
        .svc-section-head h3 { font-size: .98rem; font-weight: 800; color: #0f172a; margin: 0; }
        .svc-count-badge {
            background: linear-gradient(135deg,#0f766e,#14b8a6); color: #fff;
            font-size: .72rem; font-weight: 800; border-radius: 999px;
            padding: 3px 10px; min-width: 26px; text-align: center;
        }
        .svc-active-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
            gap: 12px; margin-bottom: 6px;
        }
        .service-card {
            border: 1px solid #e2e8f0; border-radius: 16px;
            padding: 16px 14px; background: #fff;
            display: grid; gap: 10px;
            transition: transform .15s, box-shadow .15s;
            position: relative; overflow: hidden;
        }
        .service-card::before {
            content: ''; position: absolute; top: 0; left: 0; right: 0;
            height: 3px; background: linear-gradient(90deg,#0f766e,#14b8a6);
        }
        .service-card:hover { transform: translateY(-3px); box-shadow: 0 8px 24px rgba(15,118,110,.12); }
        .svc-card-icon {
            width: 40px; height: 40px; border-radius: 12px;
            background: linear-gradient(145deg,#f0fdfa,#e0faf5);
            border: 1px solid #99f6e4;
            display: flex; align-items: center; justify-content: center;
            color: #0f766e; font-size: 1.1rem;
        }
        .service-card h3 { font-size: .9rem; font-weight: 800; color: #0f172a; margin: 0; }
        .service-card p { font-size: .78rem; color: #64748b; line-height: 1.4; margin: 0; }
        .svc-price-badge {
            display: inline-flex; align-items: center; gap: 4px;
            background: linear-gradient(135deg,#f0fdfa,#e8fdf5);
            border: 1px solid #99f6e4; border-radius: 8px;
            padding: 4px 10px; font-size: .78rem; font-weight: 800; color: #0f766e;
            align-self: flex-start;
        }
        .svc-active-badge {
            display: inline-flex; align-items: center; gap: 5px;
            background: #dcfce7; color: #166534; border-radius: 999px;
            padding: 3px 9px; font-size: .7rem; font-weight: 700; align-self: flex-start;
        }
        .svc-empty-state {
            text-align: center; padding: 28px 16px;
            border: 2px dashed #e2e8f0; border-radius: 14px;
            color: #94a3b8; font-size: .88rem; margin-bottom: 6px;
        }
        .svc-empty-state i { font-size: 2rem; display: block; margin-bottom: 8px; opacity: .4; }

        /* ── Category request section ───────────────────────────────── */
        .cat-req-section { border-top: 2px solid #e2e8f0; padding-top: 22px; margin-top: 4px; }
        .cat-req-section > h3 { font-size: 1rem; font-weight: 800; margin: 0 0 4px; color: #0f172a; }
        .cat-req-section > p  { font-size: .86rem; color: #64748b; margin-bottom: 16px; }
        .cat-req-form-card {
            background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 16px;
            padding: 18px 20px; display: grid; gap: 14px; max-width: 520px; margin-bottom: 18px;
        }
        .cat-req-field label {
            display: block; font-size: .84rem; font-weight: 700; color: #0f172a; margin-bottom: 5px;
        }
        .cat-req-field input, .cat-req-field textarea {
            width: 100%; border: 2px solid #d9e2ec; border-radius: 10px;
            padding: 9px 12px; font-family: inherit; font-size: .9rem; color: #0f172a;
            background: #fff; transition: border-color .2s;
        }
        .cat-req-field textarea { min-height: 80px; resize: vertical; }
        .cat-req-field input:focus, .cat-req-field textarea:focus {
            outline: none; border-color: #0f766e;
            box-shadow: 0 0 0 4px rgba(15,118,110,.1);
        }
        .cat-req-submit {
            display: inline-flex; align-items: center; gap: 8px; align-self: flex-start;
            background: linear-gradient(145deg,#0f766e,#115e59); color: #fff;
            border: none; border-radius: 10px; padding: 10px 18px;
            font-family: inherit; font-weight: 700; font-size: .88rem; cursor: pointer;
            transition: opacity .15s, transform .15s;
        }
        .cat-req-submit:hover { opacity: .88; transform: translateY(-1px); }
        .cat-req-status-list { display: grid; gap: 8px; }
        .cat-req-status-item {
            background: #fff; border: 1px solid #e2e8f0; border-radius: 12px;
            padding: 12px 14px; display: flex; align-items: center;
            justify-content: space-between; gap: 8px; flex-wrap: wrap;
        }
        .cat-req-status-name { font-weight: 700; font-size: .88rem; color: #0f172a; }
        .cat-req-notes { font-size: .78rem; color: #475569; margin-top: 4px; font-style: italic; }

        /*
         * Appointment slot creation form layout.
         */
        .slot-form {
            display: grid;
            gap: 10px;
            margin-bottom: 12px;
        }

        .slot-form-grid {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 10px;
        }

        .slot-field {
            display: grid;
            gap: 6px;
        }

        .slot-field label {
            font-size: 0.78rem;
            font-weight: 700;
            color: #0f172a;
        }

        .slot-field input {
            min-height: 40px;
            border: 2px solid #d9e2ec;
            border-radius: 10px;
            padding: 8px 10px;
            font-family: inherit;
            font-size: 0.84rem;
            color: #0f172a;
            background: #ffffff;
        }

        .slot-field input:focus {
            outline: none;
            border-color: var(--brand);
            box-shadow: 0 0 0 4px rgba(15, 118, 110, 0.12);
        }

        /*
         * Dashboard overview stat cards.
         */
        .dash-stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 12px;
            margin-bottom: 14px;
        }

        .dash-stat {
            border-radius: 16px;
            padding: 14px 16px;
            display: flex;
            align-items: center;
            gap: 13px;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }

        .dash-stat:hover {
            transform: translateY(-3px);
            box-shadow: 0 8px 24px rgba(15, 23, 42, 0.1);
        }

        .dash-stat.amber  { background: linear-gradient(135deg,#fff7ed,#ffedd5); border: 1.5px solid #fed7aa; }
        .dash-stat.teal   { background: linear-gradient(135deg,#f0fdfa,#ccfbf1); border: 1.5px solid #99f6e4; }
        .dash-stat.orange { background: linear-gradient(135deg,#fffbeb,#fef3c7); border: 1.5px solid #fde68a; }
        .dash-stat.indigo { background: linear-gradient(135deg,#f5f3ff,#ede9fe); border: 1.5px solid #c4b5fd; }

        .dash-stat-icon {
            width: 46px;
            height: 46px;
            border-radius: 13px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.1rem;
            flex-shrink: 0;
        }

        .dash-stat.amber  .dash-stat-icon { background: rgba(249,115,22,.15);  color: #ea580c; }
        .dash-stat.teal   .dash-stat-icon { background: rgba(20,184,166,.15);  color: #0f766e; }
        .dash-stat.orange .dash-stat-icon { background: rgba(245,158,11,.15);  color: #d97706; }
        .dash-stat.indigo .dash-stat-icon { background: rgba(99,102,241,.15);  color: #4f46e5; }

        .dash-stat-value {
            font-size: 1.55rem;
            font-weight: 800;
            color: #0f172a;
            line-height: 1;
            display: block;
        }

        .dash-stat-label {
            font-size: 0.75rem;
            color: #64748b;
            margin-top: 3px;
            display: block;
            font-weight: 600;
        }

        /*
         * Slot section: add-form card wrapper.
         */
        .slot-form-card {
            background: linear-gradient(135deg, #f8fafc, #f0f9ff);
            border: 1.5px solid #e0f2fe;
            border-radius: 16px;
            padding: 16px;
            margin-bottom: 20px;
        }

        .slot-form-card-title {
            font-size: 0.88rem;
            font-weight: 700;
            color: #0f172a;
            margin-bottom: 12px;
            display: flex;
            align-items: center;
            gap: 7px;
        }

        .slot-form-card-title i { color: var(--brand); }

        /*
         * Slot cards grid — responsive, 3-column on wide screens.
         */
        .slot-cards-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(210px, 1fr));
            gap: 14px;
        }

        .slot-card {
            border-radius: 16px;
            padding: 14px;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
            position: relative;
            overflow: hidden;
        }

        .slot-card:hover {
            transform: translateY(-3px);
            box-shadow: 0 8px 24px rgba(15, 23, 42, 0.11);
        }

        .slot-card.free {
            background: linear-gradient(135deg, #f0fdf4, #dcfce7);
            border: 1.5px solid #86efac;
        }

        .slot-card.booked {
            background: linear-gradient(135deg, #eff6ff, #dbeafe);
            border: 1.5px solid #93c5fd;
        }

        .slot-card-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 10px;
        }

        .slot-card-icon {
            width: 36px;
            height: 36px;
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.9rem;
            flex-shrink: 0;
        }

        .slot-card.free   .slot-card-icon { background: rgba(22,163,74,.15);  color: #16a34a; }
        .slot-card.booked .slot-card-icon { background: rgba(59,130,246,.15); color: #2563eb; }

        .slot-badge {
            font-size: 0.71rem;
            font-weight: 800;
            border-radius: 999px;
            padding: 3px 10px;
            border: 1px solid;
        }

        .slot-card.free   .slot-badge { background: #dcfce7; color: #15803d; border-color: #86efac; }
        .slot-card.booked .slot-badge { background: #dbeafe; color: #1d4ed8; border-color: #93c5fd; }

        .slot-date-text {
            font-size: 0.88rem;
            font-weight: 700;
            color: #0f172a;
            margin-bottom: 4px;
        }

        .slot-time-text {
            font-size: 0.82rem;
            color: #475569;
            display: flex;
            align-items: center;
            gap: 5px;
        }

        /*
         * Booked slot customer details and profile action.
         */
        .slot-booked-detail {
            margin-top: 10px;
            display: grid;
            gap: 8px;
            padding-top: 10px;
            border-top: 1px dashed #bfdbfe;
        }

        .slot-booked-detail p {
            font-size: 0.8rem;
            color: #475569;
        }

        .slot-profile-btn {
            align-self: flex-start;
            border: none;
            border-radius: 10px;
            padding: 6px 10px;
            font-size: 0.76rem;
            font-weight: 800;
            color: #ffffff;
            background: linear-gradient(140deg, #2563eb, #1d4ed8);
            cursor: pointer;
            transition: filter 0.15s;
        }

        .slot-profile-btn:hover { filter: brightness(1.08); }

        .slot-delete-form { margin-top: 10px; }

        .slot-delete-btn {
            width: 100%;
            border: 1px solid #fecdd3;
            background: #fff1f2;
            color: #be123c;
            border-radius: 10px;
            padding: 6px 10px;
            font-size: 0.76rem;
            font-weight: 700;
            cursor: pointer;
            font-family: inherit;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 5px;
            transition: background 0.15s, border-color 0.15s;
        }

        .slot-delete-btn:hover {
            background: #ffe4e6;
            border-color: #fca5a5;
        }

        /*
         * Customer profile modal for booked slot details.
         */
        .customer-profile-modal {
            position: fixed;
            inset: 0;
            display: flex;
            align-items: center;
            justify-content: center;
            background: rgba(15, 23, 42, 0);
            opacity: 0;
            visibility: hidden;
            transition: opacity 0.2s ease, visibility 0.2s ease, background 0.2s ease;
            padding: 18px;
            z-index: 200;
        }

        .customer-profile-modal.active {
            opacity: 1;
            visibility: visible;
            background: rgba(15, 23, 42, 0.45);
        }

        .customer-profile-dialog {
            background: #ffffff;
            border-radius: 18px;
            border: 1px solid rgba(15, 23, 42, 0.08);
            box-shadow: 0 18px 40px rgba(15, 23, 42, 0.2);
            width: min(92vw, 480px);
            padding: 18px;
            display: grid;
            gap: 12px;
        }

        .customer-profile-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 10px;
            border-bottom: 1px solid #e2e8f0;
            padding-bottom: 10px;
        }

        .customer-profile-header h3 {
            font-size: 1.05rem;
            font-weight: 800;
            color: #0f172a;
        }

        .customer-profile-close {
            border: none;
            background: #f1f5f9;
            color: #0f172a;
            border-radius: 10px;
            width: 36px;
            height: 36px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
        }

        .customer-profile-grid {
            display: grid;
            gap: 10px;
        }

        .customer-profile-label {
            font-size: 0.72rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-weight: 800;
            color: #64748b;
        }

        .customer-profile-value {
            font-size: 0.92rem;
            font-weight: 600;
            color: #0f172a;
            word-break: break-word;
        }

        /*
         * Request list card and status-update form styles.
         */
        .request-list {
            display: grid;
            gap: 14px;
        }

        @media (min-width: 900px) {
            .request-list {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }
        }

        .request-card {
            border: 1px solid #e2e8f0;
            border-left: 5px solid #cbd5e1;
            border-radius: 16px;
            background: #ffffff;
            padding: 16px;
            display: grid;
            gap: 10px;
            overflow: hidden;
            box-shadow: 0 4px 14px rgba(15, 23, 42, 0.07);
            transition: transform 0.18s ease, box-shadow 0.18s ease;
        }

        .request-card.pending   { border-left-color: #f59e0b; }
        .request-card.confirmed { border-left-color: #3b82f6; }
        .request-card.completed { border-left-color: #22c55e; }
        .request-card.cancelled { border-left-color: #f87171; }

        .request-head {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 8px;
            flex-wrap: wrap;
            margin: -16px -16px 0;
            padding: 12px 16px;
            border-bottom: 1px solid #f1f5f9;
            background: #f8fafc;
        }

        .request-card.pending   .request-head { background: #fffbeb; border-bottom-color: #fef3c7; }
        .request-card.confirmed .request-head { background: #eff6ff; border-bottom-color: #dbeafe; }
        .request-card.completed .request-head { background: #f0fdf4; border-bottom-color: #dcfce7; }
        .request-card.cancelled .request-head { background: #fff1f2; border-bottom-color: #fce7f3; }

        .request-head h3 {
            font-size: 0.95rem;
            color: #0f172a;
            font-weight: 800;
        }

        .status-pill {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            border-radius: 999px;
            border: 1px solid;
            padding: 4px 9px;
            font-size: 0.76rem;
            font-weight: 800;
        }

        .status-pill.pending {
            background: var(--warning-bg);
            color: var(--warning-text);
            border-color: var(--warning-border);
        }

        .status-pill.confirmed {
            background: var(--info-bg);
            color: var(--info-text);
            border-color: var(--info-border);
        }

        .status-pill.completed {
            background: var(--success-bg);
            color: var(--success-text);
            border-color: var(--success-border);
        }

        .status-pill.cancelled {
            background: var(--danger-bg);
            color: var(--danger-text);
            border-color: var(--danger-border);
        }

        .request-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 28px rgba(15, 23, 42, 0.12);
        }

        .meta-row {
            display: flex;
            flex-wrap: wrap;
            gap: 7px;
        }

        .chip {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            border: 1px solid #dbe2ea;
            border-radius: 999px;
            background: #f8fafc;
            color: #334155;
            padding: 5px 10px;
            font-size: 0.77rem;
            font-weight: 700;
        }

        .chip i { color: var(--brand); font-size: 0.75rem; }

        .customer-row {
            font-size: 0.83rem;
            color: #334155;
            line-height: 1.5;
            padding: 8px 12px;
            background: #f8fafc;
            border-radius: 10px;
            border: 1px solid #f1f5f9;
        }

        .price-row {
            font-size: 0.83rem;
            color: #334155;
            line-height: 1.4;
            display: flex;
            gap: 16px;
            flex-wrap: wrap;
            padding: 8px 12px;
            background: linear-gradient(135deg, #f0fdf4, #f8fafc);
            border: 1px solid #d1fae5;
            border-radius: 10px;
        }

        .review-row {
            font-size: 0.83rem;
            color: #334155;
            line-height: 1.4;
        }

        .request-actions {
            margin-top: 6px;
        }

        .request-link {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            font-size: 0.82rem;
            font-weight: 700;
            color: var(--brand);
            text-decoration: none;
        }

        .request-link:hover {
            color: var(--brand-deep);
        }

        .btn-message {
            display: inline-flex;
            align-items: center;
            gap: 7px;
            padding: 9px 18px;
            border-radius: 12px;
            background: linear-gradient(135deg, var(--brand), var(--brand-deep));
            color: #fff;
            font-family: inherit;
            font-size: 0.88rem;
            font-weight: 700;
            text-decoration: none;
            border: none;
            cursor: pointer;
            transition: opacity 0.15s, transform 0.15s;
        }
        .btn-message:hover { opacity: 0.88; transform: translateY(-1px); }

        .stars {
            display: inline-flex;
            align-items: center;
            gap: 2px;
            color: #f59e0b;
            font-size: 0.87rem;
        }

        .stars .star.is-empty {
            color: #cbd5e1;
        }

        .image-grid {
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: 8px;
        }

        .image-card {
            border: 1px solid #dbe2ea;
            border-radius: 10px;
            overflow: hidden;
            min-height: 94px;
            background: #fff;
        }

        .image-card img {
            width: 100%;
            height: 100%;
            min-height: 94px;
            object-fit: cover;
            display: block;
        }

        /*
         * Chat panel styling for request-level messaging.
         */
        /*
         * Chat styles removed - messages moved to sidebar
         */

        .status-form {
            display: flex;
            align-items: flex-end;
            gap: 8px;
            flex-wrap: wrap;
            padding-top: 10px;
            border-top: 1px solid #f1f5f9;
        }

        .price-input-row {
            display: flex;
            flex-direction: column;
            gap: 4px;
        }

        .price-input-row label {
            font-size: 0.78rem;
            font-weight: 700;
            color: #475569;
        }

        .price-input-row input[type="number"] {
            min-height: 40px;
            border: 2px solid #d9e2ec;
            border-radius: 11px;
            padding: 8px 10px;
            font-size: 0.9rem;
            font-family: inherit;
            color: #0f172a;
            background: #fff;
            width: 140px;
            transition: border-color 0.18s ease, box-shadow 0.18s ease;
        }

        .price-input-row input[type="number"]:focus {
            outline: none;
            border-color: var(--brand);
            box-shadow: 0 0 0 4px rgba(15, 118, 110, 0.12);
        }

        .status-form select {
            min-height: 40px;
            border: 2px solid #d9e2ec;
            border-radius: 11px;
            padding: 8px 10px;
            font-family: inherit;
            font-size: 0.84rem;
            color: #0f172a;
            background: #fff;
            min-width: 180px;
        }

        .status-form select:focus {
            outline: none;
            border-color: var(--brand);
            box-shadow: 0 0 0 4px rgba(15, 118, 110, 0.12);
        }

        .status-form button {
            min-height: 40px;
            border: none;
            border-radius: 11px;
            padding: 8px 12px;
            font-family: inherit;
            font-size: 0.83rem;
            font-weight: 800;
            color: #fff;
            background: linear-gradient(145deg, var(--brand), var(--brand-deep));
            cursor: pointer;
        }

        .empty-state {
            border: 1px dashed #cbd5e1;
            border-radius: 14px;
            background: #f8fafc;
            color: #334155;
            font-size: 0.9rem;
            font-weight: 700;
            text-align: center;
            padding: 16px;
        }

        /*
         * Responsive breakpoints for tablets and mobile phones.
         */
        @media (max-width: 1020px) {
            .summary-grid {
                grid-template-columns: repeat(3, minmax(0, 1fr));
            }

            .notification-grid {
                grid-template-columns: 1fr;
            }

            .small-grid {
                grid-template-columns: 1fr;
            }

            .profile-grid {
                grid-template-columns: 1fr;
            }
        }

        @media (max-width: 700px) {
            body {
                padding: 14px 10px 24px;
            }

            .summary-grid {
                grid-template-columns: 1fr 1fr;
            }

            .image-grid {
                grid-template-columns: 1fr;
            }

            .profile-submit {
                width: 100%;
                justify-content: center;
            }

            .service-category-row {
                grid-template-columns: 1fr;
            }
            .svc-stats-bar { grid-template-columns: 1fr; }
            .svc-active-grid { grid-template-columns: repeat(auto-fill, minmax(150px,1fr)); }

            .slot-form-grid {
                grid-template-columns: 1fr;
            }
        }

        @media (max-width: 480px) {
            .shell {
                padding: 12px 10px 24px;
                gap: 12px;
            }

            .topbar {
                padding: 12px;
                border-radius: 16px;
            }

            .header-profile h1 {
                font-size: 1.1rem;
            }

            .header-profile p {
                font-size: 0.8rem;
            }

            .avatar {
                width: 52px;
                height: 52px;
            }

            .panel {
                padding: 14px;
                border-radius: 16px;
            }

            .summary-grid {
                grid-template-columns: 1fr;
            }

            .notification-card {
                padding: 14px;
            }

            .request-card {
                padding: 14px;
            }

            .status-form {
                flex-direction: column;
                align-items: stretch;
            }

            .status-form select {
                width: 100%;
                min-width: 0;
            }

            .status-form button {
                width: 100%;
            }

            .image-grid {
                grid-template-columns: 1fr 1fr;
            }

            .slot-form-grid {
                grid-template-columns: 1fr;
            }

            .pill {
                padding: 7px 12px;
                font-size: 0.82rem;
                min-height: 36px;
            }

            .admin-chat-window {
                left: 10px;
                right: 10px;
                bottom: 86px;
                width: auto;
                height: calc(100vh - 110px);
                max-height: 480px;
                border-radius: 16px;
            }

            .admin-chat-fab {
                bottom: 16px;
            }
        }

        /*
         * Reduced-motion support for accessibility preferences.
         */
        @media (prefers-reduced-motion: reduce) {
            *,
            *::before,
            *::after {
                animation-duration: 0.01ms !important;
                animation-iteration-count: 1 !important;
                transition-duration: 0.01ms !important;
                scroll-behavior: auto !important;
            }
        }

        /*
         * Mobile sidebar toggle button and backdrop overlay.
         */
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
            color: var(--ink);
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

        /*
         * Sidebar navigation with permanent display on left side.
         * Always visible, taking 15% of the page width.
         */
        .sidebar {
            position: relative;
            left: 0;
            top: 0;
            height: 100vh;
            width: 15%;
            min-width: 180px;
            background: linear-gradient(180deg, rgba(15, 118, 110, 0.98), rgba(17, 94, 89, 0.98));
            backdrop-filter: blur(16px);
            border-right: 1px solid rgba(255, 255, 255, 0.1);
            transform: none;
            transition: none;
            z-index: 100;
            box-shadow: 4px 0 24px rgba(15, 23, 42, 0.25);
            display: flex;
            flex-direction: column;
            padding-top: 20px;
            padding-bottom: 20px;
            overflow: hidden;
            box-sizing: border-box;
        }

        .sidebar.open {
            transform: none;
        }

        @media (max-width: 1100px) {
            .sidebar {
                position: fixed;
                left: 0;
                top: 0;
                width: min(82vw, 320px);
                height: 100vh;
                transform: translateX(-100%);
                transition: transform 0.25s ease;
            }

            .sidebar.open {
                transform: translateX(0);
            }

            .sidebar-toggle {
                display: inline-flex;
            }

            .sidebar-backdrop {
                display: block;
            }

            body.sidebar-open .sidebar-backdrop {
                opacity: 1;
                pointer-events: auto;
            }

            .shell {
                width: 100%;
            }

            .topbar {
                padding-left: 56px;
            }

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

            [dir="rtl"] .topbar {
                padding-left: 0;
                padding-right: 56px;
            }
        }

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

        .sidebar-user-details {
            flex: 1;
            min-width: 0;
        }

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
            cursor: pointer;
            border: none;
            background: none;
            width: 100%;
            text-align: left;
            transition: all 0.2s ease;
            border-left: 3px solid transparent;
            position: relative;
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

        .sidebar-menu-item i {
            min-width: 20px;
            text-align: center;
            font-size: 1rem;
        }

        .menu-badge {
            position: absolute;
            top: 8px;
            right: 14px;
            min-width: 18px;
            height: 18px;
            padding: 0 6px;
            border-radius: 999px;
            background: #f97316;
            color: #fff;
            font-size: 0.7rem;
            font-weight: 800;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            animation: badgePop 0.3s cubic-bezier(0.36, 0.07, 0.19, 0.97);
        }

        @keyframes badgePop {
            0% { transform: scale(0.6); opacity: 0; }
            70% { transform: scale(1.15); }
            100% { transform: scale(1); opacity: 1; }
        }

        @keyframes fadeSlideUp {
            from { opacity: 0; transform: translateY(18px); }
            to   { opacity: 1; transform: translateY(0); }
        }

        .panel {
            animation: fadeSlideUp 0.42s cubic-bezier(0.22, 1, 0.36, 1) both;
        }

        .sidebar-footer {
            padding: 16px;
            border-top: 1px solid rgba(255, 255, 255, 0.15);
            margin-top: auto;
            flex-shrink: 0;
        }

        /*
         * Adjust main content when sidebar is open to account for fixed positioning.
         */
        body.sidebar-open {
            overflow: hidden;
        }

        /* RTL overrides */
        [dir="rtl"] body { font-family: 'Cairo', sans-serif; }
        [dir="rtl"] .sidebar { right: 0; left: auto; border-right: none; border-left: 1px solid rgba(255,255,255,.15); }
        [dir="rtl"] .dashboard-shell { margin-right: 0; margin-left: 0; }
        [dir="rtl"] input, [dir="rtl"] textarea, [dir="rtl"] select { text-align: right; }
        [dir="rtl"] .request-card { border-left: 1px solid #e2e8f0; border-right: 5px solid #cbd5e1; }
        [dir="rtl"] .request-card.pending   { border-right-color: #f59e0b; }
        [dir="rtl"] .request-card.confirmed { border-right-color: #3b82f6; }
        [dir="rtl"] .request-card.completed { border-right-color: #22c55e; }
        [dir="rtl"] .request-card.cancelled { border-right-color: #f87171; }
        [dir="rtl"] .request-head { margin: -16px -16px 0; }

        /* ── Provider cancellation-request box ── */
        .cancel-req-box {
            background: #fff7ed;
            border: 1px solid #fed7aa;
            border-radius: 14px;
            padding: 14px;
            display: grid;
            gap: 10px;
        }

        .cancel-req-header {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 0.9rem;
            font-weight: 800;
            color: #9a3412;
        }
        .cancel-req-header i { font-size: 1rem; }

        .cancel-req-info {
            font-size: 0.84rem;
            color: #7c3003;
            line-height: 1.45;
        }

        .cancel-req-reason {
            background: #fff;
            border: 1px solid #fde68a;
            border-radius: 10px;
            padding: 10px 12px;
            display: grid;
            gap: 4px;
        }
        .cancel-req-reason-lbl {
            font-size: 0.75rem;
            font-weight: 800;
            color: #92400e;
            text-transform: uppercase;
            letter-spacing: 0.4px;
        }
        .cancel-req-reason-text {
            font-size: 0.86rem;
            color: #1e293b;
            line-height: 1.5;
            white-space: pre-wrap;
            word-break: break-word;
        }

        .cancel-req-actions {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            align-items: center;
        }

        .btn-confirm-cancel {
            min-height: 40px;
            border-radius: 12px;
            border: none;
            background: linear-gradient(145deg, #dc2626, #b91c1c);
            color: #fff;
            font-family: inherit;
            font-size: 0.84rem;
            font-weight: 800;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 7px;
            padding: 8px 16px;
            transition: opacity 0.15s, transform 0.15s;
        }
        .btn-confirm-cancel:hover { opacity: 0.88; transform: translateY(-1px); }

        /* Cancelled request reason display (direct cancellations) */
        .cancelled-reason-box {
            background: #fef2f2;
            border: 1px solid #fecaca;
            border-radius: 10px;
            padding: 10px 12px;
            display: grid;
            gap: 4px;
        }
        .cancelled-reason-box .cancel-req-reason-lbl {
            display: flex;
            align-items: center;
            gap: 6px;
            color: #991b1b;
        }

        /* Notification panel cancellation reason line */
        .notification-cancel-reason {
            font-size: 0.8rem;
            color: #7f1d1d;
            background: #fef2f2;
            border-radius: 6px;
            padding: 4px 8px;
            margin-top: 2px;
            word-break: break-word;
        }
        .notif-reason-lbl {
            font-weight: 700;
        }

        /* ── Customer location map in request cards ─────────────── */
        .cust-location-box {
            margin-top: 12px;
            border: 1px solid #dbeafe;
            border-radius: 12px;
            overflow: hidden;
            background: #eff6ff;
        }

        .cust-location-header {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 8px 12px;
            font-size: .82rem;
            font-weight: 700;
            color: #1d4ed8;
            cursor: pointer;
            user-select: none;
        }

        .cust-location-header i { font-size: .9rem; }

        .cust-location-toggle-icon { margin-left: auto; transition: transform .2s; }
        [dir="rtl"] .cust-location-toggle-icon { margin-left: 0; margin-right: auto; }

        .cust-location-map-wrap {
            display: none;
            padding: 0 10px 10px;
        }

        .cust-location-map-wrap.open { display: block; }

        .cust-location-map-frame {
            width: 100%;
            height: 260px;
            border-radius: 8px;
            border: 1px solid #bfdbfe;
            background: #e5e7eb;
        }

        /* Address line shown below the customer location map */
        .cust-location-addr {
            display: flex;
            align-items: flex-start;
            gap: 6px;
            margin-top: 6px;
            padding: 0 2px;
            font-size: .78rem;
            color: #64748b;
            line-height: 1.4;
            min-height: 16px;
        }

        .cust-location-addr i { flex-shrink: 0; margin-top: 2px; color: #93c5fd; }

        /* Admin chat widget (same as customer) */
        .admin-chat-fab {
            position: fixed; bottom: 28px;
            <?php echo isRtl() ? 'left' : 'right'; ?>: 28px;
            z-index: 1000; display: flex; flex-direction: column;
            align-items: <?php echo isRtl() ? 'flex-start' : 'flex-end'; ?>; gap: 0;
        }
        .admin-chat-btn {
            width: 58px; height: 58px; border-radius: 50%; border: none; cursor: pointer;
            background: linear-gradient(135deg, #0f766e, #115e59); color: #fff; font-size: 1.3rem;
            box-shadow: 0 8px 24px rgba(15,118,110,.45);
            display: flex; align-items: center; justify-content: center;
            transition: transform .2s, box-shadow .2s; position: relative;
        }
        .admin-chat-btn:hover { transform: scale(1.08); }
        .admin-chat-unread-dot {
            position: absolute; top: 2px; right: 2px; width: 18px; height: 18px;
            border-radius: 50%; background: #ef4444; color: #fff; font-size: .65rem;
            font-weight: 800; display: flex; align-items: center; justify-content: center;
            border: 2px solid #fff;
        }
        .admin-chat-unread-dot.hidden { display: none; }
        .admin-chat-window {
            position: fixed; bottom: 100px; <?php echo isRtl()?'left':'right'; ?>: 20px;
            width: 340px; height: 460px; background: #fff; border-radius: 20px;
            box-shadow: 0 20px 60px rgba(15,23,42,.18);
            display: flex; flex-direction: column; z-index: 1001; overflow: hidden;
            transform: scale(.92) translateY(20px); opacity: 0; pointer-events: none;
            transition: transform .25s ease, opacity .25s ease;
        }
        .admin-chat-window.open { transform: scale(1) translateY(0); opacity: 1; pointer-events: auto; }
        .acw-header {
            background: linear-gradient(135deg, #0f766e, #115e59);
            color: #fff; padding: 14px 16px;
            display: flex; align-items: center; justify-content: space-between; flex-shrink: 0;
        }
        .acw-header-left { display: flex; align-items: center; gap: 10px; }
        .acw-avatar { width: 36px; height: 36px; border-radius: 50%; background: rgba(255,255,255,.2); display: flex; align-items: center; justify-content: center; font-size: 1rem; }
        .acw-title { font-size: .9rem; font-weight: 700; }
        .acw-sub   { font-size: .72rem; opacity: .85; }
        .acw-close { background: none; border: none; color: #fff; cursor: pointer; font-size: 1rem; padding: 4px; opacity: .8; }
        .acw-close:hover { opacity: 1; }
        .acw-messages { flex: 1; overflow-y: auto; padding: 14px; display: flex; flex-direction: column; gap: 8px; }
        .acw-msg-row { display: flex; justify-content: flex-start; }
        .acw-msg-row.self { justify-content: flex-end; }
        .acw-bubble { max-width: 75%; padding: 8px 12px; border-radius: 14px; font-size: .84rem; line-height: 1.5; background: #f1f5f9; color: #0f172a; border-bottom-left-radius: 3px; }
        .acw-msg-row.self .acw-bubble { background: linear-gradient(135deg, #0f766e, #115e59); color: #fff; border-bottom-left-radius: 14px; border-bottom-right-radius: 3px; }
        .acw-empty { text-align: center; color: #475569; font-size: .82rem; margin: auto; padding: 20px; }
        .acw-meta { font-size: .67rem; color: #475569; margin-top: 2px; }
        .acw-msg-row.self .acw-meta { text-align: right; color: rgba(255,255,255,.65); }
        .acw-input-row { padding: 10px 12px; border-top: 1px solid #dbe2ea; display: flex; gap: 8px; align-items: flex-end; flex-shrink: 0; }
        .acw-input { flex: 1; border: 1.5px solid #dbe2ea; border-radius: 12px; padding: 8px 12px; font-family: inherit; font-size: .85rem; resize: none; max-height: 90px; line-height: 1.45; color: #0f172a; }
        .acw-input:focus { outline: none; border-color: #0f766e; }
        .acw-send { height: 38px; min-width: 38px; padding: 0 12px; border-radius: 10px; border: none; background: linear-gradient(135deg, #0f766e, #115e59); color: #fff; font-size: .82rem; font-weight: 700; cursor: pointer; display: flex; align-items: center; gap: 5px; }
        .acw-send:disabled { opacity: .5; cursor: not-allowed; }
    </style>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/flatpickr/dist/flatpickr.min.css">
</head>
<body class="<?php echo htmlspecialchars(getLangBodyClass(), ENT_QUOTES, 'UTF-8'); ?>">
    <!-- Mobile sidebar toggle control -->
    <button class="sidebar-toggle" type="button" id="sidebarToggle" aria-label="Open navigation menu" aria-controls="sidebar" aria-expanded="false">
        <i class="fas fa-bars" aria-hidden="true"></i>
    </button>

    <!-- Mobile sidebar backdrop to dismiss the menu -->
    <div class="sidebar-backdrop" id="sidebarBackdrop" aria-hidden="true"></div>

    <aside class="sidebar" id="sidebar" aria-label="Navigation menu">
        <div class="sidebar-header">
            <h2><?php echo htmlspecialchars(t('sidebar_menu'), ENT_QUOTES, 'UTF-8'); ?></h2>
        </div>

        <div class="sidebar-user-info">
            <div class="sidebar-user-badge">
                <i class="fas fa-user-gear"></i>
            </div>
            <div class="sidebar-user-details">
                <div class="sidebar-user-id"><?php echo htmlspecialchars(t('sidebar_provider_label'), ENT_QUOTES, 'UTF-8'); ?> #<?php echo htmlspecialchars((string) $providerId, ENT_QUOTES, 'UTF-8'); ?></div>
                <div class="sidebar-user-email no-ar-numerals" dir="ltr"><?php echo htmlspecialchars($providerEmail !== '' ? $providerEmail : t('sidebar_no_email'), ENT_QUOTES, 'UTF-8'); ?></div>
            </div>
        </div>

        <nav class="sidebar-menu">
            <a href="service_provider_dashboard.php" class="sidebar-menu-item" id="navDashboard">
                <i class="fas fa-chart-line"></i>
                <?php echo htmlspecialchars(t('sidebar_dashboard'), ENT_QUOTES, 'UTF-8'); ?>
            </a>
            <a href="#profile-editor" class="sidebar-menu-item">
                <i class="fas fa-user-edit"></i>
                <?php echo htmlspecialchars(t('sidebar_edit_profile'), ENT_QUOTES, 'UTF-8'); ?>
            </a>
            <a href="#service-categories" class="sidebar-menu-item">
                <i class="fas fa-layer-group"></i>
                <?php echo htmlspecialchars(t('sidebar_services'), ENT_QUOTES, 'UTF-8'); ?>
            </a>
            <a href="#upcoming-slots" class="sidebar-menu-item">
                <i class="fas fa-clock"></i>
                <?php echo htmlspecialchars(t('sidebar_slots'), ENT_QUOTES, 'UTF-8'); ?>
            </a>
            <a href="#requests" class="sidebar-menu-item">
                <i class="fas fa-list-check"></i>
                <?php echo htmlspecialchars(t('sidebar_requests'), ENT_QUOTES, 'UTF-8'); ?>
            </a>
            <a href="#notifications" class="sidebar-menu-item">
                <i class="fas fa-bell"></i>
                <?php echo htmlspecialchars(t('sidebar_notifications'), ENT_QUOTES, 'UTF-8'); ?>
                <span class="menu-badge" id="notificationCountBadge"<?php if ($notificationCount <= 0) echo ' style="display:none"'; ?>><?php echo $notificationCount > 0 ? htmlspecialchars((string) $notificationCount, ENT_QUOTES, 'UTF-8') : ''; ?></span>
            </a>
            <a href="messages.php" class="sidebar-menu-item">
                <i class="fas fa-comments"></i>
                <?php echo htmlspecialchars(t('sidebar_messages'), ENT_QUOTES, 'UTF-8'); ?>
            </a>
            <a href="change_password.php" class="sidebar-menu-item">
                <i class="fas fa-key"></i>
                <?php echo htmlspecialchars(t('sidebar_change_password'), ENT_QUOTES, 'UTF-8'); ?>
            </a>
        </nav>

        <div class="sidebar-footer">
            <a href="logout.php" class="sidebar-menu-item">
                <i class="fas fa-right-from-bracket"></i>
                <?php echo htmlspecialchars(t('sidebar_sign_out'), ENT_QUOTES, 'UTF-8'); ?>
            </a>
        </div>
    </aside>

    <!-- Main shell containing profile context, summaries, and operational sections -->
    <main class="shell">
        <!-- Header panel with service provider identity and account actions -->
        <section class="topbar" aria-label="Service Provider header">
            <div class="header-profile">
                <div class="avatar">
                    <?php if ($providerProfile !== null && $providerProfile['photo'] !== ''): ?>
                        <img src="<?php echo htmlspecialchars($providerProfile['photo'], ENT_QUOTES, 'UTF-8'); ?>" alt="Service Provider profile photo">
                    <?php else: ?>
                        <i class="fas fa-user-gear" aria-hidden="true"></i>
                    <?php endif; ?>
                </div>
                <div>
                    <h1>
                        <?php echo htmlspecialchars($providerProfile !== null ? $providerProfile['name'] : t('prov_dash_title'), ENT_QUOTES, 'UTF-8'); ?>
                    </h1>
                    <p>
                        <span class="no-ar-numerals" dir="ltr"><?php echo htmlspecialchars($providerEmail !== '' ? $providerEmail : '', ENT_QUOTES, 'UTF-8'); ?></span><br>
                        <?php echo htmlspecialchars(t('prov_dash_subtitle'), ENT_QUOTES, 'UTF-8'); ?>
                    </p>
                </div>
            </div>
            <a href="<?php echo htmlspecialchars(langSwitchUrl(), ENT_QUOTES, 'UTF-8'); ?>"
               style="display:inline-flex;align-items:center;gap:6px;font-size:.82rem;font-weight:700;color:#0f766e;text-decoration:none;border:1.5px solid #d1d5db;padding:6px 14px;border-radius:999px;background:#fff;white-space:nowrap;">
                <i class="fa-solid fa-globe"></i><?php echo htmlspecialchars(t('lang_switch_label'), ENT_QUOTES, 'UTF-8'); ?>
            </a>
        </section>

        <!-- Error/success feedback banners for request status updates -->
        <?php if ($errorMessage !== ''): ?>
            <section class="feedback error" role="alert">
                <?php echo htmlspecialchars($errorMessage, ENT_QUOTES, 'UTF-8'); ?>
            </section>
        <?php endif; ?>

        <?php if ($successMessage !== ''): ?>
            <section class="feedback success" role="status">
                <?php echo htmlspecialchars($successMessage, ENT_QUOTES, 'UTF-8'); ?>
            </section>
        <?php endif; ?>

        <!-- Summary metrics: activity stats + ratings -->
        <section class="panel dashboard-summary" aria-label="Dashboard overview">
            <h2><?php echo htmlspecialchars(t('prov_dash_overview'), ENT_QUOTES, 'UTF-8'); ?></h2>
            <p class="lead"><?php echo htmlspecialchars(t('prov_dash_overview_lead'), ENT_QUOTES, 'UTF-8'); ?></p>

            <?php
                $totalBookingCount   = array_sum($requestStats);
                $availableSlotCount  = count(array_filter($upcomingSlots, static fn($s) => !$s['is_booked']));
                $pendingCount        = $requestStats['Pending'];
                $ratingDisplay       = ($ratingCount > 0 && $averageRating !== null)
                    ? htmlspecialchars(number_format((float) $averageRating, 1), ENT_QUOTES, 'UTF-8') . '/5'
                    : htmlspecialchars(t('prov_req_na'), ENT_QUOTES, 'UTF-8');
            ?>

            <div class="dash-stats-grid">
                <article class="dash-stat amber">
                    <div class="dash-stat-icon"><i class="fas fa-calendar-check" aria-hidden="true"></i></div>
                    <div>
                        <span class="dash-stat-value"><?php echo htmlspecialchars(toArabicNumerals((string) $totalBookingCount), ENT_QUOTES, 'UTF-8'); ?></span>
                        <span class="dash-stat-label"><?php echo htmlspecialchars(t('prov_stat_total_bookings'), ENT_QUOTES, 'UTF-8'); ?></span>
                    </div>
                </article>
                <article class="dash-stat teal">
                    <div class="dash-stat-icon"><i class="fas fa-calendar-plus" aria-hidden="true"></i></div>
                    <div>
                        <span class="dash-stat-value"><?php echo htmlspecialchars(toArabicNumerals((string) $availableSlotCount), ENT_QUOTES, 'UTF-8'); ?></span>
                        <span class="dash-stat-label"><?php echo htmlspecialchars(t('prov_stat_avail_slots'), ENT_QUOTES, 'UTF-8'); ?></span>
                    </div>
                </article>
                <article class="dash-stat orange">
                    <div class="dash-stat-icon"><i class="fas fa-clock" aria-hidden="true"></i></div>
                    <div>
                        <span class="dash-stat-value"><?php echo htmlspecialchars(toArabicNumerals((string) $pendingCount), ENT_QUOTES, 'UTF-8'); ?></span>
                        <span class="dash-stat-label"><?php echo htmlspecialchars(t('prov_stat_pending_req'), ENT_QUOTES, 'UTF-8'); ?></span>
                    </div>
                </article>
                <article class="dash-stat indigo">
                    <div class="dash-stat-icon"><i class="fas fa-star" aria-hidden="true"></i></div>
                    <div>
                        <span class="dash-stat-value"><?php echo $ratingDisplay; ?></span>
                        <span class="dash-stat-label"><?php echo htmlspecialchars(t('prov_avg_rating'), ENT_QUOTES, 'UTF-8'); ?></span>
                    </div>
                </article>
            </div>

            <div class="summary-grid">
                <article class="summary-card">
                    <p class="label"><?php echo htmlspecialchars(t('prov_total_reviews'), ENT_QUOTES, 'UTF-8'); ?></p>
                    <p class="value"><?php echo htmlspecialchars(toArabicNumerals((string) $ratingCount), ENT_QUOTES, 'UTF-8'); ?></p>
                </article>
                <article class="summary-card">
                    <p class="label"><?php echo htmlspecialchars(t('prov_ratings_title'), ENT_QUOTES, 'UTF-8'); ?></p>
                    <p class="value" style="display:flex;align-items:center;gap:4px;">
                        <?php if ($ratingCount > 0 && $averageRating !== null): ?>
                            <?php for ($si = 1; $si <= 5; $si++): ?>
                                <i class="fas fa-star star <?php echo $si <= round((float) $averageRating) ? '' : 'is-empty'; ?>" style="font-size:0.85rem;" aria-hidden="true"></i>
                            <?php endfor; ?>
                            <span style="margin-left:4px;"><?php echo htmlspecialchars(number_format((float) $averageRating, 1), ENT_QUOTES, 'UTF-8'); ?></span>
                        <?php else: ?>
                            <?php echo htmlspecialchars(t('prov_req_na'), ENT_QUOTES, 'UTF-8'); ?>
                        <?php endif; ?>
                    </p>
                </article>
            </div>
        </section>

        <!-- Notifications panel for recent messages and cancellations -->
        <section class="panel notifications" id="notifications" aria-label="Recent notifications">
            <h2><?php echo htmlspecialchars(t('prov_notifications'), ENT_QUOTES, 'UTF-8'); ?></h2>
            <p class="lead"><?php echo htmlspecialchars(t('prov_notif_lead'), ENT_QUOTES, 'UTF-8'); ?></p>

            <div class="notification-grid">
                <article class="notification-card">
                    <h3><?php echo htmlspecialchars(t('notif_msgs_from_cust'), ENT_QUOTES, 'UTF-8'); ?></h3>
                    <div id="recentMessagesBody" class="notification-body">
                    <?php if (count($recentCustomerMessages) === 0): ?>
                        <p class="empty-state"><?php echo htmlspecialchars(t('notif_no_msgs_cust'), ENT_QUOTES, 'UTF-8'); ?></p>
                    <?php else: ?>
                        <div class="notification-list" id="recentMessagesList">
                            <?php foreach ($recentCustomerMessages as $message): ?>
                                <?php
                                    $messagePreview = trim((string) $message['message']);
                                    if (mb_strlen($messagePreview) > 90) {
                                        $messagePreview = mb_substr($messagePreview, 0, 90) . '...';
                                    }
                                    $messageTimestamp = $message['created_at'] !== ''
                                        ? date('M j, H:i', strtotime($message['created_at']))
                                        : t('notif_time_na');
                                ?>
                                <div class="notification-item<?php echo $message['is_unread'] ? ' is-unread' : ''; ?>" data-notif-type="message" data-notif-id="<?php echo (int) $message['message_id']; ?>">
                                    <button class="notif-dismiss-btn" type="button" title="<?php echo htmlspecialchars(t('notif_dismiss'), ENT_QUOTES, 'UTF-8'); ?>" aria-label="<?php echo htmlspecialchars(t('notif_dismiss_label'), ENT_QUOTES, 'UTF-8'); ?>" onclick="dismissNotification(this,'message',<?php echo (int) $message['message_id']; ?>)"><i class="fas fa-times"></i></button>
                                    <div class="notification-title">
                                        <?php if ($message['is_unread']): ?><span class="notif-dot"></span><?php endif; ?><?php echo htmlspecialchars(t('notif_msg_from_cust'), ENT_QUOTES, 'UTF-8'); ?> <?php echo htmlspecialchars($message['customer_name'], ENT_QUOTES, 'UTF-8'); ?>
                                    </div>
                                    <div class="notification-text">
                                        <?php echo htmlspecialchars($messagePreview !== '' ? $messagePreview : t('notif_image'), ENT_QUOTES, 'UTF-8'); ?>
                                    </div>
                                    <div class="notification-meta">
                                        <span><?php echo htmlspecialchars(t('req_request_num'), ENT_QUOTES, 'UTF-8'); ?><?php echo htmlspecialchars((string) $message['request_id'], ENT_QUOTES, 'UTF-8'); ?></span>
                                        <span><?php echo htmlspecialchars($messageTimestamp, ENT_QUOTES, 'UTF-8'); ?></span>
                                        <a class="notification-link" href="messages.php?request_id=<?php echo (int) $message['request_id']; ?>" data-notif-action="message" data-notif-id="<?php echo (int) $message['message_id']; ?>"><?php echo htmlspecialchars(t('notif_open_chat'), ENT_QUOTES, 'UTF-8'); ?></a>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>
                    </div>
                </article>

                <article class="notification-card">
                    <h3><?php echo htmlspecialchars(t('notif_new_requests'), ENT_QUOTES, 'UTF-8'); ?></h3>
                    <div id="recentPendingBody" class="notification-body">
                    <?php if (count($recentPendingRequests) === 0): ?>
                        <p class="empty-state"><?php echo htmlspecialchars(t('notif_no_pending'), ENT_QUOTES, 'UTF-8'); ?></p>
                    <?php else: ?>
                        <div class="notification-list" id="recentPendingList">
                            <?php foreach ($recentPendingRequests as $pending): ?>
                                <?php
                                    $pendingDate = $pending['appointment_date'] !== ''
                                        ? provLocalizedDate($pending['appointment_date'], false)
                                        : t('notif_date_na');
                                    $pendingTime = $pending['appointment_time'] !== ''
                                        ? substr($pending['appointment_time'], 0, 5)
                                        : '';
                                ?>
                                <div class="notification-item<?php echo $pending['is_unread'] ? ' is-unread' : ''; ?>" data-notif-type="pending" data-notif-id="<?php echo (int) $pending['request_id']; ?>">
                                    <button class="notif-dismiss-btn" type="button" title="<?php echo htmlspecialchars(t('notif_dismiss'), ENT_QUOTES, 'UTF-8'); ?>" aria-label="<?php echo htmlspecialchars(t('notif_dismiss_label'), ENT_QUOTES, 'UTF-8'); ?>" onclick="dismissNotification(this,'pending',<?php echo (int) $pending['request_id']; ?>)"><i class="fas fa-times"></i></button>
                                    <div class="notification-title">
                                        <?php if ($pending['is_unread']): ?><span class="notif-dot"></span><?php endif; ?><?php echo htmlspecialchars(t('notif_new_request_from'), ENT_QUOTES, 'UTF-8'); ?> <?php echo htmlspecialchars($pending['customer_name'], ENT_QUOTES, 'UTF-8'); ?>
                                    </div>
                                    <div class="notification-text">
                                        <?php echo htmlspecialchars(t('req_request_num'), ENT_QUOTES, 'UTF-8'); ?><?php echo htmlspecialchars((string) $pending['request_id'], ENT_QUOTES, 'UTF-8'); ?> ·
                                        <?php echo htmlspecialchars($pending['category_name'], ENT_QUOTES, 'UTF-8'); ?>
                                    </div>
                                    <div class="notification-meta">
                                        <span>
                                            <?php echo htmlspecialchars($pendingDate, ENT_QUOTES, 'UTF-8'); ?>
                                            <?php echo $pendingTime !== '' ? ' ' . htmlspecialchars(t('notif_at'), ENT_QUOTES, 'UTF-8') . ' ' . htmlspecialchars($pendingTime, ENT_QUOTES, 'UTF-8') : ''; ?>
                                        </span>
                                        <a class="notification-link" href="#request-<?php echo htmlspecialchars((string) $pending['request_id'], ENT_QUOTES, 'UTF-8'); ?>" data-notif-action="pending" data-notif-id="<?php echo (int) $pending['request_id']; ?>">
                                            <?php echo htmlspecialchars(t('notif_view_request'), ENT_QUOTES, 'UTF-8'); ?>
                                        </a>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>
                    </div>
                </article>

                <article class="notification-card">
                    <h3><?php echo htmlspecialchars(t('notif_cancelled_reqs'), ENT_QUOTES, 'UTF-8'); ?></h3>
                    <div id="recentCancelledBody" class="notification-body">
                    <?php if (count($recentCancelledRequests) === 0): ?>
                        <p class="empty-state"><?php echo htmlspecialchars(t('notif_no_cancelled'), ENT_QUOTES, 'UTF-8'); ?></p>
                    <?php else: ?>
                        <div class="notification-list" id="recentCancelledList">
                            <?php foreach ($recentCancelledRequests as $cancelled): ?>
                                <?php
                                    $appointmentLabel = $cancelled['appointment_date'] !== ''
                                        ? provLocalizedDate($cancelled['appointment_date'], false)
                                        : t('notif_date_na');
                                    $timeLabel = $cancelled['appointment_time'] !== ''
                                        ? substr($cancelled['appointment_time'], 0, 5)
                                        : '';
                                ?>
                                <div class="notification-item<?php echo $cancelled['is_unread'] ? ' is-unread' : ''; ?>" data-notif-type="cancelled" data-notif-id="<?php echo (int) $cancelled['request_id']; ?>">
                                    <button class="notif-dismiss-btn" type="button" title="<?php echo htmlspecialchars(t('notif_dismiss'), ENT_QUOTES, 'UTF-8'); ?>" aria-label="<?php echo htmlspecialchars(t('notif_dismiss_label'), ENT_QUOTES, 'UTF-8'); ?>" onclick="dismissNotification(this,'cancelled',<?php echo (int) $cancelled['request_id']; ?>)"><i class="fas fa-times"></i></button>
                                    <div class="notification-title">
                                        <?php if ($cancelled['is_unread']): ?><span class="notif-dot"></span><?php endif; ?><?php echo htmlspecialchars(t('notif_cancelled_by'), ENT_QUOTES, 'UTF-8'); ?> <?php echo htmlspecialchars($cancelled['customer_name'], ENT_QUOTES, 'UTF-8'); ?>
                                    </div>
                                    <div class="notification-text">
                                        <?php echo htmlspecialchars(t('req_request_num'), ENT_QUOTES, 'UTF-8'); ?><?php echo htmlspecialchars((string) $cancelled['request_id'], ENT_QUOTES, 'UTF-8'); ?>
                                    </div>
                                    <div class="notification-meta">
                                        <span>
                                            <?php echo htmlspecialchars($appointmentLabel, ENT_QUOTES, 'UTF-8'); ?>
                                            <?php echo $timeLabel !== '' ? ' ' . htmlspecialchars(t('notif_at'), ENT_QUOTES, 'UTF-8') . ' ' . htmlspecialchars($timeLabel, ENT_QUOTES, 'UTF-8') : ''; ?>
                                        </span>
                                        <a class="notification-link" href="#request-<?php echo htmlspecialchars((string) $cancelled['request_id'], ENT_QUOTES, 'UTF-8'); ?>" data-notif-action="cancelled" data-notif-id="<?php echo (int) $cancelled['request_id']; ?>"><?php echo htmlspecialchars(t('notif_view_request'), ENT_QUOTES, 'UTF-8'); ?></a>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>
                    </div>
                </article>
            </div>
        </section>

        <section class="panel" id="profile-editor" aria-label="Edit profile">
            <h2><?php echo htmlspecialchars(t('prov_profile_title'), ENT_QUOTES, 'UTF-8'); ?></h2>
            <p class="lead"><?php echo htmlspecialchars(t('prov_profile_lead'), ENT_QUOTES, 'UTF-8'); ?></p>
            <form method="post" action="service_provider_dashboard.php#profile-editor" id="profileForm" class="profile-form" enctype="multipart/form-data" novalidate>
                <input type="hidden" name="form_action" value="update_profile">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars((string) $_SESSION['service_provider_profile_csrf'], ENT_QUOTES, 'UTF-8'); ?>">

                <div class="profile-photo-panel">
                    <div class="avatar profile-avatar">
                            <?php if ($providerProfile !== null && $providerProfile['photo'] !== ''): ?>
                                <img src="<?php echo htmlspecialchars($providerProfile['photo'], ENT_QUOTES, 'UTF-8'); ?>" alt="Service Provider profile photo">
                            <?php else: ?>
                                <i class="fas fa-user-gear" aria-hidden="true"></i>
                            <?php endif; ?>
                        </div>

                        <label for="profile_photo"><?php echo htmlspecialchars(t('prov_profile_photo_label'), ENT_QUOTES, 'UTF-8'); ?></label>
                        <input type="file" id="profile_photo" name="profile_photo" accept="image/jpeg,image/png,image/webp">
                        <p class="field-hint"><?php echo htmlspecialchars(t('prov_profile_photo_hint'), ENT_QUOTES, 'UTF-8'); ?></p>
                    </div>

                    <div class="profile-fields">
                        <div class="profile-field">
                            <label for="profile_name"><?php echo htmlspecialchars(t('prov_display_name'), ENT_QUOTES, 'UTF-8'); ?></label>
                            <input type="text" id="profile_name" name="profile_name" value="<?php echo htmlspecialchars($profileNameValue, ENT_QUOTES, 'UTF-8'); ?>" required>
                        </div>

                        <div class="profile-field">
                            <label for="profile_bio"><?php echo htmlspecialchars(t('prov_bio_label'), ENT_QUOTES, 'UTF-8'); ?></label>
                            <textarea id="profile_bio" name="profile_bio" rows="5" required><?php echo htmlspecialchars($profileBioValue, ENT_QUOTES, 'UTF-8'); ?></textarea>
                        </div>

                        <div class="profile-field">
                            <label for="profile_phone"><?php echo htmlspecialchars(t('prov_phone_label'), ENT_QUOTES, 'UTF-8'); ?></label>
                            <input type="text" id="profile_phone" name="profile_phone" value="<?php echo htmlspecialchars($profilePhoneValue, ENT_QUOTES, 'UTF-8'); ?>" maxlength="30" placeholder="<?php echo htmlspecialchars(t('prov_phone_ph'), ENT_QUOTES, 'UTF-8'); ?>" dir="ltr">
                        </div>
                    </div>
                </div>

                <button type="submit" class="profile-submit">
                    <i class="fas fa-save" aria-hidden="true"></i>
                    <?php echo htmlspecialchars(t('prov_save_profile'), ENT_QUOTES, 'UTF-8'); ?>
                </button>
            </form>

            <!-- Location change request — separate form, separate CSRF action -->
            <div style="margin-top:28px;padding-top:24px;border-top:1px solid rgba(15,23,42,.08);">
                <h3 style="font-size:1rem;font-weight:700;color:#0f172a;margin-bottom:4px;">
                    <i class="fas fa-map-marker-alt" style="color:#0f766e;margin-<?php echo isRtl()?'left':'right';?>:8px;"></i>
                    <?php echo htmlspecialchars(t('prov_location_current'), ENT_QUOTES, 'UTF-8'); ?>
                </h3>

                <?php if ($profileLocationValue !== ''): ?>
                    <p style="font-size:.94rem;color:#334155;margin-bottom:10px;"><?php echo htmlspecialchars($profileLocationValue, ENT_QUOTES, 'UTF-8'); ?></p>
                <?php else: ?>
                    <p style="font-size:.88rem;color:#94a3b8;margin-bottom:10px;"><?php echo htmlspecialchars(t('admin_profile_no_location'), ENT_QUOTES, 'UTF-8'); ?></p>
                <?php endif; ?>

                <?php if ($profileLocationChangeStatus === 'pending'): ?>
                    <div style="background:#fef9c3;border:1px solid #fde68a;border-radius:12px;padding:12px 14px;font-size:.88rem;color:#92400e;display:flex;align-items:center;gap:9px;margin-bottom:14px;">
                        <i class="fas fa-clock"></i>
                        <?php echo htmlspecialchars(t('prov_location_pending_notice'), ENT_QUOTES, 'UTF-8'); ?>
                        <strong style="margin-<?php echo isRtl()?'right':'left';?>:4px;"><?php echo htmlspecialchars($profilePendingLocation, ENT_QUOTES, 'UTF-8'); ?></strong>
                    </div>
                <?php else: ?>
                    <form method="post" action="service_provider_dashboard.php#profile-editor" novalidate style="max-width:480px;">
                        <input type="hidden" name="form_action" value="request_location_change">
                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars((string) $_SESSION['service_provider_profile_csrf'], ENT_QUOTES, 'UTF-8'); ?>">
                        <label for="new_location" style="display:block;font-size:.84rem;font-weight:700;color:#0f172a;margin-bottom:7px;">
                            <?php echo htmlspecialchars(t('prov_location_change_label'), ENT_QUOTES, 'UTF-8'); ?>
                        </label>
                        <div style="display:flex;gap:8px;flex-wrap:wrap;">
                            <input type="text" id="new_location" name="new_location" maxlength="255"
                                placeholder="<?php echo htmlspecialchars(t('prov_location_change_ph'), ENT_QUOTES, 'UTF-8'); ?>"
                                style="flex:1;min-width:180px;min-height:42px;border:2px solid #d9e2ec;border-radius:12px;padding:9px 12px;font-family:inherit;font-size:.9rem;color:#0f172a;">
                            <button type="submit" style="min-height:42px;border:none;border-radius:12px;padding:9px 18px;font-family:inherit;font-size:.88rem;font-weight:700;color:#fff;background:linear-gradient(145deg,#0f766e,#115e59);cursor:pointer;white-space:nowrap;display:inline-flex;align-items:center;gap:7px;">
                                <i class="fas fa-paper-plane"></i>
                                <?php echo htmlspecialchars(t('prov_location_change_label'), ENT_QUOTES, 'UTF-8'); ?>
                            </button>
                        </div>
                        <p style="margin-top:6px;font-size:.8rem;color:#64748b;"><?php echo htmlspecialchars(t('prov_location_change_hint'), ENT_QUOTES, 'UTF-8'); ?></p>
                    </form>
                <?php endif; ?>
            </div>
        </section>

        <!-- Services and future slot visibility panels -->
        <section class="small-grid" aria-label="Configured services and upcoming slots">
            <article id="service-categories" class="panel">
                <?php
                    $pendingCatReqCount = count(array_filter($categoryRequests, static fn($r) => $r['status'] === 'pending'));
                ?>
                <h2><?php echo htmlspecialchars(t('prov_services_title'), ENT_QUOTES, 'UTF-8'); ?></h2>
                <p class="lead"><?php echo htmlspecialchars(t('prov_services_lead'), ENT_QUOTES, 'UTF-8'); ?></p>

                <!-- Stats bar -->
                <div class="svc-stats-bar">
                    <div class="svc-stat-card teal">
                        <div class="svc-stat-icon teal"><i class="fas fa-layer-group" aria-hidden="true"></i></div>
                        <div>
                            <div class="svc-stat-value"><?php echo count($serviceCategories); ?></div>
                            <div class="svc-stat-label"><?php echo htmlspecialchars(t('prov_stat_available'), ENT_QUOTES, 'UTF-8'); ?></div>
                        </div>
                    </div>
                    <div class="svc-stat-card indigo">
                        <div class="svc-stat-icon indigo"><i class="fas fa-circle-check" aria-hidden="true"></i></div>
                        <div>
                            <div class="svc-stat-value"><?php echo count($providerServices); ?></div>
                            <div class="svc-stat-label"><?php echo htmlspecialchars(t('prov_stat_active'), ENT_QUOTES, 'UTF-8'); ?></div>
                        </div>
                    </div>
                    <div class="svc-stat-card amber">
                        <div class="svc-stat-icon amber"><i class="fas fa-clock" aria-hidden="true"></i></div>
                        <div>
                            <div class="svc-stat-value"><?php echo $pendingCatReqCount; ?></div>
                            <div class="svc-stat-label"><?php echo htmlspecialchars(t('prov_stat_pending_req'), ENT_QUOTES, 'UTF-8'); ?></div>
                        </div>
                    </div>
                </div>

                <!-- Active services -->
                <div class="svc-section-head">
                    <h3><?php echo htmlspecialchars(t('prov_my_active_services'), ENT_QUOTES, 'UTF-8'); ?></h3>
                    <span class="svc-count-badge"><?php echo count($providerServices); ?></span>
                </div>

                <?php if (count($providerServices) === 0): ?>
                    <div class="svc-empty-state">
                        <i class="fas fa-layer-group" aria-hidden="true"></i>
                        <?php echo htmlspecialchars(t('prov_no_linked_cats'), ENT_QUOTES, 'UTF-8'); ?>
                    </div>
                <?php else: ?>
                    <div class="svc-active-grid">
                        <?php foreach ($providerServices as $service): ?>
                            <div class="service-card">
                                <div class="svc-card-icon"><i class="fas fa-wrench" aria-hidden="true"></i></div>
                                <h3><?php echo htmlspecialchars(tCategory($service, 'name'), ENT_QUOTES, 'UTF-8'); ?></h3>
                                <p><?php echo htmlspecialchars(tCategory($service, 'description') !== '' ? tCategory($service, 'description') : t('prov_no_desc_provided'), ENT_QUOTES, 'UTF-8'); ?></p>
                                <div style="display:flex;flex-wrap:wrap;gap:6px;align-items:center;">
                                    <span class="svc-price-badge">
                                        <i class="fas fa-dollar-sign" aria-hidden="true"></i>
                                        <?php echo htmlspecialchars(number_format((float) $service['visit_price'], 2), ENT_QUOTES, 'UTF-8'); ?>
                                    </span>
                                    <span class="svc-active-badge">
                                        <i class="fas fa-circle-check" aria-hidden="true"></i>
                                        <?php echo htmlspecialchars(t('req_status_confirmed'), ENT_QUOTES, 'UTF-8'); ?>
                                    </span>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>

                <div class="service-divider" role="presentation"></div>

                <!-- Service selection form -->
                <div class="svc-section-head" style="margin-bottom:12px;">
                    <h3><?php echo htmlspecialchars(t('prov_edit_services_title'), ENT_QUOTES, 'UTF-8'); ?></h3>
                </div>

                <form class="service-form" method="post" action="service_provider_dashboard.php#service-categories" novalidate>
                    <input type="hidden" name="form_action" value="update_services">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars((string) $_SESSION['service_provider_services_csrf'], ENT_QUOTES, 'UTF-8'); ?>">

                    <?php if (count($serviceCategories) === 0): ?>
                        <div class="svc-empty-state">
                            <i class="fas fa-folder-open" aria-hidden="true"></i>
                            <?php echo htmlspecialchars(t('prov_no_categories'), ENT_QUOTES, 'UTF-8'); ?>
                        </div>
                    <?php else: ?>
                        <!-- Search bar -->
                        <div class="svc-search-wrap">
                            <i class="fas fa-search svc-search-icon" aria-hidden="true"></i>
                            <input type="text" id="svcCategorySearch" class="svc-search-input"
                                placeholder="<?php echo htmlspecialchars(t('prov_search_categories_ph'), ENT_QUOTES, 'UTF-8'); ?>"
                                autocomplete="off" aria-label="<?php echo htmlspecialchars(t('prov_search_categories_ph'), ENT_QUOTES, 'UTF-8'); ?>">
                        </div>

                        <div class="service-category-list" id="svcCategoryList">
                            <?php foreach ($serviceCategories as $category): ?>
                                <?php
                                    $categoryId  = (int) $category['category_id'];
                                    $isSelected  = in_array($categoryId, $serviceCategorySelections, true);
                                    $priceValue  = $servicePriceValues[$categoryId] ?? '';
                                    $catNameText = tCategory($category, 'name');
                                    $catDescText = tCategory($category, 'description');
                                ?>
                                <div class="service-category-row <?php echo $isSelected ? 'is-selected' : 'is-disabled'; ?>"
                                     data-cat-name="<?php echo htmlspecialchars(mb_strtolower($catNameText . ' ' . $catDescText), ENT_QUOTES, 'UTF-8'); ?>">
                                    <label class="service-category-label">
                                        <input
                                            type="checkbox"
                                            name="category_ids[]"
                                            value="<?php echo htmlspecialchars((string) $categoryId, ENT_QUOTES, 'UTF-8'); ?>"
                                            <?php echo $isSelected ? 'checked' : ''; ?>
                                        >
                                        <div>
                                            <div class="svc-cat-name"><?php echo htmlspecialchars($catNameText, ENT_QUOTES, 'UTF-8'); ?></div>
                                            <?php if ($catDescText !== ''): ?>
                                                <div class="svc-cat-desc"><?php echo htmlspecialchars($catDescText, ENT_QUOTES, 'UTF-8'); ?></div>
                                            <?php endif; ?>
                                        </div>
                                    </label>

                                    <div class="service-category-price">
                                        <label for="price-<?php echo htmlspecialchars((string) $categoryId, ENT_QUOTES, 'UTF-8'); ?>"><?php echo htmlspecialchars(t('prov_visit_price'), ENT_QUOTES, 'UTF-8'); ?></label>
                                        <div class="svc-price-input-wrap">
                                            <span class="svc-currency-sym" aria-hidden="true">$</span>
                                            <input
                                                type="text"
                                                inputmode="decimal"
                                                id="price-<?php echo htmlspecialchars((string) $categoryId, ENT_QUOTES, 'UTF-8'); ?>"
                                                name="category_prices[<?php echo htmlspecialchars((string) $categoryId, ENT_QUOTES, 'UTF-8'); ?>]"
                                                value="<?php echo htmlspecialchars($priceValue !== '' ? toArabicNumerals((string) $priceValue) : '', ENT_QUOTES, 'UTF-8'); ?>"
                                                placeholder="<?php echo getLang() === 'ar' ? '٠٫٠٠' : '0.00'; ?>"
                                                dir="ltr"
                                                <?php echo $isSelected ? '' : 'disabled'; ?>
                                            >
                                        </div>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        </div>
                        <div class="svc-no-results" id="svcNoResults" aria-live="polite">
                            <i class="fas fa-search" aria-hidden="true" style="font-size:1.6rem;opacity:.3;"></i>
                            <?php echo htmlspecialchars(t('prov_no_search_results'), ENT_QUOTES, 'UTF-8'); ?>
                        </div>

                        <div class="service-form-actions">
                            <button type="submit" class="profile-submit">
                                <i class="fas fa-floppy-disk" aria-hidden="true"></i>
                                <?php echo htmlspecialchars(t('prov_update_services'), ENT_QUOTES, 'UTF-8'); ?>
                            </button>
                        </div>
                    <?php endif; ?>
                </form>

                <!-- Category request sub-section -->
                <div class="cat-req-section">
                    <h3><?php echo htmlspecialchars(t('sidebar_cat_requests'), ENT_QUOTES, 'UTF-8'); ?></h3>
                    <p><?php echo htmlspecialchars(t('cat_req_lead'), ENT_QUOTES, 'UTF-8'); ?></p>

                    <form method="post" action="service_provider_dashboard.php#service-categories" novalidate>
                        <input type="hidden" name="form_action" value="request_category">
                        <div class="cat-req-form-card">
                            <div class="cat-req-field">
                                <label for="cat_req_name_input"><?php echo htmlspecialchars(t('cat_req_name_label'), ENT_QUOTES, 'UTF-8'); ?></label>
                                <input type="text" id="cat_req_name_input" name="cat_req_name" maxlength="200"
                                    placeholder="<?php echo htmlspecialchars(t('cat_req_name_ph'), ENT_QUOTES, 'UTF-8'); ?>" required>
                            </div>
                            <div class="cat-req-field">
                                <label for="cat_req_info_input"><?php echo htmlspecialchars(t('cat_req_info_label'), ENT_QUOTES, 'UTF-8'); ?></label>
                                <textarea id="cat_req_info_input" name="cat_req_info" maxlength="1000" rows="3"
                                    placeholder="<?php echo htmlspecialchars(t('cat_req_info_ph'), ENT_QUOTES, 'UTF-8'); ?>"></textarea>
                            </div>
                            <button type="submit" class="cat-req-submit">
                                <i class="fas fa-paper-plane" aria-hidden="true"></i>
                                <?php echo htmlspecialchars(t('cat_req_submit'), ENT_QUOTES, 'UTF-8'); ?>
                            </button>
                        </div>
                    </form>

                    <?php if (!empty($categoryRequests)): ?>
                        <h4 style="font-size:.9rem;font-weight:800;margin:16px 0 10px;color:#0f172a;"><?php echo htmlspecialchars(t('cat_req_status_title'), ENT_QUOTES, 'UTF-8'); ?></h4>
                        <div class="cat-req-status-list">
                            <?php foreach ($categoryRequests as $catReq): ?>
                                <?php
                                    $statusBg    = '#f1f5f9'; $statusColor = '#475569';
                                    $statusIcon  = 'fa-clock';
                                    if ($catReq['status'] === 'approved') { $statusBg = '#dcfce7'; $statusColor = '#166534'; $statusIcon = 'fa-circle-check'; }
                                    if ($catReq['status'] === 'rejected') { $statusBg = '#fee2e2'; $statusColor = '#991b1b'; $statusIcon = 'fa-circle-xmark'; }
                                    $statusLabel = t('cat_req_status_' . $catReq['status']);
                                ?>
                                <div class="cat-req-status-item">
                                    <div>
                                        <div class="cat-req-status-name"><?php echo htmlspecialchars($catReq['category_name'], ENT_QUOTES, 'UTF-8'); ?></div>
                                        <?php if ($catReq['admin_notes'] !== ''): ?>
                                            <p class="cat-req-notes"><i class="fas fa-comment-dots" aria-hidden="true"></i> <?php echo htmlspecialchars($catReq['admin_notes'], ENT_QUOTES, 'UTF-8'); ?></p>
                                        <?php endif; ?>
                                    </div>
                                    <span style="display:inline-flex;align-items:center;gap:5px;background:<?php echo $statusBg; ?>;color:<?php echo $statusColor; ?>;padding:4px 11px;border-radius:999px;font-size:.76rem;font-weight:700;white-space:nowrap;">
                                        <i class="fas <?php echo $statusIcon; ?>" aria-hidden="true"></i>
                                        <?php echo htmlspecialchars($statusLabel, ENT_QUOTES, 'UTF-8'); ?>
                                    </span>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>
                </div>
            </article>

            <article id="upcoming-slots" class="panel">
                <h2><?php echo htmlspecialchars(t('prov_slots_title'), ENT_QUOTES, 'UTF-8'); ?></h2>
                <p class="lead"><?php echo htmlspecialchars(t('prov_slots_lead'), ENT_QUOTES, 'UTF-8'); ?></p>

                <!-- Appointment slot creation form -->
                <div class="slot-form-card">
                    <p class="slot-form-card-title">
                        <i class="fas fa-calendar-plus" aria-hidden="true"></i>
                        <?php echo htmlspecialchars(t('prov_slot_add'), ENT_QUOTES, 'UTF-8'); ?>
                    </p>
                    <form class="slot-form" method="post" action="service_provider_dashboard.php#upcoming-slots" novalidate>
                        <input type="hidden" name="form_action" value="create_slot">
                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars((string) $_SESSION['service_provider_slot_csrf'], ENT_QUOTES, 'UTF-8'); ?>">

                        <div class="slot-form-grid">
                            <div class="slot-field">
                                <label for="slot_date"><?php echo htmlspecialchars(t('prov_slot_date'), ENT_QUOTES, 'UTF-8'); ?></label>
                                <input
                                    type="text"
                                    id="slot_date"
                                    name="slot_date"
                                    value="<?php echo htmlspecialchars($slotDateValue, ENT_QUOTES, 'UTF-8'); ?>"
                                    required
                                    readonly
                                >
                            </div>

                            <div class="slot-field">
                                <label for="slot_time"><?php echo htmlspecialchars(t('prov_slot_time'), ENT_QUOTES, 'UTF-8'); ?></label>
                                <input
                                    type="text"
                                    id="slot_time"
                                    name="slot_time"
                                    value="<?php echo htmlspecialchars($slotTimeValue, ENT_QUOTES, 'UTF-8'); ?>"
                                    required
                                    readonly
                                >
                            </div>
                        </div>

                        <p class="field-hint" style="margin-top:6px;"><?php echo htmlspecialchars(t('prov_slot_hint'), ENT_QUOTES, 'UTF-8'); ?></p>

                        <div class="service-form-actions" style="margin-top:10px;">
                            <button type="submit" class="profile-submit">
                                <i class="fas fa-plus" aria-hidden="true"></i>
                                <?php echo htmlspecialchars(t('prov_slot_add'), ENT_QUOTES, 'UTF-8'); ?>
                            </button>
                        </div>
                    </form>
                </div>

                <?php if (count($upcomingSlots) === 0): ?>
                    <p class="empty-state"><?php echo htmlspecialchars(t('prov_no_slots'), ENT_QUOTES, 'UTF-8'); ?></p>
                <?php else: ?>
                <div class="slot-cards-grid">
                <?php foreach ($upcomingSlots as $slot): ?>
                    <?php $slotStatus = $slot['is_booked'] ? 'booked' : 'free'; ?>
                    <article class="slot-card <?php echo $slotStatus; ?>">
                        <div class="slot-card-header">
                            <div class="slot-card-icon">
                                <i class="fas <?php echo $slot['is_booked'] ? 'fa-user-check' : 'fa-calendar-day'; ?>" aria-hidden="true"></i>
                            </div>
                            <span class="slot-badge">
                                <?php echo $slot['is_booked']
                                    ? htmlspecialchars(t('prov_slot_booked'), ENT_QUOTES, 'UTF-8')
                                    : htmlspecialchars(t('prov_slot_available'), ENT_QUOTES, 'UTF-8'); ?>
                            </span>
                        </div>

                        <p class="slot-date-text"><?php echo htmlspecialchars(provLocalizedDate($slot['date']), ENT_QUOTES, 'UTF-8'); ?></p>
                        <p class="slot-time-text">
                            <i class="fas fa-clock" aria-hidden="true"></i>
                            <?php echo htmlspecialchars(toArabicNumerals(substr($slot['slot'], 0, 5)), ENT_QUOTES, 'UTF-8'); ?>
                        </p>

                        <?php if ($slot['is_booked']): ?>
                            <div class="slot-booked-detail">
                                <p>
                                    <strong><?php echo htmlspecialchars(t('prov_slot_booked_by'), ENT_QUOTES, 'UTF-8'); ?></strong>
                                    <?php echo htmlspecialchars($slot['customer_name'] !== '' ? $slot['customer_name'] : t('prov_req_customer'), ENT_QUOTES, 'UTF-8'); ?>
                                </p>
                                <button
                                    type="button"
                                    class="slot-profile-btn"
                                    data-customer-name="<?php echo htmlspecialchars($slot['customer_name'], ENT_QUOTES, 'UTF-8'); ?>"
                                    data-customer-email="<?php echo htmlspecialchars($slot['customer_email'], ENT_QUOTES, 'UTF-8'); ?>"
                                    data-customer-phone="<?php echo htmlspecialchars($slot['customer_phone'], ENT_QUOTES, 'UTF-8'); ?>"
                                    data-customer-address="<?php echo htmlspecialchars($slot['customer_address'], ENT_QUOTES, 'UTF-8'); ?>"
                                    data-request-id="<?php echo htmlspecialchars((string) $slot['request_id'], ENT_QUOTES, 'UTF-8'); ?>"
                                >
                                    <i class="fas fa-user" aria-hidden="true"></i>
                                    <?php echo htmlspecialchars(t('prov_view_profile'), ENT_QUOTES, 'UTF-8'); ?>
                                </button>
                            </div>
                        <?php else: ?>
                            <form class="slot-delete-form" method="post" action="service_provider_dashboard.php#upcoming-slots">
                                <input type="hidden" name="form_action" value="delete_slot">
                                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars((string) $_SESSION['service_provider_slot_csrf'], ENT_QUOTES, 'UTF-8'); ?>">
                                <input type="hidden" name="slot_id" value="<?php echo htmlspecialchars((string) $slot['slot_id'], ENT_QUOTES, 'UTF-8'); ?>">
                                <button
                                    type="submit"
                                    class="slot-delete-btn"
                                    onclick="return confirm(<?php echo json_encode(t('prov_slot_delete_confirm')); ?>)"
                                >
                                    <i class="fas fa-trash-can" aria-hidden="true"></i>
                                    <?php echo htmlspecialchars(t('prov_slot_delete'), ENT_QUOTES, 'UTF-8'); ?>
                                </button>
                            </form>
                        <?php endif; ?>
                    </article>
                <?php endforeach; ?>
                </div>
                <?php endif; ?>
            </article>
        </section>

        <!-- Request list with customer details, evidence images, and status update controls -->
        <section class="panel requests" id="requests" aria-label="Incoming requests">
            <h2><?php echo htmlspecialchars(t('prov_requests_title'), ENT_QUOTES, 'UTF-8'); ?></h2>
            <p class="lead"><?php echo htmlspecialchars(t('prov_requests_lead'), ENT_QUOTES, 'UTF-8'); ?></p>

            <div class="svc-search-wrap" style="margin-bottom:16px;">
                <i class="fas fa-search svc-search-icon" aria-hidden="true"></i>
                <input type="text" id="reqSearch" class="svc-search-input"
                    placeholder="<?php echo htmlspecialchars(t('prov_search_requests_ph'), ENT_QUOTES, 'UTF-8'); ?>"
                    autocomplete="off"
                    aria-label="<?php echo htmlspecialchars(t('prov_search_requests_ph'), ENT_QUOTES, 'UTF-8'); ?>">
            </div>

            <div class="request-list" id="reqList">
                <?php if (count($requests) === 0): ?>
                    <article class="empty-state"><?php echo htmlspecialchars(t('prov_no_requests'), ENT_QUOTES, 'UTF-8'); ?></article>
                <?php endif; ?>

                <?php foreach ($requests as $request): ?>
                    <?php
                        $statusClass = strtolower($request['status']);
                        if (!in_array($statusClass, ['pending', 'confirmed', 'completed', 'cancelled'], true)) {
                            $statusClass = 'pending';
                        }
                        $disableStatusForm = $request['status'] === 'Cancelled';
                        $showCancelledOption = $request['can_provider_cancel'] || $request['status'] === 'Cancelled';
                    ?>
                    <article id="request-<?php echo htmlspecialchars((string) $request['request_id'], ENT_QUOTES, 'UTF-8'); ?>" class="request-card <?php echo htmlspecialchars($statusClass, ENT_QUOTES, 'UTF-8'); ?>" data-search="<?php echo htmlspecialchars(strtolower(implode(' ', [$request['request_id'], $request['customer_name'], $request['customer_email'], $request['customer_phone'], $request['category_name'], $request['status']])), ENT_QUOTES, 'UTF-8'); ?>">
                        <div class="request-head">
                            <h3><?php echo htmlspecialchars(t('prov_req_req_num'), ENT_QUOTES, 'UTF-8'); ?><?php echo htmlspecialchars((string) $request['request_id'], ENT_QUOTES, 'UTF-8'); ?></h3>
                            <span class="status-pill <?php echo htmlspecialchars($statusClass, ENT_QUOTES, 'UTF-8'); ?>">
                                <?php
                                    $provStatusLabels = [
                                        'Pending'   => t('req_status_pending'),
                                        'Confirmed' => t('req_status_confirmed'),
                                        'Completed' => t('req_status_completed'),
                                        'Cancelled' => t('req_status_cancelled'),
                                    ];
                                    echo htmlspecialchars($provStatusLabels[$request['status']] ?? $request['status'], ENT_QUOTES, 'UTF-8');
                                ?>
                            </span>
                        </div>

                        <div class="meta-row">
                            <span class="chip">
                                <i class="fas fa-wrench" aria-hidden="true"></i>
                                <?php echo htmlspecialchars($request['category_name'], ENT_QUOTES, 'UTF-8'); ?>
                            </span>
                            <span class="chip">
                                <i class="fas fa-calendar-day" aria-hidden="true"></i>
                                <?php echo htmlspecialchars(provLocalizedDate($request['appointment_date']), ENT_QUOTES, 'UTF-8'); ?>
                            </span>
                            <span class="chip">
                                <i class="fas fa-clock" aria-hidden="true"></i>
                                <?php echo htmlspecialchars(substr($request['appointment_time'], 0, 5), ENT_QUOTES, 'UTF-8'); ?>
                            </span>
                        </div>

                        <p class="customer-row">
                            <strong><?php echo htmlspecialchars(t('prov_req_customer_lbl'), ENT_QUOTES, 'UTF-8'); ?></strong>
                            <?php echo htmlspecialchars($request['customer_name'], ENT_QUOTES, 'UTF-8'); ?> |
                            <?php echo htmlspecialchars($request['customer_email'] !== '' ? $request['customer_email'] : t('prov_req_no_email'), ENT_QUOTES, 'UTF-8'); ?> |
                            <?php echo htmlspecialchars($request['customer_phone'] !== '' ? $request['customer_phone'] : t('prov_req_no_phone'), ENT_QUOTES, 'UTF-8'); ?>
                        </p>

                        <?php
                            /* Show customer location map for Pending and Confirmed requests only.
                             * Completed/Cancelled requests retain visibility for record-keeping. */
                            $custHasLocation = $request['customer_latitude'] !== null && $request['customer_longitude'] !== null;
                            $mapId = 'cust-map-' . (int) $request['request_id'];
                        ?>
                        <div class="cust-location-box">
                            <div class="cust-location-header"
                                 onclick="toggleCustMap('<?php echo htmlspecialchars($mapId, ENT_QUOTES, 'UTF-8'); ?>', this)"
                                 role="button"
                                 aria-expanded="false"
                                 aria-controls="<?php echo htmlspecialchars($mapId . '-wrap', ENT_QUOTES, 'UTF-8'); ?>">
                                <i class="fas fa-map-location-dot" aria-hidden="true"></i>
                                <?php echo htmlspecialchars(t('prov_cust_location_title'), ENT_QUOTES, 'UTF-8'); ?>
                                <?php if (!$custHasLocation): ?>
                                    &mdash; <span style="font-weight:400;color:#3b82f6;"><?php echo htmlspecialchars(t('prov_cust_location_na'), ENT_QUOTES, 'UTF-8'); ?></span>
                                <?php endif; ?>
                                <i class="fas fa-chevron-down cust-location-toggle-icon" aria-hidden="true"></i>
                            </div>
                            <div id="<?php echo htmlspecialchars($mapId . '-wrap', ENT_QUOTES, 'UTF-8'); ?>" class="cust-location-map-wrap">
                                <?php if ($custHasLocation): ?>
                                    <!-- Read-only Leaflet map for provider — customer cannot be edited here -->
                                    <div id="<?php echo htmlspecialchars($mapId, ENT_QUOTES, 'UTF-8'); ?>"
                                         class="cust-location-map-frame"
                                         data-lat="<?php echo htmlspecialchars((string) $request['customer_latitude'], ENT_QUOTES, 'UTF-8'); ?>"
                                         data-lng="<?php echo htmlspecialchars((string) $request['customer_longitude'], ENT_QUOTES, 'UTF-8'); ?>"
                                         data-label="<?php echo htmlspecialchars($request['customer_name'], ENT_QUOTES, 'UTF-8'); ?>">
                                    </div>
                                    <!-- Reverse-geocoded address populated by JS after map init -->
                                    <div id="<?php echo htmlspecialchars($mapId . '-addr', ENT_QUOTES, 'UTF-8'); ?>" class="cust-location-addr" style="display:none">
                                        <i class="fas fa-location-dot" aria-hidden="true"></i>
                                        <span></span>
                                    </div>
                                <?php else: ?>
                                    <p style="padding:10px 2px;font-size:.85rem;color:#64748b;">
                                        <?php echo htmlspecialchars(t('prov_cust_location_na'), ENT_QUOTES, 'UTF-8'); ?>
                                    </p>
                                <?php endif; ?>
                            </div>
                        </div>

                        <p class="price-row">
                            <span><strong><?php echo htmlspecialchars(t('prov_req_estimated_lbl'), ENT_QUOTES, 'UTF-8'); ?></strong> <?php echo $request['estimated_price'] !== null ? ('$' . htmlspecialchars(number_format((float) $request['estimated_price'], 2), ENT_QUOTES, 'UTF-8')) : htmlspecialchars(t('prov_req_na'), ENT_QUOTES, 'UTF-8'); ?></span>
                            <span><strong><?php echo htmlspecialchars(t('prov_req_final_lbl'), ENT_QUOTES, 'UTF-8'); ?></strong> <?php echo $request['final_price'] !== null ? ('$' . htmlspecialchars(number_format((float) $request['final_price'], 2), ENT_QUOTES, 'UTF-8')) : htmlspecialchars(t('prov_req_na'), ENT_QUOTES, 'UTF-8'); ?></span>
                        </p>

                        <p class="review-row">
                            <strong><?php echo htmlspecialchars(t('prov_req_customer_rating'), ENT_QUOTES, 'UTF-8'); ?></strong>
                            <?php if ($request['rating'] !== null && $request['rating'] >= 1 && $request['rating'] <= 5): ?>
                                <span class="stars" aria-label="<?php echo htmlspecialchars((string) $request['rating'], ENT_QUOTES, 'UTF-8'); ?> out of 5 stars">
                                    <?php for ($starIndex = 1; $starIndex <= 5; $starIndex++): ?>
                                        <i class="fas fa-star star <?php echo $starIndex <= $request['rating'] ? '' : 'is-empty'; ?>" aria-hidden="true"></i>
                                    <?php endfor; ?>
                                </span>
                                (<?php echo htmlspecialchars((string) $request['rating'], ENT_QUOTES, 'UTF-8'); ?>/5)
                            <?php else: ?>
                                <?php echo htmlspecialchars(t('prov_req_no_rating'), ENT_QUOTES, 'UTF-8'); ?>
                            <?php endif; ?>
                        </p>

                        <p class="review-row">
                            <strong><?php echo htmlspecialchars(t('prov_req_customer_review'), ENT_QUOTES, 'UTF-8'); ?></strong>
                            <?php echo $request['review'] !== ''
                                ? nl2br(htmlspecialchars($request['review'], ENT_QUOTES, 'UTF-8'))
                                : htmlspecialchars(t('prov_req_no_review'), ENT_QUOTES, 'UTF-8'); ?>
                        </p>

                        <?php if ($request['cancellation_requested']): ?>
                            <div class="cancel-req-box" role="alert">
                                <div class="cancel-req-header">
                                    <i class="fas fa-circle-exclamation" aria-hidden="true"></i>
                                    <?php echo htmlspecialchars(t('prov_cancel_req_badge'), ENT_QUOTES, 'UTF-8'); ?>
                                </div>
                                <p class="cancel-req-info"><?php echo htmlspecialchars(t('prov_cancel_req_info'), ENT_QUOTES, 'UTF-8'); ?></p>
                                <?php if ($request['cancellation_reason'] !== ''): ?>
                                    <div class="cancel-req-reason">
                                        <span class="cancel-req-reason-lbl"><?php echo htmlspecialchars(t('prov_cancel_req_reason_lbl'), ENT_QUOTES, 'UTF-8'); ?></span>
                                        <p class="cancel-req-reason-text"><?php echo nl2br(htmlspecialchars($request['cancellation_reason'], ENT_QUOTES, 'UTF-8')); ?></p>
                                    </div>
                                <?php endif; ?>
                                <div class="cancel-req-actions">
                                    <a class="btn-message" href="messages.php?request_id=<?php echo (int) $request['request_id']; ?>">
                                        <i class="fas fa-comments" aria-hidden="true"></i>
                                        <?php echo htmlspecialchars(t('prov_open_full_chat'), ENT_QUOTES, 'UTF-8'); ?>
                                    </a>
                                    <form method="post" action="service_provider_dashboard.php#requests">
                                        <input type="hidden" name="form_action" value="confirm_cancellation">
                                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars((string) $_SESSION['service_provider_status_csrf'], ENT_QUOTES, 'UTF-8'); ?>">
                                        <input type="hidden" name="request_id" value="<?php echo htmlspecialchars((string) $request['request_id'], ENT_QUOTES, 'UTF-8'); ?>">
                                        <button type="submit" class="btn-confirm-cancel" data-confirm="<?php echo htmlspecialchars(t('prov_confirm_cancel_warn'), ENT_QUOTES, 'UTF-8'); ?>">
                                            <i class="fas fa-circle-check" aria-hidden="true"></i>
                                            <?php echo htmlspecialchars(t('prov_confirm_cancel_btn'), ENT_QUOTES, 'UTF-8'); ?>
                                        </button>
                                    </form>
                                </div>
                            </div>
                        <?php elseif ($request['status'] === 'Cancelled' && $request['cancellation_reason'] !== ''): ?>
                            <div class="cancelled-reason-box">
                                <span class="cancel-req-reason-lbl">
                                    <i class="fas fa-circle-info" aria-hidden="true"></i>
                                    <?php echo htmlspecialchars(t('prov_cancel_req_reason_lbl'), ENT_QUOTES, 'UTF-8'); ?>
                                </span>
                                <p class="cancel-req-reason-text"><?php echo nl2br(htmlspecialchars($request['cancellation_reason'], ENT_QUOTES, 'UTF-8')); ?></p>
                            </div>
                        <?php elseif (in_array($request['status'], ['Confirmed', 'Completed'], true)): ?>
                            <a class="btn-message" href="messages.php?request_id=<?php echo (int) $request['request_id']; ?>">
                                <i class="fas fa-comments" aria-hidden="true"></i>
                                <?php echo htmlspecialchars(t('prov_open_full_chat'), ENT_QUOTES, 'UTF-8'); ?>
                            </a>
                        <?php endif; ?>

                        <?php if (count($request['images']) > 0): ?>
                            <div class="image-grid" aria-label="Customer uploaded problem images">
                                <?php foreach ($request['images'] as $imagePath): ?>
                                    <figure class="image-card">
                                        <img src="<?php echo htmlspecialchars($imagePath, ENT_QUOTES, 'UTF-8'); ?>" alt="Problem image for request <?php echo htmlspecialchars((string) $request['request_id'], ENT_QUOTES, 'UTF-8'); ?>">
                                    </figure>
                                <?php endforeach; ?>
                            </div>
                        <?php endif; ?>

                        <form class="status-form" method="post" action="service_provider_dashboard.php#requests">
                            <input type="hidden" name="form_action" value="update_status">
                            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars((string) $_SESSION['service_provider_status_csrf'], ENT_QUOTES, 'UTF-8'); ?>">
                            <input type="hidden" name="request_id" value="<?php echo htmlspecialchars((string) $request['request_id'], ENT_QUOTES, 'UTF-8'); ?>">
                            <label for="status-<?php echo htmlspecialchars((string) $request['request_id'], ENT_QUOTES, 'UTF-8'); ?>" class="visually-hidden" style="position:absolute;left:-9999px;">
                                Update status for request <?php echo htmlspecialchars((string) $request['request_id'], ENT_QUOTES, 'UTF-8'); ?>
                            </label>
                            <select id="status-<?php echo htmlspecialchars((string) $request['request_id'], ENT_QUOTES, 'UTF-8'); ?>" name="status" required <?php echo $disableStatusForm ? 'disabled aria-disabled="true"' : ''; ?>>
                                <option value="Pending" <?php echo $request['status'] === 'Pending' ? 'selected' : ''; ?>><?php echo htmlspecialchars(t('req_status_pending'), ENT_QUOTES, 'UTF-8'); ?></option>
                                <option value="Confirmed" <?php echo $request['status'] === 'Confirmed' ? 'selected' : ''; ?>><?php echo htmlspecialchars(t('req_status_confirmed'), ENT_QUOTES, 'UTF-8'); ?></option>
                                <option value="Completed" <?php echo $request['status'] === 'Completed' ? 'selected' : ''; ?>><?php echo htmlspecialchars(t('req_status_completed'), ENT_QUOTES, 'UTF-8'); ?></option>
                                <?php if ($showCancelledOption): ?>
                                    <option
                                        value="Cancelled"
                                        <?php echo $request['status'] === 'Cancelled' ? 'selected' : ''; ?>
                                        <?php echo $request['can_provider_cancel'] ? '' : 'disabled'; ?>
                                    >
                                        <?php echo htmlspecialchars(t('req_status_cancelled'), ENT_QUOTES, 'UTF-8'); ?>
                                    </option>
                                <?php endif; ?>
                            </select>
                            <div class="price-input-row" id="estimated-price-row-<?php echo (int) $request['request_id']; ?>" style="display:none">
                                <label for="estimated-price-<?php echo (int) $request['request_id']; ?>"><?php echo htmlspecialchars(t('prov_req_estimated_label'), ENT_QUOTES, 'UTF-8'); ?></label>
                                <input type="number" step="0.01" min="0" name="estimated_price"
                                       id="estimated-price-<?php echo (int) $request['request_id']; ?>"
                                       placeholder="0.00"
                                       value="<?php echo $request['estimated_price'] !== null ? htmlspecialchars(number_format((float) $request['estimated_price'], 2, '.', ''), ENT_QUOTES, 'UTF-8') : ''; ?>">
                            </div>
                            <div class="price-input-row" id="final-price-row-<?php echo (int) $request['request_id']; ?>" style="display:none">
                                <label for="final-price-<?php echo (int) $request['request_id']; ?>"><?php echo htmlspecialchars(t('prov_req_final_label'), ENT_QUOTES, 'UTF-8'); ?></label>
                                <input type="number" step="0.01" min="0" name="final_price"
                                       id="final-price-<?php echo (int) $request['request_id']; ?>"
                                       placeholder="0.00"
                                       value="<?php echo $request['final_price'] !== null ? htmlspecialchars(number_format((float) $request['final_price'], 2, '.', ''), ENT_QUOTES, 'UTF-8') : ''; ?>">
                            </div>
                            <button type="submit" <?php echo $disableStatusForm ? 'disabled' : ''; ?>>
                                <i class="fas fa-arrows-rotate" aria-hidden="true"></i>
                                <?php echo htmlspecialchars(t('prov_req_save_status'), ENT_QUOTES, 'UTF-8'); ?>
                            </button>
                        </form>
                    </article>
                <?php endforeach; ?>
            </div>
        </section>

        <!-- Customer profile modal for booked slots -->
        <div class="customer-profile-modal" id="customerProfileModal" aria-hidden="true">
            <div class="customer-profile-dialog" role="dialog" aria-modal="true" aria-labelledby="customerProfileTitle">
                <div class="customer-profile-header">
                    <h3 id="customerProfileTitle"><?php echo htmlspecialchars(t('prov_modal_title'), ENT_QUOTES, 'UTF-8'); ?></h3>
                    <button class="customer-profile-close" type="button" aria-label="<?php echo htmlspecialchars(t('btn_close'), ENT_QUOTES, 'UTF-8'); ?>">
                        <i class="fas fa-xmark" aria-hidden="true"></i>
                    </button>
                </div>
                <div class="customer-profile-grid">
                    <div>
                        <div class="customer-profile-label"><?php echo htmlspecialchars(t('prov_modal_name'), ENT_QUOTES, 'UTF-8'); ?></div>
                        <div class="customer-profile-value" data-field="name"><?php echo htmlspecialchars(t('prov_modal_not_avail'), ENT_QUOTES, 'UTF-8'); ?></div>
                    </div>
                    <div>
                        <div class="customer-profile-label"><?php echo htmlspecialchars(t('prov_modal_email'), ENT_QUOTES, 'UTF-8'); ?></div>
                        <div class="customer-profile-value" data-field="email"><?php echo htmlspecialchars(t('prov_modal_not_avail'), ENT_QUOTES, 'UTF-8'); ?></div>
                    </div>
                    <div>
                        <div class="customer-profile-label"><?php echo htmlspecialchars(t('prov_modal_phone'), ENT_QUOTES, 'UTF-8'); ?></div>
                        <div class="customer-profile-value" data-field="phone"><?php echo htmlspecialchars(t('prov_modal_not_avail'), ENT_QUOTES, 'UTF-8'); ?></div>
                    </div>
                    <div>
                        <div class="customer-profile-label"><?php echo htmlspecialchars(t('prov_modal_address'), ENT_QUOTES, 'UTF-8'); ?></div>
                        <div class="customer-profile-value" data-field="address"><?php echo htmlspecialchars(t('prov_modal_not_avail'), ENT_QUOTES, 'UTF-8'); ?></div>
                    </div>
                    <div>
                        <div class="customer-profile-label"><?php echo htmlspecialchars(t('prov_modal_request'), ENT_QUOTES, 'UTF-8'); ?></div>
                        <div class="customer-profile-value" data-field="request"><?php echo htmlspecialchars(t('prov_modal_not_avail'), ENT_QUOTES, 'UTF-8'); ?></div>
                    </div>
                </div>
            </div>
        </div>
    </main>

    <script>
        /*
         * Profile form submit handler to prevent double submission.
         */
        var profileForm = document.getElementById('profileForm');
        if (profileForm) {
            profileForm.addEventListener('submit', function () {
                var submitButton = profileForm.querySelector('button[type="submit"]');
                if (!submitButton) {
                    return;
                }

                submitButton.disabled = true;
                submitButton.style.opacity = '0.72';
            });

            var photoInput = document.getElementById('profile_photo');
            if (photoInput) {
                photoInput.addEventListener('change', function () {
                    var file = photoInput.files && photoInput.files[0];
                    if (!file) { return; }

                    var reader = new FileReader();
                    reader.onload = function (e) {
                        var avatarBox = profileForm.querySelector('.profile-avatar');
                        if (!avatarBox) { return; }

                        var existingIcon = avatarBox.querySelector('i');
                        if (existingIcon) { existingIcon.remove(); }

                        var existingImg = avatarBox.querySelector('img');
                        if (existingImg) {
                            existingImg.src = e.target.result;
                        } else {
                            var img = document.createElement('img');
                            img.src = e.target.result;
                            img.alt = 'Profile photo preview';
                            avatarBox.appendChild(img);
                        }
                    };
                    reader.readAsDataURL(file);
                });
            }
        }

        /*
         * Toggle service price inputs and selected state based on category checkbox.
         */
        document.querySelectorAll('.service-category-row').forEach(function (row) {
            var checkbox   = row.querySelector('input[type="checkbox"]');
            var priceInput = row.querySelector('.service-category-price input');
            if (!checkbox || !priceInput) return;

            function syncPriceState() {
                var isEnabled = checkbox.checked;
                priceInput.disabled = !isEnabled;
                row.classList.toggle('is-disabled', !isEnabled);
                row.classList.toggle('is-selected', isEnabled);
            }
            checkbox.addEventListener('change', syncPriceState);
            syncPriceState();
        });

        /*
         * Live search / filter for the incoming requests list.
         */
        (function () {
            var input = document.getElementById('reqSearch');
            var list  = document.getElementById('reqList');
            if (!input || !list) return;
            input.addEventListener('input', function () {
                var q = input.value.trim().toLowerCase();
                list.querySelectorAll('.request-card').forEach(function (card) {
                    var text = (card.dataset.search || '').toLowerCase();
                    card.style.display = (q === '' || text.indexOf(q) !== -1) ? '' : 'none';
                });
            });
        })();

        /*
         * Live search / filter for the category selection list.
         */
        (function () {
            var searchInput  = document.getElementById('svcCategorySearch');
            var list         = document.getElementById('svcCategoryList');
            var noResults    = document.getElementById('svcNoResults');
            if (!searchInput || !list) return;

            searchInput.addEventListener('input', function () {
                var q = searchInput.value.trim().toLowerCase();
                var rows = list.querySelectorAll('.service-category-row');
                var visible = 0;
                rows.forEach(function (row) {
                    var name = (row.dataset.catName || '').toLowerCase();
                    var show = q === '' || name.indexOf(q) !== -1;
                    row.style.display = show ? '' : 'none';
                    if (show) visible++;
                });
                if (noResults) {
                    noResults.style.display = visible === 0 ? 'flex' : 'none';
                }
            });
        })();

        /*
         * Prevent rapid duplicate submissions for service category updates.
         */
        var serviceForm = document.querySelector('.service-form');
        if (serviceForm) {
            serviceForm.addEventListener('submit', function () {
                var submitButton = serviceForm.querySelector('button[type="submit"]');
                if (!submitButton) return;
                submitButton.disabled = true;
                submitButton.style.opacity = '0.72';
            });
        }

        /*
         * Prevent rapid duplicate submissions for slot creation.
         */
        var slotForm = document.querySelector('.slot-form');
        if (slotForm) {
            slotForm.addEventListener('submit', function () {
                var submitButton = slotForm.querySelector('button[type="submit"]');
                if (!submitButton) {
                    return;
                }

                submitButton.disabled = true;
                submitButton.style.opacity = '0.72';
            });
        }

        /*
         * Customer profile modal for booked slot details.
         */
        (function () {
            var modal = document.getElementById('customerProfileModal');
            if (!modal) {
                return;
            }

            var closeButton = modal.querySelector('.customer-profile-close');
            var fieldMap = {
                name: modal.querySelector('[data-field="name"]'),
                email: modal.querySelector('[data-field="email"]'),
                phone: modal.querySelector('[data-field="phone"]'),
                address: modal.querySelector('[data-field="address"]'),
                request: modal.querySelector('[data-field="request"]'),
            };

            function setField(fieldKey, value) {
                if (!fieldMap[fieldKey]) {
                    return;
                }
                fieldMap[fieldKey].textContent = value !== '' ? value : provI18n.modalNotAvail;
            }

            function openModal(payload) {
                setField('name', payload.name || '');
                setField('email', payload.email || '');
                setField('phone', payload.phone || '');
                setField('address', payload.address || '');
                setField('request', payload.request || '');
                modal.classList.add('active');
                modal.setAttribute('aria-hidden', 'false');
            }

            function closeModal() {
                modal.classList.remove('active');
                modal.setAttribute('aria-hidden', 'true');
            }

            document.querySelectorAll('.slot-profile-btn').forEach(function (button) {
                button.addEventListener('click', function () {
                    var requestId = button.getAttribute('data-request-id') || '';
                    openModal({
                        name: button.getAttribute('data-customer-name') || '',
                        email: button.getAttribute('data-customer-email') || '',
                        phone: button.getAttribute('data-customer-phone') || '',
                        address: button.getAttribute('data-customer-address') || '',
                        request: requestId !== '' ? 'Request #' + requestId : '',
                    });
                });
            });

            if (closeButton) {
                closeButton.addEventListener('click', closeModal);
            }

            modal.addEventListener('click', function (event) {
                if (event.target === modal) {
                    closeModal();
                }
            });

            document.addEventListener('keydown', function (event) {
                if (event.key === 'Escape' && modal.classList.contains('active')) {
                    closeModal();
                }
            });
        })();


        /*
         * Mobile sidebar toggle behavior with backdrop support.
         */
        (function () {
            var sidebar = document.getElementById('sidebar');
            var toggleButton = document.getElementById('sidebarToggle');
            var backdrop = document.getElementById('sidebarBackdrop');

            if (!sidebar || !toggleButton || !backdrop) {
                return;
            }

            function setSidebarState(isOpen) {
                sidebar.classList.toggle('open', isOpen);
                document.body.classList.toggle('sidebar-open', isOpen);
                toggleButton.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
                toggleButton.setAttribute('aria-label', isOpen ? 'Close navigation menu' : 'Open navigation menu');
            }

            toggleButton.addEventListener('click', function () {
                setSidebarState(!sidebar.classList.contains('open'));
            });

            backdrop.addEventListener('click', function () {
                setSidebarState(false);
            });

            document.querySelectorAll('.sidebar-menu a, .sidebar-footer a').forEach(function (link) {
                link.addEventListener('click', function () {
                    if (window.innerWidth <= 900) {
                        setSidebarState(false);
                    }
                });
            });

            window.addEventListener('resize', function () {
                if (window.innerWidth > 900) {
                    setSidebarState(false);
                }
            });

            document.addEventListener('keydown', function (e) {
                if (e.key === 'Escape' && sidebar.classList.contains('open')) {
                    setSidebarState(false);
                }
            });
        })();

        /*
         * Notification system — polling, unread badge, dismiss, mark-as-read.
         */
        (function () {
            var notificationUrl = window.location.pathname + '?ajax=notifications';
            var markReadUrl     = window.location.pathname + '?ajax=mark_notifications_read';
            var dismissUrl      = window.location.pathname + '?ajax=dismiss_notification';
            var refreshIntervalMs = 5000;
            var lastUnreadCount = <?php echo (int) $notificationCount; ?>;
            var notificationBadge = document.getElementById('notificationCountBadge');
            var messagesBody  = document.getElementById('recentMessagesBody');
            var pendingBody   = document.getElementById('recentPendingBody');
            var cancelledBody = document.getElementById('recentCancelledBody');

            var latestMaxMsgId       = 0;
            var latestMaxPendingId   = 0;
            var latestMaxCancelledId = 0;

            if (!messagesBody || !pendingBody || !cancelledBody) return;

            function escapeHtml(v) {
                return String(v).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
            }

            var pageLang = document.documentElement.lang || 'en';
            function normalizeTime(v) {
                if (!v) return 'Time unavailable';
                var d = new Date(String(v).replace(' ', 'T'));
                if (isNaN(d.getTime())) return 'Time unavailable';
                var locale = pageLang === 'ar' ? 'ar-SA' : 'en-US';
                return d.toLocaleString(locale, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
            }

            function setBadge(count) {
                if (!notificationBadge) return;
                if (count > 0) {
                    if (count !== lastUnreadCount) {
                        notificationBadge.style.animation = 'none';
                        void notificationBadge.offsetWidth;
                        notificationBadge.style.animation = '';
                    }
                    notificationBadge.textContent = String(count);
                    notificationBadge.style.display = '';
                    lastUnreadCount = count;
                } else {
                    notificationBadge.style.display = 'none';
                    lastUnreadCount = 0;
                }
            }

            function markItemRead(type, id) {
                var body = new URLSearchParams();
                if (type === 'message')   body.append('last_msg_id', String(id));
                if (type === 'pending')   body.append('last_pending_id', String(id));
                if (type === 'cancelled') body.append('last_cancelled_id', String(id));
                fetch(markReadUrl, {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: body.toString(),
                }).catch(function () {});
            }

            function markAllRead() {
                var body = new URLSearchParams();
                body.append('last_msg_id',       String(latestMaxMsgId));
                body.append('last_pending_id',   String(latestMaxPendingId));
                body.append('last_cancelled_id', String(latestMaxCancelledId));
                fetch(markReadUrl, {
                    method: 'POST', credentials: 'same-origin',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: body.toString(),
                }).catch(function () {});
                setBadge(0);
            }

            window.dismissNotification = function (btn, type, id) {
                var item = btn.closest('.notification-item');
                if (!item) return;
                item.style.transition = 'opacity 0.25s, transform 0.25s';
                item.style.opacity = '0';
                item.style.transform = 'translateX(10px)';
                setTimeout(function () {
                    if (item.parentNode) item.parentNode.removeChild(item);
                    // Recount unread in DOM
                    var remaining = document.querySelectorAll('.notification-item.is-unread').length;
                    setBadge(remaining);
                }, 270);
                // Persist dismiss to session
                var body = new URLSearchParams();
                body.append('type', type);
                body.append('id', String(id));
                fetch(dismissUrl, {
                    method: 'POST', credentials: 'same-origin',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: body.toString(),
                }).catch(function () {});
            };

            function buildDismissBtn(type, id) {
                return '<button class="notif-dismiss-btn" type="button" title="' + escapeHtml(provI18n.dismiss) + '" onclick="dismissNotification(this,\'' + type + '\',' + id + ')"><i class="fas fa-times"></i></button>';
            }

            var provI18n = {
                noMsgsCust:        <?php echo json_encode(t('notif_no_msgs_cust')); ?>,
                msgFromCust:       <?php echo json_encode(t('notif_msg_from_cust')); ?>,
                custFb:            <?php echo json_encode(t('notif_customer')); ?>,
                image:             <?php echo json_encode(t('notif_image')); ?>,
                reqNum:            <?php echo json_encode(t('req_request_num')); ?>,
                openChat:          <?php echo json_encode(t('notif_open_chat')); ?>,
                noPending:         <?php echo json_encode(t('notif_no_pending')); ?>,
                newReqFrom:        <?php echo json_encode(t('notif_new_request_from')); ?>,
                dateNa:            <?php echo json_encode(t('notif_date_na')); ?>,
                atWord:            <?php echo json_encode(t('notif_at')); ?>,
                viewReq:           <?php echo json_encode(t('notif_view_request')); ?>,
                noCancelled:       <?php echo json_encode(t('notif_no_cancelled')); ?>,
                cancelledBy:       <?php echo json_encode(t('notif_cancelled_by')); ?>,
                youLabel:          <?php echo json_encode(t('prov_you_label')); ?>,
                chatCustomerLabel: <?php echo json_encode(t('prov_chat_customer_label')); ?>,
                modalNotAvail:     <?php echo json_encode(t('prov_modal_not_avail')); ?>,
                dismiss:           <?php echo json_encode(t('notif_dismiss')); ?>,
                cancelReasonLbl:   <?php echo json_encode(t('prov_cancel_req_reason_lbl')); ?>
            };

            function renderMessages(items) {
                if (!items || items.length === 0) return '<p class="empty-state">' + escapeHtml(provI18n.noMsgsCust) + '</p>';
                var html = '<div class="notification-list">';
                items.forEach(function (msg) {
                    var preview = String(msg.message || '').trim();
                    if (preview.length > 90) preview = preview.slice(0, 90) + '...';
                    var dot = msg.is_unread ? '<span class="notif-dot"></span>' : '';
                    var unreadClass = msg.is_unread ? ' is-unread' : '';
                    html += '<div class="notification-item' + unreadClass + '" data-notif-type="message" data-notif-id="' + msg.message_id + '">';
                    html += buildDismissBtn('message', msg.message_id);
                    html += '<div class="notification-title">' + dot + escapeHtml(provI18n.msgFromCust) + ' ' + escapeHtml(msg.customer_name || provI18n.custFb) + '</div>';
                    html += '<div class="notification-text">' + escapeHtml(preview) + '</div>';
                    html += '<div class="notification-meta">';
                    html += '<span>' + escapeHtml(provI18n.reqNum) + escapeHtml(msg.request_id || '') + '</span>';
                    html += '<span>' + escapeHtml(normalizeTime(msg.created_at)) + '</span>';
                    html += '<a class="notification-link" href="messages.php?request_id=' + encodeURIComponent(msg.request_id || '') + '" data-notif-action="message" data-notif-id="' + msg.message_id + '">' + escapeHtml(provI18n.openChat) + '</a>';
                    html += '</div></div>';
                    if (msg.message_id > latestMaxMsgId) latestMaxMsgId = msg.message_id;
                });
                html += '</div>';
                return html;
            }

            function renderPending(items) {
                if (!items || items.length === 0) return '<p class="empty-state">' + escapeHtml(provI18n.noPending) + '</p>';
                var html = '<div class="notification-list">';
                items.forEach(function (p) {
                    var d = p.appointment_date ? new Date(String(p.appointment_date).replace(' ','T')) : null;
                    var locale = pageLang === 'ar' ? 'ar-SA' : 'en-US';
                    var dl = d && !isNaN(d) ? d.toLocaleDateString(locale, { month: 'short', day: 'numeric', year: 'numeric' }) : provI18n.dateNa;
                    var tm = String(p.appointment_time || '').slice(0, 5);
                    var dot = p.is_unread ? '<span class="notif-dot"></span>' : '';
                    var unreadClass = p.is_unread ? ' is-unread' : '';
                    html += '<div class="notification-item' + unreadClass + '" data-notif-type="pending" data-notif-id="' + p.request_id + '">';
                    html += buildDismissBtn('pending', p.request_id);
                    html += '<div class="notification-title">' + dot + escapeHtml(provI18n.newReqFrom) + ' ' + escapeHtml(p.customer_name || provI18n.custFb) + '</div>';
                    html += '<div class="notification-text">' + escapeHtml(provI18n.reqNum) + escapeHtml(p.request_id || '') + ' · ' + escapeHtml(p.category_name || '') + '</div>';
                    html += '<div class="notification-meta">';
                    html += '<span>' + escapeHtml(dl + (tm ? ' ' + provI18n.atWord + ' ' + tm : '')) + '</span>';
                    html += '<a class="notification-link" href="#request-' + encodeURIComponent(p.request_id || '') + '" data-notif-action="pending" data-notif-id="' + p.request_id + '">' + escapeHtml(provI18n.viewReq) + '</a>';
                    html += '</div></div>';
                    if (p.request_id > latestMaxPendingId) latestMaxPendingId = p.request_id;
                });
                html += '</div>';
                return html;
            }

            function renderCancelled(items) {
                if (!items || items.length === 0) return '<p class="empty-state">' + escapeHtml(provI18n.noCancelled) + '</p>';
                var html = '<div class="notification-list">';
                items.forEach(function (c) {
                    var d = c.appointment_date ? new Date(String(c.appointment_date).replace(' ','T')) : null;
                    var locale = pageLang === 'ar' ? 'ar-SA' : 'en-US';
                    var dl = d && !isNaN(d) ? d.toLocaleDateString(locale, { month: 'short', day: 'numeric', year: 'numeric' }) : provI18n.dateNa;
                    var tm = String(c.appointment_time || '').slice(0, 5);
                    var dot = c.is_unread ? '<span class="notif-dot"></span>' : '';
                    var unreadClass = c.is_unread ? ' is-unread' : '';
                    html += '<div class="notification-item' + unreadClass + '" data-notif-type="cancelled" data-notif-id="' + c.request_id + '">';
                    html += buildDismissBtn('cancelled', c.request_id);
                    html += '<div class="notification-title">' + dot + escapeHtml(provI18n.cancelledBy) + ' ' + escapeHtml(c.customer_name || provI18n.custFb) + '</div>';
                    html += '<div class="notification-text">' + escapeHtml(provI18n.reqNum) + escapeHtml(c.request_id || '') + '</div>';
                    if (c.cancellation_reason && c.cancellation_reason.trim() !== '') {
                        html += '<div class="notification-cancel-reason"><span class="notif-reason-lbl">' + escapeHtml(provI18n.cancelReasonLbl) + ':</span> ' + escapeHtml(c.cancellation_reason) + '</div>';
                    }
                    html += '<div class="notification-meta">';
                    html += '<span>' + escapeHtml(dl + (tm ? ' ' + provI18n.atWord + ' ' + tm : '')) + '</span>';
                    html += '<a class="notification-link" href="#request-' + encodeURIComponent(c.request_id || '') + '" data-notif-action="cancelled" data-notif-id="' + c.request_id + '">' + escapeHtml(provI18n.viewReq) + '</a>';
                    html += '</div></div>';
                    if (c.request_id > latestMaxCancelledId) latestMaxCancelledId = c.request_id;
                });
                html += '</div>';
                return html;
            }

            // Intercept notification action link clicks (Open Chat / View Request)
            document.addEventListener('click', function (e) {
                var link = e.target.closest('a[data-notif-action]');
                if (!link) return;
                var action = link.getAttribute('data-notif-action');
                var id = parseInt(link.getAttribute('data-notif-id') || '0', 10);
                if (!id) return;

                // Mark this item as read immediately in the DOM
                var item = link.closest('.notification-item');
                if (item && item.classList.contains('is-unread')) {
                    item.classList.remove('is-unread');
                    var dot = item.querySelector('.notif-dot');
                    if (dot) dot.remove();
                    var remaining = document.querySelectorAll('.notification-item.is-unread').length;
                    setBadge(remaining);
                    markItemRead(action, id);
                }
            });

            // Intercept #request-{id} clicks: navigate to #requests panel first, then scroll to card
            document.addEventListener('click', function (e) {
                var link = e.target.closest('a[href^="#request-"]');
                if (!link) return;
                e.preventDefault();
                var targetId = (link.getAttribute('href') || '').slice(1);

                function scrollToCard() {
                    var target = document.getElementById(targetId);
                    if (!target) return;
                    var shell = document.querySelector('main.shell');
                    if (shell) {
                        var targetRect = target.getBoundingClientRect();
                        var shellRect  = shell.getBoundingClientRect();
                        shell.scrollTo({
                            top: shell.scrollTop + (targetRect.top - shellRect.top) - 80,
                            behavior: 'smooth'
                        });
                    }
                    target.classList.add('highlighted');
                    setTimeout(function () { target.classList.remove('highlighted'); }, 2400);
                }

                if (window.location.hash === '#requests') {
                    scrollToCard();
                } else {
                    // Show the requests panel via CSS :target, then scroll
                    window.location.hash = '#requests';
                    setTimeout(scrollToCard, 50);
                }
            });

            // Mark all as read whenever the notifications panel becomes the active hash target
            function checkHashForNotifications() {
                if (window.location.hash === '#notifications') { markAllRead(); }
            }
            var notifLink = document.querySelector('a[href="#notifications"]');
            if (notifLink) {
                notifLink.addEventListener('click', function () { markAllRead(); });
            }
            window.addEventListener('hashchange', checkHashForNotifications);
            checkHashForNotifications();

            function refreshNotifications() {
                fetch(notificationUrl, { credentials: 'same-origin' })
                    .then(function (r) { return r.json(); })
                    .then(function (payload) {
                        if (!payload || !payload.ok) return;
                        setBadge(parseInt(payload.unread_count || 0, 10));
                        messagesBody.innerHTML  = renderMessages(payload.recent_customer_messages || []);
                        pendingBody.innerHTML   = renderPending(payload.recent_pending_requests || []);
                        cancelledBody.innerHTML = renderCancelled(payload.recent_cancelled_requests || []);
                    })
                    .catch(function () {});
            }

            refreshNotifications();
            window.setInterval(refreshNotifications, refreshIntervalMs);
        })();

        /*
         * Show/hide price input fields based on selected status.
         * Confirmed → final_price   |   Completed → estimated_price
         */
        (function () {
            function syncPriceFields(select) {
                var rid = select.closest('form').querySelector('[name="request_id"]').value;
                var finalRow     = document.getElementById('final-price-row-'     + rid);
                var estimatedRow = document.getElementById('estimated-price-row-' + rid);
                if (!finalRow || !estimatedRow) return;
                estimatedRow.style.display = select.value === 'Confirmed'  ? '' : 'none';
                finalRow.style.display     = select.value === 'Completed'  ? '' : 'none';
            }

            document.querySelectorAll('.status-form select[name="status"]').forEach(function (sel) {
                syncPriceFields(sel);
                sel.addEventListener('change', function () { syncPriceFields(sel); });
            });
        })();

        /*
         * Confirm before submitting status changes to Cancelled.
         * Prevents accidental cancellations of confirmed requests.
         */
        (function () {
            document.querySelectorAll('.status-form').forEach(function (form) {
                form.addEventListener('submit', function (event) {
                    var sel = form.querySelector('select[name="status"]');
                    if (sel && sel.value === 'Cancelled') {
                        var confirmed = window.confirm('<?php echo addslashes(t('prov_confirm_cancel')); ?>');
                        if (!confirmed) {
                            event.preventDefault();
                        }
                    }
                });
            });
        })();

        /*
         * Confirm before approving a customer's cancellation request.
         */
        (function () {
            document.querySelectorAll('.btn-confirm-cancel').forEach(function (btn) {
                btn.addEventListener('click', function (event) {
                    var msg = btn.getAttribute('data-confirm');
                    if (msg && !window.confirm(msg)) {
                        event.preventDefault();
                    }
                });
            });
        })();

    </script>

    <!-- ── Admin Live Chat Widget ─────────────────────────────── -->
    <div class="admin-chat-fab">
        <button class="admin-chat-btn" id="adminChatToggle" title="<?php echo htmlspecialchars(t('admin_chat_btn'), ENT_QUOTES, 'UTF-8'); ?>">
            <i class="fa-solid fa-headset"></i>
            <span class="admin-chat-unread-dot hidden" id="adminChatBadge">0</span>
        </button>
    </div>

    <div class="admin-chat-window" id="adminChatWindow">
        <div class="acw-header">
            <div class="acw-header-left">
                <div class="acw-avatar"><i class="fa-solid fa-shield-halved"></i></div>
                <div>
                    <div class="acw-title"><?php echo htmlspecialchars(t('admin_chat_title'), ENT_QUOTES, 'UTF-8'); ?></div>
                    <div class="acw-sub"><?php echo htmlspecialchars(t('admin_chat_offline'), ENT_QUOTES, 'UTF-8'); ?></div>
                </div>
            </div>
            <button class="acw-close" id="adminChatClose"><i class="fa-solid fa-times"></i></button>
        </div>
        <div class="acw-messages" id="acwMessages">
            <div class="acw-empty" id="acwEmpty"><?php echo htmlspecialchars(t('admin_chat_no_messages'), ENT_QUOTES, 'UTF-8'); ?></div>
        </div>
        <div class="acw-input-row">
            <textarea class="acw-input" id="acwInput" rows="1"
                placeholder="<?php echo htmlspecialchars(t('admin_chat_placeholder'), ENT_QUOTES, 'UTF-8'); ?>"></textarea>
            <button class="acw-send" id="acwSend" disabled>
                <i class="fa-solid fa-paper-plane"></i>
            </button>
        </div>
    </div>

    <script>
    (function(){
        const CSRF   = <?php echo json_encode($adminChatCsrf); ?>;
        const LABELS = {
            you   : <?php echo json_encode(t('admin_chat_you')); ?>,
            admin : <?php echo json_encode(t('admin_chat_admin')); ?>,
            empty : <?php echo json_encode(t('admin_chat_no_messages')); ?>,
        };

        let lastId    = 0;
        let isOpen    = false;
        let pollTimer = null;

        const toggle   = document.getElementById('adminChatToggle');
        const win      = document.getElementById('adminChatWindow');
        const closeBtn = document.getElementById('adminChatClose');
        const input    = document.getElementById('acwInput');
        const sendBtn  = document.getElementById('acwSend');
        const msgArea  = document.getElementById('acwMessages');
        const emptyEl  = document.getElementById('acwEmpty');
        const badge    = document.getElementById('adminChatBadge');

        function esc(s){ const d=document.createElement('div');d.textContent=s;return d.innerHTML; }
        function time(ts){ return new Date(ts.replace(' ','T')).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'}); }

        function openChat(){
            isOpen = true;
            win.classList.add('open');
            fetchMessages();
            if(pollTimer) clearInterval(pollTimer);
            pollTimer = setInterval(fetchMessages, 3000);
        }
        function closeChat(){
            isOpen = false;
            win.classList.remove('open');
            if(pollTimer) clearInterval(pollTimer);
        }

        toggle.addEventListener('click', ()=> isOpen ? closeChat() : openChat());
        closeBtn.addEventListener('click', closeChat);

        async function fetchMessages(){
            try{
                const r = await fetch('admin_chat_api.php?action=fetch&since_id='+lastId);
                const d = await r.json();
                if(!d.ok) return;
                if(d.messages.length){
                    d.messages.forEach(m => appendMsg(m));
                    msgArea.scrollTop = msgArea.scrollHeight;
                    lastId = d.last_id;
                    if(emptyEl) emptyEl.style.display='none';
                }
            }catch(e){}
            if(!isOpen) fetchUnreadCount();
        }

        function appendMsg(m){
            const self = m.is_self;
            const row = document.createElement('div');
            row.className = 'acw-msg-row' + (self?' self':'');
            row.innerHTML = `<div>
                <div class="acw-bubble">${esc(m.message)}</div>
                <div class="acw-meta">${esc(self ? LABELS.you : LABELS.admin)} · ${esc(time(m.created_at))}</div>
            </div>`;
            msgArea.appendChild(row);
        }

        async function fetchUnreadCount(){
            try{
                const r = await fetch('admin_chat_api.php?action=unread_count');
                const d = await r.json();
                if(!d.ok) return;
                if(d.count > 0){
                    badge.textContent = d.count > 9 ? '9+' : d.count;
                    badge.classList.remove('hidden');
                } else {
                    badge.classList.add('hidden');
                }
            }catch(e){}
        }

        sendBtn.addEventListener('click', sendMsg);
        input.addEventListener('keydown', e => {
            if(e.key==='Enter' && !e.shiftKey){ e.preventDefault(); sendMsg(); }
        });
        input.addEventListener('input', function(){
            this.style.height='auto';
            this.style.height=Math.min(this.scrollHeight,90)+'px';
            sendBtn.disabled = !this.value.trim();
        });

        async function sendMsg(){
            const text = input.value.trim();
            if(!text) return;
            sendBtn.disabled = true;
            const body = new FormData();
            body.append('action','send');
            body.append('message', text);
            body.append('csrf_token', CSRF);
            try{
                const r = await fetch('admin_chat_api.php',{method:'POST',body});
                const d = await r.json();
                if(d.ok){
                    input.value=''; input.style.height='auto';
                    if(emptyEl) emptyEl.style.display='none';
                    appendMsg(d.message);
                    msgArea.scrollTop = msgArea.scrollHeight;
                    lastId = Math.max(lastId, d.message.message_id);
                }
            }catch(e){}
            sendBtn.disabled = !input.value.trim();
        }

        fetchUnreadCount();
        setInterval(()=>{ if(!isOpen) fetchUnreadCount(); }, 15000);
    })();

        /*
         * Panel switching — exactly one section visible at a time based on URL hash.
         * Hides the always-visible dashboard-summary when a named panel is active.
         */
        (function () {
            var main    = document.querySelector('.main-content');
            if (!main) return;
            var PANELS  = ['notifications', 'profile-editor', 'requests', 'service-categories', 'upcoming-slots'];
            var summary = main.querySelector('.panel.dashboard-summary');

            function syncView() {
                var hash    = window.location.hash;
                var matched = PANELS.indexOf(hash.slice(1)) !== -1;

                // Dashboard summary: only when no named panel is active
                if (summary) summary.style.display = matched ? 'none' : 'block';

                // Show/hide each named panel
                PANELS.forEach(function (id) {
                    var el = document.getElementById(id);
                    if (el) el.style.display = (hash === '#' + id) ? 'block' : 'none';
                });

                // Sync active state on sidebar links
                var noHash = (hash === '');
                document.querySelectorAll('.sidebar-menu-item').forEach(function (link) {
                    var href = link.getAttribute('href') || '';
                    var h    = href.replace(/^[^#]*/, '');
                    var active;
                    if (h) {
                        active = (h === hash);
                    } else if (href === 'service_provider_dashboard.php') {
                        active = noHash;
                    } else {
                        active = false;
                    }
                    link.classList.toggle('active', active);
                });
            }

            window.addEventListener('hashchange', syncView);
            syncView();
        })();
    </script>
    <script src="https://cdn.jsdelivr.net/npm/flatpickr"></script>
    <?php if (getLang() === 'ar'): ?>
    <script src="https://cdn.jsdelivr.net/npm/flatpickr/dist/l10n/ar.js"></script>
    <?php endif; ?>
    <script>
    (function () {
        var fpLocale = <?php echo getLang() === 'ar' ? '"ar"' : '"default"'; ?>;
        var arMap = {"0":"٠","1":"١","2":"٢","3":"٣","4":"٤","5":"٥","6":"٦","7":"٧","8":"٨","9":"٩"};
        function toArNums(s) { return String(s).replace(/\d/g, function(d){ return arMap[d]; }); }

        var dateInput = document.getElementById('slot_date');
        if (dateInput && typeof flatpickr !== 'undefined') {
            flatpickr(dateInput, {
                dateFormat: 'Y-m-d',
                altInput: fpLocale === 'ar',
                altFormat: 'j F Y',
                minDate: 'today',
                locale: fpLocale,
                disableMobile: true,
                onReady: function (selDates, dateStr, instance) {
                    if (fpLocale === 'ar' && instance.altInput) {
                        instance.altInput.value = toArNums(instance.altInput.value);
                    }
                },
                onChange: function (selDates, dateStr, instance) {
                    if (fpLocale === 'ar' && instance.altInput) {
                        instance.altInput.value = toArNums(instance.altInput.value);
                    }
                },
                onDayCreate: function (dObj, dStr, fp, dayElem) {
                    if (fpLocale === 'ar') {
                        dayElem.textContent = toArNums(dayElem.textContent);
                    }
                }
            });
        }
        var timeInput = document.getElementById('slot_time');
        if (timeInput && typeof flatpickr !== 'undefined') {
            flatpickr(timeInput, {
                enableTime: true,
                noCalendar: true,
                time_24hr: true,
                minuteIncrement: 15,
                altInput: fpLocale === 'ar',
                altFormat: 'H:i',
                locale: fpLocale,
                disableMobile: true,
                onReady: function (selDates, dateStr, instance) {
                    if (fpLocale === 'ar' && instance.altInput) {
                        instance.altInput.value = toArNums(instance.altInput.value);
                    }
                },
                onChange: function (selDates, dateStr, instance) {
                    if (fpLocale === 'ar' && instance.altInput) {
                        instance.altInput.value = toArNums(instance.altInput.value);
                    }
                }
            });
        }
    })();
    </script>

    <!-- Leaflet JS — served locally -->
    <script src="vendor/leaflet/leaflet.js"></script>
    <script>
    /*
     * Customer location map helpers for provider request cards.
     *
     * Maps are lazily initialised the first time a card is expanded so that
     * only the tiles for visible cards are downloaded.
     *
     * After each map initialises, a Nominatim reverse-geocode request fetches
     * a human-readable address that is displayed below the map frame.
     *
     * Providers cannot interact with or modify the customer's pin — the marker
     * is non-draggable and the map has no edit controls.
     */
    var _custMapsInit = {};

    function toggleCustMap(mapId, headerEl) {
        var wrapEl = document.getElementById(mapId + '-wrap');
        var iconEl = headerEl && headerEl.querySelector('.cust-location-toggle-icon');
        if (!wrapEl) return;

        var isOpen = wrapEl.classList.toggle('open');
        if (headerEl) headerEl.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
        if (iconEl)   iconEl.style.transform = isOpen ? 'rotate(180deg)' : '';

        /* Only initialise once per card, and only when Leaflet is available */
        if (!isOpen || _custMapsInit[mapId] || typeof L === 'undefined') return;

        var mapEl = document.getElementById(mapId);
        if (!mapEl) return;

        var lat   = parseFloat(mapEl.dataset.lat);
        var lng   = parseFloat(mapEl.dataset.lng);
        var label = mapEl.dataset.label || 'Customer';

        if (isNaN(lat) || isNaN(lng)) return;

        /* Initialise the Leaflet map centred on the customer's saved coordinates */
        var map = L.map(mapId, {
            zoomControl: true,
            /* Disable interaction so this stays a read-only view for providers */
            dragging: true,
            scrollWheelZoom: true
        }).setView([lat, lng], 16);

        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            maxZoom: 19,
            attribution: '© <a href="https://www.openstreetmap.org/copyright" target="_blank">OpenStreetMap</a>'
        }).addTo(map);

        /*
         * Custom teal house marker icon that matches the site brand.
         * Non-draggable — providers view only, cannot move the pin.
         */
        var icon = L.divIcon({
            className: '',
            html: '<div style="width:32px;height:32px;background:#0f766e;border:3px solid #fff;border-radius:50%;'
                + 'box-shadow:0 2px 8px rgba(0,0,0,.35);display:flex;align-items:center;justify-content:center;'
                + 'color:#fff;font-size:14px;"><i class=\'fas fa-house\'></i></div>',
            iconSize:    [32, 32],
            iconAnchor:  [16, 16],
            popupAnchor: [0, -20]
        });

        var pinMarker = L.marker([lat, lng], { icon: icon, draggable: false })
            .addTo(map)
            .bindPopup('<strong>' + label + '</strong>')
            .openPopup();

        /* Force a size recalculation after the hidden div becomes visible */
        setTimeout(function () { map.invalidateSize(); }, 120);

        _custMapsInit[mapId] = true;

        /*
         * Reverse-geocode the customer's coordinates via Nominatim and display
         * the nearest readable address below the map.
         * zoom=16 returns a street/neighbourhood level result.
         */
        var addrEl = document.getElementById(mapId + '-addr');
        if (addrEl) {
            var addrSpan = addrEl.querySelector('span');
            var pageLang = document.documentElement.lang || 'en';
            var geocodeUrl = 'https://nominatim.openstreetmap.org/reverse'
                           + '?format=jsonv2&lat=' + lat + '&lon=' + lng
                           + '&zoom=16&addressdetails=1';

            fetch(geocodeUrl, { headers: { 'Accept-Language': pageLang } })
                .then(function (r) { return r.json(); })
                .then(function (data) {
                    if (!addrSpan) return;
                    /* Build a concise address: road + suburb/neighbourhood + city */
                    var a = data.address || {};
                    var parts = [];
                    if (a.road)                              parts.push(a.road);
                    if (a.suburb || a.neighbourhood)         parts.push(a.suburb || a.neighbourhood);
                    if (a.city || a.town || a.village)       parts.push(a.city || a.town || a.village);
                    addrSpan.textContent = parts.length ? parts.join(', ') : (data.display_name || '');
                    /* Update the marker popup to include the address */
                    if (addrSpan.textContent) {
                        pinMarker.setPopupContent('<strong>' + label + '</strong><br><small>' + addrSpan.textContent + '</small>');
                        addrEl.style.display = '';
                    }
                })
                .catch(function () {
                    /* Silently ignore geocoding failures — the map is still useful */
                });
        }
    }
    </script>
</body>
</html>

