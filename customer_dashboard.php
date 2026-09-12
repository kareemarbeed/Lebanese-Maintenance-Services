<?php
declare(strict_types=1);

/*
 * Start/resume session so authenticated identity can be read for access control.
 */
session_start();

/*
 * Shared PDO connection for all read/write operations on dashboard data.
 */
require_once __DIR__ . '/db_connection.php';

/*
 * JSON-backed verification store for provider status display.
 */
require_once __DIR__ . '/verification_store.php';

/*
 * JSON-backed suspension store for provider status display.
 */
require_once __DIR__ . '/suspension_store.php';

/*
 * Service category helpers for filter options.
 */
require_once __DIR__ . '/service_categories.php';

/*
 * Site settings helpers for favicon.
 */
require_once __DIR__ . '/site_settings.php';

/*
 * Chat storage helpers for customer notifications.
 */
require_once __DIR__ . '/chat_store.php';
require_once __DIR__ . '/admin_chat_store.php';
require_once __DIR__ . '/lang.php';

function custLocalizedDate(string $isoDateTime, bool $withTime = false): string
{
    static $arMonths = ['January'=>'يناير','February'=>'فبراير','March'=>'مارس','April'=>'أبريل',
        'May'=>'مايو','June'=>'يونيو','July'=>'يوليو','August'=>'أغسطس',
        'September'=>'سبتمبر','October'=>'أكتوبر','November'=>'نوفمبر','December'=>'ديسمبر'];
    $ts = strtotime($isoDateTime);
    if (getLang() !== 'ar') {
        return $withTime ? date('M j, H:i', $ts) : date('M j, Y', $ts);
    }
    $month = $arMonths[date('F', $ts)] ?? date('F', $ts);
    $day   = toArabicNumerals(date('j', $ts));
    $year  = toArabicNumerals(date('Y', $ts));
    if ($withTime) {
        return $day . ' ' . $month . '، ' . toArabicNumerals(date('H:i', $ts));
    }
    return $day . ' ' . $month . ' ' . $year;
}

/*
 * Load site settings for favicon.
 */
ensureSiteSettingsTable($pdo);
$siteSettings = loadSiteSettings($pdo, ['site_favicon' => '']);
$siteFavicon = trim((string) ($siteSettings['site_favicon'] ?? ''));

/*
 * Build lookup map so verification checks are fast during rendering.
 */
$verifiedProviderLookup = buildVerifiedProviderLookup(loadVerifiedProviderIds());

/*
 * Build lookup map for suspended providers so customers do not see them.
 */
$suspendedAccountIds = loadSuspendedAccountIds();
$suspendedProviderLookup = buildSuspendedLookup((array) ($suspendedAccountIds['providers'] ?? []));

/*
 * Load global service categories for filtering.
 */
$serviceCategories = [];
$serviceCategoryLookup = [];

try {
    $serviceCategories = ensureServiceCategories($pdo);
} catch (PDOException $exception) {
    $serviceCategories = [];
}

foreach ($serviceCategories as $category) {
    $serviceCategoryLookup[(int) $category['category_id']] = $category;
}

$categoryEnToAr = [];
foreach ($serviceCategories as $category) {
    $arName = trim((string) ($category['name_ar'] ?? ''));
    if ($arName !== '') {
        $categoryEnToAr[(string) $category['name']] = $arName;
    }
}

function translateCategoryNames(string $names, array $enToAr): string {
    if (getLang() !== 'ar' || $names === '' || empty($enToAr)) return $names;
    $parts = array_map('trim', explode(',', $names));
    $translated = array_map(static fn($n) => $enToAr[$n] ?? $n, $parts);
    return implode('، ', $translated);
}

/*
 * Resolve the service provider location column if one exists in the schema.
 */
function resolveProviderLocationColumn(PDO $pdo): string
{
    foreach (['location', 'address', 'city', 'area'] as $col) {
        try {
            $pdo->query('SELECT `' . $col . '` FROM `serviceprovider` LIMIT 0');
            return $col;
        } catch (PDOException) {
            // column does not exist, try next
        }
    }

    return '';
}

$providerLocationColumn = resolveProviderLocationColumn($pdo);
$providerLocationSelect = $providerLocationColumn !== ''
    ? 'sp.`' . $providerLocationColumn . '` AS location'
    : "'' AS location";
$providerLocationGroupBy = $providerLocationColumn !== ''
    ? ', sp.`' . $providerLocationColumn . '`'
    : '';

/*
 * Enforce tab-scoped access token for protected customer pages.
 * Without a valid token in URL/form payload, this page redirects to login.
 */
$tabAccessToken = trim((string) ($_GET['tab'] ?? $_POST['tab'] ?? ''));
if (!preg_match('/^[a-f0-9]{64}$/', $tabAccessToken)) {
    header('Location: login.php');
    exit;
}

/*
 * Resolve active tab identity from the session token registry.
 * This decouples protected access from shared browser-cookie sessions.
 */
$activeTabSession = null;
if (isset($_SESSION['customer_tab_tokens']) && is_array($_SESSION['customer_tab_tokens'])) {
    $tokenPayload = $_SESSION['customer_tab_tokens'][$tabAccessToken] ?? null;
    if (is_array($tokenPayload)) {
        $activeTabSession = $tokenPayload;
    }
}

if (!is_array($activeTabSession)) {
    header('Location: login.php');
    exit;
}

/*
 * Tab identity values used in page header and request ownership checks.
 */
$customerId = (int) ($activeTabSession['user_id'] ?? 0);
$customerEmail = (string) ($activeTabSession['user_email'] ?? '');

if ($customerId <= 0) {
    header('Location: login.php');
    exit;
}

/*
 * Keep legacy session keys aligned with the validated tab identity
 * unless another role is already active in this PHP session.
 */
$existingUserType = (string) ($_SESSION['user_type'] ?? '');
if ($existingUserType === '' || $existingUserType === 'customer') {
    $_SESSION['user_id'] = $customerId;
    $_SESSION['user_email'] = $customerEmail;
    $_SESSION['user_type'] = 'customer';
}

/*
 * Read and sanitize list controls from query string.
 * - q: provider name/email/phone search
 * - category: service category filter
 * - location: free-text provider location filter
 */
$searchQuery = trim((string) ($_GET['q'] ?? ''));
$selectedCategoryId = (int) ($_GET['category'] ?? 0);
if ($selectedCategoryId > 0 && !isset($serviceCategoryLookup[$selectedCategoryId])) {
    $selectedCategoryId = 0;
}
$locationFilter = trim((string) ($_GET['location'] ?? ''));

/*
 * CSRF token for admin direct chat messages sent from this dashboard.
 */
if (!isset($_SESSION['customer_admin_chat_csrf']) || !is_string($_SESSION['customer_admin_chat_csrf'])) {
    $_SESSION['customer_admin_chat_csrf'] = bin2hex(random_bytes(32));
}
$adminChatCsrf = $_SESSION['customer_admin_chat_csrf'];

/*
 * CSRF token for customer profile editing.
 */
if (!isset($_SESSION['customer_profile_csrf']) || !is_string($_SESSION['customer_profile_csrf'])) {
    $_SESSION['customer_profile_csrf'] = bin2hex(random_bytes(32));
}

/*
 * Ensure customer table has a photo column for profile picture support.
 */
try {
    $columnCheck = $pdo->query("SHOW COLUMNS FROM `customer` LIKE 'photo'");
    if ($columnCheck !== false && $columnCheck->rowCount() === 0) {
        $pdo->exec("ALTER TABLE `customer` ADD COLUMN `photo` VARCHAR(255) NOT NULL DEFAULT ''");
    }
} catch (PDOException) {}

/*
 * Ensure customer table has latitude/longitude columns for map-based location storage.
 * DECIMAL(10,8) covers -90…+90 for latitude, DECIMAL(11,8) covers -180…+180 for longitude.
 */
try {
    $latCheck = $pdo->query("SHOW COLUMNS FROM `customer` LIKE 'latitude'");
    if ($latCheck !== false && $latCheck->rowCount() === 0) {
        $pdo->exec("ALTER TABLE `customer` ADD COLUMN `latitude`  DECIMAL(10,8) NULL DEFAULT NULL");
        $pdo->exec("ALTER TABLE `customer` ADD COLUMN `longitude` DECIMAL(11,8) NULL DEFAULT NULL");
    }
} catch (PDOException) {}

define('CUSTOMER_PHOTO_UPLOAD_DIR', __DIR__ . '/uploads/customer_photos');
define('CUSTOMER_PHOTO_WEB_PATH', 'uploads/customer_photos');
define('CUSTOMER_PHOTO_MAX_BYTES', 2_097_152);

/*
 * Customer profile edit state.
 */
$profileEditFormSubmitted = false;
$profileEditSuccess = '';
$profileEditError = '';
$profileEditValues = ['name' => '', 'phone' => '', 'email' => ''];

/*
 * Helper: validate a customer profile photo upload.
 */
function validateCustomerPhoto(?array $filePayload): ?array
{
    if ($filePayload === null || !is_array($filePayload)) {
        return null;
    }
    $uploadError = (int) ($filePayload['error'] ?? UPLOAD_ERR_NO_FILE);
    if ($uploadError === UPLOAD_ERR_NO_FILE) {
        return null;
    }
    if ($uploadError !== UPLOAD_ERR_OK) {
        throw new RuntimeException(t('cust_photo_err_upload'));
    }
    $tmpPath = (string) ($filePayload['tmp_name'] ?? '');
    if ($tmpPath === '' || !is_uploaded_file($tmpPath)) {
        throw new RuntimeException(t('cust_photo_err_upload'));
    }
    $fileSize = (int) ($filePayload['size'] ?? 0);
    if ($fileSize <= 0 || $fileSize > CUSTOMER_PHOTO_MAX_BYTES) {
        throw new RuntimeException(t('cust_photo_err_size'));
    }
    $allowedMimes = ['image/jpeg' => 'jpg', 'image/png' => 'png', 'image/webp' => 'webp'];
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    if ($finfo === false) {
        throw new RuntimeException(t('cust_photo_err_upload'));
    }
    try {
        $mime = finfo_file($finfo, $tmpPath);
        if (!is_string($mime) || !array_key_exists($mime, $allowedMimes)) {
            throw new RuntimeException(t('cust_photo_err_type'));
        }
    } finally {
        finfo_close($finfo);
    }
    return ['tmp_name' => $tmpPath, 'extension' => $allowedMimes[$mime]];
}

/*
 * Helper: store a validated customer photo on disk.
 */
function storeCustomerPhoto(array $photoInfo, int $customerId): array
{
    if (!is_dir(CUSTOMER_PHOTO_UPLOAD_DIR)) {
        $created = mkdir(CUSTOMER_PHOTO_UPLOAD_DIR, 0755, true);
        if (!$created && !is_dir(CUSTOMER_PHOTO_UPLOAD_DIR)) {
            throw new RuntimeException(t('cust_photo_err_storage'));
        }
    }
    $ext  = (string) ($photoInfo['extension'] ?? 'jpg');
    $name = 'customer_' . $customerId . '_' . date('Ymd_His') . '_' . bin2hex(random_bytes(6)) . '.' . $ext;
    $dest = CUSTOMER_PHOTO_UPLOAD_DIR . DIRECTORY_SEPARATOR . $name;
    if (!move_uploaded_file((string) $photoInfo['tmp_name'], $dest)) {
        throw new RuntimeException(t('cust_photo_err_storage'));
    }
    return ['web_path' => CUSTOMER_PHOTO_WEB_PATH . '/' . $name, 'absolute_path' => $dest];
}

/*
 * Helper: safely delete an old customer photo.
 */
function deleteCustomerPhoto(string $photoPath): void
{
    $photoPath = trim($photoPath);
    if ($photoPath === '') return;
    $base = realpath(CUSTOMER_PHOTO_UPLOAD_DIR);
    if ($base === false) return;
    $normalized = str_replace('\\', '/', $photoPath);
    if (strpos($normalized, '..') !== false) return;
    $abs = realpath(__DIR__ . '/' . $normalized) ?: (__DIR__ . '/' . $normalized);
    if (strpos($abs, $base) !== 0) return;
    if (is_file($abs)) @unlink($abs);
}

/*
 * AJAX: Save customer latitude/longitude from the map picker.
 * Called via fetch() when the customer drops a pin on the map.
 */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && trim((string) ($_GET['ajax'] ?? '')) === 'save_location') {
    header('Content-Type: application/json; charset=UTF-8');
    $rawLat = $_POST['latitude']  ?? '';
    $rawLng = $_POST['longitude'] ?? '';
    $action = trim((string) ($_POST['action'] ?? 'set'));

    if ($action === 'clear') {
        /* Customer chose to remove their pinned location. */
        try {
            $pdo->prepare('UPDATE customer SET latitude = NULL, longitude = NULL WHERE customer_id = :id')
                ->execute(['id' => $customerId]);
            echo json_encode(['ok' => true, 'message' => t('cust_map_saved')]);
        } catch (PDOException) {
            http_response_code(500);
            echo json_encode(['ok' => false, 'message' => t('err_generic')]);
        }
        exit;
    }

    $lat = filter_var($rawLat, FILTER_VALIDATE_FLOAT);
    $lng = filter_var($rawLng, FILTER_VALIDATE_FLOAT);

    if ($lat === false || $lng === false || $lat < -90 || $lat > 90 || $lng < -180 || $lng > 180) {
        http_response_code(422);
        echo json_encode(['ok' => false, 'message' => 'Invalid coordinates.']);
        exit;
    }

    try {
        $pdo->prepare('UPDATE customer SET latitude = :lat, longitude = :lng WHERE customer_id = :id')
            ->execute(['lat' => $lat, 'lng' => $lng, 'id' => $customerId]);
        echo json_encode(['ok' => true, 'message' => t('cust_map_saved')]);
    } catch (PDOException) {
        http_response_code(500);
        echo json_encode(['ok' => false, 'message' => t('err_generic')]);
    }
    exit;
}

/*
 * Handle customer profile update POST (name, phone, and optional photo).
 */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && trim((string) ($_POST['form_action'] ?? '')) === 'update_customer_profile') {
    $profileEditFormSubmitted = true;
    $postedCsrf  = (string) ($_POST['csrf_token'] ?? '');
    $newName     = trim((string) ($_POST['profile_name']  ?? ''));
    $newPhone    = trim((string) ($_POST['profile_phone'] ?? ''));
    $profileEditValues = ['name' => $newName, 'phone' => $newPhone];

    if (!hash_equals($_SESSION['customer_profile_csrf'], $postedCsrf)) {
        $profileEditError = t('prov_err_csrf');
    } elseif ($newName === '') {
        $profileEditError = t('prov_err_enter_name');
    } elseif (mb_strlen($newName) > 100) {
        $profileEditError = t('prov_err_name_too_long');
    } else {
        $newPhotoAbsPath = '';
        try {
            // Load current photo path
            $curPhotoStmt = $pdo->prepare('SELECT IFNULL(photo,\'\') AS photo FROM customer WHERE customer_id = :id LIMIT 1');
            $curPhotoStmt->execute(['id' => $customerId]);
            $currentPhoto = (string) ($curPhotoStmt->fetchColumn() ?? '');

            $photoUpload = validateCustomerPhoto($_FILES['profile_photo'] ?? null);
            $newPhotoPath = $currentPhoto;

            if ($photoUpload !== null) {
                $stored = storeCustomerPhoto($photoUpload, $customerId);
                $newPhotoPath    = (string) ($stored['web_path'] ?? '');
                $newPhotoAbsPath = (string) ($stored['absolute_path'] ?? '');
            }

            $pdo->prepare('UPDATE customer SET name = :name, phone = :phone, photo = :photo WHERE customer_id = :id')
                ->execute(['name' => $newName, 'phone' => $newPhone, 'photo' => $newPhotoPath, 'id' => $customerId]);

            if ($photoUpload !== null && $currentPhoto !== '' && $currentPhoto !== $newPhotoPath) {
                deleteCustomerPhoto($currentPhoto);
            }

            $_SESSION['customer_profile_flash_success'] = t('cust_profile_saved');
            header('Location: customer_dashboard.php?tab=' . urlencode($tabAccessToken) . '#profile-edit');
            exit;
        } catch (RuntimeException $exception) {
            if ($newPhotoAbsPath !== '' && is_file($newPhotoAbsPath)) @unlink($newPhotoAbsPath);
            $profileEditError = $exception->getMessage();
        } catch (PDOException) {
            if ($newPhotoAbsPath !== '' && is_file($newPhotoAbsPath)) @unlink($newPhotoAbsPath);
            $profileEditError = t('prov_err_profile_fail');
        }
    }
}

if (isset($_SESSION['customer_profile_flash_success'])) {
    $profileEditSuccess = $_SESSION['customer_profile_flash_success'];
    unset($_SESSION['customer_profile_flash_success']);
}

ensureAdminChatTable($pdo);

/*
 * Notification system bootstrap — runs once per session for the current customer.
 * Ensures chat table, tracking table, and session seed are ready before any AJAX handler.
 */
ensureChatTable($pdo);

try {
    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS `customer_notification_seen` (
             `customer_id`  INT NOT NULL PRIMARY KEY,
             `last_msg_id`  INT NOT NULL DEFAULT 0,
             `last_status_id` INT NOT NULL DEFAULT 0,
             `updated_at`   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
         )'
    );
} catch (PDOException) {}

if (!isset($_SESSION['customer_notif_seen'])) {
    try {
        $seenLoadStmt = $pdo->prepare(
            'SELECT last_msg_id, last_status_id
             FROM customer_notification_seen
             WHERE customer_id = :cid LIMIT 1'
        );
        $seenLoadStmt->execute([':cid' => $customerId]);
        $seenRow = $seenLoadStmt->fetch();
        $_SESSION['customer_notif_seen'] = is_array($seenRow)
            ? ['msg_id' => (int) $seenRow['last_msg_id'], 'status_id' => (int) $seenRow['last_status_id']]
            : ['msg_id' => 0, 'status_id' => 0];
    } catch (PDOException) {
        $_SESSION['customer_notif_seen'] = ['msg_id' => 0, 'status_id' => 0];
    }
}

$notificationLimit = 5;
$recentProviderMessages = [];
$recentStatusUpdates    = [];

/*
 * AJAX: Dismiss a single notification for this browser session.
 */
if (strtolower(trim((string) ($_GET['ajax'] ?? ''))) === 'dismiss_notification') {
    $dismissType = trim((string) ($_POST['type'] ?? ''));
    $dismissId   = (int) ($_POST['id'] ?? 0);

    if ($dismissId > 0 && in_array($dismissType, ['message', 'status'], true)) {
        $dismissStore = (array) ($_SESSION['customer_dismissed_notifs'] ?? []);
        if (!isset($dismissStore[$dismissType])) {
            $dismissStore[$dismissType] = [];
        }
        $dismissStore[$dismissType][$dismissId] = true;
        if (count($dismissStore[$dismissType]) > 200) {
            $dismissStore[$dismissType] = array_slice($dismissStore[$dismissType], -100, null, true);
        }
        $_SESSION['customer_dismissed_notifs'] = $dismissStore;
    }

    header('Content-Type: application/json; charset=UTF-8');
    echo json_encode(['ok' => true]);
    exit;
}

/*
 * AJAX: Mark notifications as read — clears unread badge and persists seen IDs to DB.
 */
if (strtolower(trim((string) ($_GET['ajax'] ?? ''))) === 'mark_notifications_read') {
    $seen = (array) ($_SESSION['customer_notif_seen'] ?? []);
    $seen['msg_id']    = max((int) ($seen['msg_id'] ?? 0),    (int) ($_POST['last_msg_id'] ?? 0));
    $seen['status_id'] = max((int) ($seen['status_id'] ?? 0), (int) ($_POST['last_status_id'] ?? 0));
    $_SESSION['customer_notif_seen'] = $seen;

    try {
        $persistStmt = $pdo->prepare(
            'INSERT INTO customer_notification_seen
                 (customer_id, last_msg_id, last_status_id)
             VALUES (:cid, :msg, :stat)
             ON DUPLICATE KEY UPDATE
                 last_msg_id    = GREATEST(last_msg_id,    VALUES(last_msg_id)),
                 last_status_id = GREATEST(last_status_id, VALUES(last_status_id))'
        );
        $persistStmt->execute([
            ':cid'  => $customerId,
            ':msg'  => $seen['msg_id'],
            ':stat' => $seen['status_id'],
        ]);
    } catch (PDOException) {}

    header('Content-Type: application/json; charset=UTF-8');
    echo json_encode(['ok' => true]);
    exit;
}

/*
 * AJAX: Poll for recent notifications — returns messages and request status updates.
 */
if (strtolower(trim((string) ($_GET['ajax'] ?? ''))) === 'notifications') {
    $notifSeen        = (array) ($_SESSION['customer_notif_seen'] ?? []);
    $lastSeenMsgId    = (int) ($notifSeen['msg_id'] ?? 0);
    $lastSeenStatusId = (int) ($notifSeen['status_id'] ?? 0);

    $dismissedStore   = (array) ($_SESSION['customer_dismissed_notifs'] ?? []);
    $dismissedMsgIds  = array_keys((array) ($dismissedStore['message'] ?? []));
    $dismissedStatIds = array_keys((array) ($dismissedStore['status']  ?? []));

    $pollMessages     = [];
    $pollStatusUpdates = [];

    try {
        $dismissedMsgSql = count($dismissedMsgIds) > 0
            ? ' AND rcm.message_id NOT IN (' . implode(',', array_map('intval', $dismissedMsgIds)) . ')'
            : '';
        $pollMsgStmt = $pdo->prepare(
            'SELECT rcm.message_id, rcm.request_id, rcm.message, rcm.created_at,
                    sp.name AS provider_name
             FROM request_chat_message rcm
             INNER JOIN servicerequest sr ON rcm.request_id = sr.request_id
             INNER JOIN appointmentslot asl ON sr.slot_id = asl.slot_id
             INNER JOIN serviceprovider sp ON asl.serviceprovider_id = sp.provider_id
             WHERE sr.customer_id = :cid
               AND rcm.sender_role = \'service_provider\'' . $dismissedMsgSql . '
             ORDER BY rcm.created_at DESC
             LIMIT ' . (int) $notificationLimit
        );
        $pollMsgStmt->bindValue(':cid', $customerId, PDO::PARAM_INT);
        $pollMsgStmt->execute();
        while ($r = $pollMsgStmt->fetch()) {
            $pollMessages[] = [
                'message_id'    => (int) $r['message_id'],
                'request_id'    => (int) $r['request_id'],
                'message'       => (string) ($r['message'] ?? ''),
                'created_at'    => (string) ($r['created_at'] ?? ''),
                'provider_name' => (string) ($r['provider_name'] ?? 'Service Provider'),
                'is_unread'     => (int) $r['message_id'] > $lastSeenMsgId,
            ];
        }

        $dismissedStatSql = count($dismissedStatIds) > 0
            ? ' AND sr.request_id NOT IN (' . implode(',', array_map('intval', $dismissedStatIds)) . ')'
            : '';
        $pollStatStmt = $pdo->prepare(
            'SELECT sr.request_id, sr.status,
                    sp.name AS provider_name,
                    sc.name AS category_name,
                    asl.date AS appointment_date,
                    asl.slot AS appointment_time
             FROM servicerequest sr
             INNER JOIN appointmentslot asl ON sr.slot_id = asl.slot_id
             INNER JOIN serviceprovider sp ON asl.serviceprovider_id = sp.provider_id
             LEFT JOIN servicecategory sc ON sr.category_id = sc.category_id
             WHERE sr.customer_id = :cid
               AND sr.status IN (\'Confirmed\', \'Completed\', \'Cancelled\')' . $dismissedStatSql . '
             ORDER BY sr.request_id DESC
             LIMIT ' . (int) $notificationLimit
        );
        $pollStatStmt->bindValue(':cid', $customerId, PDO::PARAM_INT);
        $pollStatStmt->execute();
        while ($r = $pollStatStmt->fetch()) {
            $pollStatusUpdates[] = [
                'request_id'       => (int) $r['request_id'],
                'status'           => (string) ($r['status'] ?? 'Pending'),
                'provider_name'    => (string) ($r['provider_name'] ?? 'Service Provider'),
                'category_name'    => (string) ($r['category_name'] ?? 'Service'),
                'appointment_date' => (string) ($r['appointment_date'] ?? ''),
                'appointment_time' => (string) ($r['appointment_time'] ?? ''),
                'is_unread'        => (int) $r['request_id'] > $lastSeenStatusId,
            ];
        }
    } catch (PDOException) {}

    $unreadCount = count(array_filter($pollMessages,      static fn($m) => $m['is_unread']))
                 + count(array_filter($pollStatusUpdates, static fn($r) => $r['is_unread']));

    header('Content-Type: application/json; charset=UTF-8');
    echo json_encode([
        'ok'                    => true,
        'unread_count'          => $unreadCount,
        'notification_count'    => count($pollMessages) + count($pollStatusUpdates),
        'recent_messages'       => $pollMessages,
        'recent_status_updates' => $pollStatusUpdates,
    ]);
    exit;
}

/*
 * Serve live-search suggestions for provider name/email while typing.
 */
if (strtolower(trim((string) ($_GET['suggest'] ?? ''))) === 'providers') {
    $suggestQuery = trim((string) ($_GET['query'] ?? ''));
    $suggestions = [];
    $seen = [];

    if ($suggestQuery !== '') {
        try {
            $suggestLocCol = $providerLocationColumn;
            $suggestLocationClause = $suggestLocCol !== ''
                ? "AND (:location_filter = '' OR sp.`{$suggestLocCol}` LIKE :location_like)"
                : "AND (:location_filter = '' OR 1=1)";
            $suggestStatement = $pdo->prepare(
                "SELECT
                    sp.provider_id,
                    sp.name,
                    sp.email,
                    sp.phone
                 FROM serviceprovider sp
                 LEFT JOIN providedservices ps
                    ON sp.provider_id = ps.provider_id
                 WHERE (:query = '' OR sp.name LIKE :query_like_name OR sp.email LIKE :query_like_email OR sp.phone LIKE :query_like_phone)
                   AND (:category_id = 0 OR ps.category_id = :category_id)
                   {$suggestLocationClause}
                 GROUP BY sp.provider_id, sp.name, sp.email, sp.phone
                 ORDER BY sp.name ASC
                 LIMIT 20"
            );
            $suggestStatement->execute([
                'query' => $suggestQuery,
                'query_like_name' => '%' . $suggestQuery . '%',
                'query_like_email' => '%' . $suggestQuery . '%',
                'query_like_phone' => '%' . $suggestQuery . '%',
                'category_id' => $selectedCategoryId,
                'location_filter' => $locationFilter,
                'location_like' => '%' . $locationFilter . '%',
            ]);

            while ($row = $suggestStatement->fetch()) {
                $providerId = (int) $row['provider_id'];
                if (!isset($verifiedProviderLookup[$providerId]) || isset($suspendedProviderLookup[$providerId])) {
                    continue;
                }

                foreach ([$row['name'], $row['email'], $row['phone']] as $candidate) {
                    $candidate = trim((string) ($candidate ?? ''));
                    if ($candidate === '') {
                        continue;
                    }

                    if (stripos($candidate, $suggestQuery) === false) {
                        continue;
                    }

                    if (isset($seen[$candidate])) {
                        continue;
                    }

                    $seen[$candidate] = true;
                    $suggestions[] = $candidate;

                    if (count($suggestions) >= 12) {
                        break 2;
                    }
                }
            }
        } catch (PDOException $exception) {
            $suggestions = [];
        }
    }

    header('Content-Type: application/json; charset=UTF-8');
    echo json_encode([
        'ok' => true,
        'suggestions' => $suggestions,
    ]);
    exit;
}

/*
 * Data containers and status messages used by the rendering layer.
 */
$dashboardError = '';
$serviceProviders = [];

/*
 * Page-load notification queries — populate initial state for HTML rendering.
 */
$notificationCount    = 0;
$pageLoadSeen         = (array) ($_SESSION['customer_notif_seen'] ?? []);
$pageLoadSeenMsgId    = (int) ($pageLoadSeen['msg_id'] ?? 0);
$pageLoadSeenStatusId = (int) ($pageLoadSeen['status_id'] ?? 0);

try {
    $initMsgStmt = $pdo->prepare(
        'SELECT rcm.message_id, rcm.request_id, rcm.message, rcm.created_at,
                sp.name AS provider_name
         FROM request_chat_message rcm
         INNER JOIN servicerequest sr ON rcm.request_id = sr.request_id
         INNER JOIN appointmentslot asl ON sr.slot_id = asl.slot_id
         INNER JOIN serviceprovider sp ON asl.serviceprovider_id = sp.provider_id
         WHERE sr.customer_id = :cid
           AND rcm.sender_role = \'service_provider\'
         ORDER BY rcm.created_at DESC
         LIMIT ' . (int) $notificationLimit
    );
    $initMsgStmt->bindValue(':cid', $customerId, PDO::PARAM_INT);
    $initMsgStmt->execute();
    while ($r = $initMsgStmt->fetch()) {
        $isUnread = (int) $r['message_id'] > $pageLoadSeenMsgId;
        if ($isUnread) $notificationCount++;
        $recentProviderMessages[] = [
            'message_id'    => (int) $r['message_id'],
            'request_id'    => (int) $r['request_id'],
            'message'       => (string) ($r['message'] ?? ''),
            'created_at'    => (string) ($r['created_at'] ?? ''),
            'provider_name' => (string) ($r['provider_name'] ?? 'Service Provider'),
            'is_unread'     => $isUnread,
        ];
    }

    $initStatStmt = $pdo->prepare(
        'SELECT sr.request_id, sr.status,
                sp.name AS provider_name,
                sc.name AS category_name,
                asl.date AS appointment_date,
                asl.slot AS appointment_time
         FROM servicerequest sr
         INNER JOIN appointmentslot asl ON sr.slot_id = asl.slot_id
         INNER JOIN serviceprovider sp ON asl.serviceprovider_id = sp.provider_id
         LEFT JOIN servicecategory sc ON sr.category_id = sc.category_id
         WHERE sr.customer_id = :cid
           AND sr.status IN (\'Confirmed\', \'Completed\', \'Cancelled\')
         ORDER BY sr.request_id DESC
         LIMIT ' . (int) $notificationLimit
    );
    $initStatStmt->bindValue(':cid', $customerId, PDO::PARAM_INT);
    $initStatStmt->execute();
    while ($r = $initStatStmt->fetch()) {
        $isUnread = (int) $r['request_id'] > $pageLoadSeenStatusId;
        if ($isUnread) $notificationCount++;
        $recentStatusUpdates[] = [
            'request_id'       => (int) $r['request_id'],
            'status'           => (string) ($r['status'] ?? 'Pending'),
            'provider_name'    => (string) ($r['provider_name'] ?? 'Service Provider'),
            'category_name'    => (string) ($r['category_name'] ?? 'Service'),
            'appointment_date' => (string) ($r['appointment_date'] ?? ''),
            'appointment_time' => (string) ($r['appointment_time'] ?? ''),
            'is_unread'        => $isUnread,
        ];
    }
} catch (PDOException) {
    $recentProviderMessages = [];
    $recentStatusUpdates    = [];
}

try {
    /*
     * Provider listing query:
     * - Aggregates categories and visit pricing per service provider
     * - Optional location column is included when present in the schema
     * - Verification status is derived from the JSON store after the query
     */

    /* Build location-filter SQL fragment before embedding it into the query string. */
    $providerLocationFilterClause = $providerLocationColumn !== ''
        ? "(:locationFilter = '' OR sp.`{$providerLocationColumn}` LIKE :locationLike)"
        : "(:locationFilter = '' OR 1=1)";

    $serviceProviderQuery = "
        SELECT
            sp.provider_id,
            sp.name,
            sp.phone,
            sp.email,
            sp.photo,
            {$providerLocationSelect},
            MIN(ps.visit_price) AS min_price,
            MAX(ps.visit_price) AS max_price,
            GROUP_CONCAT(DISTINCT sc.name ORDER BY sc.name SEPARATOR ', ') AS service_names
        FROM serviceprovider sp
        LEFT JOIN providedservices ps
            ON sp.provider_id = ps.provider_id
        LEFT JOIN servicecategory sc
            ON ps.category_id = sc.category_id
        WHERE (:searchTerm = '' OR sp.name LIKE :searchLikeName OR sp.email LIKE :searchLikeEmail OR sp.phone LIKE :searchLikePhone)
            AND (:categoryIdCheck = 0 OR ps.category_id = :categoryId)
            AND {$providerLocationFilterClause}
        GROUP BY sp.provider_id, sp.name, sp.phone, sp.email, sp.photo{$providerLocationGroupBy}
        ORDER BY sp.name ASC
    ";

    $serviceProviderStatement = $pdo->prepare($serviceProviderQuery);
    $serviceProviderStatement->execute([
        'searchTerm' => $searchQuery,
        'searchLikeName' => '%' . $searchQuery . '%',
        'searchLikeEmail' => '%' . $searchQuery . '%',
        'searchLikePhone' => '%' . $searchQuery . '%',
        'categoryIdCheck' => $selectedCategoryId,
        'categoryId' => $selectedCategoryId,
        'locationFilter' => $locationFilter,
        'locationLike' => '%' . $locationFilter . '%',
    ]);

    /*
     * Normalize database values into rendering-friendly rows.
     */
    while ($row = $serviceProviderStatement->fetch()) {
        $providerId = (int) $row['provider_id'];
        $isVerified = isset($verifiedProviderLookup[$providerId]);

        if (!$isVerified || isset($suspendedProviderLookup[$providerId])) {
            continue;
        }

        $serviceNames = (string) ($row['service_names'] ?? '');
        $locationText = trim((string) ($row['location'] ?? ''));

        $serviceProviders[] = [
            'provider_id' => $providerId,
            'name' => (string) $row['name'],
            'phone' => (string) ($row['phone'] ?? ''),
            'email' => (string) ($row['email'] ?? ''),
            'photo' => (string) ($row['photo'] ?? ''),
            'location' => $locationText,
            'min_price' => isset($row['min_price']) ? (float) $row['min_price'] : null,
            'max_price' => isset($row['max_price']) ? (float) $row['max_price'] : null,
            'service_names' => $serviceNames,
            'is_verified' => $isVerified,
        ];
    }

    /*
     * Present verified providers first, then sort by name.
     */
    usort(
        $serviceProviders,
        static function (array $left, array $right): int {
            if ($left['is_verified'] === $right['is_verified']) {
                return strcasecmp($left['name'], $right['name']);
            }

            return $left['is_verified'] ? -1 : 1;
        }
    );
} catch (PDOException $exception) {
    /*
     * Generic message avoids exposing SQL internals while still informing the user.
     */
    $dashboardError = 'Unable to load service providers right now. Please try again later.';
}

/*
 * Fetch customer profile information for display and edit form defaults.
 */
$customerProfile = null;
try {
    $customerProfileQuery = $pdo->prepare(
        'SELECT customer_id, name, email, phone, address,
                IFNULL(photo,\'\') AS photo,
                latitude, longitude
         FROM customer WHERE customer_id = :customer_id LIMIT 1'
    );
    $customerProfileQuery->execute(['customer_id' => $customerId]);
    $customerProfile = $customerProfileQuery->fetch(PDO::FETCH_ASSOC);
} catch (PDOException $exception) {
    $customerProfile = null;
}

if (!$profileEditFormSubmitted && $customerProfile !== null) {
    $profileEditValues = [
        'name'  => (string) ($customerProfile['name']  ?? ''),
        'phone' => (string) ($customerProfile['phone'] ?? ''),
        'email' => (string) ($customerProfile['email'] ?? ''),
    ];
}

/* Saved coordinates for the map widget — null when customer has not pinned a location. */
$existingLat = is_array($customerProfile) ? ($customerProfile['latitude']  ?? null) : null;
$existingLng = is_array($customerProfile) ? ($customerProfile['longitude'] ?? null) : null;
$hasLocation = $existingLat !== null && $existingLng !== null;

/* Collect distinct provider locations for the location filter dropdown. */
$availableLocations = [];
if ($providerLocationColumn !== '') {
    try {
        $locStmt = $pdo->query(
            'SELECT DISTINCT `' . $providerLocationColumn . '` AS loc
             FROM serviceprovider
             WHERE `' . $providerLocationColumn . '` IS NOT NULL
               AND TRIM(`' . $providerLocationColumn . '`) != \'\'
             ORDER BY `' . $providerLocationColumn . '` ASC'
        );
        while ($locRow = $locStmt->fetch()) {
            $loc = trim((string) ($locRow['loc'] ?? ''));
            if ($loc !== '') {
                $availableLocations[] = $loc;
            }
        }
    } catch (PDOException) {}
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
    <title><?php echo htmlspecialchars(t('cust_dash_title'), ENT_QUOTES, 'UTF-8'); ?> - <?php echo htmlspecialchars(t('site_name'), ENT_QUOTES, 'UTF-8'); ?></title>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <?php if (isRtl()): ?>
    <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <?php endif; ?>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <!-- Leaflet CSS — served locally so the map works without internet access -->
    <link rel="stylesheet" href="vendor/leaflet/leaflet.css">
    <style>
        /*
         * Global reset and base tokens for consistent spacing and colors.
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
            --accent: #ea580c;
            --surface: #f8fafc;
            --card: #ffffff;
            --ok-bg: #ecfdf5;
            --ok-border: #86efac;
            --ok-text: #166534;
            --warn-bg: #fff7ed;
            --warn-border: #fdba74;
            --warn-text: #9a3412;
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
                radial-gradient(circle at 8% 10%, rgba(20, 184, 166, 0.18), transparent 34%),
                radial-gradient(circle at 92% 8%, rgba(249, 115, 22, 0.2), transparent 30%),
                linear-gradient(130deg, #ecfeff, #f8fafc 45%, #fff7ed);
            display: flex;
            flex-direction: row;
        }

        /*
         * Main content frame that caps width for readability on large screens.
         * Adjusted for sidebar layout - sidebar takes 15%, main content takes 85%.
         */
        .dashboard-shell {
            flex: 1;
            width: 85%;
            max-width: none;
            margin: 0;
            display: flex;
            flex-direction: column;
            gap: 18px;
            padding: 24px 20px 38px;
            overflow-y: auto;
        }

        /*
         * Top header with account context and navigation actions.
         */
        .topbar {
            background: rgba(255, 255, 255, 0.85);
            border: 1px solid rgba(255, 255, 255, 0.8);
            border-radius: 24px;
            backdrop-filter: blur(14px);
            box-shadow: 0 14px 40px rgba(15, 23, 42, 0.1);
            padding: 20px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 14px;
            flex-wrap: wrap;
        }

        .brand h1 {
            font-size: 1.45rem;
            font-weight: 800;
            color: #042f2e;
            margin-bottom: 4px;
        }

        .brand p {
            font-size: 0.9rem;
            color: var(--muted);
        }

        .pill {
            display: inline-flex;
            align-items: center;
            gap: 7px;
            min-height: 40px;
            padding: 8px 14px;
            border-radius: 999px;
            font-size: 0.86rem;
            font-weight: 700;
            text-decoration: none;
            border: 1px solid var(--line);
            color: #0f172a;
            background: #fff;
        }

        .pill.logout {
            background: linear-gradient(145deg, var(--brand), var(--brand-deep));
            border-color: transparent;
            color: #fff;
        }

        .pill.logout:hover {
            filter: brightness(1.03);
            transform: translateY(-1px);
        }

        /*
         * Filter/search panel driving dashboard list queries.
         */
        .filters {
            background: rgba(255, 255, 255, 0.9);
            border: 1px solid rgba(255, 255, 255, 0.8);
            border-radius: 24px;
            padding: 18px;
            box-shadow: 0 14px 40px rgba(15, 23, 42, 0.08);
        }

        .filters form {
            display: grid;
            grid-template-columns: 1.2fr minmax(160px, 0.65fr) minmax(160px, 0.65fr) auto;
            gap: 10px;
            align-items: center;
        }

        .field {
            position: relative;
        }

        .field i {
            position: absolute;
            left: 12px;
            top: 50%;
            transform: translateY(-50%);
            color: #64748b;
            font-size: 0.95rem;
            pointer-events: none;
        }

        .field input,
        .field select {
            width: 100%;
            min-height: 46px;
            border: 2px solid #d9e2ec;
            border-radius: 14px;
            padding: 10px 12px 10px 36px;
            font-family: inherit;
            font-size: 0.93rem;
            color: var(--ink);
            background: #ffffff;
        }

        .field input:focus,
        .field select:focus {
            outline: none;
            border-color: var(--brand);
            box-shadow: 0 0 0 4px rgba(15, 118, 110, 0.12);
        }

        .btn {
            min-height: 46px;
            border: none;
            border-radius: 14px;
            padding: 10px 14px;
            font-family: inherit;
            font-size: 0.93rem;
            font-weight: 800;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            text-decoration: none;
        }

        .btn.primary {
            color: #fff;
            background: linear-gradient(145deg, var(--brand), var(--brand-deep));
        }

        .btn.primary:hover {
            box-shadow: 0 10px 24px rgba(15, 118, 110, 0.32);
        }

        .btn.secondary {
            color: #0f172a;
            background: #ffffff;
            border: 2px solid #d9e2ec;
        }

        .btn:hover {
            transform: translateY(-1px);
        }

        /*
         * Error and empty-state messaging containers.
         */
        .feedback {
            border-radius: 16px;
            padding: 14px 16px;
            font-size: 0.92rem;
            font-weight: 700;
            border: 1px solid;
        }

        .feedback.error {
            background: #fff1f2;
            border-color: #fecdd3;
            color: #be123c;
        }

        .feedback.empty {
            background: #f8fafc;
            border-color: #dbe2ea;
            color: #334155;
        }

        /*
         * Service Provider card grid and card presentation styling.
         */
        .provider-grid {
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: 14px;
        }

        .provider-card {
            background: rgba(255, 255, 255, 0.92);
            border: 1px solid rgba(255, 255, 255, 0.85);
            border-radius: 22px;
            box-shadow: 0 12px 28px rgba(15, 23, 42, 0.08);
            padding: 16px;
            display: flex;
            flex-direction: column;
            gap: 13px;
            min-height: 260px;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }

        .provider-card:hover {
            transform: translateY(-4px);
            box-shadow: 0 20px 42px rgba(15, 23, 42, 0.13);
        }

        .provider-header {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .provider-photo {
            width: 62px;
            height: 62px;
            border-radius: 18px;
            overflow: hidden;
            background: linear-gradient(135deg, rgba(15, 118, 110, 0.14), rgba(15, 118, 110, 0.06));
            flex-shrink: 0;
            border: 1px solid rgba(15, 118, 110, 0.15);
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--brand);
            font-size: 1.3rem;
        }

        .provider-photo img {
            width: 100%;
            height: 100%;
            object-fit: cover;
            display: block;
        }

        .provider-name {
            font-size: 1rem;
            font-weight: 800;
            color: #0f172a;
            margin-bottom: 4px;
        }

        .provider-contact {
            font-size: 0.82rem;
            color: #64748b;
            line-height: 1.35;
        }

        /*
         * Provider detail rows for category, price, and location.
         */
        .provider-details {
            display: grid;
            gap: 10px;
            padding: 12px;
            border-radius: 16px;
            border: 1px solid rgba(226, 232, 240, 0.8);
            background: rgba(248, 250, 252, 0.8);
        }

        .detail-row {
            display: grid;
            gap: 4px;
        }

        .detail-label {
            font-size: 0.72rem;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.6px;
            color: #64748b;
        }

        .detail-value {
            font-size: 0.9rem;
            font-weight: 600;
            color: #0f172a;
            line-height: 1.4;
            word-break: break-word;
        }

        .badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 5px 10px;
            border-radius: 999px;
            font-size: 0.77rem;
            font-weight: 800;
            border: 1px solid;
            width: fit-content;
        }

        .badge.verified {
            background: var(--ok-bg);
            border-color: var(--ok-border);
            color: var(--ok-text);
        }

        .badge.unverified {
            background: var(--warn-bg);
            border-color: var(--warn-border);
            color: var(--warn-text);
        }

        .provider-bio {
            font-size: 0.88rem;
            color: #334155;
            line-height: 1.45;
            min-height: 60px;
        }

        .meta-list {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
        }

        .meta-chip {
            border-radius: 999px;
            padding: 6px 10px;
            font-size: 0.77rem;
            font-weight: 700;
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            color: #334155;
        }

        .service-text {
            font-size: 0.82rem;
            line-height: 1.4;
            color: #475569;
        }

        .rating-strip {
            display: flex;
            align-items: center;
            gap: 7px;
            font-size: 0.8rem;
            color: #334155;
            flex-wrap: wrap;
        }

        .rating-stars {
            display: inline-flex;
            align-items: center;
            gap: 2px;
            color: #f59e0b;
        }

        .rating-stars .star.is-empty {
            color: #cbd5e1;
        }

        .provider-actions {
            margin-top: auto;
            display: grid;
            grid-template-columns: 1fr;
            gap: 8px;
        }

        .provider-actions .btn {
            width: 100%;
            min-height: 42px;
            font-size: 0.86rem;
            border-radius: 12px;
        }

        /*
         * Profile modal styling.
         * Modal displays customer information in a centered overlay.
         */
        .profile-modal {
            position: fixed;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 500;
            opacity: 0;
            visibility: hidden;
            transition: opacity 0.3s ease, visibility 0.3s ease;
            padding: 20px;
        }

        .profile-modal.active {
            background: rgba(0, 0, 0, 0.4);
            opacity: 1;
            visibility: visible;
        }

        .profile-modal-content {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(16px);
            border: 1px solid rgba(255, 255, 255, 0.8);
            border-radius: 24px;
            padding: 32px;
            box-shadow: 0 26px 60px rgba(15, 23, 42, 0.16);
            max-width: 480px;
            width: 100%;
            animation: modalSlideIn 0.35s ease;
        }

        @keyframes modalSlideIn {
            from {
                opacity: 0;
                transform: scale(0.92) translateY(20px);
            }
            to {
                opacity: 1;
                transform: scale(1) translateY(0);
            }
        }

        .profile-modal.active .profile-modal-content {
            animation: modalSlideIn 0.35s ease;
        }

        .profile-modal-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 24px;
            border-bottom: 2px solid #dbe2ea;
            padding-bottom: 16px;
        }

        .profile-modal-header h2 {
            font-size: 1.45rem;
            font-weight: 800;
            color: #042f2e;
            margin: 0;
        }

        .profile-modal-close {
            background: none;
            border: none;
            font-size: 1.35rem;
            color: #94a3b8;
            cursor: pointer;
            padding: 0;
            width: 40px;
            height: 40px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 10px;
            transition: all 0.25s ease;
        }

        .profile-modal-close:hover {
            background: #f8fafc;
            color: var(--brand);
        }

        .profile-info-group {
            margin-bottom: 18px;
            padding-bottom: 16px;
            border-bottom: 1px solid #e5e7eb;
        }

        .profile-info-group:last-child {
            border-bottom: none;
            margin-bottom: 0;
            padding-bottom: 0;
        }

        .profile-info-label {
            display: block;
            font-size: 0.85rem;
            font-weight: 700;
            color: #64748b;
            margin-bottom: 6px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .profile-info-value {
            font-size: 1.02rem;
            color: #0f172a;
            font-weight: 600;
            word-break: break-word;
        }

        .profile-info-value.email {
            color: var(--brand);
            word-break: break-all;
        }

        /* ── Customer location map widget ─────────────────────────── */
        .location-map-section {
            margin-top: 24px;
            border-top: 1px solid var(--line);
            padding-top: 20px;
        }

        .location-map-section h3 {
            font-size: 1rem;
            font-weight: 700;
            color: var(--ink);
            margin-bottom: 6px;
        }

        .location-map-section .map-lead {
            font-size: .85rem;
            color: var(--muted);
            margin-bottom: 14px;
        }

        #custLocationMap {
            width: 100%;
            height: 300px;
            border-radius: 14px;
            border: 2px solid var(--line);
            background: #e5e7eb;
            cursor: crosshair;
        }

        .map-coords-row {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-top: 10px;
            flex-wrap: wrap;
        }

        .map-coords-badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            background: var(--ok-bg);
            border: 1px solid var(--ok-border);
            color: var(--ok-text);
            border-radius: 20px;
            padding: 4px 12px;
            font-size: .82rem;
            font-weight: 600;
        }

        .map-coords-badge.no-location {
            background: #f1f5f9;
            border-color: var(--line);
            color: var(--muted);
        }

        .map-action-btns {
            display: flex;
            gap: 8px;
            margin-top: 12px;
            flex-wrap: wrap;
        }

        .map-save-btn, .map-clear-btn {
            min-height: 38px;
            border: none;
            border-radius: 10px;
            padding: 7px 16px;
            font-family: inherit;
            font-size: .85rem;
            font-weight: 700;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 7px;
            transition: opacity .15s;
        }

        .map-save-btn {
            background: linear-gradient(145deg, var(--brand), var(--brand-deep));
            color: #fff;
        }

        .map-save-btn:disabled { opacity: .55; cursor: default; }

        .map-clear-btn {
            background: #fee2e2;
            color: #b91c1c;
        }

        /* GPS / "Use My Location" button */
        .map-gps-btn {
            min-height: 38px;
            border: 1px solid #bfdbfe;
            border-radius: 10px;
            padding: 7px 16px;
            font-family: inherit;
            font-size: .85rem;
            font-weight: 700;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 7px;
            background: #eff6ff;
            color: #1d4ed8;
            transition: background .15s;
        }

        .map-gps-btn:hover:not(:disabled) { background: #dbeafe; }
        .map-gps-btn:disabled { opacity: .55; cursor: default; }

        /* Reverse-geocoded address display */
        .map-address-row {
            display: flex;
            align-items: flex-start;
            gap: 6px;
            margin-top: 8px;
            font-size: .83rem;
            color: var(--muted);
            min-height: 18px;
            line-height: 1.45;
        }

        .map-address-row i { flex-shrink: 0; margin-top: 2px; color: #94a3b8; }

        /* Hint text below map */
        .map-hint-text {
            display: flex;
            align-items: center;
            gap: 5px;
            font-size: .78rem;
            color: #94a3b8;
            margin-top: 6px;
        }

        .map-feedback {
            margin-top: 8px;
            font-size: .84rem;
            font-weight: 600;
            min-height: 20px;
        }

        .map-feedback.ok   { color: var(--ok-text); }
        .map-feedback.err  { color: #b91c1c; }

        /*
         * Responsive breakpoints for tablet and mobile sizes.
         */
        @media (max-width: 1020px) {
            .provider-grid {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }

            /* On tablet, wrap into two columns */
            .filters form {
                grid-template-columns: 1fr 1fr;
            }

            .filters .btn {
                width: 100%;
            }
        }

        @media (max-width: 720px) {
            body {
                padding: 14px 12px 28px;
            }

            .topbar,
            .filters {
                border-radius: 18px;
                padding: 14px;
            }

            .provider-grid {
                grid-template-columns: 1fr;
            }

            .filters form {
                grid-template-columns: 1fr;
            }

            .brand h1 {
                font-size: 1.2rem;
            }
        }

        @media (max-width: 480px) {
            body {
                padding: 10px 10px 22px;
                gap: 12px;
            }

            .topbar {
                padding: 12px;
                border-radius: 16px;
            }

            .brand h1 {
                font-size: 1.05rem;
            }

            .pill {
                padding: 7px 12px;
                font-size: 0.82rem;
                min-height: 36px;
            }

            .provider-card {
                padding: 14px;
                border-radius: 18px;
            }

            .provider-avatar {
                width: 56px;
                height: 56px;
            }

            .provider-name {
                font-size: 1rem;
            }

            .provider-actions .btn {
                min-height: 38px;
                font-size: 0.82rem;
            }

            .filters {
                padding: 12px;
            }

            .search-panel input[type="text"] {
                font-size: 0.9rem;
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
            overflow-x: hidden;
            overflow-y: hidden;
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

            .dashboard-shell {
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

        /*
         * Reduce animation/transitions for users preferring minimal motion.
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

        /* ── Notification badge on sidebar links ── */
        .sidebar-menu-item {
            position: relative;
        }

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

        /* ── Notifications panel (hidden by default, shown via CSS :target when #notifications hash is active) ── */
        .panel {
            display: none;
            background: rgba(255, 255, 255, 0.94);
            border: 1px solid rgba(255, 255, 255, 0.92);
            border-radius: 20px;
            box-shadow: 0 12px 28px rgba(15, 23, 42, 0.08);
            padding: 20px;
        }

        .panel:target {
            display: block;
        }

        /* Hide the provider search/grid when a panel is targeted */
        .panel:target ~ .filters,
        .panel:target ~ .feedback,
        .panel:target ~ .provider-grid,
        #profile-edit:target ~ .filters,
        #profile-edit:target ~ .feedback,
        #profile-edit:target ~ .provider-grid,
        #notifications:target ~ #profile-edit,
        #profile-edit:target ~ #notifications {
            display: none;
        }

        .panel h2 {
            font-size: 1.1rem;
            color: #042f2e;
            font-weight: 800;
            margin-bottom: 8px;
        }

        .panel p.lead {
            font-size: 0.88rem;
            color: var(--muted);
            margin-bottom: 16px;
        }

        .notification-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
            gap: 14px;
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
            position: relative;
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

        .notification-body .empty-state {
            font-size: 0.82rem;
            color: var(--muted);
            padding: 10px 4px;
        }

        /* Status badge inside notification items */
        .notif-status-badge {
            display: inline-flex;
            align-items: center;
            gap: 4px;
            padding: 2px 8px;
            border-radius: 999px;
            font-size: 0.7rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.03em;
        }

        .notif-status-badge.confirmed  { background: #d1fae5; color: #065f46; }
        .notif-status-badge.completed  { background: #dbeafe; color: #1e40af; }
        .notif-status-badge.cancelled  { background: #fee2e2; color: #991b1b; }

        /* ── RTL overrides ──────────────────────────────────────── */
        [dir="rtl"] body { font-family: 'Cairo', sans-serif; }
        [dir="rtl"] .sidebar { right: 0; left: auto; border-right: none; border-left: 1px solid var(--line); }
        [dir="rtl"] .dashboard-shell { margin-right: 0; margin-left: 0; }
        [dir="rtl"] .field i { left: auto; right: 12px; }
        [dir="rtl"] .field input, [dir="rtl"] .field select { padding-left: 12px; padding-right: 36px; text-align: right; }
        [dir="rtl"] .pill i { margin-left: 0; margin-right: 0; }
        [dir="rtl"] .sidebar-menu-item { text-align: right; }
        [dir="rtl"] .sidebar-menu-item i { margin-right: 0; margin-left: 10px; }
        [dir="rtl"] .provider-card-actions { flex-direction: row-reverse; }

        /* ── Admin chat floating widget ─────────────────────────── */
        .admin-chat-fab {
            position: fixed;
            bottom: 28px;
            <?php echo isRtl() ? 'left' : 'right'; ?>: 28px;
            z-index: 1000;
            display: flex;
            flex-direction: column;
            align-items: <?php echo isRtl() ? 'flex-start' : 'flex-end'; ?>;
            gap: 0;
        }

        .admin-chat-btn {
            width: 58px; height: 58px; border-radius: 50%; border: none; cursor: pointer;
            background: linear-gradient(135deg, var(--brand), var(--brand-deep));
            color: #fff; font-size: 1.3rem;
            box-shadow: 0 8px 24px rgba(15,118,110,.45);
            display: flex; align-items: center; justify-content: center;
            transition: transform .2s, box-shadow .2s;
            position: relative;
        }
        .admin-chat-btn:hover { transform: scale(1.08); box-shadow: 0 12px 32px rgba(15,118,110,.55); }

        .admin-chat-unread-dot {
            position: absolute; top: 2px; right: 2px;
            width: 18px; height: 18px; border-radius: 50%;
            background: #ef4444; color: #fff;
            font-size: .65rem; font-weight: 800;
            display: flex; align-items: center; justify-content: center;
            border: 2px solid #fff;
        }
        .admin-chat-unread-dot.hidden { display: none; }

        .admin-chat-window {
            position: fixed;
            bottom: 100px;
            <?php echo isRtl() ? 'left' : 'right'; ?>: 20px;
            width: 340px; height: 460px;
            background: #fff;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(15,23,42,.18);
            display: flex; flex-direction: column;
            z-index: 1001;
            overflow: hidden;
            transform: scale(.92) translateY(20px);
            opacity: 0;
            pointer-events: none;
            transition: transform .25s ease, opacity .25s ease;
        }
        .admin-chat-window.open {
            transform: scale(1) translateY(0);
            opacity: 1;
            pointer-events: auto;
        }

        .acw-header {
            background: linear-gradient(135deg, var(--brand), var(--brand-deep));
            color: #fff; padding: 14px 16px;
            display: flex; align-items: center; justify-content: space-between;
            flex-shrink: 0;
        }
        .acw-header-left { display: flex; align-items: center; gap: 10px; }
        .acw-avatar {
            width: 36px; height: 36px; border-radius: 50%;
            background: rgba(255,255,255,.2);
            display: flex; align-items: center; justify-content: center;
            font-size: 1rem;
        }
        .acw-title   { font-size: .9rem; font-weight: 700; }
        .acw-sub     { font-size: .72rem; opacity: .85; }
        .acw-close   { background: none; border: none; color: #fff; cursor: pointer; font-size: 1rem; padding: 4px; opacity: .8; }
        .acw-close:hover { opacity: 1; }

        .acw-messages {
            flex: 1; overflow-y: auto; padding: 14px;
            display: flex; flex-direction: column; gap: 8px;
        }

        .acw-msg-row { display: flex; justify-content: flex-start; }
        .acw-msg-row.self { justify-content: flex-end; }
        .acw-bubble {
            max-width: 75%; padding: 8px 12px; border-radius: 14px;
            font-size: .84rem; line-height: 1.5;
            background: #f1f5f9; color: var(--ink);
            border-bottom-left-radius: 3px;
        }
        .acw-msg-row.self .acw-bubble {
            background: linear-gradient(135deg, var(--brand), var(--brand-deep));
            color: #fff; border-bottom-left-radius: 14px; border-bottom-right-radius: 3px;
        }
        .acw-empty {
            text-align: center; color: var(--muted); font-size: .82rem; margin: auto;
            padding: 20px;
        }
        .acw-meta { font-size: .67rem; color: var(--muted); margin-top: 2px; }
        .acw-msg-row.self .acw-meta { text-align: right; color: rgba(255,255,255,.65); }

        .acw-input-row {
            padding: 10px 12px; border-top: 1px solid var(--line);
            display: flex; gap: 8px; align-items: flex-end; flex-shrink: 0;
        }
        .acw-input {
            flex: 1; border: 1.5px solid var(--line); border-radius: 12px;
            padding: 8px 12px; font-family: inherit; font-size: .85rem;
            resize: none; max-height: 90px; line-height: 1.45; color: var(--ink);
        }
        .acw-input:focus { outline: none; border-color: var(--brand); }
        .acw-send {
            height: 38px; min-width: 38px; padding: 0 12px; border-radius: 10px; border: none;
            background: linear-gradient(135deg, var(--brand), var(--brand-deep));
            color: #fff; font-size: .82rem; font-weight: 700; cursor: pointer;
            display: flex; align-items: center; gap: 5px;
        }
        .acw-send:disabled { opacity: .5; cursor: not-allowed; }
    </style>
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
                <i class="fas fa-user-circle"></i>
            </div>
            <div class="sidebar-user-details">
                <div class="sidebar-user-id"><?php echo htmlspecialchars(t('sidebar_customer_label'), ENT_QUOTES, 'UTF-8'); ?> #<?php echo htmlspecialchars((string) $customerId, ENT_QUOTES, 'UTF-8'); ?></div>
                <div class="sidebar-user-email no-ar-numerals" dir="ltr"><?php echo htmlspecialchars($customerEmail !== '' ? $customerEmail : t('sidebar_no_email'), ENT_QUOTES, 'UTF-8'); ?></div>
            </div>
        </div>

        <nav class="sidebar-menu">
            <a href="customer_dashboard.php?tab=<?php echo urlencode($tabAccessToken); ?>" class="sidebar-menu-item">
                <i class="fas fa-chart-line"></i>
                <?php echo htmlspecialchars(t('sidebar_dashboard'), ENT_QUOTES, 'UTF-8'); ?>
            </a>
            <a href="customer_requests.php?tab=<?php echo urlencode($tabAccessToken); ?>" class="sidebar-menu-item">
                <i class="fas fa-list-check"></i>
                <?php echo htmlspecialchars(t('sidebar_my_requests'), ENT_QUOTES, 'UTF-8'); ?>
            </a>
            <a href="#notifications" class="sidebar-menu-item" id="notifSidebarLink">
                <i class="fas fa-bell"></i>
                <?php echo htmlspecialchars(t('sidebar_notifications'), ENT_QUOTES, 'UTF-8'); ?>
                <span class="menu-badge" id="notificationCountBadge"<?php if ($notificationCount <= 0) echo ' style="display:none"'; ?>><?php echo $notificationCount > 0 ? htmlspecialchars((string) $notificationCount, ENT_QUOTES, 'UTF-8') : ''; ?></span>
            </a>
            <a href="messages.php?tab=<?php echo urlencode($tabAccessToken); ?>" class="sidebar-menu-item">
                <i class="fas fa-comments"></i>
                <?php echo htmlspecialchars(t('sidebar_messages'), ENT_QUOTES, 'UTF-8'); ?>
            </a>
            <a href="change_password.php?tab=<?php echo urlencode($tabAccessToken); ?>" class="sidebar-menu-item">
                <i class="fas fa-key"></i>
                <?php echo htmlspecialchars(t('sidebar_change_password'), ENT_QUOTES, 'UTF-8'); ?>
            </a>
            <a href="#profile-edit" class="sidebar-menu-item" id="navMyProfile">
                <i class="fas fa-user-circle"></i>
                <?php echo htmlspecialchars(t('sidebar_my_profile'), ENT_QUOTES, 'UTF-8'); ?>
            </a>
        </nav>

        <div class="sidebar-footer">
            <a href="logout.php" class="sidebar-menu-item">
                <i class="fas fa-right-from-bracket"></i>
                <?php echo htmlspecialchars(t('sidebar_sign_out'), ENT_QUOTES, 'UTF-8'); ?>
            </a>
        </div>
    </aside>

    <!-- Main dashboard shell containing header, notifications panel, filters, and provider list -->
    <main class="dashboard-shell">
        <!-- Header with account context and logout action -->
        <section class="topbar" aria-label="Customer account bar">
            <div class="brand">
                <h1><?php echo htmlspecialchars(t('cust_dash_title'), ENT_QUOTES, 'UTF-8'); ?></h1>
                <?php
                    /* Use the customer's full name when available; fall back to email. */
                    $welcomeDisplayName = trim((string) ($customerProfile['name'] ?? ''));
                    if ($welcomeDisplayName === '') {
                        $welcomeDisplayName = $customerEmail;
                    }
                ?>
                <p><?php echo htmlspecialchars(t('cust_dash_welcome'), ENT_QUOTES, 'UTF-8'); ?>, <span><?php echo htmlspecialchars($welcomeDisplayName, ENT_QUOTES, 'UTF-8'); ?></span>. <?php echo htmlspecialchars(t('cust_dash_subtitle'), ENT_QUOTES, 'UTF-8'); ?>.</p>
            </div>
            <a href="<?php echo htmlspecialchars(langSwitchUrl(), ENT_QUOTES, 'UTF-8'); ?>" class="pill" title="<?php echo htmlspecialchars(t('lang_switch_label'), ENT_QUOTES, 'UTF-8'); ?>">
                <i class="fa-solid fa-globe"></i><?php echo htmlspecialchars(t('lang_switch_label'), ENT_QUOTES, 'UTF-8'); ?>
            </a>
        </section>

        <!-- Profile Edit panel — shown when #profile-edit hash is active -->
        <section class="panel" id="profile-edit" aria-label="Edit profile">
            <h2><?php echo htmlspecialchars(t('cust_profile_edit_title'), ENT_QUOTES, 'UTF-8'); ?></h2>
            <p class="lead"><?php echo htmlspecialchars(t('cust_profile_edit_lead_noaddr'), ENT_QUOTES, 'UTF-8'); ?></p>

            <?php if ($profileEditError !== ''): ?>
                <div class="feedback error" role="alert" style="margin-bottom:14px;"><?php echo htmlspecialchars($profileEditError, ENT_QUOTES, 'UTF-8'); ?></div>
            <?php endif; ?>
            <?php if ($profileEditSuccess !== ''): ?>
                <div class="feedback" style="background:var(--ok-bg);border-color:var(--ok-border);color:var(--ok-text);margin-bottom:14px;"><?php echo htmlspecialchars($profileEditSuccess, ENT_QUOTES, 'UTF-8'); ?></div>
            <?php endif; ?>

            <?php
                $currentPhotoDisplay = (string) ($customerProfile['photo'] ?? '');
            ?>
            <form method="post" action="customer_dashboard.php#profile-edit" enctype="multipart/form-data" novalidate style="display:flex;flex-direction:column;gap:18px;max-width:480px;">
                <input type="hidden" name="form_action" value="update_customer_profile">
                <input type="hidden" name="tab" value="<?php echo htmlspecialchars($tabAccessToken, ENT_QUOTES, 'UTF-8'); ?>">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars((string) $_SESSION['customer_profile_csrf'], ENT_QUOTES, 'UTF-8'); ?>">

                <!-- Profile photo preview + upload -->
                <div>
                    <label style="display:block;font-size:.84rem;font-weight:700;color:#0f172a;margin-bottom:10px;">
                        <?php echo htmlspecialchars(t('cust_photo_label'), ENT_QUOTES, 'UTF-8'); ?>
                    </label>
                    <div style="display:flex;align-items:center;gap:16px;flex-wrap:wrap;">
                        <div id="custPhotoPreviewWrap" style="width:80px;height:80px;border-radius:50%;overflow:hidden;background:#e2e8f0;flex-shrink:0;border:3px solid #e2e8f0;">
                            <?php if ($currentPhotoDisplay !== ''): ?>
                                <img id="custPhotoPreview" src="<?php echo htmlspecialchars($currentPhotoDisplay, ENT_QUOTES, 'UTF-8'); ?>" alt="" style="width:100%;height:100%;object-fit:cover;">
                            <?php else: ?>
                                <img id="custPhotoPreview" src="" alt="" style="width:100%;height:100%;object-fit:cover;display:none;">
                                <div id="custPhotoPlaceholder" style="width:100%;height:100%;display:flex;align-items:center;justify-content:center;color:#94a3b8;font-size:2rem;"><i class="fas fa-user"></i></div>
                            <?php endif; ?>
                        </div>
                        <div>
                            <label for="cust_profile_photo" style="display:inline-flex;align-items:center;gap:7px;min-height:36px;border:2px solid #d9e2ec;border-radius:10px;padding:6px 14px;font-family:inherit;font-size:.85rem;font-weight:700;color:#334155;cursor:pointer;background:#fff;transition:border-color .2s;">
                                <i class="fas fa-camera"></i>
                                <?php echo htmlspecialchars(t('cust_photo_change'), ENT_QUOTES, 'UTF-8'); ?>
                            </label>
                            <input type="file" id="cust_profile_photo" name="profile_photo" accept="image/jpeg,image/png,image/webp" style="display:none;">
                            <p style="margin-top:5px;font-size:.78rem;color:#94a3b8;"><?php echo htmlspecialchars(t('cust_photo_hint'), ENT_QUOTES, 'UTF-8'); ?></p>
                        </div>
                    </div>
                </div>

                <div style="display:grid;gap:12px;">
                    <div>
                        <label for="cust_pf_name" style="display:block;font-size:.84rem;font-weight:700;color:#0f172a;margin-bottom:5px;"><?php echo htmlspecialchars(t('cust_profile_name'), ENT_QUOTES, 'UTF-8'); ?></label>
                        <input type="text" id="cust_pf_name" name="profile_name" value="<?php echo htmlspecialchars($profileEditValues['name'], ENT_QUOTES, 'UTF-8'); ?>" maxlength="100" required style="width:100%;min-height:42px;border:2px solid #d9e2ec;border-radius:12px;padding:9px 12px;font-family:inherit;font-size:.9rem;color:#0f172a;">
                    </div>
                    <div>
                        <label for="cust_pf_phone" style="display:block;font-size:.84rem;font-weight:700;color:#0f172a;margin-bottom:5px;"><?php echo htmlspecialchars(t('cust_profile_phone'), ENT_QUOTES, 'UTF-8'); ?></label>
                        <input type="text" id="cust_pf_phone" name="profile_phone" value="<?php echo htmlspecialchars($profileEditValues['phone'], ENT_QUOTES, 'UTF-8'); ?>" maxlength="30" dir="ltr" style="width:100%;min-height:42px;border:2px solid #d9e2ec;border-radius:12px;padding:9px 12px;font-family:inherit;font-size:.9rem;color:#0f172a;">
                    </div>
                </div>

                <div>
                    <button type="submit" style="min-height:42px;border:none;border-radius:12px;padding:10px 18px;font-family:inherit;font-size:.9rem;font-weight:800;color:#fff;background:linear-gradient(145deg,var(--brand),var(--brand-deep));cursor:pointer;display:inline-flex;align-items:center;gap:8px;">
                        <i class="fas fa-save" aria-hidden="true"></i>
                        <?php echo htmlspecialchars(t('cust_profile_save'), ENT_QUOTES, 'UTF-8'); ?>
                    </button>
                </div>
            </form>

            <script>
                (function () {
                    var photoInput   = document.getElementById('cust_profile_photo');
                    var previewImg   = document.getElementById('custPhotoPreview');
                    var placeholder  = document.getElementById('custPhotoPlaceholder');
                    if (!photoInput || !previewImg) return;
                    photoInput.addEventListener('change', function () {
                        var file = photoInput.files && photoInput.files[0];
                        if (!file) return;
                        var reader = new FileReader();
                        reader.onload = function (e) {
                            previewImg.src = e.target.result;
                            previewImg.style.display = 'block';
                            if (placeholder) placeholder.style.display = 'none';
                        };
                        reader.readAsDataURL(file);
                    });
                })();
            </script>

            <!-- ── Customer location map widget ─────────────────────── -->
            <div class="location-map-section" id="cust-location-section">
                <h3>
                    <i class="fas fa-map-marker-alt" aria-hidden="true"></i>
                    <?php echo htmlspecialchars(t('cust_map_section_title'), ENT_QUOTES, 'UTF-8'); ?>
                </h3>
                <p class="map-lead"><?php echo htmlspecialchars(t('cust_map_section_lead'), ENT_QUOTES, 'UTF-8'); ?></p>

                <!-- Interactive Leaflet map — customer clicks/drags to place a pin -->
                <div id="custLocationMap" role="application" aria-label="<?php echo htmlspecialchars(t('cust_map_section_title'), ENT_QUOTES, 'UTF-8'); ?>"></div>

                <!-- Hint text shown below map -->
                <p class="map-hint-text" id="mapHintText">
                    <i class="fas fa-info-circle" aria-hidden="true"></i>
                    <?php echo htmlspecialchars(t('cust_map_drag_hint'), ENT_QUOTES, 'UTF-8'); ?>
                </p>

                <!-- Status badge: shows "Location pinned (lat, lng)" or "No location set" -->
                <div class="map-coords-row">
                    <span id="mapCoordsBadge" class="map-coords-badge <?php echo $hasLocation ? '' : 'no-location'; ?>">
                        <i class="fas fa-<?php echo $hasLocation ? 'circle-check' : 'circle-xmark'; ?>" aria-hidden="true"></i>
                        <span id="mapCoordsText">
                            <?php if ($hasLocation): ?>
                                <?php echo htmlspecialchars(t('cust_map_coords_set'), ENT_QUOTES, 'UTF-8'); ?>
                                (<?php echo htmlspecialchars(number_format((float)$existingLat, 6), ENT_QUOTES, 'UTF-8'); ?>,
                                 <?php echo htmlspecialchars(number_format((float)$existingLng, 6), ENT_QUOTES, 'UTF-8'); ?>)
                            <?php else: ?>
                                <?php echo htmlspecialchars(t('cust_map_no_location'), ENT_QUOTES, 'UTF-8'); ?>
                            <?php endif; ?>
                        </span>
                    </span>
                </div>

                <!-- Reverse-geocoded address display, updated whenever pin is moved -->
                <div class="map-address-row" id="mapAddressRow" style="<?php echo $hasLocation ? '' : 'display:none'; ?>">
                    <i class="fas fa-location-dot" aria-hidden="true"></i>
                    <span id="mapAddress"><?php echo htmlspecialchars(t('cust_map_addr_loading'), ENT_QUOTES, 'UTF-8'); ?></span>
                </div>

                <!-- Action buttons: Save, GPS, Clear -->
                <div class="map-action-btns">
                    <button type="button" id="mapSaveBtn" class="map-save-btn" disabled>
                        <i class="fas fa-floppy-disk" aria-hidden="true"></i>
                        <?php echo htmlspecialchars(t('cust_map_pick_btn'), ENT_QUOTES, 'UTF-8'); ?>
                    </button>
                    <!-- GPS button: retrieves browser geolocation and moves pin -->
                    <button type="button" id="mapGpsBtn" class="map-gps-btn">
                        <i class="fas fa-location-crosshairs" aria-hidden="true"></i>
                        <?php echo htmlspecialchars(t('cust_map_use_gps'), ENT_QUOTES, 'UTF-8'); ?>
                    </button>
                    <button type="button" id="mapClearBtn" class="map-clear-btn"<?php echo $hasLocation ? '' : ' style="display:none"'; ?>>
                        <i class="fas fa-trash-alt" aria-hidden="true"></i>
                        <?php echo htmlspecialchars(t('cust_map_clear_btn'), ENT_QUOTES, 'UTF-8'); ?>
                    </button>
                </div>
                <div id="mapFeedback" class="map-feedback"></div>
            </div>

        </section>

        <!-- Notifications panel — hidden by default, shown when #notifications hash is active -->
        <section class="panel notifications" id="notifications" aria-label="Recent notifications">
            <h2><?php echo htmlspecialchars(t('cust_notifications'), ENT_QUOTES, 'UTF-8'); ?></h2>
            <p class="lead"><?php echo htmlspecialchars(t('notif_lead'), ENT_QUOTES, 'UTF-8'); ?></p>

            <div class="notification-grid">
                <article class="notification-card">
                    <h3><?php echo htmlspecialchars(t('notif_latest_msgs'), ENT_QUOTES, 'UTF-8'); ?></h3>
                    <div id="recentMessagesBody" class="notification-body">
                    <?php if (count($recentProviderMessages) === 0): ?>
                        <p class="empty-state"><?php echo htmlspecialchars(t('notif_no_msgs'), ENT_QUOTES, 'UTF-8'); ?></p>
                    <?php else: ?>
                        <div class="notification-list">
                            <?php foreach ($recentProviderMessages as $message): ?>
                                <?php
                                    $messagePreview = trim((string) $message['message']);
                                    if (mb_strlen($messagePreview) > 90) {
                                        $messagePreview = mb_substr($messagePreview, 0, 90) . '...';
                                    }
                                    $messageTimestamp = $message['created_at'] !== ''
                                        ? custLocalizedDate((string) $message['created_at'], true)
                                        : t('notif_time_na');
                                ?>
                                <div class="notification-item<?php echo $message['is_unread'] ? ' is-unread' : ''; ?>" data-notif-type="message" data-notif-id="<?php echo (int) $message['message_id']; ?>">
                                    <button class="notif-dismiss-btn" type="button" title="<?php echo htmlspecialchars(t('notif_dismiss'), ENT_QUOTES, 'UTF-8'); ?>" aria-label="<?php echo htmlspecialchars(t('notif_dismiss_label'), ENT_QUOTES, 'UTF-8'); ?>" onclick="customerDismissNotif(this,'message',<?php echo (int) $message['message_id']; ?>)"><i class="fas fa-times"></i></button>
                                    <div class="notification-title">
                                        <?php if ($message['is_unread']): ?><span class="notif-dot"></span><?php endif; ?><?php echo htmlspecialchars(t('notif_msg_from'), ENT_QUOTES, 'UTF-8'); ?> <?php echo htmlspecialchars($message['provider_name'], ENT_QUOTES, 'UTF-8'); ?>
                                    </div>
                                    <div class="notification-text">
                                        <?php echo htmlspecialchars($messagePreview !== '' ? $messagePreview : t('notif_image'), ENT_QUOTES, 'UTF-8'); ?>
                                    </div>
                                    <div class="notification-meta">
                                        <span><?php echo htmlspecialchars(t('req_request_num'), ENT_QUOTES, 'UTF-8'); ?><?php echo (int) $message['request_id']; ?></span>
                                        <span><?php echo htmlspecialchars($messageTimestamp, ENT_QUOTES, 'UTF-8'); ?></span>
                                        <a class="notification-link" href="messages.php?request_id=<?php echo (int) $message['request_id']; ?>&amp;tab=<?php echo urlencode($tabAccessToken); ?>" data-notif-action="message" data-notif-id="<?php echo (int) $message['message_id']; ?>"><?php echo htmlspecialchars(t('notif_open_chat'), ENT_QUOTES, 'UTF-8'); ?></a>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>
                    </div>
                </article>

                <article class="notification-card">
                    <h3><?php echo htmlspecialchars(t('notif_updates'), ENT_QUOTES, 'UTF-8'); ?></h3>
                    <div id="recentStatusBody" class="notification-body">
                    <?php if (count($recentStatusUpdates) === 0): ?>
                        <p class="empty-state"><?php echo htmlspecialchars(t('notif_no_updates'), ENT_QUOTES, 'UTF-8'); ?></p>
                    <?php else: ?>
                        <div class="notification-list">
                            <?php foreach ($recentStatusUpdates as $update): ?>
                                <?php
                                    $updateDate = $update['appointment_date'] !== ''
                                        ? custLocalizedDate((string) $update['appointment_date'])
                                        : t('notif_date_na');
                                    $updateTime = $update['appointment_time'] !== ''
                                        ? toArabicNumerals(substr($update['appointment_time'], 0, 5))
                                        : '';
                                    $statusLower = strtolower($update['status']);
                                    $statusLabel = match($statusLower) {
                                        'confirmed' => t('notif_status_accepted'),
                                        'completed' => t('req_status_completed'),
                                        'cancelled' => t('req_status_cancelled'),
                                        default     => ucfirst($statusLower),
                                    };
                                ?>
                                <div class="notification-item<?php echo $update['is_unread'] ? ' is-unread' : ''; ?>" data-notif-type="status" data-notif-id="<?php echo (int) $update['request_id']; ?>">
                                    <button class="notif-dismiss-btn" type="button" title="<?php echo htmlspecialchars(t('notif_dismiss'), ENT_QUOTES, 'UTF-8'); ?>" aria-label="<?php echo htmlspecialchars(t('notif_dismiss_label'), ENT_QUOTES, 'UTF-8'); ?>" onclick="customerDismissNotif(this,'status',<?php echo (int) $update['request_id']; ?>)"><i class="fas fa-times"></i></button>
                                    <div class="notification-title">
                                        <?php if ($update['is_unread']): ?><span class="notif-dot"></span><?php endif; ?><?php echo htmlspecialchars(t('req_request_num'), ENT_QUOTES, 'UTF-8'); ?><?php echo (int) $update['request_id']; ?>
                                        <span class="notif-status-badge <?php echo htmlspecialchars($statusLower, ENT_QUOTES, 'UTF-8'); ?>" style="margin-left:6px"><?php echo htmlspecialchars($statusLabel, ENT_QUOTES, 'UTF-8'); ?></span>
                                    </div>
                                    <div class="notification-text">
                                        <?php echo htmlspecialchars($update['provider_name'], ENT_QUOTES, 'UTF-8'); ?> &middot;
                                        <?php echo htmlspecialchars($update['category_name'], ENT_QUOTES, 'UTF-8'); ?>
                                    </div>
                                    <div class="notification-meta">
                                        <span><?php echo htmlspecialchars($updateDate . ($updateTime !== '' ? ' ' . t('notif_at') . ' ' . $updateTime : ''), ENT_QUOTES, 'UTF-8'); ?></span>
                                        <a class="notification-link" href="customer_requests.php?tab=<?php echo urlencode($tabAccessToken); ?>#request-<?php echo (int) $update['request_id']; ?>" data-notif-action="status" data-notif-id="<?php echo (int) $update['request_id']; ?>"><?php echo htmlspecialchars(t('notif_view_req'), ENT_QUOTES, 'UTF-8'); ?></a>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>
                    </div>
                </article>
            </div>
        </section>

        <!-- Search and filter controls mapped to query-string parameters -->
        <section class="filters" aria-label="Provider filters">
            <form method="get" action="customer_dashboard.php">
                <input type="hidden" name="tab" value="<?php echo htmlspecialchars($tabAccessToken, ENT_QUOTES, 'UTF-8'); ?>">

                <div class="field">
                    <i class="fas fa-magnifying-glass" aria-hidden="true"></i>
                    <input
                        type="search"
                        name="q"
                        id="q"
                        value="<?php echo htmlspecialchars($searchQuery, ENT_QUOTES, 'UTF-8'); ?>"
                        placeholder="<?php echo htmlspecialchars(t('cust_search_name_email'), ENT_QUOTES, 'UTF-8'); ?>"
                        autocomplete="off"
                        list="providerSuggestions"
                        data-suggest="providers"
                    >
                    <datalist id="providerSuggestions"></datalist>
                </div>

                <div class="field">
                    <i class="fas fa-layer-group" aria-hidden="true"></i>
                    <select name="category" id="category">
                        <option value="0" <?php echo $selectedCategoryId === 0 ? 'selected' : ''; ?>><?php echo htmlspecialchars(t('cust_all_categories'), ENT_QUOTES, 'UTF-8'); ?></option>
                        <?php if (count($serviceCategories) === 0): ?>
                            <option value="0"><?php echo htmlspecialchars(t('cust_no_categories'), ENT_QUOTES, 'UTF-8'); ?></option>
                        <?php else: ?>
                            <?php foreach ($serviceCategories as $category): ?>
                                <?php $categoryId = (int) $category['category_id']; ?>
                                <option value="<?php echo htmlspecialchars((string) $categoryId, ENT_QUOTES, 'UTF-8'); ?>" <?php echo $selectedCategoryId === $categoryId ? 'selected' : ''; ?>>
                                    <?php echo htmlspecialchars(tCategory($category, 'name'), ENT_QUOTES, 'UTF-8'); ?>
                                </option>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </select>
                </div>

                <!-- Location filter: dropdown of distinct provider locations -->
                <div class="field">
                    <i class="fas fa-map-marker-alt" aria-hidden="true"></i>
                    <select name="location" id="location-filter">
                        <option value="" <?php echo $locationFilter === '' ? 'selected' : ''; ?>><?php echo htmlspecialchars(t('cust_all_locations'), ENT_QUOTES, 'UTF-8'); ?></option>
                        <?php foreach ($availableLocations as $loc): ?>
                            <option value="<?php echo htmlspecialchars($loc, ENT_QUOTES, 'UTF-8'); ?>" <?php echo $locationFilter === $loc ? 'selected' : ''; ?>>
                                <?php echo htmlspecialchars($loc, ENT_QUOTES, 'UTF-8'); ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>

                <a class="btn secondary" href="customer_dashboard.php?tab=<?php echo urlencode($tabAccessToken); ?>">
                    <i class="fas fa-rotate-left" aria-hidden="true"></i>
                    <?php echo htmlspecialchars(t('btn_reset'), ENT_QUOTES, 'UTF-8'); ?>
                </a>
            </form>
        </section>

        <?php if ($dashboardError !== ''): ?>
            <section class="feedback error" role="alert" style="text-align: center; padding: 40px 24px;">
                <h2 style="font-size: 1.25rem; margin-bottom: 8px;">Unable to load providers</h2>
                <p style="color: #7f1d1d;"><?php echo htmlspecialchars($dashboardError, ENT_QUOTES, 'UTF-8'); ?></p>
            </section>
        <?php elseif (count($serviceProviders) === 0): ?>
            <section class="feedback empty" role="status" style="text-align: center; padding: 40px 24px;">
                <h2 style="font-size: 1.5rem; margin-bottom: 10px; color: #0f172a;">No providers found</h2>
                <p style="color: #64748b; margin-bottom: 24px;">Try adjusting your search or selecting a different category.</p>
            </section>
        <?php else: ?>
            <section class="provider-grid" aria-label="Service provider search results">
                <?php foreach ($serviceProviders as $provider): ?>
                    <article class="provider-card">
                        <div class="provider-header">
                            <div class="provider-photo">
                                <?php if ($provider['photo'] !== ''): ?>
                                    <img src="<?php echo htmlspecialchars($provider['photo'], ENT_QUOTES, 'UTF-8'); ?>" alt="Photo of <?php echo htmlspecialchars($provider['name'], ENT_QUOTES, 'UTF-8'); ?>">
                                <?php else: ?>
                                    <i class="fas fa-user"></i>
                                <?php endif; ?>
                            </div>
                            <div>
                                <div class="provider-name"><?php echo htmlspecialchars($provider['name'], ENT_QUOTES, 'UTF-8'); ?></div>
                                <div class="provider-contact">
                                    <span class="no-ar-numerals" dir="ltr"><?php echo htmlspecialchars($provider['email'], ENT_QUOTES, 'UTF-8'); ?></span>
                                    <?php if ($provider['phone'] !== ''): ?>
                                        &bull; <span dir="ltr"><?php echo htmlspecialchars($provider['phone'], ENT_QUOTES, 'UTF-8'); ?></span>
                                    <?php endif; ?>
                                </div>
                            </div>
                        </div>

                        <?php
                            $priceLabel = 'Price not available';
                            if ($provider['min_price'] !== null && $provider['max_price'] !== null) {
                                if (abs($provider['min_price'] - $provider['max_price']) < 0.01) {
                                    $priceLabel = '$' . number_format((float) $provider['min_price'], 2);
                                } else {
                                    $priceLabel = '$' . number_format((float) $provider['min_price'], 2)
                                        . ' - $' . number_format((float) $provider['max_price'], 2);
                                }
                            }
                        ?>

                        <div class="provider-details">
                            <div class="detail-row">
                                <span class="detail-label"><?php echo htmlspecialchars(t('cust_lbl_category'), ENT_QUOTES, 'UTF-8'); ?></span>
                                <span class="detail-value">
                                    <?php echo htmlspecialchars($provider['service_names'] !== '' ? translateCategoryNames($provider['service_names'], $categoryEnToAr) : t('cust_no_categories'), ENT_QUOTES, 'UTF-8'); ?>
                                </span>
                            </div>
                            <div class="detail-row">
                                <span class="detail-label"><?php echo htmlspecialchars(t('cust_lbl_visit_price'), ENT_QUOTES, 'UTF-8'); ?></span>
                                <span class="detail-value"><?php echo htmlspecialchars($priceLabel, ENT_QUOTES, 'UTF-8'); ?></span>
                            </div>
                            <div class="detail-row">
                                <span class="detail-label"><?php echo htmlspecialchars(t('cust_lbl_location'), ENT_QUOTES, 'UTF-8'); ?></span>
                                <span class="detail-value">
                                    <?php echo htmlspecialchars($provider['location'] !== '' ? $provider['location'] : t('cust_lbl_location_na'), ENT_QUOTES, 'UTF-8'); ?>
                                </span>
                            </div>
                        </div>

                        <div class="provider-actions">
                            <a class="btn primary" href="provider/<?php echo (int) $provider['provider_id']; ?>?tab=<?php echo urlencode($tabAccessToken); ?>">
                                <i class="fas fa-arrow-right" aria-hidden="true"></i>
                                <?php echo htmlspecialchars(t('cust_view_profile'), ENT_QUOTES, 'UTF-8'); ?>
                            </a>
                        </div>
                    </article>
                <?php endforeach; ?>
            </section>
        <?php endif; ?>

    </main>

    <script>
        /*
         * Live search suggestions and auto-submit for provider filters.
         */
        (function () {
            var filterForm = document.querySelector('.filters form');
            if (!filterForm) {
                return;
            }

            var searchInput = filterForm.querySelector('input[type="search"][data-suggest]');
            var categorySelect = filterForm.querySelector('select[name="category"]');
            var datalistId = searchInput ? searchInput.getAttribute('list') : '';
            var datalist = datalistId ? document.getElementById(datalistId) : null;
            var debounceTimer = null;

            function clearSuggestions() {
                if (datalist) {
                    datalist.innerHTML = '';
                }
            }

            function updateSuggestions() {
                if (!searchInput || !datalist) {
                    return;
                }

                var query = (searchInput.value || '').trim();
                clearSuggestions();

                if (query.length < 1) {
                    return;
                }

                var params = new URLSearchParams(new FormData(filterForm));
                params.set('suggest', searchInput.getAttribute('data-suggest') || 'providers');
                params.set('query', query);

                fetch('customer_dashboard.php?' + params.toString())
                    .then(function (response) { return response.json(); })
                    .then(function (payload) {
                        if (!payload || !payload.ok || !Array.isArray(payload.suggestions)) {
                            return;
                        }

                        payload.suggestions.forEach(function (suggestion) {
                            var option = document.createElement('option');
                            option.value = suggestion;
                            datalist.appendChild(option);
                        });
                    })
                    .catch(function () {
                        return;
                    });
            }

            function scheduleSubmit() {
                if (debounceTimer) {
                    window.clearTimeout(debounceTimer);
                }

                debounceTimer = window.setTimeout(function () {
                    if (searchInput) {
                        try {
                            sessionStorage.setItem('custSearchFocusName', searchInput.name || '');
                        } catch (e) {}
                    }
                    filterForm.submit();
                }, 420);
            }

            /* Restore focus to the search input after a filter-triggered page reload. */
            (function () {
                var focusName = '';
                try { focusName = sessionStorage.getItem('custSearchFocusName') || ''; } catch (e) {}
                if (!focusName) return;
                try { sessionStorage.removeItem('custSearchFocusName'); } catch (e) {}
                var target = filterForm.querySelector('input[type="search"][name="' + focusName + '"]');
                if (!target) return;
                target.focus();
                var len = target.value.length;
                try { target.setSelectionRange(len, len); } catch (e) {}
            }());

            if (searchInput) {
                searchInput.addEventListener('input', function () {
                    updateSuggestions();
                    scheduleSubmit();
                });
            }

            if (categorySelect) {
                categorySelect.addEventListener('change', function () {
                    filterForm.submit();
                });
            }

            var locationSelect = filterForm.querySelector('select[name="location"]');
            if (locationSelect) {
                locationSelect.addEventListener('change', function () {
                    filterForm.submit();
                });
            }
        })();

        /*
         * Keep submit controls responsive by disabling rapid double clicks.
         * This reduces accidental duplicate requests from repeated taps.
         */
        document.querySelectorAll('.filters form').forEach(function(formElement) {
            formElement.addEventListener('submit', function() {
                var submitButton = formElement.querySelector('button[type="submit"]');
                if (!submitButton) {
                    return;
                }

                submitButton.disabled = true;
                submitButton.style.opacity = '0.72';
            });
        });

        /*
         * Customer notification system — polling, badge, dismiss, mark-as-read.
         */
        (function () {
            var tabToken      = <?php echo json_encode($tabAccessToken); ?>;
            var baseUrl       = window.location.pathname + '?tab=' + encodeURIComponent(tabToken);
            var notifUrl      = baseUrl + '&ajax=notifications';
            var markReadUrl   = baseUrl + '&ajax=mark_notifications_read';
            var dismissUrl    = baseUrl + '&ajax=dismiss_notification';
            var pollMs        = 5000;

            var lastUnread    = <?php echo (int) $notificationCount; ?>;
            var badge         = document.getElementById('notificationCountBadge');
            var messagesBody  = document.getElementById('recentMessagesBody');
            var statusBody    = document.getElementById('recentStatusBody');

            var latestMaxMsgId    = 0;
            var latestMaxStatusId = 0;

            if (!messagesBody || !statusBody) return;

            function escapeHtml(v) {
                return String(v)
                    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
                    .replace(/>/g, '&gt;').replace(/"/g, '&quot;')
                    .replace(/'/g, '&#39;');
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
                if (!badge) return;
                if (count > 0) {
                    if (count !== lastUnread) {
                        badge.style.animation = 'none';
                        void badge.offsetWidth;
                        badge.style.animation = '';
                    }
                    badge.textContent = String(count);
                    badge.style.display = '';
                } else {
                    badge.style.display = 'none';
                }
                lastUnread = count;
            }

            function markItemRead(type, id) {
                var body = new URLSearchParams();
                if (type === 'message') body.append('last_msg_id',    String(id));
                if (type === 'status')  body.append('last_status_id', String(id));
                fetch(markReadUrl, {
                    method: 'POST', credentials: 'same-origin',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: body.toString(),
                }).catch(function () {});
            }

            function markAllRead() {
                var body = new URLSearchParams();
                body.append('last_msg_id',    String(latestMaxMsgId));
                body.append('last_status_id', String(latestMaxStatusId));
                fetch(markReadUrl, {
                    method: 'POST', credentials: 'same-origin',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: body.toString(),
                }).catch(function () {});
                setBadge(0);
            }

            window.customerDismissNotif = function (btn, type, id) {
                var item = btn.closest('.notification-item');
                if (!item) return;
                item.style.transition = 'opacity 0.25s, transform 0.25s';
                item.style.opacity = '0';
                item.style.transform = 'translateX(10px)';
                setTimeout(function () {
                    if (item.parentNode) item.parentNode.removeChild(item);
                    setBadge(document.querySelectorAll('.notification-item.is-unread').length);
                }, 270);
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
                return '<button class="notif-dismiss-btn" type="button" title="' + escapeHtml(i18n.dismiss) + '" onclick="customerDismissNotif(this,\'' + type + '\',' + id + ')"><i class="fas fa-times"></i></button>';
            }

            function statusBadgeHtml(status) {
                var lower = String(status).toLowerCase();
                var label = lower === 'confirmed' ? i18n.accepted : lower === 'completed' ? i18n.completed : lower === 'cancelled' ? i18n.cancelled : status;
                return '<span class="notif-status-badge ' + escapeHtml(lower) + '" style="margin-left:6px">' + escapeHtml(label) + '</span>';
            }

            var i18n = {
                noMsgs:       <?php echo json_encode(t('notif_no_msgs')); ?>,
                msgFrom:      <?php echo json_encode(t('notif_msg_from')); ?>,
                providerFb:   <?php echo json_encode(t('notif_service_provider')); ?>,
                image:        <?php echo json_encode(t('notif_image')); ?>,
                reqNum:       <?php echo json_encode(t('req_request_num')); ?>,
                openChat:     <?php echo json_encode(t('notif_open_chat')); ?>,
                noUpdates:    <?php echo json_encode(t('notif_no_updates')); ?>,
                dateNa:       <?php echo json_encode(t('notif_date_na')); ?>,
                accepted:     <?php echo json_encode(t('notif_status_accepted')); ?>,
                completed:    <?php echo json_encode(t('req_status_completed')); ?>,
                cancelled:    <?php echo json_encode(t('req_status_cancelled')); ?>,
                atWord:       <?php echo json_encode(t('notif_at')); ?>,
                viewReq:      <?php echo json_encode(t('notif_view_req')); ?>,
                dismiss:      <?php echo json_encode(t('notif_dismiss')); ?>
            };

            function renderMessages(items) {
                if (!items || items.length === 0) return '<p class="empty-state">' + escapeHtml(i18n.noMsgs) + '</p>';
                var html = '<div class="notification-list">';
                items.forEach(function (msg) {
                    var preview = String(msg.message || '').trim();
                    if (preview.length > 90) preview = preview.slice(0, 90) + '...';
                    if (preview === '') preview = i18n.image;
                    var dot = msg.is_unread ? '<span class="notif-dot"></span>' : '';
                    var cls = msg.is_unread ? ' is-unread' : '';
                    html += '<div class="notification-item' + cls + '" data-notif-type="message" data-notif-id="' + msg.message_id + '">';
                    html += buildDismissBtn('message', msg.message_id);
                    html += '<div class="notification-title">' + dot + escapeHtml(i18n.msgFrom) + ' ' + escapeHtml(msg.provider_name || i18n.providerFb) + '</div>';
                    html += '<div class="notification-text">' + escapeHtml(preview) + '</div>';
                    html += '<div class="notification-meta">';
                    html += '<span>' + escapeHtml(i18n.reqNum) + escapeHtml(msg.request_id || '') + '</span>';
                    html += '<span>' + escapeHtml(normalizeTime(msg.created_at)) + '</span>';
                    html += '<a class="notification-link" href="messages.php?request_id=' + encodeURIComponent(msg.request_id || '') + '&tab=' + encodeURIComponent(tabToken) + '" data-notif-action="message" data-notif-id="' + msg.message_id + '">' + escapeHtml(i18n.openChat) + '</a>';
                    html += '</div></div>';
                    if (msg.message_id > latestMaxMsgId) latestMaxMsgId = msg.message_id;
                });
                html += '</div>';
                return html;
            }

            function renderStatusUpdates(items) {
                if (!items || items.length === 0) return '<p class="empty-state">' + escapeHtml(i18n.noUpdates) + '</p>';
                var html = '<div class="notification-list">';
                items.forEach(function (u) {
                    var d = u.appointment_date ? new Date(String(u.appointment_date).replace(' ', 'T')) : null;
                    var locale = pageLang === 'ar' ? 'ar-SA' : 'en-US';
                    var dl = d && !isNaN(d) ? d.toLocaleDateString(locale, { month: 'short', day: 'numeric', year: 'numeric' }) : i18n.dateNa;
                    var tm = String(u.appointment_time || '').slice(0, 5);
                    var dot = u.is_unread ? '<span class="notif-dot"></span>' : '';
                    var cls = u.is_unread ? ' is-unread' : '';
                    html += '<div class="notification-item' + cls + '" data-notif-type="status" data-notif-id="' + u.request_id + '">';
                    html += buildDismissBtn('status', u.request_id);
                    html += '<div class="notification-title">' + dot + escapeHtml(i18n.reqNum) + escapeHtml(u.request_id || '') + statusBadgeHtml(u.status || '') + '</div>';
                    html += '<div class="notification-text">' + escapeHtml(u.provider_name || i18n.providerFb) + ' &middot; ' + escapeHtml(u.category_name || '') + '</div>';
                    html += '<div class="notification-meta">';
                    html += '<span>' + escapeHtml(dl + (tm ? ' ' + i18n.atWord + ' ' + tm : '')) + '</span>';
                    html += '<a class="notification-link" href="customer_requests.php?tab=' + encodeURIComponent(tabToken) + '#request-' + encodeURIComponent(u.request_id || '') + '" data-notif-action="status" data-notif-id="' + u.request_id + '">' + escapeHtml(i18n.viewReq) + '</a>';
                    html += '</div></div>';
                    if (u.request_id > latestMaxStatusId) latestMaxStatusId = u.request_id;
                });
                html += '</div>';
                return html;
            }

            // Mark individual item as read when its action link is clicked
            document.addEventListener('click', function (e) {
                var link = e.target.closest('a[data-notif-action]');
                if (!link) return;
                var action = link.getAttribute('data-notif-action');
                var id = parseInt(link.getAttribute('data-notif-id') || '0', 10);
                if (!id) return;
                var item = link.closest('.notification-item');
                if (item && item.classList.contains('is-unread')) {
                    item.classList.remove('is-unread');
                    var dot = item.querySelector('.notif-dot');
                    if (dot) dot.remove();
                    setBadge(document.querySelectorAll('.notification-item.is-unread').length);
                    markItemRead(action, id);
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
                fetch(notifUrl, { credentials: 'same-origin' })
                    .then(function (r) { return r.json(); })
                    .then(function (payload) {
                        if (!payload || !payload.ok) return;
                        setBadge(parseInt(payload.unread_count || 0, 10));
                        messagesBody.innerHTML = renderMessages(payload.recent_messages || []);
                        statusBody.innerHTML   = renderStatusUpdates(payload.recent_status_updates || []);
                    })
                    .catch(function () {});
            }

            refreshNotifications();
            window.setInterval(refreshNotifications, pollMs);
        })();

        /*
         * Highlight the active sidebar item based on the current page URL.
         */
        (function () {
            var currentPage = window.location.pathname.split('/').pop().split('?')[0];
            document.querySelectorAll('.sidebar-menu a').forEach(function (link) {
                var href = link.getAttribute('href') || '';
                var linkPage = href.split('/').pop().split('?')[0];
                if (linkPage === currentPage) {
                    link.classList.add('active');
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

            document.querySelectorAll('.sidebar-menu a, .sidebar-menu button, .sidebar-footer a').forEach(function (link) {
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
         * Panel switching — exactly one section visible at a time based on URL hash.
         */
        (function () {
            var main   = document.querySelector('.dashboard-shell');
            if (!main) return;
            var PANELS = ['notifications', 'profile-edit'];

            function syncView() {
                var hash    = window.location.hash;
                var matched = PANELS.indexOf(hash.slice(1)) !== -1;

                // Show/hide each named panel
                PANELS.forEach(function (id) {
                    var el = document.getElementById(id);
                    if (el) el.style.display = (hash === '#' + id) ? 'block' : 'none';
                });

                // Lazily initialise the customer location map when this panel first opens
                if (hash === '#profile-edit' && typeof window._custMapInit === 'function') {
                    window._custMapInit();
                }

                // Show/hide main dashboard content (filters, feedback banners, provider grid)
                var filters = main.querySelector('.filters');
                var grid    = main.querySelector('.provider-grid');
                if (filters) filters.style.display = matched ? 'none' : '';
                if (grid)    grid.style.display     = matched ? 'none' : '';
                main.querySelectorAll('section.feedback').forEach(function (f) {
                    f.style.display = matched ? 'none' : '';
                });

                // Sync active state on sidebar links
                document.querySelectorAll('.sidebar-menu-item').forEach(function (link) {
                    var h = (link.getAttribute('href') || '').replace(/^[^#]*/, '');
                    link.classList.toggle('active', !!h && h === hash);
                });
            }

            window.addEventListener('hashchange', syncView);
            syncView();
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
        const CSRF    = <?php echo json_encode($adminChatCsrf); ?>;
        const TAB     = <?php echo json_encode($tabAccessToken); ?>;
        const LABELS  = {
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
                const r = await fetch(`admin_chat_api.php?action=fetch&tab=${encodeURIComponent(TAB)}&since_id=${lastId}`);
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
                const r = await fetch(`admin_chat_api.php?action=unread_count&tab=${encodeURIComponent(TAB)}`);
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
            this.style.height = Math.min(this.scrollHeight,90)+'px';
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
            body.append('tab', TAB);
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

        // Poll unread count every 15s when chat is closed
        fetchUnreadCount();
        setInterval(()=>{ if(!isOpen) fetchUnreadCount(); }, 15000);
    })();
    </script>

    <!-- Leaflet JS — served locally so the map works without internet access -->
    <script src="vendor/leaflet/leaflet.js"></script>
    <script>
    /*
     * Customer location map — lazy initialisation.
     *
     * ROOT CAUSE OF BLANK MAP:
     *   Leaflet cannot measure a container that is display:none (gets 0×0).
     *   Calling invalidateSize() afterwards is unreliable.
     *
     * FIX:
     *   window._custMapInit() is the single entry-point.  It creates the
     *   L.map() instance the FIRST time it is called (i.e. when the
     *   #profile-edit panel is actually visible), then becomes a no-op.
     *   The panel-switcher's syncView() calls it; a hashchange listener
     *   provides a fallback for direct-URL navigation.
     */
    (function () {
        /* ── PHP-injected values ──────────────────────────────────── */
        var TAB       = <?php echo json_encode($tabAccessToken); ?>;
        var SAVED_LAT = <?php echo json_encode($existingLat !== null ? (float)$existingLat : null); ?>;
        var SAVED_LNG = <?php echo json_encode($existingLng !== null ? (float)$existingLng : null); ?>;
        var SAVE_URL  = 'customer_dashboard.php?tab=' + encodeURIComponent(TAB) + '&ajax=save_location';

        var I18N = {
            noLocation   : <?php echo json_encode(t('cust_map_no_location')); ?>,
            coordsSet    : <?php echo json_encode(t('cust_map_coords_set')); ?>,
            saved        : <?php echo json_encode(t('cust_map_saved')); ?>,
            errGeneric   : <?php echo json_encode(t('err_generic')); ?>,
            gpsLoading   : <?php echo json_encode(t('cust_map_gps_loading')); ?>,
            gpsError     : <?php echo json_encode(t('cust_map_gps_error')); ?>,
            gpsNoSupport : <?php echo json_encode(t('cust_map_gps_unsupported')); ?>,
            addrLoading  : <?php echo json_encode(t('cust_map_addr_loading')); ?>,
            addrUnknown  : <?php echo json_encode(t('cust_map_addr_unknown')); ?>,
            clearConfirm : <?php echo json_encode(t('cust_map_clear_btn') . '?'); ?>
        };

        /* ── DOM references ───────────────────────────────────────── */
        var mapEl       = document.getElementById('custLocationMap');
        var saveBtn     = document.getElementById('mapSaveBtn');
        var clearBtn    = document.getElementById('mapClearBtn');
        var gpsBtn      = document.getElementById('mapGpsBtn');
        var coordsBadge = document.getElementById('mapCoordsBadge');
        var coordsText  = document.getElementById('mapCoordsText');
        var feedback    = document.getElementById('mapFeedback');
        var addrRow     = document.getElementById('mapAddressRow');
        var addrSpan    = document.getElementById('mapAddress');

        /* Bail out if required DOM or Leaflet is unavailable */
        if (!mapEl || !saveBtn || typeof L === 'undefined') return;

        /* ── Map state ────────────────────────────────────────────── */
        var map          = null;   /* Leaflet instance — null until first reveal */
        var marker       = null;   /* draggable pin */
        var pendingLat   = null;
        var pendingLng   = null;
        var geocodeTimer = null;
        var _ready       = false;  /* true after initMap() runs once */

        /* ── Helpers ──────────────────────────────────────────────── */

        function updateBadge(lat, lng, saved) {
            if (lat === null || lng === null) {
                coordsBadge.className = 'map-coords-badge no-location';
                coordsBadge.querySelector('i').className = 'fas fa-circle-xmark';
                coordsText.textContent = I18N.noLocation;
                clearBtn.style.display = 'none';
                if (addrRow) addrRow.style.display = 'none';
            } else {
                coordsBadge.className = 'map-coords-badge';
                coordsBadge.querySelector('i').className = 'fas fa-circle-check';
                coordsText.textContent = I18N.coordsSet + ' (' + lat.toFixed(6) + ', ' + lng.toFixed(6) + ')';
                if (saved) clearBtn.style.display = '';
                if (addrRow) addrRow.style.display = '';
            }
        }

        function clearFeedback() {
            feedback.textContent = '';
            feedback.className   = 'map-feedback';
        }

        /* Place or reposition the draggable pin */
        function setPin(lat, lng) {
            var ll = L.latLng(lat, lng);
            if (marker) {
                marker.setLatLng(ll);
            } else {
                marker = L.marker(ll, { draggable: true }).addTo(map);
                marker.on('dragend', function () {
                    var p    = marker.getLatLng();
                    pendingLat = p.lat;
                    pendingLng = p.lng;
                    saveBtn.disabled = false;
                    clearFeedback();
                    updateBadge(pendingLat, pendingLng, false);
                    scheduleGeocode(pendingLat, pendingLng);
                });
            }
            pendingLat = lat;
            pendingLng = lng;
        }

        /* Reverse geocoding via Nominatim — debounced 600 ms */
        function scheduleGeocode(lat, lng) {
            if (geocodeTimer) clearTimeout(geocodeTimer);
            if (addrSpan) addrSpan.textContent = I18N.addrLoading;
            if (addrRow)  addrRow.style.display = '';
            geocodeTimer = setTimeout(function () { doGeocode(lat, lng); }, 600);
        }

        function doGeocode(lat, lng) {
            var lang = document.documentElement.lang || 'en';
            fetch('https://nominatim.openstreetmap.org/reverse?format=jsonv2&lat='
                  + lat + '&lon=' + lng + '&zoom=16&addressdetails=1',
                  { headers: { 'Accept-Language': lang } })
                .then(function (r) { return r.json(); })
                .then(function (d) {
                    if (!addrSpan) return;
                    var a = d.address || {};
                    var parts = [];
                    if (a.road)                        parts.push(a.road);
                    if (a.suburb || a.neighbourhood)   parts.push(a.suburb || a.neighbourhood);
                    if (a.city || a.town || a.village) parts.push(a.city || a.town || a.village);
                    addrSpan.textContent = parts.length ? parts.join(', ')
                                                        : (d.display_name || I18N.addrUnknown);
                })
                .catch(function () {
                    if (addrSpan) addrSpan.textContent = I18N.addrUnknown;
                });
        }

        /* ── Lazy map factory ─────────────────────────────────────── */
        /*
         * initMap() is called only when the #profile-edit panel is visible.
         * At that point mapEl has its CSS height (300 px) so Leaflet measures
         * the container correctly and loads tiles immediately.
         */
        function initMap() {
            if (_ready) return;   /* already initialised */
            _ready = true;

            var cLat  = SAVED_LAT !== null ? SAVED_LAT : 33.8938;
            var cLng  = SAVED_LNG !== null ? SAVED_LNG : 35.5018;
            var cZoom = SAVED_LAT !== null ? 16 : 12;

            map = L.map('custLocationMap', { zoomControl: true }).setView([cLat, cLng], cZoom);

            L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
                maxZoom: 19,
                attribution: '© <a href="https://www.openstreetmap.org/copyright" target="_blank">' +
                             'OpenStreetMap</a> contributors'
            }).addTo(map);

            /* Restore saved marker */
            if (SAVED_LAT !== null && SAVED_LNG !== null) {
                setPin(SAVED_LAT, SAVED_LNG);
                scheduleGeocode(SAVED_LAT, SAVED_LNG);
            }

            /* Click anywhere on the map to drop / move pin */
            map.on('click', function (e) {
                setPin(e.latlng.lat, e.latlng.lng);
                saveBtn.disabled = false;
                clearFeedback();
                updateBadge(pendingLat, pendingLng, false);
                scheduleGeocode(pendingLat, pendingLng);
            });

            /* GPS button */
            if (gpsBtn) {
                gpsBtn.addEventListener('click', function () {
                    if (!navigator.geolocation) {
                        feedback.textContent = I18N.gpsNoSupport;
                        feedback.className   = 'map-feedback err';
                        return;
                    }
                    gpsBtn.disabled  = true;
                    var orig = gpsBtn.innerHTML;
                    gpsBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> ' + I18N.gpsLoading;

                    navigator.geolocation.getCurrentPosition(
                        function (pos) {
                            var lat = pos.coords.latitude;
                            var lng = pos.coords.longitude;
                            setPin(lat, lng);
                            map.setView([lat, lng], 17);
                            saveBtn.disabled = false;
                            clearFeedback();
                            updateBadge(pendingLat, pendingLng, false);
                            scheduleGeocode(lat, lng);
                            gpsBtn.disabled  = false;
                            gpsBtn.innerHTML = orig;
                        },
                        function () {
                            feedback.textContent = I18N.gpsError;
                            feedback.className   = 'map-feedback err';
                            gpsBtn.disabled  = false;
                            gpsBtn.innerHTML = orig;
                        },
                        { enableHighAccuracy: true, timeout: 10000, maximumAge: 0 }
                    );
                });
            }

            /* Save button */
            saveBtn.addEventListener('click', function () {
                if (pendingLat === null || pendingLng === null) return;
                saveBtn.disabled = true;
                var body = new URLSearchParams();
                body.append('action', 'set');
                body.append('latitude',  pendingLat);
                body.append('longitude', pendingLng);
                fetch(SAVE_URL, { method: 'POST', body: body })
                    .then(function (r) { return r.json(); })
                    .then(function (d) {
                        if (d.ok) {
                            feedback.textContent = d.message || I18N.saved;
                            feedback.className   = 'map-feedback ok';
                            SAVED_LAT = pendingLat;
                            SAVED_LNG = pendingLng;
                            updateBadge(SAVED_LAT, SAVED_LNG, true);
                        } else {
                            feedback.textContent = d.message || I18N.errGeneric;
                            feedback.className   = 'map-feedback err';
                            saveBtn.disabled = false;
                        }
                    })
                    .catch(function () {
                        feedback.textContent = I18N.errGeneric;
                        feedback.className   = 'map-feedback err';
                        saveBtn.disabled = false;
                    });
            });

            /* Clear button */
            clearBtn.addEventListener('click', function () {
                if (!confirm(I18N.clearConfirm)) return;
                var body = new URLSearchParams();
                body.append('action', 'clear');
                fetch(SAVE_URL, { method: 'POST', body: body })
                    .then(function (r) { return r.json(); })
                    .then(function (d) {
                        if (d.ok) {
                            if (marker) { map.removeLayer(marker); marker = null; }
                            SAVED_LAT = SAVED_LNG = pendingLat = pendingLng = null;
                            saveBtn.disabled = true;
                            feedback.textContent = d.message || '';
                            feedback.className   = 'map-feedback ok';
                            updateBadge(null, null, false);
                            if (addrSpan) addrSpan.textContent = '';
                        }
                    })
                    .catch(function () {
                        feedback.textContent = I18N.errGeneric;
                        feedback.className   = 'map-feedback err';
                    });
            });
        }

        /* ── Public entry-point called by panel-switcher ──────────── */
        /*
         * window._custMapInit() is invoked by syncView() (panel-switcher)
         * and by the hashchange listener below.  Using double-
         * requestAnimationFrame ensures the browser has painted the
         * now-visible panel before Leaflet reads the container dimensions.
         */
        window._custMapInit = function () {
            requestAnimationFrame(function () {
                requestAnimationFrame(function () {
                    initMap();
                    if (map) map.invalidateSize();
                });
            });
        };

        /* Initialise now if the page was opened directly at #profile-edit */
        if (window.location.hash === '#profile-edit') {
            window._custMapInit();
        }

        /* Also handle navigating to #profile-edit by typing in the address bar */
        window.addEventListener('hashchange', function () {
            if (window.location.hash === '#profile-edit') {
                window._custMapInit();
            }
        });
    })();
    </script>
</body>
</html>


