<?php
declare(strict_types=1);

/*
 * Start/resume session so tab-scoped authentication can be enforced.
 */
session_start();

/*
 * Shared PDO connection for request history reads and review/rating updates.
 */
require_once __DIR__ . '/db_connection.php';
require_once __DIR__ . '/site_settings.php';
require_once __DIR__ . '/service_categories.php';
require_once __DIR__ . '/lang.php';

ensureSiteSettingsTable($pdo);
$siteFavicon = resolveSiteFavicon($pdo);

try {
    $colCheck = $pdo->query("SHOW COLUMNS FROM servicerequest LIKE 'cancellation_reason'");
    if ($colCheck !== false && $colCheck->rowCount() === 0) {
        $pdo->exec("ALTER TABLE servicerequest ADD COLUMN cancellation_reason TEXT NULL");
    }
} catch (PDOException) {}
try {
    $colCheck2 = $pdo->query("SHOW COLUMNS FROM servicerequest LIKE 'cancellation_requested'");
    if ($colCheck2 !== false && $colCheck2->rowCount() === 0) {
        $pdo->exec("ALTER TABLE servicerequest ADD COLUMN cancellation_requested TINYINT(1) NOT NULL DEFAULT 0");
    }
} catch (PDOException) {}

function reqLocalizedDate(string $isoDate): string
{
    static $arDays = ['Sunday'=>'الأحد','Monday'=>'الاثنين','Tuesday'=>'الثلاثاء',
        'Wednesday'=>'الأربعاء','Thursday'=>'الخميس','Friday'=>'الجمعة','Saturday'=>'السبت'];
    static $arMonths = ['January'=>'يناير','February'=>'فبراير','March'=>'مارس','April'=>'أبريل',
        'May'=>'مايو','June'=>'يونيو','July'=>'يوليو','August'=>'أغسطس',
        'September'=>'سبتمبر','October'=>'أكتوبر','November'=>'نوفمبر','December'=>'ديسمبر'];
    $ts = strtotime($isoDate);
    if (getLang() !== 'ar') return date('D, M j, Y', $ts);
    $day   = $arDays[date('l', $ts)]   ?? date('l', $ts);
    $month = $arMonths[date('F', $ts)] ?? date('F', $ts);
    return $day . '، ' . toArabicNumerals(date('j', $ts)) . ' ' . $month . ' ' . toArabicNumerals(date('Y', $ts));
}

$reqCategoryEnToAr = [];
try {
    $reqCategories = loadServiceCategories($pdo);
    foreach ($reqCategories as $reqCat) {
        $arName = trim((string) ($reqCat['name_ar'] ?? ''));
        if ($arName !== '') {
            $reqCategoryEnToAr[(string) $reqCat['name']] = $arName;
        }
    }
} catch (PDOException $e) {
    $reqCategories = [];
}

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
 * Resolve active tab identity from session token registry.
 * This allows independent protected access behavior per browser tab.
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
 * Identity values for ownership checks and page-level account display.
 */
$customerId = (int) ($activeTabSession['user_id'] ?? 0);
$customerEmail = (string) ($activeTabSession['user_email'] ?? '');

if ($customerId <= 0) {
    header('Location: login.php');
    exit;
}

/*
 * Keep legacy session keys synchronized with the validated tab identity
 * unless another role is already active in this PHP session.
 */
$existingUserType = (string) ($_SESSION['user_type'] ?? '');
if ($existingUserType === '' || $existingUserType === 'customer') {
    $_SESSION['user_id'] = $customerId;
    $_SESSION['user_email'] = $customerEmail;
    $_SESSION['user_type'] = 'customer';
}

/*
 * Create a CSRF token dedicated to rating/review updates from this page.
 */
if (!isset($_SESSION['customer_review_csrf']) || !is_string($_SESSION['customer_review_csrf'])) {
    $_SESSION['customer_review_csrf'] = bin2hex(random_bytes(32));
}

/*
 * Create a CSRF token dedicated to request cancellation updates.
 */
if (!isset($_SESSION['customer_cancel_csrf']) || !is_string($_SESSION['customer_cancel_csrf'])) {
    $_SESSION['customer_cancel_csrf'] = bin2hex(random_bytes(32));
}

/*
 * Create a CSRF token dedicated to customer chat messages.
 */
if (!isset($_SESSION['customer_chat_csrf']) || !is_string($_SESSION['customer_chat_csrf'])) {
    $_SESSION['customer_chat_csrf'] = bin2hex(random_bytes(32));
}

/*
 * Notification badge count for sidebar — counts unread provider messages and request status updates.
 */
$customerNotifCount = 0;
try {
    if (!isset($_SESSION['customer_notif_seen'])) {
        try {
            $seenStmt = $pdo->prepare(
                'SELECT last_msg_id, last_status_id
                 FROM customer_notification_seen
                 WHERE customer_id = :cid LIMIT 1'
            );
            $seenStmt->execute([':cid' => $customerId]);
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
        ':cid1'      => $customerId,
        ':msg_id'    => $seenMsgId,
        ':cid2'      => $customerId,
        ':status_id' => $seenStatusId,
    ]);
    $countRow = $notifCountStmt->fetch();
    $customerNotifCount = (int) ($countRow['total_unread'] ?? 0);
} catch (PDOException) {}

/*
 * Page status values and collections used by rendering.
 */
$errorMessage = '';
$successMessage = '';
$requests = [];
$statusCounts = [
    'Pending' => 0,
    'Confirmed' => 0,
    'Completed' => 0,
    'Cancelled' => 0,
];

/*
 * Flash message lifecycle for PRG flow after successful updates.
 */
if (isset($_SESSION['customer_requests_flash_success']) && is_string($_SESSION['customer_requests_flash_success'])) {
    $successMessage = $_SESSION['customer_requests_flash_success'];
    unset($_SESSION['customer_requests_flash_success']);
}

/*
 * Handle review/rating updates and customer cancellations.
 */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $formAction = trim((string) ($_POST['form_action'] ?? ''));

    if ($formAction === 'cancel_request') {
        $postedCsrfToken = (string) ($_POST['csrf_token'] ?? '');
        $requestId       = (int) ($_POST['request_id'] ?? 0);
        $cancelReason    = trim((string) ($_POST['cancel_reason'] ?? ''));

        if (!hash_equals($_SESSION['customer_cancel_csrf'], $postedCsrfToken)) {
            $errorMessage = 'Invalid request token. Please refresh the page and try again.';
        } elseif ($requestId <= 0) {
            $errorMessage = 'Invalid request selected for cancellation.';
        } else {
            try {
                $ownershipCheck = $pdo->prepare(
                    'SELECT request_id, status,
                            IFNULL(cancellation_requested, 0) AS cancellation_requested
                     FROM servicerequest
                     WHERE request_id = :request_id
                       AND customer_id = :customer_id
                     LIMIT 1'
                );
                $ownershipCheck->execute([
                    'request_id'  => $requestId,
                    'customer_id' => $customerId,
                ]);

                $requestRow        = $ownershipCheck->fetch();
                $currentStatus     = (string) ($requestRow['status'] ?? '');
                $alreadyRequested  = (int) ($requestRow['cancellation_requested'] ?? 0) === 1;

                if ($requestRow === false) {
                    $errorMessage = 'Request not found for your account.';
                } elseif ($currentStatus === 'Pending') {
                    /*
                     * Pending requests are cancelled directly; reason is optional.
                     */
                    $pdo->prepare(
                        'UPDATE servicerequest
                         SET status = "Cancelled",
                             cancellation_reason = :reason
                         WHERE request_id = :request_id
                           AND customer_id = :customer_id'
                    )->execute([
                        'reason'      => $cancelReason !== '' ? $cancelReason : null,
                        'request_id'  => $requestId,
                        'customer_id' => $customerId,
                    ]);
                    $_SESSION['customer_requests_flash_success'] = t('req_cancel_success');
                    header('Location: customer_requests.php?tab=' . urlencode($tabAccessToken) . '#request-' . urlencode((string) $requestId));
                    exit;
                } elseif ($currentStatus === 'Confirmed') {
                    /*
                     * Confirmed requests require a reason and provider approval.
                     * Mark cancellation_requested = 1; status stays Confirmed until provider confirms.
                     */
                    if ($alreadyRequested) {
                        $errorMessage = 'A cancellation request for this appointment is already pending provider review.';
                    } elseif ($cancelReason === '') {
                        $errorMessage = t('req_cancel_reason_required');
                    } else {
                        $pdo->prepare(
                            'UPDATE servicerequest
                             SET cancellation_requested = 1,
                                 cancellation_reason    = :reason
                             WHERE request_id  = :request_id
                               AND customer_id = :customer_id'
                        )->execute([
                            'reason'      => $cancelReason,
                            'request_id'  => $requestId,
                            'customer_id' => $customerId,
                        ]);
                        $_SESSION['customer_requests_flash_success'] = t('req_cancel_success');
                        header('Location: customer_requests.php?tab=' . urlencode($tabAccessToken) . '#request-' . urlencode((string) $requestId));
                        exit;
                    }
                } else {
                    $errorMessage = 'Only pending or confirmed requests can be cancelled.';
                }
            } catch (PDOException $exception) {
                $errorMessage = 'Unable to process your cancellation request right now. Please try again.';
            }
        }
    } else {
        $postedCsrfToken = (string) ($_POST['csrf_token'] ?? '');
        $requestId = (int) ($_POST['request_id'] ?? 0);
        $ratingValue = (int) ($_POST['rating'] ?? 0);
        $reviewText = trim((string) ($_POST['review'] ?? ''));

        /*
         * Server-side validation for CSRF, ownership, status, and rating bounds.
         */
        if (!hash_equals($_SESSION['customer_review_csrf'], $postedCsrfToken)) {
            $errorMessage = 'Invalid request token. Please refresh the page and try again.';
        } elseif ($requestId <= 0) {
            $errorMessage = 'Invalid request selected for review update.';
        } elseif ($ratingValue < 1 || $ratingValue > 5) {
            $errorMessage = 'Please choose a rating between 1 and 5 stars.';
        } elseif (mb_strlen($reviewText) > 2000) {
            $errorMessage = 'Review text must be 2000 characters or fewer.';
        } else {
            try {
                /*
                 * Verify request belongs to current customer and is eligible for review updates.
                 */
                $ownershipCheck = $pdo->prepare(
                    'SELECT request_id, status
                     FROM servicerequest
                     WHERE request_id = :request_id
                       AND customer_id = :customer_id
                     LIMIT 1'
                );
                $ownershipCheck->execute([
                    'request_id' => $requestId,
                    'customer_id' => $customerId,
                ]);

                $requestRow = $ownershipCheck->fetch();
                if ($requestRow === false) {
                    $errorMessage = 'Request not found for your account.';
                } elseif ((string) ($requestRow['status'] ?? '') !== 'Completed') {
                    $errorMessage = 'Ratings can only be added or updated for completed requests.';
                } else {
                    /*
                     * Persist customer rating and optional review text to the request record.
                     */
                    $updateReview = $pdo->prepare(
                        'UPDATE servicerequest
                         SET rating = :rating,
                             review = :review
                         WHERE request_id = :request_id
                           AND customer_id = :customer_id'
                    );
                    $updateReview->execute([
                        'rating' => $ratingValue,
                        'review' => $reviewText === '' ? null : $reviewText,
                        'request_id' => $requestId,
                        'customer_id' => $customerId,
                    ]);

                    $_SESSION['customer_requests_flash_success'] = 'Your rating and review have been saved.';
                    header('Location: customer_requests.php?tab=' . urlencode($tabAccessToken) . '#request-' . urlencode((string) $requestId));
                    exit;
                }
            } catch (PDOException $exception) {
                $errorMessage = 'Unable to update rating right now. Please try again.';
            }
        }
    }
}

$filterStatus = trim((string) ($_GET['status'] ?? ''));
$sortOrder = trim((string) ($_GET['sort'] ?? 'newest'));

if (!in_array($filterStatus, ['Pending', 'Confirmed', 'Completed', 'Cancelled'], true)) {
    $filterStatus = '';
}
if ($sortOrder !== 'oldest') {
    $sortOrder = 'newest';
}

$displayRequests = [];

try {
    /*
     * Request history query:
     * - joins provider, category, and appointment slot details
     * - returns images, prices, status, and existing review/rating values
     * - sorted newest appointment first; client-side sort applied in PHP for oldest-first
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
            sc.name AS category_name,
            sc.description AS category_description,
            asl.date AS appointment_date,
            asl.slot AS appointment_time,
            sp.provider_id,
            sp.name AS provider_name,
            sp.email AS provider_email,
            sp.phone AS provider_phone
         FROM servicerequest sr
         INNER JOIN appointmentslot asl
            ON sr.slot_id = asl.slot_id
         INNER JOIN serviceprovider sp
            ON asl.serviceprovider_id = sp.provider_id
         LEFT JOIN servicecategory sc
            ON sr.category_id = sc.category_id
         WHERE sr.customer_id = :customer_id
         ORDER BY asl.date DESC, asl.slot DESC, sr.request_id DESC'
    );
    $requestsStatement->execute(['customer_id' => $customerId]);

    /*
     * Normalize rows for rendering and compute status counters.
     */
    while ($row = $requestsStatement->fetch()) {
        $status = (string) ($row['status'] ?? 'Pending');
        if (isset($statusCounts[$status])) {
            $statusCounts[$status] += 1;
        }

        $images = [];
        foreach (['image1', 'image2', 'image3'] as $imageColumn) {
            $imagePath = trim((string) ($row[$imageColumn] ?? ''));
            if ($imagePath !== '') {
                $images[] = $imagePath;
            }
        }

        $ratingRaw = $row['rating'] ?? null;
        $ratingValue = $ratingRaw !== null ? (int) $ratingRaw : null;

        $requests[] = [
            'request_id' => (int) $row['request_id'],
            'status' => $status,
            'review' => trim((string) ($row['review'] ?? '')),
            'rating' => $ratingValue,
            'estimated_price' => $row['estimated_price'] !== null ? (float) $row['estimated_price'] : null,
            'final_price' => $row['final_price'] !== null ? (float) $row['final_price'] : null,
            'category_name' => (string) ($row['category_name'] ?? 'General service'),
            'category_description' => trim((string) ($row['category_description'] ?? '')),
            'appointment_date' => (string) ($row['appointment_date'] ?? ''),
            'appointment_time' => (string) ($row['appointment_time'] ?? ''),
            'provider_id' => (int) ($row['provider_id'] ?? 0),
            'provider_name' => (string) ($row['provider_name'] ?? 'Unknown provider'),
            'provider_email' => (string) ($row['provider_email'] ?? ''),
            'provider_phone' => (string) ($row['provider_phone'] ?? ''),
            'images' => $images,
            'cancellation_reason'    => (string) ($row['cancellation_reason'] ?? ''),
            'cancellation_requested' => (int) ($row['cancellation_requested'] ?? 0) === 1,
            'cancellation_pending'   => $status === 'Confirmed' && (int) ($row['cancellation_requested'] ?? 0) === 1,
            'can_rate'   => $status === 'Completed',
            'can_cancel' => ($status === 'Pending') || ($status === 'Confirmed' && (int) ($row['cancellation_requested'] ?? 0) === 0),
        ];
    }
    if ($sortOrder === 'oldest') {
        usort($requests, static function (array $a, array $b): int {
            $cmp = strcmp($a['appointment_date'], $b['appointment_date']);
            if ($cmp !== 0) {
                return $cmp;
            }
            $cmp = strcmp($a['appointment_time'], $b['appointment_time']);
            if ($cmp !== 0) {
                return $cmp;
            }
            return $a['request_id'] <=> $b['request_id'];
        });
    }

    $displayRequests = $filterStatus !== ''
        ? array_values(array_filter($requests, static function (array $r) use ($filterStatus): bool {
            return $r['status'] === $filterStatus;
        }))
        : $requests;
} catch (PDOException $exception) {
    $errorMessage = $errorMessage === ''
        ? 'Unable to load your request history right now. Please try again.'
        : $errorMessage;
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
    <title><?php echo htmlspecialchars(t('req_title'), ENT_QUOTES, 'UTF-8'); ?> - <?php echo htmlspecialchars(t('site_name'), ENT_QUOTES, 'UTF-8'); ?></title>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <?php if (isRtl()): ?>
    <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <?php endif; ?>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        /*
         * Global reset and color/spacing tokens shared across the page.
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
            --surface: #f8fafc;
            --card: #ffffff;
            --ok-bg: #ecfdf5;
            --ok-text: #166534;
            --ok-border: #86efac;
            --warn-bg: #fff7ed;
            --warn-text: #9a3412;
            --warn-border: #fdba74;
            --danger-bg: #fff1f2;
            --danger-text: #be123c;
            --danger-border: #fecdd3;
            --neutral-bg: #f1f5f9;
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
        }

        body {
            min-height: 100vh;
            font-family: 'Plus Jakarta Sans', sans-serif;
            color: var(--ink);
            background:
                radial-gradient(circle at 10% 0%, rgba(20, 184, 166, 0.18), transparent 36%),
                radial-gradient(circle at 90% 8%, rgba(251, 146, 60, 0.19), transparent 33%),
                linear-gradient(130deg, #ecfeff, #f8fafc 45%, #fff7ed);
            display: flex;
            flex-direction: row;
        }

        /*
         * Main content area — takes remaining width beside the sidebar.
         */
        .shell {
            flex: 1;
            min-width: 0;
            display: flex;
            flex-direction: column;
            gap: 14px;
            padding: 24px 20px 38px;
        }

        /*
         * Top navigation and account-context bar.
         */
        .topbar {
            background: rgba(255, 255, 255, 0.9);
            border: 1px solid rgba(255, 255, 255, 0.9);
            border-radius: 22px;
            padding: 16px;
            box-shadow: 0 14px 34px rgba(15, 23, 42, 0.09);
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 10px;
            flex-wrap: wrap;
        }

        .topbar-title h1 {
            font-size: 1.28rem;
            color: #042f2e;
            font-weight: 800;
            margin-bottom: 4px;
        }

        .topbar-title p {
            font-size: 0.86rem;
            color: var(--muted);
        }

        .topbar-actions {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            align-items: center;
        }

        .pill-link {
            min-height: 40px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 7px;
            padding: 8px 14px;
            border-radius: 999px;
            border: 1px solid var(--line);
            background: #fff;
            color: #0f172a;
            font-size: 0.84rem;
            font-weight: 700;
            text-decoration: none;
            transition: transform 0.18s ease, box-shadow 0.18s ease;
        }

        .pill-link:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 18px rgba(15, 23, 42, 0.1);
        }

        .pill-link.primary {
            border: none;
            color: #fff;
            background: linear-gradient(145deg, var(--brand), var(--brand-deep));
        }

        .pill-link.primary:hover {
            box-shadow: 0 10px 24px rgba(15, 118, 110, 0.32);
        }

        /*
         * Feedback banners for errors and successful updates.
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
            border-color: var(--danger-border);
            color: var(--danger-text);
        }

        .feedback.success {
            background: var(--ok-bg);
            border-color: var(--ok-border);
            color: var(--ok-text);
        }

        /*
         * Compact summary cards showing status distribution across requests.
         */
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 10px;
        }

        .summary-card {
            background: rgba(255, 255, 255, 0.92);
            border: 1px solid rgba(255, 255, 255, 0.9);
            border-radius: 16px;
            padding: 12px;
            box-shadow: 0 10px 24px rgba(15, 23, 42, 0.08);
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }

        .summary-card:hover {
            transform: translateY(-3px);
            box-shadow: 0 16px 32px rgba(15, 23, 42, 0.12);
        }

        .summary-card .label {
            font-size: 0.8rem;
            color: #64748b;
            margin-bottom: 4px;
        }

        .summary-card .value {
            font-size: 1.2rem;
            font-weight: 800;
            color: #0f172a;
        }

        /*
         * Request list container and per-request card layout.
         */
        .requests-list {
            display: grid;
            gap: 14px;
        }

        @media (min-width: 900px) {
            .requests-list {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }
        }

        .request-card {
            background: #ffffff;
            border: 1px solid #e2e8f0;
            border-left: 5px solid #cbd5e1;
            border-radius: 18px;
            box-shadow: 0 4px 14px rgba(15, 23, 42, 0.07);
            padding: 16px;
            display: grid;
            gap: 10px;
            overflow: hidden;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }

        .request-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 12px 28px rgba(15, 23, 42, 0.12);
        }

        .request-card.pending   { border-left-color: #f59e0b; }
        .request-card.confirmed { border-left-color: #3b82f6; }
        .request-card.completed { border-left-color: #22c55e; }
        .request-card.cancelled { border-left-color: #f87171; }

        @keyframes requestHighlight {
            0%   { box-shadow: 0 0 0 4px rgba(15, 118, 110, 0.55), 0 18px 38px rgba(15, 23, 42, 0.11); }
            60%  { box-shadow: 0 0 0 3px rgba(15, 118, 110, 0.25), 0 12px 28px rgba(15, 23, 42, 0.08); }
            100% { box-shadow: 0 12px 28px rgba(15, 23, 42, 0.08); }
        }

        .request-card.highlighted {
            animation: requestHighlight 2.2s ease forwards;
            scroll-margin-top: 28px;
        }

        .request-head {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 10px;
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

        .request-head h2 {
            font-size: 1rem;
            font-weight: 800;
            color: #0f172a;
        }

        .status-pill {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            border-radius: 999px;
            padding: 5px 10px;
            font-size: 0.77rem;
            font-weight: 800;
            border: 1px solid;
        }

        .status-pill.pending {
            background: var(--warn-bg);
            color: var(--warn-text);
            border-color: var(--warn-border);
        }

        .status-pill.confirmed {
            background: var(--info-bg);
            color: var(--info-text);
            border-color: var(--info-border);
        }

        .status-pill.completed {
            background: var(--ok-bg);
            color: var(--ok-text);
            border-color: var(--ok-border);
        }

        .status-pill.cancelled {
            background: var(--danger-bg);
            color: var(--danger-text);
            border-color: var(--danger-border);
        }

        .request-meta {
            display: flex;
            flex-wrap: wrap;
            gap: 7px;
        }

        .meta-chip {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            border: 1px solid var(--line);
            border-radius: 999px;
            background: #f8fafc;
            color: #334155;
            padding: 5px 10px;
            font-size: 0.78rem;
            font-weight: 700;
        }

        .meta-chip i { color: var(--brand); font-size: 0.75rem; }

        .provider-link {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            font-size: 0.86rem;
            font-weight: 800;
            color: #0f766e;
            text-decoration: none;
            width: fit-content;
            background: #f0fdf4;
            border: 1px solid #d1fae5;
            border-radius: 999px;
            padding: 5px 12px;
        }

        .provider-link:hover {
            background: #dcfce7;
            color: #115e59;
        }

        .description,
        .review-display {
            font-size: 0.86rem;
            line-height: 1.45;
            color: #334155;
        }

        .price-row {
            font-size: 0.83rem;
            color: #334155;
            display: flex;
            gap: 16px;
            flex-wrap: wrap;
            padding: 8px 12px;
            background: linear-gradient(135deg, #f0fdf4, #f8fafc);
            border: 1px solid #d1fae5;
            border-radius: 10px;
        }

        /*
         * Image preview grid for problem photos attached to each request.
         */
        .image-grid {
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: 8px;
        }

        .image-card {
            border: 1px solid #dbe2ea;
            border-radius: 12px;
            overflow: hidden;
            background: #fff;
            min-height: 110px;
        }

        .image-card img {
            width: 100%;
            height: 100%;
            min-height: 110px;
            object-fit: cover;
            display: block;
        }

        /*
         * Star rendering for stored ratings and rating input forms.
         */
        .stars-readonly {
            display: inline-flex;
            align-items: center;
            gap: 2px;
            color: #f59e0b;
        }

        .stars-readonly .star.is-empty {
            color: #cbd5e1;
        }

        .rating-text {
            font-size: 0.82rem;
            color: #334155;
        }

        .review-form {
            border: 1px solid #dbe2ea;
            border-radius: 12px;
            padding: 10px;
            background: #fff;
            display: grid;
            gap: 10px;
        }

        .review-form h3 {
            font-size: 0.9rem;
            color: #0f172a;
        }

        .star-picker {
            display: flex;
            flex-direction: row-reverse;
            justify-content: flex-end;
            gap: 4px;
        }

        .star-picker input {
            position: absolute;
            opacity: 0;
            pointer-events: none;
        }

        .star-picker label {
            cursor: pointer;
            font-size: 1.15rem;
            color: #cbd5e1;
            line-height: 1;
        }

        .star-picker label:hover,
        .star-picker label:hover ~ label,
        .star-picker input:checked ~ label {
            color: #f59e0b;
        }

        .review-form textarea {
            width: 100%;
            min-height: 98px;
            border: 2px solid #d9e2ec;
            border-radius: 12px;
            padding: 10px;
            font-family: inherit;
            font-size: 0.86rem;
            resize: vertical;
            color: #0f172a;
        }

        .review-form textarea:focus {
            outline: none;
            border-color: var(--brand);
            box-shadow: 0 0 0 4px rgba(15, 118, 110, 0.12);
        }

        .review-form .hint {
            font-size: 0.76rem;
            color: #64748b;
            line-height: 1.35;
        }

        .btn-save {
            min-height: 44px;
            border: none;
            border-radius: 12px;
            font-family: inherit;
            font-size: 0.88rem;
            font-weight: 800;
            color: #fff;
            background: linear-gradient(145deg, var(--brand), var(--brand-deep));
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            width: fit-content;
            padding: 10px 14px;
        }

        .cancel-form {
            display: flex;
            justify-content: flex-start;
        }

        .btn-cancel {
            min-height: 40px;
            border-radius: 12px;
            border: 1px solid var(--danger-border);
            background: var(--danger-bg);
            color: var(--danger-text);
            font-family: inherit;
            font-size: 0.84rem;
            font-weight: 800;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 8px 12px;
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

        .empty-state {
            border: 1px dashed #cbd5e1;
            background: #f8fafc;
            color: #334155;
            border-radius: 16px;
            padding: 18px;
            font-size: 0.92rem;
            font-weight: 700;
            text-align: center;
        }

        /*
         * Filter bar for status and sort controls.
         */
        .filter-bar {
            background: rgba(255, 255, 255, 0.92);
            border: 1px solid rgba(255, 255, 255, 0.9);
            border-radius: 18px;
            padding: 12px 14px;
            box-shadow: 0 10px 24px rgba(15, 23, 42, 0.07);
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
            align-items: center;
            justify-content: space-between;
        }

        .filter-group {
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
            align-items: center;
        }

        .filter-label {
            font-size: 0.78rem;
            color: #64748b;
            font-weight: 700;
            white-space: nowrap;
        }

        .filter-pill {
            min-height: 32px;
            border-radius: 999px;
            border: 1px solid #dbe2ea;
            background: #f8fafc;
            color: #334155;
            font-size: 0.78rem;
            font-weight: 700;
            padding: 5px 11px;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 5px;
            transition: background 0.15s ease, border-color 0.15s ease, color 0.15s ease;
            cursor: pointer;
        }

        .filter-pill:hover {
            background: #e2e8f0;
        }

        .filter-pill.is-active {
            background: linear-gradient(145deg, #0f766e, #115e59);
            border-color: transparent;
            color: #fff;
        }

        .request-card:nth-child(3) { animation-delay: 0.08s; }
        .request-card:nth-child(4) { animation-delay: 0.12s; }
        .request-card:nth-child(5) { animation-delay: 0.16s; }

        /*
         * Responsive behavior for tablets and mobile phones.
         */
        @media (max-width: 980px) {
            .summary-grid {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }
        }

        @media (max-width: 720px) {
            .topbar {
                border-radius: 16px;
                padding: 13px;
                padding-left: 56px;
            }

            .summary-grid {
                grid-template-columns: 1fr;
            }

            .image-grid {
                grid-template-columns: 1fr;
            }

            .filter-bar {
                gap: 8px;
            }

            .filter-group {
                width: 100%;
                overflow-x: auto;
                flex-wrap: nowrap;
                padding-bottom: 2px;
                scrollbar-width: none;
            }

            .filter-group::-webkit-scrollbar {
                display: none;
            }

            .requests-list {
                grid-template-columns: 1fr;
            }
        }

        @media (max-width: 480px) {
            .topbar {
                padding: 12px;
                padding-left: 56px;
            }

            .topbar h1 {
                font-size: 1.1rem;
            }

            .topbar-back {
                padding: 7px 12px;
                font-size: 0.82rem;
            }

            .request-card {
                padding: 14px;
                border-radius: 16px;
            }

            .request-actions {
                flex-direction: column;
            }

            .request-actions .btn {
                width: 100%;
                justify-content: center;
            }

            .status-pill {
                font-size: 0.72rem;
                padding: 4px 8px;
            }

            .section-card {
                padding: 14px;
                border-radius: 16px;
            }
        }

        /*
         * Reduced-motion mode for users with motion sensitivity preferences.
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

        .sidebar {
            position: sticky;
            left: 0;
            top: 0;
            height: 100vh;
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

        body.sidebar-open {
            overflow: hidden;
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
        [dir="rtl"] input, [dir="rtl"] textarea, [dir="rtl"] select { text-align: right; }
        [dir="rtl"] .field i { left: auto; right: 12px; }
        [dir="rtl"] .field input, [dir="rtl"] .field select { padding-left: 12px; padding-right: 36px; }
        [dir="rtl"] .request-card { border-left: 1px solid #e2e8f0; border-right: 5px solid #cbd5e1; }
        [dir="rtl"] .request-card.pending   { border-right-color: #f59e0b; }
        [dir="rtl"] .request-card.confirmed { border-right-color: #3b82f6; }
        [dir="rtl"] .request-card.completed { border-right-color: #22c55e; }
        [dir="rtl"] .request-card.cancelled { border-right-color: #f87171; }
        [dir="rtl"] .request-head { margin: -16px -16px 0; }

        /* ── Cancellation flow ── */
        .cancel-section { display: grid; gap: 8px; }

        .btn-cancel-toggle {
            min-height: 40px;
            border-radius: 12px;
            border: 1px solid var(--danger-border);
            background: var(--danger-bg);
            color: var(--danger-text);
            font-family: inherit;
            font-size: 0.84rem;
            font-weight: 800;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 8px 14px;
            width: fit-content;
            transition: background 0.15s, box-shadow 0.15s;
        }
        .btn-cancel-toggle:hover {
            background: #ffe4e6;
            box-shadow: 0 4px 12px rgba(190,18,60,.12);
        }

        .cancel-panel {
            background: #fff8f1;
            border: 1px solid #fed7aa;
            border-radius: 14px;
            padding: 14px;
            display: grid;
            gap: 10px;
        }

        .cancel-notice {
            display: flex;
            align-items: flex-start;
            gap: 8px;
            font-size: 0.84rem;
            font-weight: 600;
            line-height: 1.45;
            border-radius: 10px;
            padding: 10px 12px;
        }
        .cancel-notice--warn {
            background: #fff7ed;
            border: 1px solid #fdba74;
            color: #9a3412;
        }
        .cancel-notice i { margin-top: 2px; flex-shrink: 0; }

        .cancel-field { display: grid; gap: 5px; }
        .cancel-field label {
            font-size: 0.83rem;
            font-weight: 700;
            color: #0f172a;
        }
        .cancel-field .required { color: #be123c; margin-left: 3px; }
        .cancel-field textarea {
            width: 100%;
            min-height: 80px;
            border: 2px solid #d9e2ec;
            border-radius: 10px;
            padding: 9px 11px;
            font-family: inherit;
            font-size: 0.86rem;
            resize: vertical;
            color: #0f172a;
        }
        .cancel-field textarea:focus {
            outline: none;
            border-color: var(--brand);
            box-shadow: 0 0 0 3px rgba(15,118,110,.12);
        }

        .cancel-form-actions {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            align-items: center;
        }

        .btn-cancel-submit {
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
        .btn-cancel-submit:hover { opacity: 0.88; transform: translateY(-1px); }

        .btn-cancel-abort {
            min-height: 40px;
            border-radius: 12px;
            border: 1px solid var(--neutral-border);
            background: #f8fafc;
            color: var(--neutral-text);
            font-family: inherit;
            font-size: 0.84rem;
            font-weight: 700;
            cursor: pointer;
            padding: 8px 14px;
        }
        .btn-cancel-abort:hover { background: #e2e8f0; }

        .cancel-pending-notice {
            display: flex;
            align-items: flex-start;
            gap: 10px;
            background: #f0f9ff;
            border: 1px solid #bae6fd;
            border-radius: 12px;
            padding: 12px 14px;
            color: #0369a1;
        }
        .cancel-pending-notice i { font-size: 1rem; margin-top: 1px; flex-shrink: 0; }
        .cancel-pending-title {
            font-size: 0.86rem;
            font-weight: 800;
            margin-bottom: 3px;
        }
        .cancel-pending-body {
            font-size: 0.8rem;
            opacity: 0.85;
            line-height: 1.4;
        }
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
            <a href="customer_requests.php?tab=<?php echo urlencode($tabAccessToken); ?>" class="sidebar-menu-item active">
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
            <a href="messages.php?tab=<?php echo urlencode($tabAccessToken); ?>" class="sidebar-menu-item">
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
        </nav>

        <div class="sidebar-footer">
            <a href="logout.php" class="sidebar-menu-item">
                <i class="fas fa-right-from-bracket"></i>
                <?php echo htmlspecialchars(t('sidebar_sign_out'), ENT_QUOTES, 'UTF-8'); ?>
            </a>
        </div>
    </aside>

    <!-- Full-page shell containing navigation, summaries, and request history cards -->
    <main class="shell">
        <!-- Top bar for navigation and account context -->
        <section class="topbar" aria-label="Requests navigation bar">
            <div class="topbar-title">
                <h1><?php echo htmlspecialchars(t('req_title'), ENT_QUOTES, 'UTF-8'); ?></h1>
                <p><?php echo htmlspecialchars(t('req_subtitle'), ENT_QUOTES, 'UTF-8'); ?></p>
            </div>
            <a href="<?php echo htmlspecialchars(langSwitchUrl(), ENT_QUOTES, 'UTF-8'); ?>"
               style="display:inline-flex;align-items:center;gap:6px;font-size:.82rem;font-weight:700;color:#0f766e;text-decoration:none;border:1.5px solid #dbe2ea;padding:6px 14px;border-radius:999px;background:#fff;white-space:nowrap;">
                <i class="fa-solid fa-globe"></i><?php echo htmlspecialchars(t('lang_switch_label'), ENT_QUOTES, 'UTF-8'); ?>
            </a>
        </section>

        <!-- Error/success banners for update and fetch operations -->
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

        <!-- Status summary cards for quick overview of request distribution -->
        <section class="summary-grid" aria-label="Request status summary">
            <article class="summary-card">
                <p class="label"><?php echo htmlspecialchars(t('req_status_pending'), ENT_QUOTES, 'UTF-8'); ?></p>
                <p class="value"><?php echo htmlspecialchars((string) $statusCounts['Pending'], ENT_QUOTES, 'UTF-8'); ?></p>
            </article>
            <article class="summary-card">
                <p class="label"><?php echo htmlspecialchars(t('req_status_confirmed'), ENT_QUOTES, 'UTF-8'); ?></p>
                <p class="value"><?php echo htmlspecialchars((string) $statusCounts['Confirmed'], ENT_QUOTES, 'UTF-8'); ?></p>
            </article>
            <article class="summary-card">
                <p class="label"><?php echo htmlspecialchars(t('req_status_completed'), ENT_QUOTES, 'UTF-8'); ?></p>
                <p class="value"><?php echo htmlspecialchars((string) $statusCounts['Completed'], ENT_QUOTES, 'UTF-8'); ?></p>
            </article>
            <article class="summary-card">
                <p class="label"><?php echo htmlspecialchars(t('req_status_cancelled'), ENT_QUOTES, 'UTF-8'); ?></p>
                <p class="value"><?php echo htmlspecialchars((string) $statusCounts['Cancelled'], ENT_QUOTES, 'UTF-8'); ?></p>
            </article>
        </section>

        <!-- Filter and sort controls -->
        <?php
            $baseFilterUrl = 'customer_requests.php?tab=' . urlencode($tabAccessToken);
            function filterUrl(string $base, string $status, string $sort): string {
                $url = $base;
                if ($status !== '') {
                    $url .= '&status=' . urlencode($status);
                }
                $url .= '&sort=' . urlencode($sort);
                return $url;
            }
            $statusLabels = [
                'Pending'   => t('req_status_pending'),
                'Confirmed' => t('req_status_confirmed'),
                'Completed' => t('req_status_completed'),
                'Cancelled' => t('req_status_cancelled'),
            ];
        ?>
        <section class="filter-bar" aria-label="Filter and sort controls">
            <div class="filter-group">
                <span class="filter-label"><?php echo htmlspecialchars(t('filter_status_label'), ENT_QUOTES, 'UTF-8'); ?></span>
                <a class="filter-pill <?php echo $filterStatus === '' ? 'is-active' : ''; ?>" href="<?php echo htmlspecialchars(filterUrl($baseFilterUrl, '', $sortOrder), ENT_QUOTES, 'UTF-8'); ?>">
                    <?php echo htmlspecialchars(t('filter_all'), ENT_QUOTES, 'UTF-8'); ?> <span>(<?php echo array_sum($statusCounts); ?>)</span>
                </a>
                <?php foreach (['Pending', 'Confirmed', 'Completed', 'Cancelled'] as $statusOption): ?>
                    <a class="filter-pill <?php echo $filterStatus === $statusOption ? 'is-active' : ''; ?>" href="<?php echo htmlspecialchars(filterUrl($baseFilterUrl, $statusOption, $sortOrder), ENT_QUOTES, 'UTF-8'); ?>">
                        <?php echo htmlspecialchars($statusLabels[$statusOption], ENT_QUOTES, 'UTF-8'); ?>
                        <span>(<?php echo htmlspecialchars((string) ($statusCounts[$statusOption] ?? 0), ENT_QUOTES, 'UTF-8'); ?>)</span>
                    </a>
                <?php endforeach; ?>
            </div>
            <div class="filter-group">
                <span class="filter-label"><?php echo htmlspecialchars(t('filter_sort_label'), ENT_QUOTES, 'UTF-8'); ?></span>
                <a class="filter-pill <?php echo $sortOrder === 'newest' ? 'is-active' : ''; ?>" href="<?php echo htmlspecialchars(filterUrl($baseFilterUrl, $filterStatus, 'newest'), ENT_QUOTES, 'UTF-8'); ?>">
                    <i class="fas fa-arrow-down-wide-short" aria-hidden="true"></i> <?php echo htmlspecialchars(t('filter_latest'), ENT_QUOTES, 'UTF-8'); ?>
                </a>
                <a class="filter-pill <?php echo $sortOrder === 'oldest' ? 'is-active' : ''; ?>" href="<?php echo htmlspecialchars(filterUrl($baseFilterUrl, $filterStatus, 'oldest'), ENT_QUOTES, 'UTF-8'); ?>">
                    <i class="fas fa-arrow-up-wide-short" aria-hidden="true"></i> <?php echo htmlspecialchars(t('filter_oldest'), ENT_QUOTES, 'UTF-8'); ?>
                </a>
            </div>
        </section>

        <!-- Main request history list -->
        <section class="requests-list" aria-label="Customer request history">
            <?php if (count($displayRequests) === 0): ?>
                <article class="empty-state">
                    <?php if ($filterStatus !== ''): ?>
                        <?php echo htmlspecialchars(t('filter_no_status_results', ['status' => ($statusLabels[$filterStatus] ?? $filterStatus)]), ENT_QUOTES, 'UTF-8'); ?>
                        <a href="<?php echo htmlspecialchars($baseFilterUrl . '&sort=' . urlencode($sortOrder), ENT_QUOTES, 'UTF-8'); ?>" style="color:#0f766e;font-weight:800;text-decoration:none;"><?php echo htmlspecialchars(t('filter_view_all'), ENT_QUOTES, 'UTF-8'); ?></a>
                    <?php else: ?>
                        <?php echo htmlspecialchars(t('req_empty_start'), ENT_QUOTES, 'UTF-8'); ?>
                    <?php endif; ?>
                </article>
            <?php endif; ?>

            <?php foreach ($displayRequests as $request): ?>
                <?php
                    $statusClass = strtolower($request['status']);
                    if (!in_array($statusClass, ['pending', 'confirmed', 'completed', 'cancelled'], true)) {
                        $statusClass = 'pending';
                    }
                    $requestRating = $request['rating'];
                ?>
                <article id="request-<?php echo htmlspecialchars((string) $request['request_id'], ENT_QUOTES, 'UTF-8'); ?>" class="request-card <?php echo htmlspecialchars($statusClass, ENT_QUOTES, 'UTF-8'); ?>">
                    <header class="request-head">
                        <h2><?php echo htmlspecialchars(t('req_request_num'), ENT_QUOTES, 'UTF-8'); ?><?php echo htmlspecialchars((string) $request['request_id'], ENT_QUOTES, 'UTF-8'); ?></h2>
                        <span class="status-pill <?php echo htmlspecialchars($statusClass, ENT_QUOTES, 'UTF-8'); ?>">
                            <?php echo htmlspecialchars($statusLabels[$request['status']] ?? $request['status'], ENT_QUOTES, 'UTF-8'); ?>
                        </span>
                    </header>

                    <div class="request-meta">
                        <span class="meta-chip">
                            <i class="fas fa-wrench" aria-hidden="true"></i>
                            <?php
                                $dispCatName = $request['category_name'];
                                if (getLang() === 'ar' && isset($reqCategoryEnToAr[$dispCatName])) {
                                    $dispCatName = $reqCategoryEnToAr[$dispCatName];
                                }
                                echo htmlspecialchars($dispCatName, ENT_QUOTES, 'UTF-8');
                            ?>
                        </span>
                        <span class="meta-chip">
                            <i class="fas fa-calendar-day" aria-hidden="true"></i>
                            <?php echo htmlspecialchars(reqLocalizedDate($request['appointment_date']), ENT_QUOTES, 'UTF-8'); ?>
                        </span>
                        <span class="meta-chip">
                            <i class="fas fa-clock" aria-hidden="true"></i>
                            <?php echo htmlspecialchars(toArabicNumerals(substr($request['appointment_time'], 0, 5)), ENT_QUOTES, 'UTF-8'); ?>
                        </span>
                    </div>

                    <a class="provider-link" href="provider/<?php echo (int) $request['provider_id']; ?>?tab=<?php echo urlencode($tabAccessToken); ?>">
                        <i class="fas fa-id-card" aria-hidden="true"></i>
                        <?php echo htmlspecialchars($request['provider_name'], ENT_QUOTES, 'UTF-8'); ?>
                    </a>

                    <p class="description">
                        <?php echo htmlspecialchars($request['category_description'] !== '' ? $request['category_description'] : t('req_no_desc'), ENT_QUOTES, 'UTF-8'); ?>
                    </p>

                    <p class="price-row">
                        <span><?php echo htmlspecialchars(t('req_price_estimated'), ENT_QUOTES, 'UTF-8'); ?> <?php echo $request['estimated_price'] !== null ? ('$' . htmlspecialchars(toArabicNumerals(number_format((float) $request['estimated_price'], 2)), ENT_QUOTES, 'UTF-8')) : htmlspecialchars(t('prov_req_na'), ENT_QUOTES, 'UTF-8'); ?></span>
                        <span><?php echo htmlspecialchars(t('req_price_final'), ENT_QUOTES, 'UTF-8'); ?> <?php echo $request['final_price'] !== null ? ('$' . htmlspecialchars(toArabicNumerals(number_format((float) $request['final_price'], 2)), ENT_QUOTES, 'UTF-8')) : htmlspecialchars(t('prov_req_na'), ENT_QUOTES, 'UTF-8'); ?></span>
                    </p>

                    <?php if ($request['cancellation_pending']): ?>
                        <div class="cancel-pending-notice" role="status">
                            <i class="fas fa-hourglass-half" aria-hidden="true"></i>
                            <div>
                                <p class="cancel-pending-title"><?php echo htmlspecialchars(t('req_cancel_pending_msg'), ENT_QUOTES, 'UTF-8'); ?></p>
                                <p class="cancel-pending-body"><?php echo htmlspecialchars(t('req_cancel_pending_note'), ENT_QUOTES, 'UTF-8'); ?></p>
                            </div>
                        </div>
                    <?php elseif ($request['can_cancel']): ?>
                        <?php $cancelPanelId = 'cancel-panel-' . (int) $request['request_id']; ?>
                        <div class="cancel-section">
                            <button type="button" class="btn-cancel-toggle" data-target="<?php echo htmlspecialchars($cancelPanelId, ENT_QUOTES, 'UTF-8'); ?>">
                                <i class="fas fa-ban" aria-hidden="true"></i>
                                <?php echo htmlspecialchars(t('req_cancel_btn'), ENT_QUOTES, 'UTF-8'); ?>
                            </button>
                            <div class="cancel-panel" id="<?php echo htmlspecialchars($cancelPanelId, ENT_QUOTES, 'UTF-8'); ?>" style="display:none">
                                <?php if ($request['status'] === 'Confirmed'): ?>
                                    <p class="cancel-notice cancel-notice--warn">
                                        <i class="fas fa-triangle-exclamation" aria-hidden="true"></i>
                                        <?php echo htmlspecialchars(t('req_cancel_confirmed_warning'), ENT_QUOTES, 'UTF-8'); ?>
                                    </p>
                                <?php endif; ?>
                                <form method="post" action="customer_requests.php?tab=<?php echo urlencode($tabAccessToken); ?>#request-<?php echo urlencode((string) $request['request_id']); ?>">
                                    <input type="hidden" name="form_action" value="cancel_request">
                                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars((string) $_SESSION['customer_cancel_csrf'], ENT_QUOTES, 'UTF-8'); ?>">
                                    <input type="hidden" name="tab" value="<?php echo htmlspecialchars($tabAccessToken, ENT_QUOTES, 'UTF-8'); ?>">
                                    <input type="hidden" name="request_id" value="<?php echo htmlspecialchars((string) $request['request_id'], ENT_QUOTES, 'UTF-8'); ?>">
                                    <div class="cancel-field">
                                        <label for="cancel-reason-<?php echo (int) $request['request_id']; ?>">
                                            <?php echo htmlspecialchars(t('req_cancel_reason_label'), ENT_QUOTES, 'UTF-8'); ?>
                                            <?php if ($request['status'] === 'Confirmed'): ?>
                                                <span class="required" aria-hidden="true">*</span>
                                            <?php endif; ?>
                                        </label>
                                        <textarea
                                            id="cancel-reason-<?php echo (int) $request['request_id']; ?>"
                                            name="cancel_reason"
                                            rows="3"
                                            placeholder="<?php echo htmlspecialchars(t('req_cancel_reason_ph'), ENT_QUOTES, 'UTF-8'); ?>"
                                            maxlength="1000"
                                            <?php echo $request['status'] === 'Confirmed' ? 'required' : ''; ?>
                                        ></textarea>
                                    </div>
                                    <div class="cancel-form-actions">
                                        <button type="submit" class="btn-cancel-submit">
                                            <i class="fas fa-ban" aria-hidden="true"></i>
                                            <?php echo htmlspecialchars(t('req_cancel_confirm_btn'), ENT_QUOTES, 'UTF-8'); ?>
                                        </button>
                                        <button type="button" class="btn-cancel-abort" data-target="<?php echo htmlspecialchars($cancelPanelId, ENT_QUOTES, 'UTF-8'); ?>">
                                            <?php echo htmlspecialchars(t('req_cancel_abort_btn'), ENT_QUOTES, 'UTF-8'); ?>
                                        </button>
                                    </div>
                                </form>
                            </div>
                        </div>
                    <?php endif; ?>

                    <?php if (count($request['images']) > 0): ?>
                        <div class="image-grid" aria-label="Uploaded problem images">
                            <?php foreach ($request['images'] as $imagePath): ?>
                                <figure class="image-card">
                                    <img src="<?php echo htmlspecialchars($imagePath, ENT_QUOTES, 'UTF-8'); ?>" alt="Problem image for request <?php echo htmlspecialchars((string) $request['request_id'], ENT_QUOTES, 'UTF-8'); ?>">
                                </figure>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>

                    <div class="review-display">
                        <p>
                            <strong><?php echo htmlspecialchars(t('req_current_rating'), ENT_QUOTES, 'UTF-8'); ?></strong>
                            <?php if ($requestRating !== null && $requestRating >= 1 && $requestRating <= 5): ?>
                                <span class="stars-readonly" aria-label="<?php echo htmlspecialchars((string) $requestRating, ENT_QUOTES, 'UTF-8'); ?> stars">
                                    <?php for ($star = 1; $star <= 5; $star++): ?>
                                        <i class="fas fa-star star <?php echo $star <= $requestRating ? '' : 'is-empty'; ?>" aria-hidden="true"></i>
                                    <?php endfor; ?>
                                </span>
                                <span class="rating-text"><?php echo htmlspecialchars((string) $requestRating, ENT_QUOTES, 'UTF-8'); ?>/5</span>
                            <?php else: ?>
                                <span class="rating-text"><?php echo htmlspecialchars(t('req_no_rating'), ENT_QUOTES, 'UTF-8'); ?></span>
                            <?php endif; ?>
                        </p>

                        <p>
                            <strong><?php echo htmlspecialchars(t('req_current_review'), ENT_QUOTES, 'UTF-8'); ?></strong>
                            <?php echo $request['review'] !== ''
                                ? nl2br(htmlspecialchars($request['review'], ENT_QUOTES, 'UTF-8'))
                                : htmlspecialchars(t('req_no_review'), ENT_QUOTES, 'UTF-8'); ?>
                        </p>
                    </div>

                    <?php if (in_array($request['status'], ['Confirmed', 'Completed'], true)): ?>
                        <a class="btn-message" href="messages.php?request_id=<?php echo (int) $request['request_id']; ?>&amp;tab=<?php echo urlencode($tabAccessToken); ?>">
                            <i class="fas fa-comments" aria-hidden="true"></i>
                            <?php echo htmlspecialchars(t('req_chat_btn'), ENT_QUOTES, 'UTF-8'); ?>
                        </a>
                    <?php endif; ?>

                    <?php if ($request['can_rate']): ?>
                        <form class="review-form" method="post" action="customer_requests.php?tab=<?php echo urlencode($tabAccessToken); ?>#request-<?php echo urlencode((string) $request['request_id']); ?>" novalidate>
                            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars((string) $_SESSION['customer_review_csrf'], ENT_QUOTES, 'UTF-8'); ?>">
                            <input type="hidden" name="tab" value="<?php echo htmlspecialchars($tabAccessToken, ENT_QUOTES, 'UTF-8'); ?>">
                            <input type="hidden" name="request_id" value="<?php echo htmlspecialchars((string) $request['request_id'], ENT_QUOTES, 'UTF-8'); ?>">

                            <h3><?php echo htmlspecialchars(t('req_rate_title'), ENT_QUOTES, 'UTF-8'); ?></h3>

                            <div class="star-picker" aria-label="Rating selector for request <?php echo htmlspecialchars((string) $request['request_id'], ENT_QUOTES, 'UTF-8'); ?>">
                                <?php for ($star = 5; $star >= 1; $star--): ?>
                                    <?php $starId = 'request-' . (string) $request['request_id'] . '-star-' . (string) $star; ?>
                                    <input
                                        type="radio"
                                        id="<?php echo htmlspecialchars($starId, ENT_QUOTES, 'UTF-8'); ?>"
                                        name="rating"
                                        value="<?php echo htmlspecialchars((string) $star, ENT_QUOTES, 'UTF-8'); ?>"
                                        <?php
                                            $effectiveRating = $requestRating !== null && $requestRating >= 1 && $requestRating <= 5 ? $requestRating : 0;
                                            echo $effectiveRating === $star ? 'checked' : '';
                                        ?>
                                        required
                                    >
                                    <label for="<?php echo htmlspecialchars($starId, ENT_QUOTES, 'UTF-8'); ?>" title="<?php echo htmlspecialchars((string) $star, ENT_QUOTES, 'UTF-8'); ?> star<?php echo $star > 1 ? 's' : ''; ?>">
                                        <i class="fas fa-star" aria-hidden="true"></i>
                                    </label>
                                <?php endfor; ?>
                            </div>

                            <textarea name="review" maxlength="2000" placeholder="<?php echo htmlspecialchars(t('req_review_placeholder'), ENT_QUOTES, 'UTF-8'); ?>"><?php echo htmlspecialchars($request['review'], ENT_QUOTES, 'UTF-8'); ?></textarea>
                            <p class="hint"><?php echo htmlspecialchars(t('req_review_hint'), ENT_QUOTES, 'UTF-8'); ?></p>

                            <button class="btn-save" type="submit">
                                <i class="fas fa-floppy-disk" aria-hidden="true"></i>
                                <?php echo htmlspecialchars(t('req_save_review'), ENT_QUOTES, 'UTF-8'); ?>
                            </button>
                        </form>
                    <?php endif; ?>
                </article>
            <?php endforeach; ?>
        </section>
    </main>

    <script>
        /*
         * Prevent duplicate submit clicks on rating forms.
         * This helps avoid accidental repeated updates when network is slow.
         */
        document.querySelectorAll('.review-form').forEach(function (formElement) {
            formElement.addEventListener('submit', function () {
                var submitButton = formElement.querySelector('button[type="submit"]');
                if (!submitButton) {
                    return;
                }

                submitButton.disabled = true;
                submitButton.style.opacity = '0.72';
            });
        });

        /*
         * Toggle visibility of inline cancellation reason panels.
         */
        document.querySelectorAll('.btn-cancel-toggle').forEach(function (btn) {
            btn.addEventListener('click', function () {
                var targetId = btn.getAttribute('data-target');
                var panel = document.getElementById(targetId);
                if (!panel) return;
                var isVisible = panel.style.display !== 'none';
                panel.style.display = isVisible ? 'none' : 'grid';
                if (!isVisible) {
                    var textarea = panel.querySelector('textarea');
                    if (textarea) textarea.focus();
                }
            });
        });

        document.querySelectorAll('.btn-cancel-abort').forEach(function (btn) {
            btn.addEventListener('click', function () {
                var targetId = btn.getAttribute('data-target');
                var panel = document.getElementById(targetId);
                if (panel) panel.style.display = 'none';
            });
        });

        document.querySelectorAll('.btn-cancel-submit').forEach(function (btn) {
            btn.closest('form') && btn.closest('form').addEventListener('submit', function () {
                btn.disabled = true;
                btn.style.opacity = '0.72';
            });
        });


        /* Scroll-to and highlight a specific request card when arriving via a #request-{id} fragment link */
        (function () {
            var hash = window.location.hash;
            if (!hash || !hash.startsWith('#request-')) return;

            var targetId = hash.slice(1); // e.g. "request-42"
            var card = document.getElementById(targetId);
            if (!card) return;

            // Small delay so the browser's own scroll doesn't interfere
            setTimeout(function () {
                card.scrollIntoView({ behavior: 'smooth', block: 'center' });
                card.classList.add('highlighted');
                setTimeout(function () { card.classList.remove('highlighted'); }, 2400);
            }, 80);
        })();

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
</body>
</html>

