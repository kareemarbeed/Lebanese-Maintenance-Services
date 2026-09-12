<?php
declare(strict_types=1);

session_start();

// Compute absolute base path early so all redirects and links are correct
// regardless of whether this page was accessed via a clean URL or directly.
$appBase = rtrim(str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'])), '/');

require_once __DIR__ . '/db_connection.php';
require_once __DIR__ . '/verification_store.php';
require_once __DIR__ . '/suspension_store.php';
require_once __DIR__ . '/site_settings.php';
require_once __DIR__ . '/lang.php';

// Admin-only guard
if (!isset($_SESSION['user_type']) || (string) $_SESSION['user_type'] !== 'admin') {
    header('Location: ' . $appBase . '/login.php');
    exit;
}

ensureSiteSettingsTable($pdo);
$siteSettings = loadSiteSettings($pdo, ['site_favicon' => '']);
$siteFavicon  = trim((string) ($siteSettings['site_favicon'] ?? ''));

// Read and validate route params
$profileType = strtolower(trim((string) ($_GET['type'] ?? '')));
$profileId   = (int) ($_GET['id']   ?? 0);

if (!in_array($profileType, ['provider', 'customer'], true) || $profileId <= 0) {
    header('Location: ' . $appBase . '/admin_dashboard.php');
    exit;
}

// Review sorting / pagination / filter
$allowedSorts = ['newest', 'highest', 'lowest'];
$reviewSort   = trim((string) ($_GET['sort'] ?? 'newest'));
if (!in_array($reviewSort, $allowedSorts, true)) {
    $reviewSort = 'newest';
}

$ratingFilter = (int) ($_GET['stars'] ?? 0);
if ($ratingFilter < 1 || $ratingFilter > 5) {
    $ratingFilter = 0;
}

$reviewsPerPage = 10;
$reviewPage     = max(1, (int) ($_GET['page'] ?? 1));
$reviewOffset   = ($reviewPage - 1) * $reviewsPerPage;

$sortClause = match ($reviewSort) {
    'highest' => 'sr.rating DESC, sr.request_id DESC',
    'lowest'  => 'sr.rating ASC,  sr.request_id DESC',
    default   => 'sr.request_id DESC',
};

// Verification / suspension lookups
$verifiedProviderLookup  = buildVerifiedProviderLookup(loadVerifiedProviderIds());
$suspendedAccountIds     = loadSuspendedAccountIds();
$suspendedProviderLookup = buildSuspendedLookup((array) ($suspendedAccountIds['providers'] ?? []));
$suspendedCustomerLookup = buildSuspendedLookup((array) ($suspendedAccountIds['customers'] ?? []));

$userData     = null;
$reviews      = [];
$reviewTotal  = 0;
$reviewPages  = 1;
$ratingStats  = ['avg' => null, 'count' => 0, 'dist' => [5=>0,4=>0,3=>0,2=>0,1=>0]];
$errorMessage = '';

// ── Ensure schema columns exist ───────────────────────────────────────────────
$schemaMigrations = [
    ['serviceprovider', 'pending_location',       "ALTER TABLE serviceprovider ADD COLUMN pending_location VARCHAR(255) NOT NULL DEFAULT ''"],
    ['serviceprovider', 'location_change_status', "ALTER TABLE serviceprovider ADD COLUMN location_change_status ENUM('none','pending') NOT NULL DEFAULT 'none'"],
    ['serviceprovider', 'photo',                  "ALTER TABLE serviceprovider ADD COLUMN photo VARCHAR(255) NOT NULL DEFAULT ''"],
    ['serviceprovider', 'created_at',             "ALTER TABLE serviceprovider ADD COLUMN created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"],
    ['customer',        'photo',                  "ALTER TABLE customer ADD COLUMN photo VARCHAR(255) NOT NULL DEFAULT ''"],
    ['customer',        'created_at',             "ALTER TABLE customer ADD COLUMN created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"],
];
foreach ($schemaMigrations as [$tbl, $col, $ddl]) {
    try {
        $chk = $pdo->query("SHOW COLUMNS FROM `$tbl` LIKE '$col'");
        if ($chk !== false && $chk->rowCount() === 0) {
            $pdo->exec($ddl);
        }
    } catch (PDOException $migEx) {
        error_log("[admin_user_profile] migration failed for $tbl.$col: " . $migEx->getMessage());
    }
}

// ── Load profile data ─────────────────────────────────────────────────────────
if ($profileType === 'provider') {
    try {
        $stmt = $pdo->prepare(
            'SELECT sp.provider_id AS id,
                    sp.name, sp.email, sp.phone,
                    IFNULL(sp.bio,\'\') AS bio,
                    IFNULL(sp.photo,\'\') AS photo,
                    IFNULL(sp.location,\'\') AS location,
                    IFNULL(sp.pending_location,\'\') AS pending_location,
                    IFNULL(sp.location_change_status,\'none\') AS location_change_status,
                    IFNULL(sp.created_at,\'\') AS registered_at
             FROM serviceprovider sp
             WHERE sp.provider_id = :id
             LIMIT 1'
        );
        $stmt->execute(['id' => $profileId]);
        $row = $stmt->fetch();
        if ($row !== false) {
            // Total request count
            $reqCnt = $pdo->prepare(
                'SELECT COUNT(DISTINCT sr.request_id)
                 FROM servicerequest sr
                 INNER JOIN appointmentslot asl ON sr.slot_id = asl.slot_id
                 WHERE asl.serviceprovider_id = :id'
            );
            $reqCnt->execute(['id' => $profileId]);

            $userData = [
                'id'                     => (int) $row['id'],
                'name'                   => (string) $row['name'],
                'email'                  => (string) ($row['email'] ?? ''),
                'phone'                  => (string) ($row['phone'] ?? ''),
                'bio'                    => (string) $row['bio'],
                'photo'                  => (string) $row['photo'],
                'location'               => (string) $row['location'],
                'pending_location'       => (string) $row['pending_location'],
                'location_change_status' => (string) $row['location_change_status'],
                'is_verified'            => isset($verifiedProviderLookup[$profileId]),
                'is_suspended'           => isset($suspendedProviderLookup[$profileId]),
                'email_verified'         => true,
                'address'                => '',
                'registered_at'          => (string) $row['registered_at'],
                'request_count'          => (int) ($reqCnt->fetchColumn() ?? 0),
            ];
        }
    } catch (PDOException $e) {
        error_log('[admin_user_profile] provider query id=' . $profileId . ': ' . $e->getMessage());
        $errorMessage = t('admin_profile_not_found');
    }

    // ── Provider rating stats ─────────────────────────────────────────────────
    if ($userData !== null) {
        try {
            $statsStmt = $pdo->prepare(
                'SELECT sr.rating
                 FROM servicerequest sr
                 INNER JOIN appointmentslot asl ON sr.slot_id = asl.slot_id
                 WHERE asl.serviceprovider_id = :pid AND sr.rating IS NOT NULL'
            );
            $statsStmt->execute(['pid' => $profileId]);
            $allRatings = $statsStmt->fetchAll(PDO::FETCH_COLUMN);
            if (count($allRatings) > 0) {
                $ratingStats['count'] = count($allRatings);
                $ratingStats['avg']   = round(array_sum($allRatings) / count($allRatings), 1);
                foreach ($allRatings as $r) {
                    $key = max(1, min(5, (int) $r));
                    $ratingStats['dist'][$key]++;
                }
            }
        } catch (PDOException $e) {}

        // ── Count total reviews (for pagination) with filter ─────────────────
        try {
            $filterClause = $ratingFilter > 0 ? ' AND sr.rating = :stars' : '';
            $cntParams    = ['pid' => $profileId];
            if ($ratingFilter > 0) $cntParams['stars'] = $ratingFilter;

            $cntStmt = $pdo->prepare(
                'SELECT COUNT(*) FROM servicerequest sr
                 INNER JOIN appointmentslot asl ON sr.slot_id = asl.slot_id
                 WHERE asl.serviceprovider_id = :pid AND sr.rating IS NOT NULL' . $filterClause
            );
            $cntStmt->execute($cntParams);
            $reviewTotal = (int) $cntStmt->fetchColumn();
            $reviewPages = max(1, (int) ceil($reviewTotal / $reviewsPerPage));
            $reviewPage  = min($reviewPage, $reviewPages);
            $reviewOffset = ($reviewPage - 1) * $reviewsPerPage;
        } catch (PDOException $e) {}

        // ── Load paginated reviews ────────────────────────────────────────────
        try {
            $filterClause = $ratingFilter > 0 ? ' AND sr.rating = :stars' : '';
            $revParams    = ['pid' => $profileId, 'lim' => $reviewsPerPage, 'off' => $reviewOffset];
            if ($ratingFilter > 0) $revParams['stars'] = $ratingFilter;

            $revStmt = $pdo->prepare(
                'SELECT sr.request_id, sr.rating, IFNULL(sr.review,\'\') AS review,
                        asl.date AS appointment_date,
                        COALESCE(c.name, \'Customer\') AS reviewer_name,
                        c.customer_id AS reviewer_id
                 FROM servicerequest sr
                 INNER JOIN appointmentslot asl ON sr.slot_id = asl.slot_id
                 LEFT JOIN customer c ON sr.customer_id = c.customer_id
                 WHERE asl.serviceprovider_id = :pid AND sr.rating IS NOT NULL' . $filterClause .
                ' ORDER BY ' . $sortClause .
                ' LIMIT :lim OFFSET :off'
            );
            $revStmt->bindValue(':pid', $profileId, PDO::PARAM_INT);
            $revStmt->bindValue(':lim', $reviewsPerPage, PDO::PARAM_INT);
            $revStmt->bindValue(':off', $reviewOffset, PDO::PARAM_INT);
            if ($ratingFilter > 0) $revStmt->bindValue(':stars', $ratingFilter, PDO::PARAM_INT);
            $revStmt->execute();
            $reviews = $revStmt->fetchAll(PDO::FETCH_ASSOC);
        } catch (PDOException $e) {}
    }
} else {
    // ── Customer profile ──────────────────────────────────────────────────────
    try {
        $stmt = $pdo->prepare(
            'SELECT c.customer_id AS id, c.name, c.email, c.phone,
                    IFNULL(c.photo,\'\') AS photo,
                    IFNULL(c.is_verified,1) AS is_verified_email,
                    IFNULL(c.created_at,\'\') AS registered_at,
                    c.latitude, c.longitude
             FROM customer c
             WHERE c.customer_id = :id
             LIMIT 1'
        );
        $stmt->execute(['id' => $profileId]);
        $row = $stmt->fetch();
        if ($row !== false) {
            $reqCnt = $pdo->prepare(
                'SELECT COUNT(*) FROM servicerequest WHERE customer_id = :id'
            );
            $reqCnt->execute(['id' => $profileId]);

            $userData = [
                'id'                     => (int) $row['id'],
                'name'                   => (string) $row['name'],
                'email'                  => (string) ($row['email'] ?? ''),
                'phone'                  => (string) ($row['phone'] ?? ''),
                'bio'                    => '',
                'photo'                  => (string) $row['photo'],
                'location'               => '',
                'pending_location'       => '',
                'location_change_status' => 'none',
                'is_verified'            => false,
                'is_suspended'           => isset($suspendedCustomerLookup[$profileId]),
                'email_verified'         => (bool) $row['is_verified_email'],
                'latitude'               => $row['latitude'] !== null ? (float) $row['latitude']  : null,
                'longitude'              => $row['longitude'] !== null ? (float) $row['longitude'] : null,
                'registered_at'          => (string) $row['registered_at'],
                'request_count'          => (int) ($reqCnt->fetchColumn() ?? 0),
            ];
        }
    } catch (PDOException $e) {
        error_log('[admin_user_profile] customer query id=' . $profileId . ': ' . $e->getMessage());
        $errorMessage = t('admin_profile_not_found');
    }

    // ── Customer review activity ──────────────────────────────────────────────
    if ($userData !== null) {
        try {
            $filterClause = $ratingFilter > 0 ? ' AND sr.rating = :stars' : '';
            $cntParams    = ['cid' => $profileId];
            if ($ratingFilter > 0) $cntParams['stars'] = $ratingFilter;

            $cntStmt = $pdo->prepare(
                'SELECT COUNT(*) FROM servicerequest sr WHERE sr.customer_id = :cid AND sr.rating IS NOT NULL' . $filterClause
            );
            $cntStmt->execute($cntParams);
            $reviewTotal = (int) $cntStmt->fetchColumn();
            $reviewPages = max(1, (int) ceil($reviewTotal / $reviewsPerPage));
            $reviewPage  = min($reviewPage, $reviewPages);
            $reviewOffset = ($reviewPage - 1) * $reviewsPerPage;
        } catch (PDOException $e) {}

        try {
            $filterClause = $ratingFilter > 0 ? ' AND sr.rating = :stars' : '';
            $revParams    = ['cid' => $profileId];
            if ($ratingFilter > 0) $revParams['stars'] = $ratingFilter;

            $revStmt = $pdo->prepare(
                'SELECT sr.request_id, sr.rating, IFNULL(sr.review,\'\') AS review,
                        asl.date AS appointment_date,
                        COALESCE(sp.name, \'Provider\') AS provider_name,
                        sp.provider_id
                 FROM servicerequest sr
                 INNER JOIN appointmentslot asl ON sr.slot_id = asl.slot_id
                 INNER JOIN serviceprovider sp ON asl.serviceprovider_id = sp.provider_id
                 WHERE sr.customer_id = :cid AND sr.rating IS NOT NULL' . $filterClause .
                ' ORDER BY ' . $sortClause .
                ' LIMIT :lim OFFSET :off'
            );
            $revStmt->bindValue(':cid', $profileId, PDO::PARAM_INT);
            $revStmt->bindValue(':lim', $reviewsPerPage, PDO::PARAM_INT);
            $revStmt->bindValue(':off', $reviewOffset, PDO::PARAM_INT);
            if ($ratingFilter > 0) $revStmt->bindValue(':stars', $ratingFilter, PDO::PARAM_INT);
            $revStmt->execute();
            $reviews = $revStmt->fetchAll(PDO::FETCH_ASSOC);
        } catch (PDOException $e) {}
    }
}

if ($userData === null && $errorMessage === '') {
    $errorMessage = t('admin_profile_not_found');
}

$pageTitle  = $profileType === 'provider' ? t('admin_profile_provider') : t('admin_profile_customer');

$backUrl = $appBase . '/admin_dashboard.php';

// Helper: build star HTML (integer 1–5)
function starHtml(int $rating): string
{
    $html = '<span class="stars" aria-label="' . $rating . ' out of 5">';
    for ($i = 1; $i <= 5; $i++) {
        $html .= $i <= $rating
            ? '<i class="fas fa-star"></i>'
            : '<i class="far fa-star"></i>';
    }
    $html .= '</span>';
    return $html;
}

// Helper: half-star average display
function avgStarHtml(float $avg): string
{
    $html = '<span class="stars" aria-label="' . $avg . ' out of 5">';
    for ($i = 1; $i <= 5; $i++) {
        if ($avg >= $i) {
            $html .= '<i class="fas fa-star"></i>';
        } elseif ($avg >= $i - 0.5) {
            $html .= '<i class="fas fa-star-half-alt"></i>';
        } else {
            $html .= '<i class="far fa-star"></i>';
        }
    }
    $html .= '</span>';
    return $html;
}

// Helper: build pagination URL (preserves all current params)
function pageUrl(int $page): string
{
    $params = $_GET;
    $params['page'] = $page;
    return '?' . http_build_query($params);
}

function sortUrl(string $sort): string
{
    $params = $_GET;
    $params['sort'] = $sort;
    $params['page'] = 1;
    return '?' . http_build_query($params);
}

function starsUrl(int $stars): string
{
    $params = $_GET;
    if ($stars > 0) { $params['stars'] = $stars; } else { unset($params['stars']); }
    $params['page'] = 1;
    return '?' . http_build_query($params);
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
    <title><?php echo htmlspecialchars($pageTitle, ENT_QUOTES, 'UTF-8'); ?> — <?php echo htmlspecialchars(t('site_name'), ENT_QUOTES, 'UTF-8'); ?></title>
    <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&display=swap" rel="stylesheet">
    <?php if (isRtl()): ?>
    <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <?php endif; ?>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }

        :root {
            --brand: #0f766e;
            --brand-deep: #115e59;
            --ink: #0f172a;
            --muted: #475569;
            --surface: #f8fafc;
            --card: rgba(255,255,255,.94);
            --line: rgba(15,23,42,.08);
            --star: #f59e0b;
        }

        body {
            font-family: 'Space Grotesk', sans-serif;
            color: var(--ink);
            min-height: 100vh;
            background:
                radial-gradient(circle at 8% 12%, rgba(15,118,110,.15), transparent 38%),
                radial-gradient(circle at 92% 8%, rgba(249,115,22,.18), transparent 35%),
                linear-gradient(135deg, #f8fafc, #ecfeff 55%, #fff7ed);
            padding: 28px 16px 60px;
        }

        [dir="rtl"] body { font-family: 'Cairo', sans-serif; }

        .shell { max-width: 960px; margin: 0 auto; display: flex; flex-direction: column; gap: 20px; }

        /* Back button */
        .back-btn {
            display: inline-flex; align-items: center; gap: 8px;
            padding: 9px 18px; border-radius: 12px;
            background: #fff; border: 1.5px solid var(--line);
            color: var(--ink); font-family: inherit; font-size: .9rem; font-weight: 600;
            text-decoration: none; transition: box-shadow .2s, transform .2s;
        }
        .back-btn:hover { transform: translateY(-1px); box-shadow: 0 6px 18px rgba(15,23,42,.1); }

        /* Profile card */
        .profile-card {
            background: var(--card);
            border-radius: 24px;
            border: 1px solid rgba(255,255,255,.8);
            box-shadow: 0 20px 50px rgba(15,23,42,.1);
            overflow: hidden;
        }

        /* Hero strip */
        .profile-hero {
            background: linear-gradient(135deg, var(--brand), var(--brand-deep));
            padding: 32px 28px 24px;
            display: flex; align-items: flex-end; gap: 20px; flex-wrap: wrap;
        }

        .profile-avatar {
            width: 96px; height: 96px; border-radius: 50%;
            border: 4px solid rgba(255,255,255,.35);
            background: rgba(255,255,255,.15); overflow: hidden; flex-shrink: 0;
            display: flex; align-items: center; justify-content: center;
            font-size: 2.4rem; color: rgba(255,255,255,.8);
        }
        .profile-avatar img { width:100%; height:100%; object-fit:cover; }

        .profile-hero-info { flex:1; min-width:0; }
        .profile-hero-info h1 { font-size:1.5rem; font-weight:700; color:#fff; margin-bottom:6px; }

        .badge {
            display: inline-flex; align-items: center; gap:5px;
            padding: 4px 10px; border-radius: 999px;
            font-size:.78rem; font-weight:700; margin:2px;
        }
        .badge.verified   { background:rgba(255,255,255,.25); color:#fff; }
        .badge.unverified { background:rgba(249,115,22,.3); color:#fff; }
        .badge.suspended  { background:rgba(239,68,68,.35); color:#fff; }
        .badge.active     { background:rgba(22,163,74,.3); color:#fff; }
        .badge.type-badge { background:rgba(255,255,255,.15); color:#fff; }

        /* Stats row */
        .stats-row { display:flex; gap:12px; flex-wrap:wrap; padding:20px 28px; }
        .stat-chip {
            display:flex; flex-direction:column; align-items:center;
            background:linear-gradient(145deg,var(--brand),var(--brand-deep));
            color:#fff; border-radius:16px; padding:14px 22px; min-width:100px;
        }
        .stat-chip.dark { background:linear-gradient(145deg,#334155,#1e293b); }
        .stat-chip.amber { background:linear-gradient(145deg,#d97706,#92400e); }
        .stat-chip .stat-num { font-size:1.5rem; font-weight:700; }
        .stat-chip .stat-lbl { font-size:.76rem; opacity:.85; margin-top:2px; text-align:center; }

        /* Info grid */
        .profile-body {
            padding:0 28px 24px;
            display:grid; grid-template-columns:1fr 1fr; gap:14px;
        }
        @media (max-width:600px) {
            .profile-body { grid-template-columns:1fr; }
            .profile-hero { padding:22px 18px 18px; }
            .stats-row, .profile-body { padding-left:18px; padding-right:18px; }
        }

        .info-block {
            background:var(--surface); border-radius:12px;
            padding:14px 16px; border:1px solid var(--line);
        }
        .info-block.full { grid-column:1/-1; }
        .info-block label {
            display:block; font-size:.75rem; font-weight:700; color:var(--muted);
            text-transform:uppercase; letter-spacing:.05em; margin-bottom:5px;
        }
        .info-block .value { font-size:.93rem; font-weight:600; color:var(--ink); word-break:break-word; }
        .info-block .value.muted { color:#94a3b8; font-weight:500; font-style:italic; }

        /* Pending location banner */
        .pending-banner {
            margin: 0 28px 0;
            background:#fef9c3; border:1px solid #fde68a;
            border-radius:12px; padding:12px 16px;
            font-size:.9rem; color:#92400e;
            display:flex; align-items:center; gap:10px;
        }

        /* ── Reviews section ───────────────────────────────────────────────── */
        .reviews-section {
            border-top: 1px solid var(--line);
            padding: 28px;
        }

        .reviews-section h2 {
            font-size: 1.15rem; font-weight: 700; color: var(--ink);
            margin-bottom: 4px;
        }
        .reviews-section .section-lead {
            font-size: .88rem; color: var(--muted); margin-bottom: 18px;
        }

        /* Rating distribution */
        .rating-overview {
            display: flex; gap: 20px; flex-wrap: wrap; margin-bottom: 24px;
        }
        .rating-big {
            display: flex; flex-direction: column; align-items: center;
            background: var(--surface); border: 1px solid var(--line);
            border-radius: 16px; padding: 18px 24px; min-width: 120px;
        }
        .rating-big .num { font-size: 2.8rem; font-weight: 800; color: var(--ink); line-height: 1; }
        .rating-big .stars { margin: 6px 0 4px; font-size: 1rem; }
        .rating-big .cnt { font-size: .78rem; color: var(--muted); }

        .dist-bars { flex: 1; min-width: 200px; display: flex; flex-direction: column; gap: 6px; }
        .dist-row { display: flex; align-items: center; gap: 8px; font-size: .82rem; }
        .dist-label { width: 54px; font-weight: 600; color: var(--muted); white-space: nowrap; }
        .dist-track { flex: 1; height: 8px; border-radius: 999px; background: #e2e8f0; overflow: hidden; }
        .dist-fill  { height: 100%; border-radius: 999px; background: var(--star); transition: width .4s; }
        .dist-count { width: 28px; text-align: right; color: var(--muted); }

        /* Controls bar */
        .controls-bar {
            display: flex; align-items: center; gap: 8px; flex-wrap: wrap;
            margin-bottom: 16px;
        }
        .ctrl-select {
            padding: 7px 12px; border: 1.5px solid #d9e2ec; border-radius: 10px;
            font-family: inherit; font-size: .85rem; font-weight: 600;
            background: #fff; color: var(--ink); cursor: pointer;
        }
        .ctrl-select:focus { outline: none; border-color: var(--brand); }

        .filter-chips { display: flex; gap: 6px; flex-wrap: wrap; }
        .filter-chip {
            display: inline-flex; align-items: center; gap: 4px;
            padding: 5px 12px; border-radius: 999px; font-size: .8rem; font-weight: 700;
            border: 1.5px solid #d9e2ec; background: #fff; color: var(--muted);
            text-decoration: none; transition: all .15s;
        }
        .filter-chip:hover, .filter-chip.active {
            border-color: var(--brand); background: rgba(15,118,110,.08); color: var(--brand);
        }
        .filter-chip i { font-size: .7rem; }

        /* Review cards */
        .review-card {
            background: var(--surface); border: 1px solid var(--line);
            border-radius: 14px; padding: 16px 18px; margin-bottom: 12px;
        }
        .review-card-header {
            display: flex; align-items: flex-start; justify-content: space-between;
            flex-wrap: wrap; gap: 8px; margin-bottom: 8px;
        }
        .review-meta { display: flex; flex-direction: column; gap: 3px; }
        .review-meta .reviewer-name { font-weight: 700; font-size: .92rem; color: var(--ink); }
        .review-meta .review-date   { font-size: .78rem; color: var(--muted); }
        .review-comment { font-size: .9rem; color: #334155; line-height: 1.55; margin-top: 6px; }
        .review-comment.no-comment { color: #94a3b8; font-style: italic; }
        .review-provider-link { font-size: .82rem; color: var(--brand); text-decoration: none; font-weight: 600; }
        .review-provider-link:hover { text-decoration: underline; }

        /* Star styling */
        .stars { display: inline-flex; gap: 2px; }
        .stars .fas.fa-star, .stars .fas.fa-star-half-alt { color: var(--star); }
        .stars .far.fa-star { color: #d1d5db; }

        /* Pagination */
        .pagination { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; margin-top: 20px; }
        .page-btn {
            display: inline-flex; align-items: center; justify-content: center;
            min-width: 36px; height: 36px; border-radius: 10px; padding: 0 10px;
            border: 1.5px solid #d9e2ec; background: #fff;
            font-family: inherit; font-size: .85rem; font-weight: 600; color: var(--ink);
            text-decoration: none; transition: all .15s; cursor: pointer;
        }
        .page-btn:hover { border-color: var(--brand); color: var(--brand); }
        .page-btn.active { background: var(--brand); border-color: var(--brand); color: #fff; }
        .page-btn.disabled { opacity: .4; pointer-events: none; }

        /* Empty / error states */
        .empty-state { text-align: center; padding: 40px 20px; color: var(--muted); font-size: .95rem; }
        .empty-state i { font-size: 2.2rem; color: #e2e8f0; display: block; margin-bottom: 10px; }
        .error-card { padding: 60px 28px; }
    </style>
</head>
<body>
<div class="shell">

    <!-- Back bar -->
    <div style="display:flex;align-items:center;gap:10px;">
        <a href="<?php echo htmlspecialchars($backUrl, ENT_QUOTES, 'UTF-8'); ?>" class="back-btn">
            <i class="fas fa-arrow-<?php echo isRtl() ? 'right' : 'left'; ?>"></i>
            <?php echo htmlspecialchars(t('admin_profile_back'), ENT_QUOTES, 'UTF-8'); ?>
        </a>
        <span style="color:var(--muted);font-size:.88rem;"><?php echo htmlspecialchars($pageTitle, ENT_QUOTES, 'UTF-8'); ?></span>
    </div>

    <?php if ($errorMessage !== '' || $userData === null): ?>
        <div class="profile-card">
            <div class="error-card empty-state">
                <i class="fas fa-user-slash"></i>
                <?php echo htmlspecialchars($errorMessage ?: t('admin_profile_not_found'), ENT_QUOTES, 'UTF-8'); ?>
            </div>
        </div>
    <?php else: ?>
    <div class="profile-card">

        <!-- ── Hero ─────────────────────────────────────────────────────── -->
        <div class="profile-hero">
            <div class="profile-avatar">
                <?php if ($userData['photo'] !== ''): ?>
                    <img src="<?php echo htmlspecialchars($appBase . '/' . $userData['photo'], ENT_QUOTES, 'UTF-8'); ?>" alt="">
                <?php else: ?>
                    <i class="fas fa-user"></i>
                <?php endif; ?>
            </div>
            <div class="profile-hero-info">
                <h1><?php echo htmlspecialchars($userData['name'], ENT_QUOTES, 'UTF-8'); ?></h1>
                <div>
                    <span class="badge type-badge">
                        <i class="fas fa-<?php echo $profileType === 'provider' ? 'screwdriver-wrench' : 'user'; ?>"></i>
                        <?php echo htmlspecialchars($profileType === 'provider' ? t('admin_interactions_provider') : t('admin_interactions_customer'), ENT_QUOTES, 'UTF-8'); ?>
                    </span>
                    <?php if ($profileType === 'provider'): ?>
                        <span class="badge <?php echo $userData['is_verified'] ? 'verified' : 'unverified'; ?>">
                            <i class="fas fa-<?php echo $userData['is_verified'] ? 'circle-check' : 'circle-exclamation'; ?>"></i>
                            <?php echo htmlspecialchars($userData['is_verified'] ? t('admin_profile_verified') : t('admin_profile_unverified'), ENT_QUOTES, 'UTF-8'); ?>
                        </span>
                    <?php else: ?>
                        <span class="badge <?php echo $userData['email_verified'] ? 'verified' : 'unverified'; ?>">
                            <i class="fas fa-envelope"></i>
                            <?php echo htmlspecialchars($userData['email_verified'] ? t('admin_profile_email_verified') : t('admin_profile_email_unverified'), ENT_QUOTES, 'UTF-8'); ?>
                        </span>
                    <?php endif; ?>
                    <span class="badge <?php echo $userData['is_suspended'] ? 'suspended' : 'active'; ?>">
                        <i class="fas fa-<?php echo $userData['is_suspended'] ? 'user-lock' : 'user-check'; ?>"></i>
                        <?php echo htmlspecialchars($userData['is_suspended'] ? t('admin_profile_suspended') : t('admin_profile_active'), ENT_QUOTES, 'UTF-8'); ?>
                    </span>
                    <?php if ($profileType === 'provider' && $ratingStats['avg'] !== null): ?>
                        <span class="badge" style="background:rgba(245,158,11,.3);color:#fff;">
                            <i class="fas fa-star"></i> <?php echo $ratingStats['avg']; ?>
                        </span>
                    <?php endif; ?>
                </div>
            </div>
        </div>

        <!-- ── Stats row ─────────────────────────────────────────────────── -->
        <div class="stats-row">
            <div class="stat-chip">
                <span class="stat-num"><?php echo $userData['request_count']; ?></span>
                <span class="stat-lbl"><?php echo htmlspecialchars(t('admin_profile_requests'), ENT_QUOTES, 'UTF-8'); ?></span>
            </div>
            <?php if ($profileType === 'provider' && $ratingStats['count'] > 0): ?>
                <div class="stat-chip amber">
                    <span class="stat-num"><?php echo $ratingStats['avg']; ?></span>
                    <span class="stat-lbl"><?php echo htmlspecialchars(t('admin_prov_ratings_avg'), ENT_QUOTES, 'UTF-8'); ?></span>
                </div>
                <div class="stat-chip" style="background:linear-gradient(145deg,#0369a1,#075985);">
                    <span class="stat-num"><?php echo $ratingStats['count']; ?></span>
                    <span class="stat-lbl"><?php echo htmlspecialchars(t('admin_prov_ratings_total'), ENT_QUOTES, 'UTF-8'); ?></span>
                </div>
            <?php elseif ($profileType === 'customer'): ?>
                <div class="stat-chip" style="background:linear-gradient(145deg,#0369a1,#075985);">
                    <span class="stat-num"><?php echo $reviewTotal; ?></span>
                    <span class="stat-lbl"><?php echo htmlspecialchars(t('admin_cust_reviews_title'), ENT_QUOTES, 'UTF-8'); ?></span>
                </div>
            <?php endif; ?>
            <?php if ($userData['registered_at'] !== ''): ?>
                <div class="stat-chip dark">
                    <span class="stat-num" style="font-size:.95rem;"><?php echo htmlspecialchars(substr($userData['registered_at'], 0, 10), ENT_QUOTES, 'UTF-8'); ?></span>
                    <span class="stat-lbl"><?php echo htmlspecialchars(t('admin_profile_registered'), ENT_QUOTES, 'UTF-8'); ?></span>
                </div>
            <?php endif; ?>
        </div>

        <!-- ── Pending location banner (providers) ───────────────────────── -->
        <?php if ($profileType === 'provider' && $userData['location_change_status'] === 'pending' && $userData['pending_location'] !== ''): ?>
            <div class="pending-banner" style="margin:0 28px 16px;">
                <i class="fas fa-clock"></i>
                <?php echo htmlspecialchars(t('prov_location_pending_notice'), ENT_QUOTES, 'UTF-8'); ?>
                <strong style="margin-<?php echo isRtl()?'right':'left';?>:4px;"><?php echo htmlspecialchars($userData['pending_location'], ENT_QUOTES, 'UTF-8'); ?></strong>
                <a href="<?php echo htmlspecialchars($appBase, ENT_QUOTES, 'UTF-8'); ?>/admin_dashboard.php#location-requests" style="margin-<?php echo isRtl()?'right':'left';?>:auto;font-size:.82rem;color:#92400e;text-decoration:underline;">
                    <?php echo htmlspecialchars(t('admin_nav_location_requests'), ENT_QUOTES, 'UTF-8'); ?> →
                </a>
            </div>
        <?php endif; ?>

        <!-- ── Info grid ─────────────────────────────────────────────────── -->
        <div class="profile-body">
            <div class="info-block">
                <label><?php echo htmlspecialchars(t('admin_profile_name'), ENT_QUOTES, 'UTF-8'); ?></label>
                <div class="value"><?php echo htmlspecialchars($userData['name'], ENT_QUOTES, 'UTF-8'); ?></div>
            </div>
            <div class="info-block">
                <label><?php echo htmlspecialchars(t('admin_profile_email'), ENT_QUOTES, 'UTF-8'); ?></label>
                <div class="value" dir="ltr"><?php echo htmlspecialchars($userData['email'], ENT_QUOTES, 'UTF-8'); ?></div>
            </div>
            <div class="info-block">
                <label><?php echo htmlspecialchars(t('admin_profile_phone'), ENT_QUOTES, 'UTF-8'); ?></label>
                <div class="value <?php echo $userData['phone'] === '' ? 'muted' : ''; ?>" dir="ltr">
                    <?php echo htmlspecialchars($userData['phone'] ?: '—', ENT_QUOTES, 'UTF-8'); ?>
                </div>
            </div>
            <?php if ($profileType === 'provider'): ?>
                <div class="info-block">
                    <label><?php echo htmlspecialchars(t('admin_profile_location'), ENT_QUOTES, 'UTF-8'); ?></label>
                    <?php if ($userData['location'] !== ''): ?>
                        <div class="value"><i class="fas fa-map-marker-alt" style="color:var(--brand);margin-<?php echo isRtl()?'left':'right';?>:5px;"></i><?php echo htmlspecialchars($userData['location'], ENT_QUOTES, 'UTF-8'); ?></div>
                    <?php else: ?>
                        <div class="value muted"><?php echo htmlspecialchars(t('admin_profile_no_location'), ENT_QUOTES, 'UTF-8'); ?></div>
                    <?php endif; ?>
                </div>
                <div class="info-block full">
                    <label><?php echo htmlspecialchars(t('admin_profile_bio'), ENT_QUOTES, 'UTF-8'); ?></label>
                    <?php if ($userData['bio'] !== ''): ?>
                        <div class="value" style="font-weight:400;line-height:1.6;"><?php echo nl2br(htmlspecialchars($userData['bio'], ENT_QUOTES, 'UTF-8')); ?></div>
                    <?php else: ?>
                        <div class="value muted"><?php echo htmlspecialchars(t('admin_profile_no_bio'), ENT_QUOTES, 'UTF-8'); ?></div>
                    <?php endif; ?>
                </div>
            <?php else: ?>
                <?php
                    $custLat = $userData['latitude']  ?? null;
                    $custLng = $userData['longitude'] ?? null;
                ?>
                <div class="info-block full">
                    <label><?php echo htmlspecialchars(t('prov_cust_location_title'), ENT_QUOTES, 'UTF-8'); ?></label>
                    <?php if ($custLat !== null && $custLng !== null): ?>
                        <div class="value">
                            <i class="fas fa-map-marker-alt" style="color:var(--brand);margin-<?php echo isRtl()?'left':'right';?>:5px;"></i>
                            <?php echo htmlspecialchars(number_format($custLat, 6), ENT_QUOTES, 'UTF-8'); ?>,
                            <?php echo htmlspecialchars(number_format($custLng, 6), ENT_QUOTES, 'UTF-8'); ?>
                            <a href="https://www.openstreetmap.org/?mlat=<?php echo urlencode((string)$custLat); ?>&mlon=<?php echo urlencode((string)$custLng); ?>#map=16/<?php echo urlencode((string)$custLat); ?>/<?php echo urlencode((string)$custLng); ?>"
                               target="_blank" rel="noopener noreferrer"
                               style="margin-<?php echo isRtl()?'right':'left';?>:8px;font-size:.82rem;color:var(--brand);text-decoration:none;font-weight:600;">
                                <i class="fas fa-external-link-alt" style="font-size:.75rem;"></i>
                                <?php echo htmlspecialchars(t('prov_cust_location_view'), ENT_QUOTES, 'UTF-8'); ?>
                            </a>
                        </div>
                    <?php else: ?>
                        <div class="value muted"><?php echo htmlspecialchars(t('prov_cust_location_na'), ENT_QUOTES, 'UTF-8'); ?></div>
                    <?php endif; ?>
                </div>
            <?php endif; ?>
            <div class="info-block">
                <label><?php echo htmlspecialchars(t('admin_profile_photo'), ENT_QUOTES, 'UTF-8'); ?></label>
                <?php if ($userData['photo'] !== ''): ?>
                    <img src="<?php echo htmlspecialchars($appBase . '/' . $userData['photo'], ENT_QUOTES, 'UTF-8'); ?>" alt=""
                         style="margin-top:6px;width:64px;height:64px;object-fit:cover;border-radius:12px;border:2px solid var(--line);">
                <?php else: ?>
                    <div class="value muted"><?php echo htmlspecialchars(t('admin_profile_no_photo'), ENT_QUOTES, 'UTF-8'); ?></div>
                <?php endif; ?>
            </div>
        </div>

        <!-- ══════════════════════════════════════════════════════════════════ -->
        <!-- ── Reviews section ────────────────────────────────────────────── -->
        <div class="reviews-section">

            <h2>
                <i class="fas fa-star" style="color:var(--star);margin-<?php echo isRtl()?'left':'right';?>:8px;font-size:.95em;"></i>
                <?php echo htmlspecialchars($profileType === 'provider' ? t('admin_prov_ratings_title') : t('admin_cust_reviews_title'), ENT_QUOTES, 'UTF-8'); ?>
            </h2>
            <p class="section-lead">
                <?php if ($profileType === 'customer'): ?>
                    <?php echo htmlspecialchars(t('admin_cust_reviews_lead'), ENT_QUOTES, 'UTF-8'); ?>
                <?php endif; ?>
            </p>

            <?php if ($profileType === 'provider' && $ratingStats['count'] > 0): ?>
                <!-- Rating overview: big number + distribution bars -->
                <div class="rating-overview">
                    <div class="rating-big">
                        <span class="num"><?php echo $ratingStats['avg']; ?></span>
                        <span class="stars"><?php echo avgStarHtml($ratingStats['avg'] ?? 0); ?></span>
                        <span class="cnt"><?php echo $ratingStats['count']; ?> <?php echo htmlspecialchars(t('admin_prov_ratings_total'), ENT_QUOTES, 'UTF-8'); ?></span>
                    </div>
                    <div class="dist-bars">
                        <?php foreach ([5, 4, 3, 2, 1] as $star): ?>
                            <?php $pct = $ratingStats['count'] > 0 ? round($ratingStats['dist'][$star] / $ratingStats['count'] * 100) : 0; ?>
                            <div class="dist-row">
                                <span class="dist-label"><i class="fas fa-star" style="color:var(--star);font-size:.7rem;"></i> <?php echo $star; ?></span>
                                <span class="dist-track"><span class="dist-fill" style="width:<?php echo $pct; ?>%;"></span></span>
                                <span class="dist-count"><?php echo $ratingStats['dist'][$star]; ?></span>
                            </div>
                        <?php endforeach; ?>
                    </div>
                </div>
            <?php endif; ?>

            <!-- Controls: sort + star filter -->
            <?php if ($reviewTotal > 0 || $ratingFilter > 0): ?>
            <div class="controls-bar">
                <div style="display:flex;align-items:center;gap:6px;">
                    <i class="fas fa-sort" style="color:var(--muted);font-size:.85rem;"></i>
                    <a href="<?php echo htmlspecialchars(sortUrl('newest'), ENT_QUOTES, 'UTF-8'); ?>" class="filter-chip <?php echo $reviewSort === 'newest' ? 'active' : ''; ?>">
                        <?php echo htmlspecialchars(t('admin_reviews_sort_newest'), ENT_QUOTES, 'UTF-8'); ?>
                    </a>
                    <a href="<?php echo htmlspecialchars(sortUrl('highest'), ENT_QUOTES, 'UTF-8'); ?>" class="filter-chip <?php echo $reviewSort === 'highest' ? 'active' : ''; ?>">
                        <i class="fas fa-star"></i> <?php echo htmlspecialchars(t('admin_reviews_sort_highest'), ENT_QUOTES, 'UTF-8'); ?>
                    </a>
                    <a href="<?php echo htmlspecialchars(sortUrl('lowest'), ENT_QUOTES, 'UTF-8'); ?>" class="filter-chip <?php echo $reviewSort === 'lowest' ? 'active' : ''; ?>">
                        <i class="far fa-star"></i> <?php echo htmlspecialchars(t('admin_reviews_sort_lowest'), ENT_QUOTES, 'UTF-8'); ?>
                    </a>
                </div>
                <div class="filter-chips" style="margin-<?php echo isRtl()?'right':'left';?>:auto;">
                    <a href="<?php echo htmlspecialchars(starsUrl(0), ENT_QUOTES, 'UTF-8'); ?>" class="filter-chip <?php echo $ratingFilter === 0 ? 'active' : ''; ?>">
                        <?php echo htmlspecialchars(t('admin_reviews_filter_all'), ENT_QUOTES, 'UTF-8'); ?>
                    </a>
                    <?php foreach ([5,4,3,2,1] as $s): ?>
                        <a href="<?php echo htmlspecialchars(starsUrl($s), ENT_QUOTES, 'UTF-8'); ?>" class="filter-chip <?php echo $ratingFilter === $s ? 'active' : ''; ?>">
                            <i class="fas fa-star" style="color:var(--star);"></i> <?php echo $s; ?>
                        </a>
                    <?php endforeach; ?>
                </div>
            </div>
            <?php endif; ?>

            <!-- Review cards -->
            <?php if (count($reviews) === 0): ?>
                <div class="empty-state">
                    <i class="far fa-star"></i>
                    <?php echo htmlspecialchars($profileType === 'provider' ? t('admin_prov_ratings_empty') : t('admin_cust_reviews_empty'), ENT_QUOTES, 'UTF-8'); ?>
                </div>
            <?php else: ?>
                <?php foreach ($reviews as $review): ?>
                    <?php $rating = (int) $review['rating']; ?>
                    <div class="review-card">
                        <div class="review-card-header">
                            <div class="review-meta">
                                <?php if ($profileType === 'provider'): ?>
                                    <span class="reviewer-name">
                                        <i class="fas fa-user" style="color:var(--muted);font-size:.8rem;margin-<?php echo isRtl()?'left':'right';?>:5px;"></i>
                                        <?php echo htmlspecialchars((string) $review['reviewer_name'], ENT_QUOTES, 'UTF-8'); ?>
                                    </span>
                                <?php else: ?>
                                    <a href="<?php echo htmlspecialchars($appBase, ENT_QUOTES, 'UTF-8'); ?>/admin/user/provider/<?php echo (int) $review['provider_id']; ?>" class="review-provider-link">
                                        <i class="fas fa-screwdriver-wrench" style="font-size:.8rem;margin-<?php echo isRtl()?'left':'right';?>:5px;"></i>
                                        <?php echo htmlspecialchars((string) $review['provider_name'], ENT_QUOTES, 'UTF-8'); ?>
                                    </a>
                                <?php endif; ?>
                                <span class="review-date"><?php echo htmlspecialchars((string) $review['appointment_date'], ENT_QUOTES, 'UTF-8'); ?></span>
                            </div>
                            <div><?php echo starHtml($rating); ?></div>
                        </div>
                        <?php $comment = trim((string) $review['review']); ?>
                        <div class="review-comment <?php echo $comment === '' ? 'no-comment' : ''; ?>">
                            <?php echo htmlspecialchars($comment !== '' ? $comment : t('admin_reviews_no_comment'), ENT_QUOTES, 'UTF-8'); ?>
                        </div>
                    </div>
                <?php endforeach; ?>

                <!-- Pagination -->
                <?php if ($reviewPages > 1): ?>
                    <div class="pagination">
                        <a href="<?php echo htmlspecialchars(pageUrl(max(1, $reviewPage - 1)), ENT_QUOTES, 'UTF-8'); ?>"
                           class="page-btn <?php echo $reviewPage <= 1 ? 'disabled' : ''; ?>">
                            <i class="fas fa-chevron-<?php echo isRtl()?'right':'left';?>"></i>
                        </a>
                        <?php
                            $pStart = max(1, $reviewPage - 2);
                            $pEnd   = min($reviewPages, $reviewPage + 2);
                            if ($pStart > 1) { ?><a href="<?php echo htmlspecialchars(pageUrl(1), ENT_QUOTES, 'UTF-8'); ?>" class="page-btn">1</a><?php if ($pStart > 2) echo '<span style="padding:0 4px;color:var(--muted);">…</span>'; }
                            for ($p = $pStart; $p <= $pEnd; $p++): ?>
                                <a href="<?php echo htmlspecialchars(pageUrl($p), ENT_QUOTES, 'UTF-8'); ?>"
                                   class="page-btn <?php echo $p === $reviewPage ? 'active' : ''; ?>"><?php echo $p; ?></a>
                        <?php endfor;
                            if ($pEnd < $reviewPages) { if ($pEnd < $reviewPages - 1) echo '<span style="padding:0 4px;color:var(--muted);">…</span>'; ?><a href="<?php echo htmlspecialchars(pageUrl($reviewPages), ENT_QUOTES, 'UTF-8'); ?>" class="page-btn"><?php echo $reviewPages; ?></a><?php } ?>
                        <a href="<?php echo htmlspecialchars(pageUrl(min($reviewPages, $reviewPage + 1)), ENT_QUOTES, 'UTF-8'); ?>"
                           class="page-btn <?php echo $reviewPage >= $reviewPages ? 'disabled' : ''; ?>">
                            <i class="fas fa-chevron-<?php echo isRtl()?'right':'left';?>"></i>
                        </a>
                        <span style="font-size:.82rem;color:var(--muted);margin-<?php echo isRtl()?'right':'left';?>:6px;">
                            <?php echo htmlspecialchars(t('admin_reviews_page'), ENT_QUOTES, 'UTF-8'); ?>
                            <?php echo $reviewPage; ?> / <?php echo $reviewPages; ?>
                        </span>
                    </div>
                <?php endif; ?>
            <?php endif; ?>
        </div>

    </div>
    <?php endif; ?>
</div>
</body>
</html>
