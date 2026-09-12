<?php
declare(strict_types=1);

session_start();

require_once __DIR__ . '/db_connection.php';
require_once __DIR__ . '/site_settings.php';
require_once __DIR__ . '/lang.php';
require_once __DIR__ . '/email_verification_store.php';
require_once __DIR__ . '/mailer.php';

ensureEmailVerificationTable($pdo);
ensureSiteSettingsTable($pdo);
$siteSettings = loadSiteSettings($pdo, ['site_favicon' => '']);
$siteFavicon  = trim((string) ($siteSettings['site_favicon'] ?? ''));

/*
 * One-time DB migrations: add first_name / last_name columns to both account tables.
 * Uses IF NOT EXISTS logic so re-runs are safe.
 */
try {
    $r = $pdo->query("SHOW COLUMNS FROM customer LIKE 'first_name'");
    if ($r !== false && $r->rowCount() === 0) {
        $pdo->exec("ALTER TABLE customer ADD COLUMN first_name VARCHAR(100) NOT NULL DEFAULT '' AFTER name");
        $pdo->exec("ALTER TABLE customer ADD COLUMN last_name  VARCHAR(100) NOT NULL DEFAULT '' AFTER first_name");
    }
} catch (PDOException $e) {}

try {
    $r = $pdo->query("SHOW COLUMNS FROM serviceprovider LIKE 'first_name'");
    if ($r !== false && $r->rowCount() === 0) {
        $pdo->exec("ALTER TABLE serviceprovider ADD COLUMN first_name VARCHAR(100) NOT NULL DEFAULT '' AFTER name");
        $pdo->exec("ALTER TABLE serviceprovider ADD COLUMN last_name  VARCHAR(100) NOT NULL DEFAULT '' AFTER first_name");
    }
} catch (PDOException $e) {}

try {
    $r = $pdo->query("SHOW COLUMNS FROM customer LIKE 'latitude'");
    if ($r !== false && $r->rowCount() === 0) {
        $pdo->exec("ALTER TABLE customer ADD COLUMN latitude  DECIMAL(10,8) NULL DEFAULT NULL");
        $pdo->exec("ALTER TABLE customer ADD COLUMN longitude DECIMAL(11,8) NULL DEFAULT NULL");
    }
} catch (PDOException $e) {}

if (!isset($_SESSION['csrf_token']) || !is_string($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

/* ── View-state defaults ── */
$errorMessage       = '';
$successMessage     = '';
$firstNameValue     = '';
$lastNameValue      = '';
$phoneValue         = '';
$emailValue         = '';
$latValue           = '';
$lngValue           = '';
$bioValue           = '';
$locationValue      = '';
$selectedUserType   = 'customer';
$showEmailProviderHint = false;

/* ── Email provider allow-list ── */
const ALLOWED_EMAIL_DOMAINS = [
    'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com',
    'icloud.com', 'live.com', 'msn.com', 'aol.com',
    'protonmail.com', 'maintenanceservice.lb',
    'liu.edu.lb', 'students.liu.edu.lb',
];
$allowedDomainMessage = 'Please use an email from: ' . implode(', ', ALLOWED_EMAIL_DOMAINS) . '.';

function isStrongPassword(string $pw): bool {
    return (bool) preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z0-9]).{8,}$/', $pw);
}

function isAllowedEmailDomain(string $email): bool {
    $d = strtolower(ltrim((string) strrchr($email, '@'), '@'));
    return $d !== '' && in_array($d, ALLOWED_EMAIL_DOMAINS, true);
}

/* ── Tab-scoped token helper (unchanged) ── */
function issueCustomerTabAccessToken(int $userId, string $userEmail): string {
    if (!isset($_SESSION['customer_tab_tokens']) || !is_array($_SESSION['customer_tab_tokens'])) {
        $_SESSION['customer_tab_tokens'] = [];
    }
    $token = bin2hex(random_bytes(32));
    $_SESSION['customer_tab_tokens'][$token] = ['user_id' => $userId, 'user_email' => $userEmail, 'issued_at' => time()];
    if (count($_SESSION['customer_tab_tokens']) > 25) {
        uasort($_SESSION['customer_tab_tokens'], static fn($a,$b) => ($a['issued_at']??0)<=>($b['issued_at']??0));
        $_SESSION['customer_tab_tokens'] = array_slice($_SESSION['customer_tab_tokens'], -25, null, true);
    }
    return $token;
}

function resetSessionForRole(string $role): void {
    if (session_status() === PHP_SESSION_ACTIVE) { session_regenerate_id(true); }
    $_SESSION = [];
    $_SESSION['user_type'] = $role;
}

/* ══════════════════════════════════════════════════
   POST handler
══════════════════════════════════════════════════ */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $postedCsrf     = (string) ($_POST['csrf_token'] ?? '');
    $selectedUserType = strtolower(trim((string) ($_POST['user_type'] ?? 'customer')));
    $firstNameValue = trim((string) ($_POST['first_name'] ?? ''));
    $lastNameValue  = trim((string) ($_POST['last_name']  ?? ''));
    $phoneValue     = trim((string) ($_POST['phone']      ?? ''));
    $emailValue     = trim((string) ($_POST['email']      ?? ''));
    $passwordValue  = (string) ($_POST['password']         ?? '');
    $confirmPwValue = (string) ($_POST['confirm_password'] ?? '');
    $latValue       = trim((string) ($_POST['reg_lat']     ?? ''));
    $lngValue       = trim((string) ($_POST['reg_lng']     ?? ''));
    $bioValue       = trim((string) ($_POST['bio']         ?? ''));
    $locationValue  = trim((string) ($_POST['provider_location'] ?? ''));

    /* Combined full name for the legacy `name` column */
    $fullName = $firstNameValue . ($lastNameValue !== '' ? ' ' . $lastNameValue : '');

    /* ── Validation chain ── */
    if (!hash_equals($_SESSION['csrf_token'], $postedCsrf)) {
        $errorMessage = t('err_invalid_token');
    } elseif (!in_array($selectedUserType, ['customer', 'service_provider'], true)) {
        $errorMessage = 'Please choose a valid account type.';
    } elseif ($firstNameValue === '') {
        $errorMessage = t('register_err_first_name_empty');
    } elseif (mb_strlen($firstNameValue) > 100) {
        $errorMessage = t('register_err_first_name_long');
    } elseif ($lastNameValue === '') {
        $errorMessage = t('register_err_last_name_empty');
    } elseif (mb_strlen($lastNameValue) > 100) {
        $errorMessage = t('register_err_last_name_long');
    } elseif ($phoneValue === '') {
        $errorMessage = t('register_err_phone_empty');
    } elseif (!preg_match('/^[0-9+()\-\s]{7,20}$/', $phoneValue)) {
        $errorMessage = t('register_err_phone_invalid');
    } elseif (!filter_var($emailValue, FILTER_VALIDATE_EMAIL)) {
        $showEmailProviderHint = true;
        $errorMessage = t('register_err_email_invalid');
    } elseif (!isAllowedEmailDomain($emailValue)) {
        $showEmailProviderHint = true;
        $errorMessage = $allowedDomainMessage;
    } elseif (!isStrongPassword($passwordValue)) {
        $errorMessage = t('register_err_pw_weak');
    } elseif ($passwordValue !== $confirmPwValue) {
        $errorMessage = t('register_err_pw_mismatch');
    } elseif ($selectedUserType === 'customer' && ($latValue === '' || $lngValue === '')) {
        $errorMessage = t('register_err_map_location_required');
    } elseif ($selectedUserType === 'customer' && (
            filter_var($latValue, FILTER_VALIDATE_FLOAT) === false ||
            filter_var($lngValue, FILTER_VALIDATE_FLOAT) === false ||
            (float) $latValue < -90  || (float) $latValue > 90 ||
            (float) $lngValue < -180 || (float) $lngValue > 180
        )) {
        $errorMessage = t('register_err_map_location_required');
    } elseif ($selectedUserType === 'service_provider' && $bioValue === '') {
        $errorMessage = t('register_err_bio_empty');
    } elseif ($selectedUserType === 'service_provider' && mb_strlen($bioValue) > 2000) {
        $errorMessage = 'Bio must be 2 000 characters or fewer.';
    } elseif ($selectedUserType === 'service_provider' && $locationValue === '') {
        $errorMessage = t('register_err_location_empty');
    } elseif ($selectedUserType === 'service_provider' && mb_strlen($locationValue) > 255) {
        $errorMessage = t('register_provider_location_long');
    } else {
        try {
            /* Duplicate email / phone guard across both tables */
            $custEmail = $pdo->prepare('SELECT customer_id FROM customer WHERE email = :e LIMIT 1');
            $custEmail->execute(['e' => $emailValue]);
            $provEmail = $pdo->prepare('SELECT provider_id FROM serviceprovider WHERE email = :e LIMIT 1');
            $provEmail->execute(['e' => $emailValue]);

            $custPhone = $pdo->prepare('SELECT customer_id FROM customer WHERE phone = :p LIMIT 1');
            $custPhone->execute(['p' => $phoneValue]);
            $provPhone = $pdo->prepare('SELECT provider_id FROM serviceprovider WHERE phone = :p LIMIT 1');
            $provPhone->execute(['p' => $phoneValue]);

            if ($custEmail->fetchColumn() !== false || $provEmail->fetchColumn() !== false) {
                $errorMessage = t('register_err_email_exists');
            } elseif ($custPhone->fetchColumn() !== false || $provPhone->fetchColumn() !== false) {
                $errorMessage = t('register_err_phone_exists');
            } else {
                $hash = password_hash($passwordValue, PASSWORD_DEFAULT);
                if ($hash === false) {
                    $errorMessage = 'Unable to create account right now. Please try again.';
                } else {
                    $createdCustomerId = 0;

                    if ($selectedUserType === 'customer') {
                        $ins = $pdo->prepare(
                            'INSERT INTO customer
                               (name, first_name, last_name, phone, email, password, latitude, longitude, is_verified)
                             VALUES
                               (:name, :fn, :ln, :phone, :email, :password, :lat, :lng, 0)'
                        );
                        $ins->execute([
                            'name'    => $fullName,
                            'fn'      => $firstNameValue,
                            'ln'      => $lastNameValue,
                            'phone'   => $phoneValue,
                            'email'   => $emailValue,
                            'password'=> $hash,
                            'lat'     => (float) $latValue,
                            'lng'     => (float) $lngValue,
                        ]);
                        $createdCustomerId = (int) $pdo->lastInsertId();
                    } else {
                        /* Ensure location column exists (legacy migration guard) */
                        try {
                            $lc = $pdo->query("SHOW COLUMNS FROM serviceprovider LIKE 'location'");
                            if ($lc !== false && $lc->rowCount() === 0) {
                                $pdo->exec("ALTER TABLE serviceprovider ADD COLUMN location VARCHAR(255) NOT NULL DEFAULT ''");
                            }
                        } catch (PDOException $me) {}

                        $ins = $pdo->prepare(
                            'INSERT INTO serviceprovider
                               (name, first_name, last_name, phone, email, password, bio, photo, location, is_verified)
                             VALUES
                               (:name, :fn, :ln, :phone, :email, :password, :bio, :photo, :location, 0)'
                        );
                        $ins->execute([
                            'name'    => $fullName,
                            'fn'      => $firstNameValue,
                            'ln'      => $lastNameValue,
                            'phone'   => $phoneValue,
                            'email'   => $emailValue,
                            'password'=> $hash,
                            'bio'     => $bioValue,
                            'photo'   => null,
                            'location'=> $locationValue,
                        ]);
                    }

                    /* Email verification flow */
                    if ($selectedUserType === 'customer' && $createdCustomerId > 0) {
                        $code = createVerificationCode($pdo, $emailValue, 'customer');
                        $sent = sendVerificationEmail($emailValue, $code);
                        $_SESSION['verify_pending_email']       = $emailValue;
                        $_SESSION['verify_pending_type']        = 'customer';
                        $_SESSION['verify_pending_customer_id'] = $createdCustomerId;
                        if (!$sent) { $_SESSION['verify_email_send_failed'] = true; }
                        header('Location: verify_email.php');
                        exit;
                    }

                    if ($selectedUserType === 'service_provider') {
                        $createdProviderId = (int) $pdo->lastInsertId();
                        $code = createVerificationCode($pdo, $emailValue, 'service_provider');
                        $sent = sendVerificationEmail($emailValue, $code);
                        $_SESSION['verify_pending_email']       = $emailValue;
                        $_SESSION['verify_pending_type']        = 'service_provider';
                        $_SESSION['verify_pending_provider_id'] = $createdProviderId;
                        if (!$sent) { $_SESSION['verify_email_send_failed'] = true; }
                        header('Location: verify_email.php');
                        exit;
                    }
                }
            }
        } catch (PDOException $e) {
            $errorMessage = 'Unable to create account right now. Please try again.';
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
    <title><?php echo htmlspecialchars(t('register_title'), ENT_QUOTES, 'UTF-8'); ?> — <?php echo htmlspecialchars(t('site_name'), ENT_QUOTES, 'UTF-8'); ?></title>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:ital,wght@0,400;0,500;0,600;0,700;0,800;1,400&display=swap" rel="stylesheet">
    <?php if (isRtl()): ?>
    <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <?php endif; ?>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link rel="stylesheet" href="vendor/leaflet/leaflet.css">
    <style>
        /* ── Reset ─────────────────────────────────────────── */
        *, *::before, *::after { margin:0; padding:0; box-sizing:border-box; }
        html, body { width:100%; overflow-x:hidden; }

        /* ── Design tokens ──────────────────────────────────── */
        :root {
            --brand:        #0f766e;
            --brand-deep:   #115e59;
            --brand-xdeep:  #065f46;
            --accent:       #f97316;
            --accent-soft:  #fff7ed;
            --ink:          #0f172a;
            --muted:        #64748b;
            --line:         #e2e8f0;
            --card-bg:      rgba(255,255,255,0.97);
            --radius-card:  28px;
            --radius-input: 14px;
            --shadow-card:  0 32px 72px rgba(15,23,42,0.18);
        }

        /* ── Page background ────────────────────────────────── */
        body {
            font-family: 'Plus Jakarta Sans', sans-serif;
            min-height: 100vh;
            display: flex;
            align-items: flex-start;
            justify-content: center;
            padding: 32px 16px 48px;
            background:
                radial-gradient(ellipse at 15% 0%,  rgba(20,184,166,.22) 0%, transparent 50%),
                radial-gradient(ellipse at 85% 5%,  rgba(249,115,22,.20) 0%, transparent 45%),
                radial-gradient(ellipse at 50% 90%, rgba(15,118,110,.14) 0%, transparent 50%),
                linear-gradient(160deg, #ecfeff 0%, #f8fafc 55%, #fff7ed 100%);
        }

        /* Ambient floating shapes */
        .bg-shape {
            position: fixed; border-radius: 50%; filter: blur(90px);
            pointer-events: none; z-index: 0; animation: floatShape 18s ease-in-out infinite;
        }
        .bg-shape-1 { width:380px; height:380px; top:-120px; left:-100px; background:rgba(20,184,166,.30); }
        .bg-shape-2 { width:480px; height:480px; right:-140px; bottom:-160px; background:rgba(249,115,22,.25); animation-delay:-9s; }
        .bg-shape-3 { width:300px; height:300px; top:45%; left:60%; background:rgba(99,102,241,.18); animation-delay:-4s; }

        @keyframes floatShape {
            0%,100% { transform:translate(0,0) scale(1); }
            33%      { transform:translate(30px,-20px) scale(1.05); }
            66%      { transform:translate(-25px,25px) scale(.95); }
        }

        /* ── Card wrapper ───────────────────────────────────── */
        .reg-card {
            position: relative;
            z-index: 1;
            width: 100%;
            max-width: 680px;
            background: var(--card-bg);
            border-radius: var(--radius-card);
            box-shadow: var(--shadow-card);
            border: 1px solid rgba(255,255,255,.7);
            overflow: hidden;
            animation: cardIn .55s cubic-bezier(.22,1,.36,1) both;
        }

        @keyframes cardIn {
            from { opacity:0; transform:translateY(28px) scale(.98); }
            to   { opacity:1; transform:translateY(0)    scale(1);   }
        }

        /* ── Card header (gradient) ─────────────────────────── */
        .reg-header {
            background: linear-gradient(140deg, #0c6e67 0%, #0f766e 45%, #134e4a 100%);
            padding: 32px 36px 0;
            position: relative;
            overflow: hidden;
        }

        .reg-header::before {
            content: '';
            position: absolute;
            inset: 0;
            background:
                radial-gradient(circle at 80% 20%, rgba(255,255,255,.10) 0%, transparent 55%),
                radial-gradient(circle at 10% 80%, rgba(249,115,22,.15) 0%, transparent 45%);
            pointer-events: none;
        }

        .reg-header-top {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 28px;
            position: relative;
        }

        .reg-header-top .back-link {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            color: rgba(255,255,255,.75);
            text-decoration: none;
            font-size: .82rem;
            font-weight: 600;
            transition: color .2s;
        }
        .reg-header-top .back-link:hover { color:#fff; }

        .lang-btn {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            background: rgba(255,255,255,.15);
            border: 1px solid rgba(255,255,255,.25);
            border-radius: 999px;
            color: #fff;
            font-family: inherit;
            font-size: .8rem;
            font-weight: 700;
            padding: 5px 12px;
            text-decoration: none;
            transition: background .2s;
            cursor: pointer;
        }
        .lang-btn:hover { background: rgba(255,255,255,.25); }

        /* Hero area */
        .reg-hero {
            text-align: center;
            padding-bottom: 28px;
            position: relative;
        }

        .reg-logo {
            width: 70px; height: 70px;
            margin: 0 auto 16px;
            border-radius: 20px;
            background: rgba(255,255,255,.18);
            border: 2px solid rgba(255,255,255,.3);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.7rem;
            color: #fff;
            box-shadow: 0 10px 28px rgba(0,0,0,.18);
        }

        .reg-hero h1 {
            font-size: 1.7rem;
            font-weight: 800;
            color: #fff;
            margin-bottom: 6px;
            letter-spacing: -.3px;
        }

        .reg-hero p {
            font-size: .9rem;
            color: rgba(255,255,255,.75);
        }

        /* Account-type tabs */
        .reg-tabs {
            display: flex;
            gap: 8px;
            background: rgba(0,0,0,.18);
            border-radius: 16px 16px 0 0;
            padding: 8px 8px 0;
            margin-top: 24px;
            position: relative;
        }

        .tab-btn {
            flex: 1;
            border: none;
            border-radius: 12px 12px 0 0;
            padding: 11px 14px;
            font-family: inherit;
            font-size: .88rem;
            font-weight: 700;
            color: rgba(255,255,255,.65);
            background: transparent;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 7px;
            transition: all .25s ease;
        }

        .tab-btn.active {
            background: var(--card-bg);
            color: var(--brand);
            box-shadow: 0 -4px 14px rgba(0,0,0,.08);
        }

        .tab-btn:not(.active):hover {
            color: #fff;
            background: rgba(255,255,255,.12);
        }

        .tab-btn .tab-icon {
            width: 26px; height: 26px;
            border-radius: 8px;
            background: currentColor;
            opacity: .15;
            display: flex; align-items: center; justify-content: center;
            font-size: .75rem;
        }
        .tab-btn.active .tab-icon { opacity: 1; background: rgba(15,118,110,.12); color: var(--brand); }
        .tab-btn i { position: relative; z-index: 1; }

        /* ── Card body ──────────────────────────────────────── */
        .reg-body {
            padding: 32px 36px 36px;
        }

        /* Alert / message banners */
        .reg-alert {
            display: flex;
            align-items: flex-start;
            gap: 10px;
            border-radius: 14px;
            padding: 13px 15px;
            font-size: .88rem;
            font-weight: 600;
            margin-bottom: 22px;
            animation: alertSlide .3s ease;
        }
        @keyframes alertSlide {
            from { opacity:0; transform:translateY(-8px); }
            to   { opacity:1; transform:translateY(0); }
        }

        .reg-alert.is-error {
            background: #fff1f2;
            color: #be123c;
            border: 1.5px solid #fecdd3;
        }
        .reg-alert.is-success {
            background: #ecfdf5;
            color: #065f46;
            border: 1.5px solid #a7f3d0;
        }
        .reg-alert.is-hidden { display: none; }
        .reg-alert-icon { font-size: 1rem; margin-top: 1px; flex-shrink: 0; }

        /* Section headers */
        .reg-section { margin-bottom: 20px; }

        .reg-section-head {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 16px;
        }

        .section-num {
            width: 26px; height: 26px;
            border-radius: 8px;
            background: linear-gradient(135deg, var(--brand), var(--brand-deep));
            color: #fff;
            font-size: .75rem;
            font-weight: 800;
            display: flex; align-items: center; justify-content: center;
            flex-shrink: 0;
        }

        .section-title {
            font-size: .8rem;
            font-weight: 700;
            color: var(--muted);
            text-transform: uppercase;
            letter-spacing: .6px;
        }

        .section-divider {
            flex: 1;
            height: 1px;
            background: var(--line);
        }

        /* ── Form grid ──────────────────────────────────────── */
        .reg-grid {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 14px;
        }

        .reg-field { display: flex; flex-direction: column; gap: 6px; }
        .reg-field.full { grid-column: 1 / -1; }

        .reg-field label {
            font-size: .82rem;
            font-weight: 700;
            color: #1e293b;
        }

        /* Input wrapper */
        .input-wrap {
            position: relative;
            display: flex;
            align-items: center;
        }

        .input-icon {
            position: absolute;
            left: 14px;
            color: #94a3b8;
            font-size: .95rem;
            pointer-events: none;
            z-index: 1;
            transition: color .2s;
        }

        .input-wrap:focus-within .input-icon { color: var(--brand); }

        .input-wrap input,
        .input-wrap textarea {
            width: 100%;
            border: 2px solid var(--line);
            border-radius: var(--radius-input);
            padding: 12px 14px 12px 42px;
            font-family: inherit;
            font-size: .9rem;
            color: var(--ink);
            background: #fff;
            min-height: 48px;
            transition: border-color .22s, box-shadow .22s;
        }

        .input-wrap input.has-toggle { padding-right: 46px; }

        .input-wrap textarea {
            min-height: 105px;
            resize: vertical;
            padding-top: 12px;
            line-height: 1.5;
        }

        .input-wrap input:focus,
        .input-wrap textarea:focus {
            outline: none;
            border-color: var(--brand);
            box-shadow: 0 0 0 4px rgba(15,118,110,.13);
        }

        .input-wrap input.is-invalid,
        .input-wrap textarea.is-invalid {
            border-color: #f43f5e;
            box-shadow: 0 0 0 4px rgba(244,63,94,.10);
        }

        .input-wrap input.is-valid {
            border-color: #22c55e;
        }

        /* Password toggle */
        .pw-toggle {
            position: absolute;
            right: 12px;
            border: none;
            background: transparent;
            color: #94a3b8;
            cursor: pointer;
            padding: 6px;
            display: flex; align-items: center; justify-content: center;
            transition: color .2s;
            z-index: 1;
        }
        .pw-toggle:hover { color: var(--brand); }
        .pw-toggle i { font-size: .95rem; }

        /* Field hint */
        .field-hint {
            font-size: .75rem;
            color: var(--muted);
            line-height: 1.4;
        }
        .field-hint.is-hidden { display: none; }

        /* Password strength */
        .pw-strength-wrap { display: none; margin-top: 4px; }
        .pw-strength-wrap.show { display: block; }

        .pw-bar-bg {
            height: 5px;
            border-radius: 999px;
            background: #e5e7eb;
            overflow: hidden;
            margin-bottom: 5px;
        }
        .pw-bar-fill {
            height: 100%;
            border-radius: 999px;
            width: 0;
            transition: width .3s ease, background .3s ease;
        }

        .pw-label {
            font-size: .74rem;
            font-weight: 700;
            margin-bottom: 5px;
        }
        .pw-label.weak   { color: #ef4444; }
        .pw-label.fair   { color: #f97316; }
        .pw-label.good   { color: #eab308; }
        .pw-label.strong { color: #22c55e; }

        .pw-rules {
            display: grid;
            grid-template-columns: repeat(2,1fr);
            gap: 2px 10px;
        }
        .pw-rule {
            font-size: .72rem;
            color: #94a3b8;
            display: flex; align-items: center; gap: 5px;
            transition: color .2s;
        }
        .pw-rule.ok { color: #16a34a; }
        .pw-rule i { font-size: .65rem; }

        /* Confirm match indicator */
        .confirm-match {
            display: none;
            font-size: .75rem;
            font-weight: 700;
            margin-top: 4px;
            align-items: center;
            gap: 5px;
        }
        .confirm-match.show { display: flex; }
        .confirm-match.ok   { color: #16a34a; }
        .confirm-match.fail { color: #ef4444; }

        /* Conditional provider / customer fields */
        .cond-fields { display: none; }
        .cond-fields.show { display: block; }

        /* ── Submit button ───────────────────────────────────── */
        .reg-submit {
            width: 100%;
            min-height: 52px;
            margin-top: 8px;
            border: none;
            border-radius: 16px;
            background: linear-gradient(145deg, var(--brand), var(--brand-deep));
            color: #fff;
            font-family: inherit;
            font-size: 1rem;
            font-weight: 800;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 9px;
            transition: transform .2s, box-shadow .2s, opacity .2s;
            box-shadow: 0 6px 20px rgba(15,118,110,.30);
        }
        .reg-submit:hover {
            transform: translateY(-2px);
            box-shadow: 0 14px 32px rgba(15,118,110,.38);
        }
        .reg-submit:active { transform: translateY(0); }
        .reg-submit:disabled { opacity: .65; cursor: not-allowed; transform: none; }

        /* ── Footer links ────────────────────────────────────── */
        .reg-footer {
            margin-top: 22px;
            text-align: center;
            display: flex;
            flex-direction: column;
            gap: 8px;
        }

        .reg-footer p {
            font-size: .88rem;
            color: var(--muted);
        }

        .reg-footer a {
            color: var(--brand);
            font-weight: 700;
            text-decoration: none;
            transition: color .2s;
        }
        .reg-footer a:hover { color: var(--brand-deep); }

        .reg-footer .divider {
            display: flex;
            align-items: center;
            gap: 10px;
            color: #cbd5e1;
            font-size: .78rem;
        }
        .reg-footer .divider::before,
        .reg-footer .divider::after {
            content: '';
            flex: 1;
            height: 1px;
            background: var(--line);
        }

        /* ── Responsive ─────────────────────────────────────── */
        @media (max-width: 680px) {
            body { padding: 20px 12px 40px; }
            .reg-header { padding: 24px 24px 0; }
            .reg-body   { padding: 24px 24px 28px; }
            .reg-grid   { grid-template-columns: 1fr; }
            .reg-field.full { grid-column: auto; }
            .reg-hero h1 { font-size: 1.45rem; }
        }

        @media (max-width: 420px) {
            .reg-card { border-radius: 20px; }
            .reg-hero h1 { font-size: 1.25rem; }
            .reg-tabs { gap: 4px; padding: 6px 6px 0; }
            .tab-btn { font-size: .8rem; padding: 9px 10px; }
        }

        @media (prefers-reduced-motion: reduce) {
            *, *::before, *::after {
                animation-duration: .01ms !important;
                transition-duration: .01ms !important;
            }
        }

        /* ── RTL overrides ──────────────────────────────────── */
        [dir="rtl"] body { font-family: 'Cairo', sans-serif; }
        [dir="rtl"] .input-icon { left: auto; right: 14px; }
        [dir="rtl"] .input-wrap input,
        [dir="rtl"] .input-wrap textarea { padding-left: 14px; padding-right: 42px; text-align: right; }
        [dir="rtl"] .input-wrap input.has-toggle { padding-left: 46px; padding-right: 42px; }
        [dir="rtl"] .pw-toggle { right: auto; left: 12px; }
        [dir="rtl"] .back-link i { transform: scaleX(-1); }
        [dir="rtl"] .reg-header-top { flex-direction: row-reverse; }

        /* ── Registration map widget ────────────────────────────── */
        .reg-map-wrap {
            display: flex;
            flex-direction: column;
            gap: 10px;
        }
        .reg-map-label {
            font-size: .82rem;
            font-weight: 700;
            color: #1e293b;
            display: flex;
            align-items: center;
            gap: 6px;
        }
        .reg-map-label .req-star {
            color: #f43f5e;
            font-size: .7rem;
        }
        .reg-map-container {
            width: 100%;
            height: 300px;
            border-radius: 14px;
            border: 2px solid var(--line);
            overflow: hidden;
            transition: border-color .2s;
        }
        .reg-map-container.map-required-error {
            border-color: #f43f5e;
            box-shadow: 0 0 0 4px rgba(244,63,94,.10);
        }
        .reg-map-hint {
            font-size: .76rem;
            color: var(--muted);
            display: flex;
            align-items: center;
            gap: 6px;
        }
        .reg-map-status {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: .82rem;
            font-weight: 600;
            padding: 8px 12px;
            border-radius: 10px;
            background: #f1f5f9;
            color: var(--muted);
        }
        .reg-map-status.has-pin {
            background: #ecfdf5;
            color: #065f46;
        }
        .reg-map-status.has-pin i { color: #22c55e; }
        .reg-map-gps-btn {
            display: inline-flex;
            align-items: center;
            gap: 7px;
            border: 2px solid var(--line);
            border-radius: 10px;
            background: #fff;
            color: #334155;
            font-family: inherit;
            font-size: .82rem;
            font-weight: 700;
            padding: 7px 14px;
            cursor: pointer;
            transition: border-color .2s, color .2s;
        }
        .reg-map-gps-btn:hover { border-color: var(--brand); color: var(--brand); }
        .reg-map-gps-btn:disabled { opacity: .6; cursor: not-allowed; }
        @media (max-width: 480px) {
            .reg-map-container { height: 250px; }
        }
    </style>
</head>
<body>
    <!-- Ambient background -->
    <div class="bg-shape bg-shape-1" aria-hidden="true"></div>
    <div class="bg-shape bg-shape-2" aria-hidden="true"></div>
    <div class="bg-shape bg-shape-3" aria-hidden="true"></div>

    <div class="reg-card" role="main">

        <!-- ═══ GRADIENT HEADER ═════════════════════════════ -->
        <div class="reg-header">
            <div class="reg-header-top">
                <a href="home.php" class="back-link">
                    <i class="fas fa-arrow-left" aria-hidden="true"></i>
                    <?php echo htmlspecialchars(t('nav_back_home'), ENT_QUOTES, 'UTF-8'); ?>
                </a>
                <a href="<?php echo htmlspecialchars(langSwitchUrl(), ENT_QUOTES, 'UTF-8'); ?>" class="lang-btn">
                    <i class="fa-solid fa-globe" aria-hidden="true"></i>
                    <?php echo htmlspecialchars(t('lang_switch_label'), ENT_QUOTES, 'UTF-8'); ?>
                </a>
            </div>

            <div class="reg-hero">
                <div class="reg-logo" aria-hidden="true">
                    <i class="fas fa-user-plus"></i>
                </div>
                <h1><?php echo htmlspecialchars(t('register_title'), ENT_QUOTES, 'UTF-8'); ?></h1>
                <p><?php echo htmlspecialchars(t('register_subtitle'), ENT_QUOTES, 'UTF-8'); ?></p>
            </div>

            <!-- Account-type tabs -->
            <div class="reg-tabs" role="tablist" aria-label="Account type">
                <button
                    type="button"
                    class="tab-btn <?php echo $selectedUserType === 'customer' ? 'active' : ''; ?>"
                    data-type="customer"
                    role="tab"
                    aria-selected="<?php echo $selectedUserType === 'customer' ? 'true' : 'false'; ?>"
                    onclick="selectType(this)"
                >
                    <i class="fas fa-user" aria-hidden="true"></i>
                    <?php echo htmlspecialchars(t('register_tab_customer'), ENT_QUOTES, 'UTF-8'); ?>
                </button>
                <button
                    type="button"
                    class="tab-btn <?php echo $selectedUserType === 'service_provider' ? 'active' : ''; ?>"
                    data-type="service_provider"
                    role="tab"
                    aria-selected="<?php echo $selectedUserType === 'service_provider' ? 'true' : 'false'; ?>"
                    onclick="selectType(this)"
                >
                    <i class="fas fa-screwdriver-wrench" aria-hidden="true"></i>
                    <?php echo htmlspecialchars(t('register_tab_provider'), ENT_QUOTES, 'UTF-8'); ?>
                </button>
            </div>
        </div><!-- /.reg-header -->

        <!-- ═══ FORM BODY ═══════════════════════════════════ -->
        <div class="reg-body">

            <!-- Server-side error banner -->
            <?php if ($errorMessage !== ''): ?>
                <div class="reg-alert is-error" role="alert">
                    <i class="fas fa-circle-exclamation reg-alert-icon" aria-hidden="true"></i>
                    <span><?php echo htmlspecialchars($errorMessage, ENT_QUOTES, 'UTF-8'); ?></span>
                </div>
            <?php endif; ?>

            <!-- Client-side error (JS-driven) -->
            <div id="clientAlert" class="reg-alert is-error is-hidden" role="alert" aria-live="polite">
                <i class="fas fa-circle-exclamation reg-alert-icon" aria-hidden="true"></i>
                <span id="clientAlertText"></span>
            </div>

            <form id="regForm" method="post" action="register.php" novalidate>
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars((string) $_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">
                <input type="hidden" name="user_type" id="userTypeInput" value="<?php echo htmlspecialchars($selectedUserType, ENT_QUOTES, 'UTF-8'); ?>">

                <!-- ── Section 1: Personal Information ──────── -->
                <div class="reg-section">
                    <div class="reg-section-head">
                        <span class="section-num">1</span>
                        <span class="section-title"><?php echo htmlspecialchars(t('register_section_personal'), ENT_QUOTES, 'UTF-8'); ?></span>
                        <span class="section-divider" aria-hidden="true"></span>
                    </div>

                    <div class="reg-grid">
                        <!-- First Name -->
                        <div class="reg-field">
                            <label for="first_name"><?php echo htmlspecialchars(t('register_first_name'), ENT_QUOTES, 'UTF-8'); ?></label>
                            <div class="input-wrap">
                                <i class="fas fa-user input-icon" aria-hidden="true"></i>
                                <input
                                    type="text"
                                    id="first_name"
                                    name="first_name"
                                    value="<?php echo htmlspecialchars($firstNameValue, ENT_QUOTES, 'UTF-8'); ?>"
                                    placeholder="<?php echo htmlspecialchars(t('register_ph_first_name'), ENT_QUOTES, 'UTF-8'); ?>"
                                    autocomplete="given-name"
                                    maxlength="100"
                                    required
                                >
                            </div>
                        </div>

                        <!-- Last Name -->
                        <div class="reg-field">
                            <label for="last_name"><?php echo htmlspecialchars(t('register_last_name'), ENT_QUOTES, 'UTF-8'); ?></label>
                            <div class="input-wrap">
                                <i class="fas fa-user input-icon" aria-hidden="true"></i>
                                <input
                                    type="text"
                                    id="last_name"
                                    name="last_name"
                                    value="<?php echo htmlspecialchars($lastNameValue, ENT_QUOTES, 'UTF-8'); ?>"
                                    placeholder="<?php echo htmlspecialchars(t('register_ph_last_name'), ENT_QUOTES, 'UTF-8'); ?>"
                                    autocomplete="family-name"
                                    maxlength="100"
                                    required
                                >
                            </div>
                        </div>

                        <!-- Email -->
                        <div class="reg-field full">
                            <label for="email"><?php echo htmlspecialchars(t('register_email'), ENT_QUOTES, 'UTF-8'); ?></label>
                            <div class="input-wrap">
                                <i class="fas fa-envelope input-icon" aria-hidden="true"></i>
                                <input
                                    type="email"
                                    id="email"
                                    name="email"
                                    dir="ltr"
                                    value="<?php echo htmlspecialchars($emailValue, ENT_QUOTES, 'UTF-8'); ?>"
                                    placeholder="you@example.com"
                                    autocomplete="email"
                                    required
                                >
                            </div>
                            <span id="emailProviderHint" class="field-hint <?php echo $showEmailProviderHint ? '' : 'is-hidden'; ?>">
                                <i class="fas fa-circle-info" style="color:#f97316;margin-right:3px;" aria-hidden="true"></i>
                                <?php echo htmlspecialchars(implode(', ', ALLOWED_EMAIL_DOMAINS), ENT_QUOTES, 'UTF-8'); ?>
                            </span>
                        </div>

                        <!-- Phone -->
                        <div class="reg-field full">
                            <label for="phone"><?php echo htmlspecialchars(t('register_phone'), ENT_QUOTES, 'UTF-8'); ?></label>
                            <div class="input-wrap">
                                <i class="fas fa-phone input-icon" aria-hidden="true"></i>
                                <input
                                    type="tel"
                                    id="phone"
                                    name="phone"
                                    dir="ltr"
                                    value="<?php echo htmlspecialchars($phoneValue, ENT_QUOTES, 'UTF-8'); ?>"
                                    placeholder="+961 XX XXX XXX"
                                    autocomplete="tel"
                                    maxlength="20"
                                    required
                                >
                            </div>
                        </div>
                    </div>
                </div>

                <!-- ── Section 2: Security ───────────────────── -->
                <div class="reg-section">
                    <div class="reg-section-head">
                        <span class="section-num">2</span>
                        <span class="section-title"><?php echo htmlspecialchars(t('register_section_security'), ENT_QUOTES, 'UTF-8'); ?></span>
                        <span class="section-divider" aria-hidden="true"></span>
                    </div>

                    <div class="reg-grid">
                        <!-- Password -->
                        <div class="reg-field">
                            <label for="password"><?php echo htmlspecialchars(t('register_password'), ENT_QUOTES, 'UTF-8'); ?></label>
                            <div class="input-wrap">
                                <i class="fas fa-lock input-icon" aria-hidden="true"></i>
                                <input
                                    type="password"
                                    id="password"
                                    name="password"
                                    class="has-toggle"
                                    placeholder="••••••••"
                                    autocomplete="new-password"
                                    required
                                    oninput="onPwInput(this.value)"
                                >
                                <button type="button" class="pw-toggle" onclick="togglePw('password','pwToggleIcon1')" aria-label="Toggle password">
                                    <i class="fas fa-eye" id="pwToggleIcon1"></i>
                                </button>
                            </div>
                            <!-- Strength meter -->
                            <div id="pwStrengthWrap" class="pw-strength-wrap" aria-live="polite">
                                <div class="pw-bar-bg"><div id="pwBarFill" class="pw-bar-fill"></div></div>
                                <span id="pwStrengthLabel" class="pw-label"></span>
                                <div class="pw-rules">
                                    <span class="pw-rule" id="rLen"><i class="fas fa-circle"></i> <?php echo htmlspecialchars(t('pw_rule_len'), ENT_QUOTES, 'UTF-8'); ?></span>
                                    <span class="pw-rule" id="rUpper"><i class="fas fa-circle"></i> <?php echo htmlspecialchars(t('pw_rule_upper'), ENT_QUOTES, 'UTF-8'); ?></span>
                                    <span class="pw-rule" id="rLower"><i class="fas fa-circle"></i> <?php echo htmlspecialchars(t('pw_rule_lower'), ENT_QUOTES, 'UTF-8'); ?></span>
                                    <span class="pw-rule" id="rNum"><i class="fas fa-circle"></i> <?php echo htmlspecialchars(t('pw_rule_num'), ENT_QUOTES, 'UTF-8'); ?></span>
                                    <span class="pw-rule" id="rSpecial"><i class="fas fa-circle"></i> <?php echo htmlspecialchars(t('pw_rule_special'), ENT_QUOTES, 'UTF-8'); ?></span>
                                </div>
                            </div>
                        </div>

                        <!-- Confirm Password -->
                        <div class="reg-field">
                            <label for="confirm_password"><?php echo htmlspecialchars(t('register_confirm'), ENT_QUOTES, 'UTF-8'); ?></label>
                            <div class="input-wrap">
                                <i class="fas fa-shield-halved input-icon" aria-hidden="true"></i>
                                <input
                                    type="password"
                                    id="confirm_password"
                                    name="confirm_password"
                                    class="has-toggle"
                                    placeholder="••••••••"
                                    autocomplete="new-password"
                                    required
                                    oninput="onConfirmInput(this.value)"
                                >
                                <button type="button" class="pw-toggle" onclick="togglePw('confirm_password','pwToggleIcon2')" aria-label="Toggle confirm password">
                                    <i class="fas fa-eye" id="pwToggleIcon2"></i>
                                </button>
                            </div>
                            <div id="confirmMatch" class="confirm-match" aria-live="polite">
                                <i class="fas fa-circle-check" id="confirmMatchIcon" aria-hidden="true"></i>
                                <span id="confirmMatchText"></span>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- ── Section 3: Additional Details ─────────── -->
                <div class="reg-section">
                    <div class="reg-section-head">
                        <span class="section-num">3</span>
                        <span class="section-title"><?php echo htmlspecialchars(t('register_section_details'), ENT_QUOTES, 'UTF-8'); ?></span>
                        <span class="section-divider" aria-hidden="true"></span>
                    </div>

                    <!-- Customer: Location map -->
                    <div id="customerFields" class="cond-fields <?php echo $selectedUserType === 'customer' ? 'show' : ''; ?>">
                        <div class="reg-map-wrap">
                            <span class="reg-map-label">
                                <i class="fas fa-map-marker-alt" aria-hidden="true"></i>
                                <?php echo htmlspecialchars(t('register_map_location_label'), ENT_QUOTES, 'UTF-8'); ?>
                                <span class="req-star" aria-hidden="true">*</span>
                            </span>
                            <p class="reg-map-hint">
                                <i class="fas fa-info-circle" aria-hidden="true"></i>
                                <?php echo htmlspecialchars(t('register_map_location_hint'), ENT_QUOTES, 'UTF-8'); ?>
                            </p>
                            <div id="regLocationMap" class="reg-map-container" role="application" aria-label="<?php echo htmlspecialchars(t('register_map_location_label'), ENT_QUOTES, 'UTF-8'); ?>"></div>
                            <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
                                <button type="button" id="regGpsBtn" class="reg-map-gps-btn">
                                    <i class="fas fa-location-crosshairs" aria-hidden="true"></i>
                                    <?php echo htmlspecialchars(t('cust_map_use_gps'), ENT_QUOTES, 'UTF-8'); ?>
                                </button>
                            </div>
                            <div id="regMapStatus" class="reg-map-status" aria-live="polite">
                                <i class="fas fa-circle-xmark" aria-hidden="true"></i>
                                <span id="regMapStatusText"><?php echo htmlspecialchars(t('cust_map_no_location'), ENT_QUOTES, 'UTF-8'); ?></span>
                            </div>
                            <input type="hidden" id="reg_lat" name="reg_lat" value="<?php echo htmlspecialchars($latValue, ENT_QUOTES, 'UTF-8'); ?>">
                            <input type="hidden" id="reg_lng" name="reg_lng" value="<?php echo htmlspecialchars($lngValue, ENT_QUOTES, 'UTF-8'); ?>">
                        </div>
                    </div>

                    <!-- Provider: Bio + Service Location -->
                    <div id="providerFields" class="cond-fields <?php echo $selectedUserType === 'service_provider' ? 'show' : ''; ?>">
                        <div class="reg-grid" style="margin-bottom:14px;">
                            <div class="reg-field full">
                                <label for="bio"><?php echo htmlspecialchars(t('prov_profile_bio'), ENT_QUOTES, 'UTF-8'); ?></label>
                                <div class="input-wrap">
                                    <i class="fas fa-briefcase input-icon" style="top:16px;transform:none;" aria-hidden="true"></i>
                                    <textarea
                                        id="bio"
                                        name="bio"
                                        placeholder="<?php echo htmlspecialchars(t('register_provider_bio_ph'), ENT_QUOTES, 'UTF-8'); ?>"
                                        <?php echo $selectedUserType === 'service_provider' ? 'required' : ''; ?>
                                        maxlength="2000"
                                    ><?php echo htmlspecialchars($bioValue, ENT_QUOTES, 'UTF-8'); ?></textarea>
                                </div>
                            </div>
                            <div class="reg-field full">
                                <label for="provider_location"><?php echo htmlspecialchars(t('register_provider_address'), ENT_QUOTES, 'UTF-8'); ?></label>
                                <div class="input-wrap">
                                    <i class="fas fa-map-location-dot input-icon" aria-hidden="true"></i>
                                    <input
                                        type="text"
                                        id="provider_location"
                                        name="provider_location"
                                        value="<?php echo htmlspecialchars($locationValue, ENT_QUOTES, 'UTF-8'); ?>"
                                        placeholder="<?php echo htmlspecialchars(t('register_provider_address_ph'), ENT_QUOTES, 'UTF-8'); ?>"
                                        maxlength="255"
                                        <?php echo $selectedUserType === 'service_provider' ? 'required' : ''; ?>
                                    >
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- ── Submit ─────────────────────────────────── -->
                <button type="submit" id="submitBtn" class="reg-submit">
                    <span id="submitLabel"><?php echo htmlspecialchars(t('register_button'), ENT_QUOTES, 'UTF-8'); ?></span>
                    <i id="submitIcon" class="fas fa-arrow-right" aria-hidden="true"></i>
                </button>
            </form>

            <!-- Footer links -->
            <div class="reg-footer">
                <div class="divider"><?php echo htmlspecialchars(t('register_have_account'), ENT_QUOTES, 'UTF-8'); ?></div>
                <p>
                    <a href="login.php">
                        <i class="fas fa-right-to-bracket" style="margin-<?php echo isRtl() ? 'left' : 'right'; ?>:4px;" aria-hidden="true"></i>
                        <?php echo htmlspecialchars(t('register_login_link'), ENT_QUOTES, 'UTF-8'); ?>
                    </a>
                </p>
                <p>
                    <a href="forgot_password.php" style="font-weight:500;color:var(--muted);font-size:.85rem;">
                        <i class="fas fa-key" style="margin-<?php echo isRtl() ? 'left' : 'right'; ?>:4px;" aria-hidden="true"></i>
                        <?php echo htmlspecialchars(t('register_forgot_pw_link'), ENT_QUOTES, 'UTF-8'); ?>
                    </a>
                </p>
            </div>

        </div><!-- /.reg-body -->
    </div><!-- /.reg-card -->

    <script>
    (function () {
        'use strict';

        /* ── Element refs ── */
        var userTypeInput   = document.getElementById('userTypeInput');
        var customerFields  = document.getElementById('customerFields');
        var providerFields  = document.getElementById('providerFields');
        var regLatInput     = document.getElementById('reg_lat');
        var regLngInput     = document.getElementById('reg_lng');
        var bioTA           = document.getElementById('bio');
        var locationInput   = document.getElementById('provider_location');
        var pwInput         = document.getElementById('password');
        var confirmInput    = document.getElementById('confirm_password');
        var emailInput      = document.getElementById('email');
        var phoneInput      = document.getElementById('phone');
        var firstNameInput  = document.getElementById('first_name');
        var lastNameInput   = document.getElementById('last_name');
        var clientAlert     = document.getElementById('clientAlert');
        var clientAlertText = document.getElementById('clientAlertText');
        var emailHint       = document.getElementById('emailProviderHint');
        var submitBtn       = document.getElementById('submitBtn');
        var submitLabel     = document.getElementById('submitLabel');
        var submitIcon      = document.getElementById('submitIcon');

        /* ── Validation constants ── */
        var emailRx    = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        var phoneRx    = /^[0-9+()\-\s]{7,20}$/;
        var pwRx       = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z0-9]).{8,}$/;
        var allowedDomains = <?php echo json_encode(ALLOWED_EMAIL_DOMAINS, JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_AMP|JSON_HEX_QUOT); ?>;
        var domainMsg  = <?php echo json_encode($allowedDomainMessage, JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_AMP|JSON_HEX_QUOT); ?>;

        /* i18n snippets injected from PHP */
        var i18n = {
            pwMatch:      <?php echo json_encode(t('register_pw_match'),   JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_AMP|JSON_HEX_QUOT); ?>,
            pwNoMatch:    <?php echo json_encode(t('register_pw_no_match'), JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_AMP|JSON_HEX_QUOT); ?>,
            weak:         <?php echo json_encode(t('pw_weak'),   JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_AMP|JSON_HEX_QUOT); ?>,
            fair:         <?php echo json_encode(t('pw_fair'),   JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_AMP|JSON_HEX_QUOT); ?>,
            good:         <?php echo json_encode(t('pw_good'),   JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_AMP|JSON_HEX_QUOT); ?>,
            strong:       <?php echo json_encode(t('pw_strong'), JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_AMP|JSON_HEX_QUOT); ?>,
            creating:     <?php echo json_encode(t('register_creating'), JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_AMP|JSON_HEX_QUOT); ?>,
            fnEmpty:      <?php echo json_encode(t('register_err_first_name_empty'), JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_AMP|JSON_HEX_QUOT); ?>,
            lnEmpty:      <?php echo json_encode(t('register_err_last_name_empty'),  JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_AMP|JSON_HEX_QUOT); ?>,
            phoneEmpty:   <?php echo json_encode(t('register_err_phone_empty'),   JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_AMP|JSON_HEX_QUOT); ?>,
            phoneInval:   <?php echo json_encode(t('register_err_phone_invalid'), JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_AMP|JSON_HEX_QUOT); ?>,
            emailEmpty:   <?php echo json_encode(t('register_err_email_empty'),   JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_AMP|JSON_HEX_QUOT); ?>,
            emailInval:   <?php echo json_encode(t('register_err_email_invalid'), JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_AMP|JSON_HEX_QUOT); ?>,
            pwWeak:       <?php echo json_encode(t('register_err_pw_weak'),      JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_AMP|JSON_HEX_QUOT); ?>,
            pwMismatch:   <?php echo json_encode(t('register_err_pw_mismatch'),  JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_AMP|JSON_HEX_QUOT); ?>,
            mapLocReq:    <?php echo json_encode(t('register_err_map_location_required'), JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_AMP|JSON_HEX_QUOT); ?>,
            bioEmpty:     <?php echo json_encode(t('register_err_bio_empty'),       JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_AMP|JSON_HEX_QUOT); ?>,
            locEmpty:     <?php echo json_encode(t('register_err_location_empty'),  JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_AMP|JSON_HEX_QUOT); ?>,
            noLocation:   <?php echo json_encode(t('cust_map_no_location'),         JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_AMP|JSON_HEX_QUOT); ?>,
            coordsSet:    <?php echo json_encode(t('cust_map_coords_set'),          JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_AMP|JSON_HEX_QUOT); ?>,
            gpsLoading:   <?php echo json_encode(t('cust_map_gps_loading'),         JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_AMP|JSON_HEX_QUOT); ?>,
            gpsError:     <?php echo json_encode(t('cust_map_gps_error'),           JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_AMP|JSON_HEX_QUOT); ?>,
            gpsNoSupport: <?php echo json_encode(t('cust_map_gps_unsupported'),     JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_AMP|JSON_HEX_QUOT); ?>,
        };

        /* ── Account-type toggle ── */
        window.selectType = function (btn) {
            document.querySelectorAll('.tab-btn').forEach(function (b) {
                var active = b === btn;
                b.classList.toggle('active', active);
                b.setAttribute('aria-selected', active ? 'true' : 'false');
            });

            var type = btn.dataset.type || 'customer';
            if (userTypeInput) userTypeInput.value = type;

            var isCustomer = type === 'customer';
            if (customerFields) customerFields.classList.toggle('show', isCustomer);
            if (providerFields) providerFields.classList.toggle('show', !isCustomer);

            if (bioTA)         bioTA.required         = !isCustomer;
            if (locationInput) locationInput.required  = !isCustomer;

            /* Initialise the registration map when the customer tab becomes visible */
            if (isCustomer) {
                requestAnimationFrame(function () {
                    requestAnimationFrame(function () {
                        initRegMap();
                    });
                });
            }
        };

        /* Re-apply required states after PHP repopulation */
        var activeTab = document.querySelector('.tab-btn.active');
        if (activeTab) selectType(activeTab);

        /* ── Password toggle ── */
        window.togglePw = function (inputId, iconId) {
            var inp  = document.getElementById(inputId);
            var icon = document.getElementById(iconId);
            if (!inp || !icon) return;
            var show = inp.type === 'password';
            inp.type = show ? 'text' : 'password';
            icon.className = show ? 'fas fa-eye-slash' : 'fas fa-eye';
        };

        /* ── Password strength ── */
        window.onPwInput = function (val) {
            var wrap  = document.getElementById('pwStrengthWrap');
            var fill  = document.getElementById('pwBarFill');
            var lbl   = document.getElementById('pwStrengthLabel');
            if (!wrap || !fill || !lbl) return;

            if (!val) { wrap.classList.remove('show'); return; }
            wrap.classList.add('show');

            var hLen     = val.length >= 8;
            var hUpper   = /[A-Z]/.test(val);
            var hLower   = /[a-z]/.test(val);
            var hNum     = /\d/.test(val);
            var hSpecial = /[^a-zA-Z0-9]/.test(val);
            var score    = [hLen,hUpper,hLower,hNum,hSpecial].filter(Boolean).length;

            function setRule(id, ok) {
                var el = document.getElementById(id);
                if (el) el.classList.toggle('ok', ok);
            }
            setRule('rLen', hLen); setRule('rUpper', hUpper);
            setRule('rLower', hLower); setRule('rNum', hNum); setRule('rSpecial', hSpecial);

            var pct, color, cls, text;
            if      (score <= 2) { pct=25;  color='#ef4444'; cls='weak';   text=i18n.weak;   }
            else if (score === 3){ pct=50;  color='#f97316'; cls='fair';   text=i18n.fair;   }
            else if (score === 4){ pct=75;  color='#eab308'; cls='good';   text=i18n.good;   }
            else                 { pct=100; color='#22c55e'; cls='strong'; text=i18n.strong; }

            fill.style.width      = pct + '%';
            fill.style.background = color;
            lbl.className         = 'pw-label ' + cls;
            lbl.textContent       = text;

            /* Update confirm match if confirm has a value */
            if (confirmInput && confirmInput.value) onConfirmInput(confirmInput.value);
        };

        /* ── Confirm password real-time match ── */
        window.onConfirmInput = function (val) {
            var box  = document.getElementById('confirmMatch');
            var icon = document.getElementById('confirmMatchIcon');
            var txt  = document.getElementById('confirmMatchText');
            if (!box || !icon || !txt) return;

            if (!val) { box.classList.remove('show'); return; }
            box.classList.add('show');

            var match = pwInput && val === pwInput.value;
            box.className  = 'confirm-match show ' + (match ? 'ok' : 'fail');
            icon.className = match ? 'fas fa-circle-check' : 'fas fa-circle-xmark';
            txt.textContent= match ? i18n.pwMatch : i18n.pwNoMatch;

            if (confirmInput) confirmInput.classList.toggle('is-valid',   match);
            if (confirmInput) confirmInput.classList.toggle('is-invalid', !match);
        };

        /* ── Helper: show/hide email provider hint ── */
        function showEmailHint(show) {
            if (!emailHint) return;
            emailHint.classList.toggle('is-hidden', !show);
        }

        /* ── Client-side error banner ── */
        function showErr(msg) {
            if (!clientAlert || !clientAlertText) return;
            clientAlertText.textContent = msg;
            clientAlert.classList.remove('is-hidden');
            clientAlert.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }
        function clearErr() {
            if (!clientAlert) return;
            clientAlert.classList.add('is-hidden');
            clientAlertText.textContent = '';
        }

        function getEmailDomain(email) {
            var idx = email.lastIndexOf('@');
            return idx === -1 ? '' : email.slice(idx + 1).toLowerCase();
        }

        /* ── Form submit validation ── */
        var form = document.getElementById('regForm');
        if (form) {
            form.addEventListener('invalid', function(e){ e.preventDefault(); }, true);

            form.addEventListener('submit', function (e) {
                var fn      = firstNameInput ? firstNameInput.value.trim() : '';
                var ln      = lastNameInput  ? lastNameInput.value.trim()  : '';
                var phone   = phoneInput  ? phoneInput.value.trim()  : '';
                var email   = emailInput  ? emailInput.value.trim()  : '';
                var pw      = pwInput     ? pwInput.value            : '';
                var cpw     = confirmInput? confirmInput.value       : '';
                var type    = userTypeInput ? userTypeInput.value    : 'customer';
                var bio     = bioTA       ? bioTA.value.trim()       : '';
                var loc     = locationInput ? locationInput.value.trim() : '';
                var lat     = regLatInput ? regLatInput.value.trim() : '';
                var lng     = regLngInput ? regLngInput.value.trim() : '';

                showEmailHint(false);
                clearErr();

                /* Trim inputs */
                if (firstNameInput) firstNameInput.value = fn;
                if (lastNameInput)  lastNameInput.value  = ln;
                if (phoneInput)     phoneInput.value     = phone;
                if (emailInput)     emailInput.value     = email;
                if (bioTA)          bioTA.value          = bio;
                if (locationInput)  locationInput.value  = loc;

                function fail(msg, el) {
                    e.preventDefault();
                    showErr(msg);
                    if (el) { el.focus(); el.classList.add('is-invalid'); }
                }
                function failMap(msg) {
                    e.preventDefault();
                    showErr(msg);
                    var mc = document.getElementById('regLocationMap');
                    if (mc) mc.classList.add('map-required-error');
                    var ms = document.getElementById('regMapStatus');
                    if (ms) ms.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
                }

                if (!fn)                            { fail(i18n.fnEmpty,    firstNameInput); return; }
                if (!ln)                            { fail(i18n.lnEmpty,    lastNameInput);  return; }
                if (!phone)                         { fail(i18n.phoneEmpty, phoneInput); return; }
                if (!phoneRx.test(phone))           { fail(i18n.phoneInval, phoneInput); return; }
                if (!email)                         { fail(i18n.emailEmpty, emailInput); return; }
                if (!emailRx.test(email))           { showEmailHint(true); fail(i18n.emailInval, emailInput); return; }
                if (allowedDomains.indexOf(getEmailDomain(email)) === -1) { showEmailHint(true); fail(domainMsg, emailInput); return; }
                if (!pwRx.test(pw))                 { fail(i18n.pwWeak,    pwInput); return; }
                if (pw !== cpw)                     { fail(i18n.pwMismatch, confirmInput); return; }
                if (type === 'customer' && (!lat || !lng)) { failMap(i18n.mapLocReq); return; }
                if (type === 'service_provider' && !bio)  { fail(i18n.bioEmpty,  bioTA);         return; }
                if (type === 'service_provider' && !loc)  { fail(i18n.locEmpty,  locationInput); return; }

                clearErr();
                /* Loading state */
                if (submitBtn) submitBtn.disabled = true;
                if (submitLabel) submitLabel.textContent = i18n.creating;
                if (submitIcon)  submitIcon.className    = 'fas fa-spinner fa-spin';
            });

            /* Remove is-invalid / map-required-error on interaction */
            form.addEventListener('input', function(e) {
                if (e.target.classList.contains('is-invalid')) {
                    e.target.classList.remove('is-invalid');
                }
            });
            form.addEventListener('click', function(e) {
                var mc = document.getElementById('regLocationMap');
                if (mc) mc.classList.remove('map-required-error');
            });
        }

    }());
    </script>

    <!-- Leaflet JS — served locally so the map works without internet access -->
    <script src="vendor/leaflet/leaflet.js"></script>
    <script>
    (function () {
        'use strict';

        /* i18n strings needed by the map widget (i18n from the form IIFE is not in scope here) */
        var mapI18n = {
            noLocation  : <?php echo json_encode(t('cust_map_no_location'),     JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_AMP|JSON_HEX_QUOT); ?>,
            coordsSet   : <?php echo json_encode(t('cust_map_coords_set'),      JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_AMP|JSON_HEX_QUOT); ?>,
            gpsLoading  : <?php echo json_encode(t('cust_map_gps_loading'),     JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_AMP|JSON_HEX_QUOT); ?>,
            gpsError    : <?php echo json_encode(t('cust_map_gps_error'),       JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_AMP|JSON_HEX_QUOT); ?>,
            gpsNoSupport: <?php echo json_encode(t('cust_map_gps_unsupported'), JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_AMP|JSON_HEX_QUOT); ?>,
        };

        /* Saved lat/lng from server-side re-population (after a failed POST) */
        var SAVED_LAT = <?php echo ($latValue !== '' && filter_var($latValue, FILTER_VALIDATE_FLOAT) !== false) ? json_encode((float) $latValue) : 'null'; ?>;
        var SAVED_LNG = <?php echo ($lngValue !== '' && filter_var($lngValue, FILTER_VALIDATE_FLOAT) !== false) ? json_encode((float) $lngValue) : 'null'; ?>;

        var mapEl      = document.getElementById('regLocationMap');
        var latInput   = document.getElementById('reg_lat');
        var lngInput   = document.getElementById('reg_lng');
        var gpsBtn     = document.getElementById('regGpsBtn');
        var statusBox  = document.getElementById('regMapStatus');
        var statusText = document.getElementById('regMapStatusText');

        var regMap    = null;
        var regMarker = null;
        var _mapReady = false;

        function setStatus(lat, lng) {
            if (lat === null || lng === null) {
                statusBox.className  = 'reg-map-status';
                statusBox.querySelector('i').className = 'fas fa-circle-xmark';
                statusText.textContent = mapI18n.noLocation;
            } else {
                statusBox.className  = 'reg-map-status has-pin';
                statusBox.querySelector('i').className = 'fas fa-circle-check';
                statusText.textContent = mapI18n.coordsSet + ' (' + lat.toFixed(6) + ', ' + lng.toFixed(6) + ')';
            }
        }

        function placePin(lat, lng) {
            var ll = L.latLng(lat, lng);
            if (regMarker) {
                regMarker.setLatLng(ll);
            } else {
                regMarker = L.marker(ll, { draggable: true }).addTo(regMap);
                regMarker.on('dragend', function () {
                    var p = regMarker.getLatLng();
                    latInput.value = p.lat;
                    lngInput.value = p.lng;
                    setStatus(p.lat, p.lng);
                    var mc = document.getElementById('regLocationMap');
                    if (mc) mc.classList.remove('map-required-error');
                });
            }
            latInput.value = lat;
            lngInput.value = lng;
            setStatus(lat, lng);
            var mc = document.getElementById('regLocationMap');
            if (mc) mc.classList.remove('map-required-error');
        }

        window.initRegMap = function () {
            if (_mapReady || !mapEl || typeof L === 'undefined') return;
            _mapReady = true;

            var cLat  = SAVED_LAT !== null ? SAVED_LAT : 33.8938;
            var cLng  = SAVED_LNG !== null ? SAVED_LNG : 35.5018;
            var cZoom = SAVED_LAT !== null ? 16 : 12;

            regMap = L.map('regLocationMap', { zoomControl: true }).setView([cLat, cLng], cZoom);

            L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
                maxZoom: 19,
                attribution: '© <a href="https://www.openstreetmap.org/copyright" target="_blank">OpenStreetMap</a> contributors'
            }).addTo(regMap);

            if (SAVED_LAT !== null && SAVED_LNG !== null) {
                placePin(SAVED_LAT, SAVED_LNG);
            }

            regMap.on('click', function (e) {
                placePin(e.latlng.lat, e.latlng.lng);
            });

            if (gpsBtn) {
                gpsBtn.addEventListener('click', function () {
                    if (!navigator.geolocation) {
                        statusText.textContent = mapI18n.gpsNoSupport;
                        return;
                    }
                    gpsBtn.disabled  = true;
                    var orig = gpsBtn.innerHTML;
                    gpsBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> ' + mapI18n.gpsLoading;
                    navigator.geolocation.getCurrentPosition(
                        function (pos) {
                            var lat = pos.coords.latitude;
                            var lng = pos.coords.longitude;
                            placePin(lat, lng);
                            regMap.setView([lat, lng], 17);
                            gpsBtn.disabled  = false;
                            gpsBtn.innerHTML = orig;
                        },
                        function () {
                            statusBox.className = 'reg-map-status';
                            statusText.textContent = mapI18n.gpsError;
                            gpsBtn.disabled  = false;
                            gpsBtn.innerHTML = orig;
                        },
                        { enableHighAccuracy: true, timeout: 10000, maximumAge: 0 }
                    );
                });
            }
        };

        /* Auto-init if customer tab is active on page load */
        var activeTypeBtn = document.querySelector('.tab-btn.active');
        if (!activeTypeBtn || activeTypeBtn.dataset.type === 'customer') {
            requestAnimationFrame(function () {
                requestAnimationFrame(function () {
                    window.initRegMap();
                });
            });
        }
    }());
    </script>
</body>
</html>
