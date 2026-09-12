<?php
declare(strict_types=1);

session_start();

require_once __DIR__ . '/db_connection.php';
require_once __DIR__ . '/auth_config.php';
require_once __DIR__ . '/email_verification_store.php';
require_once __DIR__ . '/mailer.php';

ensureEmailVerificationTable($pdo);

require_once __DIR__ . '/suspension_store.php';
require_once __DIR__ . '/site_settings.php';
require_once __DIR__ . '/lang.php';

ensureSiteSettingsTable($pdo);
$loginSiteDefaults = [
    'site_favicon'      => '',
    'site_name'         => '',
    'site_tagline'      => '',
    'feature_1_title'   => '',
    'feature_1_body'    => '',
    'feature_2_title'   => '',
    'feature_2_body'    => '',
    'feature_3_title'   => '',
    'feature_3_body'    => '',
    'site_name_ar'        => '',
    'feature_1_title_ar'  => '',
    'feature_1_body_ar'   => '',
    'feature_2_title_ar'  => '',
    'feature_2_body_ar'   => '',
    'feature_3_title_ar'  => '',
    'feature_3_body_ar'   => '',
];
$siteSettings = loadSiteSettings($pdo, $loginSiteDefaults);
$siteFavicon  = trim((string) ($siteSettings['site_favicon'] ?? ''));

function loginSettingAr(array $settings, string $key, string $fallbackTKey = ''): string {
    if (getLang() === 'ar') {
        $arVal = trim((string) ($settings[$key . '_ar'] ?? ''));
        if ($arVal !== '') return $arVal;
        if ($fallbackTKey !== '') {
            $tVal = t($fallbackTKey);
            if ($tVal !== $fallbackTKey) return $tVal;
        }
    }
    $adminVal = trim((string) ($settings[$key] ?? ''));
    return $adminVal !== '' ? $adminVal : ($fallbackTKey !== '' ? t($fallbackTKey) : '');
}

const LOGIN_PHONE_REGEX = '/^[0-9+()\-\s]{7,20}$/';

$errorMessage     = '';
$successMessage   = '';
$identifierValue  = '';
$selectedUserType = 'customer';
$rememberChecked  = false;
$loginBlocked     = false;

$hasTabTokens     = isset($_SESSION['customer_tab_tokens']) && is_array($_SESSION['customer_tab_tokens']) && count($_SESSION['customer_tab_tokens']) > 0;
$hasActiveSession = isset($_SESSION['user_type']) && (string) $_SESSION['user_type'] !== '';

$activeSessionRole  = '';
$activeDashboardUrl = '';
if ($hasActiveSession || $hasTabTokens) {
    $loginBlocked       = true;
    $activeSessionRole  = strtolower((string) ($_SESSION['user_type'] ?? ''));
    if ($activeSessionRole === 'admin') {
        $activeDashboardUrl = 'admin_dashboard.php';
    } elseif ($activeSessionRole === 'service_provider') {
        $activeDashboardUrl = 'service_provider_dashboard.php';
    } elseif ($activeSessionRole === 'customer' || $hasTabTokens) {
        $firstToken = '';
        if (isset($_SESSION['customer_tab_tokens']) && is_array($_SESSION['customer_tab_tokens'])) {
            $firstToken = (string) (array_key_first($_SESSION['customer_tab_tokens']) ?? '');
        }
        $activeDashboardUrl = $firstToken !== '' ? 'customer_dashboard.php?tab=' . urlencode($firstToken) : 'customer_dashboard.php';
    }
}

$suspendedAccountIds      = loadSuspendedAccountIds();
$suspendedCustomerLookup  = buildSuspendedLookup((array) ($suspendedAccountIds['customers'] ?? []));
$suspendedProviderLookup  = buildSuspendedLookup((array) ($suspendedAccountIds['providers']  ?? []));

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
    $savedLang = $_SESSION['lang'] ?? 'en';
    if (session_status() === PHP_SESSION_ACTIVE) { session_regenerate_id(true); }
    $_SESSION = [];
    $_SESSION['user_type'] = $role;
    $_SESSION['lang']      = $savedLang;
}

/* ══ POST handler (unchanged logic) ═══════════════════════════════════════ */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !$loginBlocked) {
    $identifierValue  = trim((string) ($_POST['email']     ?? ''));
    $passwordValue    = (string) ($_POST['password']       ?? '');
    $selectedUserType = strtolower(trim((string) ($_POST['user_type'] ?? 'customer')));
    $rememberChecked  = isset($_POST['remember']);

    if ($identifierValue === '') {
        $errorMessage = 'Please enter your email address or phone number.';
    } elseif ($passwordValue === '') {
        $errorMessage = 'Please enter your password.';
    } elseif (!in_array($selectedUserType, ['customer', 'service_provider'], true)) {
        $errorMessage = 'Please choose a valid account type.';
    } else {
        $identifierType = '';
        if (filter_var($identifierValue, FILTER_VALIDATE_EMAIL)) {
            $identifierType = 'email';
        } elseif (preg_match(LOGIN_PHONE_REGEX, $identifierValue)) {
            $identifierType = 'phone';
        } else {
            $errorMessage = 'Please enter a valid email address or phone number.';
        }

        if ($errorMessage === '') {
            $isAdminLogin = strcasecmp($identifierValue, ADMIN_EMAIL) === 0;

            if ($isAdminLogin) {
                ensureSiteSettingsTable($pdo);
                $siteSettings       = loadSiteSettings($pdo, ['admin_password_hash' => '']);
                $adminPasswordHash  = trim((string) ($siteSettings['admin_password_hash'] ?? '')) !== ''
                    ? trim((string) $siteSettings['admin_password_hash'])
                    : ADMIN_PASSWORD_HASH;

                if (!password_verify($passwordValue, $adminPasswordHash)) {
                    $errorMessage = 'Invalid email or password.';
                } else {
                    resetSessionForRole('admin');
                    $_SESSION['user_id']    = 0;
                    $_SESSION['user_email'] = ADMIN_EMAIL;
                    $_SESSION['remember_me']= $rememberChecked;
                    header('Location: admin_dashboard.php');
                    exit;
                }
            } else {
                try {
                    if ($selectedUserType === 'customer') {
                        $stmt = $pdo->prepare(
                            $identifierType === 'phone'
                                ? "SELECT customer_id AS id, email, phone, password, 'customer' AS user_type, IFNULL(is_verified,1) AS is_verified FROM customer WHERE phone = :id LIMIT 1"
                                : "SELECT customer_id AS id, email, phone, password, 'customer' AS user_type, IFNULL(is_verified,1) AS is_verified FROM customer WHERE email = :id LIMIT 1"
                        );
                    } else {
                        $stmt = $pdo->prepare(
                            $identifierType === 'phone'
                                ? "SELECT provider_id AS id, email, phone, password, 'service_provider' AS user_type, IFNULL(is_verified,1) AS is_verified FROM serviceprovider WHERE phone = :id LIMIT 1"
                                : "SELECT provider_id AS id, email, phone, password, 'service_provider' AS user_type, IFNULL(is_verified,1) AS is_verified FROM serviceprovider WHERE email = :id LIMIT 1"
                        );
                    }
                    $stmt->execute(['id' => $identifierValue]);
                    $user = $stmt->fetch();

                    $pwOk = false;
                    if ($user) {
                        $stored   = (string) $user['password'];
                        $hashInfo = password_get_info($stored);
                        if ($hashInfo['algo'] === null) {
                            $errorMessage = 'Your account password must be reset before login.';
                        } else {
                            $pwOk = password_verify($passwordValue, $stored);
                        }
                    }

                    if ($errorMessage === '' && $user && $pwOk) {
                        $uid = (int) $user['id'];
                        $utype = strtolower((string) $user['user_type']);
                        if ($utype === 'customer' && isset($suspendedCustomerLookup[$uid])) {
                            $errorMessage = 'Your account is suspended. Please contact support.';
                        } elseif ($utype === 'service_provider' && isset($suspendedProviderLookup[$uid])) {
                            $errorMessage = 'Your account is suspended. Please contact support.';
                        }
                    }

                    if ($errorMessage === '' && $user && $pwOk) {
                        $utype      = strtolower((string) $user['user_type']);
                        $isVerified = (int) ($user['is_verified'] ?? 1);
                        if (!$isVerified) {
                            $unverEmail = (string) $user['email'];
                            $newCode    = createVerificationCode($pdo, $unverEmail, $utype);
                            sendVerificationEmail($unverEmail, $newCode);
                            $_SESSION['verify_pending_email']   = $unverEmail;
                            $_SESSION['verify_pending_type']    = $utype;
                            if ($utype === 'customer') {
                                $_SESSION['verify_pending_customer_id'] = (int) $user['id'];
                            } else {
                                $_SESSION['verify_pending_provider_id'] = (int) $user['id'];
                            }
                            header('Location: verify_email.php');
                            exit;
                        }
                    }

                    if ($errorMessage === '' && (!$user || !$pwOk)) {
                        $errorMessage = 'Invalid email or password.';
                    } elseif ($errorMessage === '') {
                        $role = strtolower((string) $user['user_type']);
                        resetSessionForRole($role);
                        $_SESSION['user_id']    = (int) $user['id'];
                        $_SESSION['user_email'] = (string) $user['email'];
                        $_SESSION['user_phone'] = (string) $user['phone'];
                        $_SESSION['remember_me']= $rememberChecked;

                        if ((string) $_SESSION['user_type'] === 'customer') {
                            $tok = issueCustomerTabAccessToken((int) $user['id'], (string) $user['email']);
                            header('Location: customer_dashboard.php?tab=' . urlencode($tok));
                            exit;
                        }
                        if ((string) $_SESSION['user_type'] === 'service_provider') {
                            header('Location: service_provider_dashboard.php');
                            exit;
                        }
                        $successMessage = 'Login successful.';
                    }
                } catch (PDOException $e) {
                    $errorMessage = 'Unable to log in right now. Please try again.';
                }
            }
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
    <title><?php echo htmlspecialchars(t('login_title'), ENT_QUOTES, 'UTF-8'); ?> — <?php echo htmlspecialchars(t('site_name'), ENT_QUOTES, 'UTF-8'); ?></title>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <?php if (isRtl()): ?>
    <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <?php endif; ?>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        /* ── Reset ─────────────────────────────── */
        *, *::before, *::after { margin:0; padding:0; box-sizing:border-box; }
        html, body { width:100%; overflow-x:hidden; }

        /* ── Tokens ─────────────────────────────── */
        :root {
            --brand:       #0f766e;
            --brand-deep:  #115e59;
            --brand-xdeep: #065f46;
            --accent:      #f97316;
            --accent-deep: #ea580c;
            --ink:         #0f172a;
            --muted:       #64748b;
            --line:        #e2e8f0;
            --panel-grad:  linear-gradient(145deg, #0c6e67 0%, #0f766e 40%, #134e4a 75%, #052e16 100%);
            --radius:      28px;
        }

        /* ── Page ───────────────────────────────── */
        body {
            font-family: 'Plus Jakarta Sans', sans-serif;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 24px 16px;
            background:
                radial-gradient(ellipse at 8%  5%,  rgba(20,184,166,.25), transparent 45%),
                radial-gradient(ellipse at 92% 90%, rgba(249,115,22,.22), transparent 42%),
                radial-gradient(ellipse at 55% 50%, rgba(99,102,241,.10), transparent 55%),
                linear-gradient(155deg, #ecfeff 0%, #f8fafc 50%, #fff7ed 100%);
        }

        /* Ambient blobs */
        .blob { position:fixed; border-radius:50%; filter:blur(100px); pointer-events:none; animation:blobDrift 20s ease-in-out infinite; }
        .blob-1 { width:440px; height:440px; top:-130px; left:-130px; background:rgba(15,118,110,.20); }
        .blob-2 { width:520px; height:520px; right:-150px; bottom:-160px; background:rgba(249,115,22,.18); animation-delay:-10s; }
        .blob-3 { width:300px; height:300px; top:40%; left:45%; background:rgba(99,102,241,.12); animation-delay:-5s; }

        @keyframes blobDrift {
            0%,100% { transform:translate(0,0) scale(1); }
            33%      { transform:translate(35px,-30px) scale(1.06); }
            66%      { transform:translate(-28px,32px) scale(.94); }
        }

        /* ── Main wrapper ───────────────────────── */
        .login-wrap {
            position: relative; z-index: 1;
            width: 100%;
            max-width: 900px;
            display: grid;
            grid-template-columns: 1fr 1fr;
            border-radius: var(--radius);
            overflow: hidden;
            box-shadow: 0 36px 80px rgba(15,23,42,.22), 0 0 0 1px rgba(255,255,255,.55);
            animation: wrapIn .6s cubic-bezier(.22,1,.36,1) both;
        }

        @keyframes wrapIn {
            from { opacity:0; transform:translateY(32px) scale(.97); }
            to   { opacity:1; transform:translateY(0)    scale(1);   }
        }

        /* ═══ LEFT BRAND PANEL ═════════════════════════════ */
        .brand-panel {
            background: var(--panel-grad);
            padding: 48px 40px;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            position: relative;
            overflow: hidden;
        }

        /* Decorative circles inside brand panel */
        .brand-panel::before {
            content: '';
            position: absolute;
            width: 340px; height: 340px;
            border-radius: 50%;
            border: 1px solid rgba(255,255,255,.08);
            top: -100px; right: -100px;
            pointer-events: none;
        }
        .brand-panel::after {
            content: '';
            position: absolute;
            width: 220px; height: 220px;
            border-radius: 50%;
            border: 1px solid rgba(255,255,255,.06);
            bottom: -60px; left: -60px;
            pointer-events: none;
        }

        /* Floating accent dot */
        .brand-panel .accent-dot {
            position: absolute;
            width: 120px; height: 120px;
            border-radius: 50%;
            background: radial-gradient(circle, rgba(249,115,22,.35), transparent 70%);
            bottom: 100px; right: 30px;
            pointer-events: none;
        }

        .brand-top { position: relative; }

        .brand-logo-wrap {
            width: 64px; height: 64px;
            border-radius: 18px;
            background: rgba(255,255,255,.15);
            border: 1.5px solid rgba(255,255,255,.25);
            display: flex; align-items: center; justify-content: center;
            font-size: 1.6rem; color: #fff;
            box-shadow: 0 10px 28px rgba(0,0,0,.20);
            margin-bottom: 20px;
        }

        .brand-title {
            font-size: 1.55rem;
            font-weight: 800;
            color: #fff;
            line-height: 1.2;
            margin-bottom: 10px;
        }

        .brand-sub {
            font-size: .88rem;
            color: rgba(255,255,255,.65);
            line-height: 1.55;
            margin-bottom: 36px;
        }

        /* Feature list */
        .brand-features { position: relative; }

        .feature-item {
            display: flex;
            align-items: flex-start;
            gap: 12px;
            margin-bottom: 18px;
        }

        .feature-icon {
            width: 38px; height: 38px; flex-shrink: 0;
            border-radius: 11px;
            display: flex; align-items: center; justify-content: center;
            font-size: .9rem;
        }

        .feature-icon.teal   { background: rgba(20,184,166,.25); color: #5eead4; }
        .feature-icon.orange { background: rgba(249,115,22,.25); color: #fdba74; }
        .feature-icon.indigo { background: rgba(99,102,241,.25); color: #a5b4fc; }
        .feature-icon.green  { background: rgba(34,197,94,.25);  color: #86efac; }

        .feature-text h4 { font-size: .85rem; font-weight: 700; color: #fff; margin-bottom: 2px; }
        .feature-text p  { font-size: .78rem; color: rgba(255,255,255,.55); line-height: 1.4; }

        /* Brand footer */
        .brand-footer {
            position: relative;
            border-top: 1px solid rgba(255,255,255,.12);
            padding-top: 18px;
            font-size: .78rem;
            color: rgba(255,255,255,.45);
        }

        /* ═══ RIGHT FORM PANEL ══════════════════════════════ */
        .form-panel {
            background: #fff;
            padding: 40px 44px 44px;
            display: flex;
            flex-direction: column;
        }

        /* Top bar: lang switch + back link */
        .form-top-bar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 28px;
            flex-wrap: wrap;
            gap: 8px;
        }

        .back-link {
            display: inline-flex; align-items: center; gap: 5px;
            color: var(--muted); font-size: .82rem; font-weight: 600;
            text-decoration: none; transition: color .2s;
        }
        .back-link:hover { color: var(--brand); }

        .lang-pill {
            display: inline-flex; align-items: center; gap: 5px;
            background: #f8fafc;
            border: 1.5px solid var(--line);
            border-radius: 999px;
            color: var(--brand);
            font-family: inherit;
            font-size: .8rem; font-weight: 700;
            padding: 5px 13px;
            text-decoration: none; cursor: pointer;
            transition: background .2s, border-color .2s;
        }
        .lang-pill:hover { background: #f0fdfa; border-color: var(--brand); }

        /* Form title */
        .form-title {
            font-size: 1.45rem;
            font-weight: 800;
            color: var(--ink);
            margin-bottom: 4px;
        }

        .form-subtitle {
            font-size: .88rem;
            color: var(--muted);
            margin-bottom: 24px;
        }

        /* ── Account type tabs ───────────────────── */
        .type-tabs {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 8px;
            margin-bottom: 24px;
            background: #f1f5f9;
            border-radius: 14px;
            padding: 5px;
        }

        .type-tab {
            border: none; border-radius: 10px;
            background: transparent;
            padding: 10px 12px;
            font-family: inherit; font-size: .86rem; font-weight: 700;
            color: var(--muted);
            cursor: pointer;
            display: flex; align-items: center; justify-content: center; gap: 7px;
            transition: all .22s ease;
        }

        .type-tab.active {
            background: #fff;
            color: var(--brand);
            box-shadow: 0 2px 10px rgba(15,23,42,.09);
        }

        .type-tab:not(.active):hover { color: var(--ink); }

        .type-tab i { font-size: .9rem; }

        /* ── Alert banner ────────────────────────── */
        .login-alert {
            display: flex; align-items: flex-start; gap: 10px;
            border-radius: 12px;
            padding: 12px 14px;
            font-size: .86rem; font-weight: 600;
            margin-bottom: 18px;
            animation: alertPop .25s ease;
        }
        @keyframes alertPop {
            from { opacity:0; transform:translateY(-6px); }
            to   { opacity:1; transform:translateY(0); }
        }

        .login-alert.is-error   { background:#fff1f2; color:#be123c; border:1.5px solid #fecdd3; }
        .login-alert.is-success { background:#ecfdf5; color:#065f46; border:1.5px solid #a7f3d0; }
        .login-alert.is-warn    { background:#fff7ed; color:#9a3412; border:1.5px solid #fdba74; }
        .login-alert.is-hidden  { display:none; }
        .alert-icon { flex-shrink:0; font-size: .95rem; margin-top:1px; }

        /* ── Form fields ─────────────────────────── */
        .field-group { margin-bottom: 18px; }

        .field-group label {
            display: block;
            font-size: .83rem; font-weight: 700;
            color: #1e293b;
            margin-bottom: 7px;
        }

        .field-wrap {
            position: relative;
            display: flex; align-items: center;
        }

        .field-icon {
            position: absolute; left: 14px;
            color: #94a3b8; font-size: .95rem;
            pointer-events: none; z-index: 1;
            transition: color .2s;
        }

        .field-wrap:focus-within .field-icon { color: var(--brand); }

        .field-wrap input {
            width: 100%;
            border: 2px solid var(--line);
            border-radius: 12px;
            padding: 13px 14px 13px 42px;
            font-family: inherit; font-size: .92rem;
            color: var(--ink); background: #fafbfc;
            min-height: 50px;
            transition: border-color .22s, box-shadow .22s, background .22s;
        }

        .field-wrap input.has-toggle { padding-right: 46px; }

        .field-wrap input:focus {
            outline: none;
            border-color: var(--brand);
            background: #fff;
            box-shadow: 0 0 0 4px rgba(15,118,110,.12);
        }

        .field-wrap input.is-invalid {
            border-color: #f43f5e;
            box-shadow: 0 0 0 4px rgba(244,63,94,.10);
        }

        /* Password toggle */
        .pw-eye {
            position: absolute; right: 12px;
            border: none; background: transparent;
            color: #94a3b8; cursor: pointer; padding: 6px;
            display: flex; align-items: center; z-index: 1;
            transition: color .2s;
        }
        .pw-eye:hover { color: var(--brand); }
        .pw-eye i { font-size: .92rem; }

        /* Remember / Forgot row */
        .form-meta-row {
            display: flex; align-items: center;
            justify-content: space-between;
            margin-bottom: 22px; gap: 8px; flex-wrap: wrap;
        }

        .remember-label {
            display: flex; align-items: center; gap: 7px;
            cursor: pointer; font-size: .84rem; color: var(--muted); font-weight: 500;
            user-select: none;
        }

        .remember-label input[type="checkbox"] {
            width: 17px; height: 17px;
            accent-color: var(--brand); cursor: pointer;
            border-radius: 4px; flex-shrink: 0;
        }

        .forgot-link {
            font-size: .84rem; font-weight: 700;
            color: var(--brand); text-decoration: none;
            transition: color .2s;
            white-space: nowrap;
        }
        .forgot-link:hover { color: var(--brand-deep); text-decoration: underline; }

        /* ── Submit button ────────────────────────── */
        .btn-login {
            width: 100%; min-height: 52px;
            border: none; border-radius: 14px;
            background: linear-gradient(145deg, var(--brand), var(--brand-deep));
            color: #fff;
            font-family: inherit; font-size: .97rem; font-weight: 800;
            cursor: pointer;
            display: flex; align-items: center; justify-content: center; gap: 9px;
            position: relative; overflow: hidden;
            transition: transform .22s, box-shadow .22s, opacity .22s;
            box-shadow: 0 6px 22px rgba(15,118,110,.28);
        }

        .btn-login::after {
            content: '';
            position: absolute; inset: 0;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,.18), transparent);
            transform: translateX(-100%);
            transition: transform .55s ease;
        }

        .btn-login:hover { transform:translateY(-2px); box-shadow:0 14px 34px rgba(15,118,110,.36); }
        .btn-login:hover::after { transform:translateX(100%); }
        .btn-login:active { transform:translateY(0); }
        .btn-login:disabled { opacity:.65; cursor:not-allowed; transform:none; }

        .btn-login .btn-arrow { transition: transform .22s; }
        .btn-login:hover .btn-arrow { transform: translateX(4px); }

        /* ── Footer links ─────────────────────────── */
        .form-footer {
            margin-top: 20px;
            text-align: center;
            font-size: .88rem;
            color: var(--muted);
        }

        .form-footer a {
            color: var(--brand); font-weight: 700;
            text-decoration: none; transition: color .2s;
        }
        .form-footer a:hover { color: var(--brand-deep); }

        .footer-divider {
            display: flex; align-items: center; gap: 10px;
            color: #cbd5e1; font-size: .78rem;
            margin: 12px 0;
        }
        .footer-divider::before, .footer-divider::after {
            content:''; flex:1; height:1px; background:var(--line);
        }

        /* ── Already-logged-in state ─────────────── */
        .already-in {
            text-align: center;
            padding: 10px 0 6px;
        }

        .already-icon {
            width: 72px; height: 72px;
            border-radius: 22px;
            background: linear-gradient(135deg,#f0fdf4,#dcfce7);
            border: 1.5px solid #86efac;
            display: flex; align-items: center; justify-content: center;
            margin: 0 auto 18px;
            font-size: 1.8rem; color: #16a34a;
        }

        .already-in h2 { font-size:1.15rem; font-weight:800; color:var(--ink); margin-bottom:8px; }
        .already-in p  { font-size:.88rem; color:var(--muted); line-height:1.55; margin-bottom:22px; }

        .btn-go-dash {
            display: flex; align-items: center; justify-content: center; gap: 8px;
            width: 100%; min-height: 50px;
            background: linear-gradient(145deg, var(--brand), var(--brand-deep));
            color: #fff; border: none; border-radius: 14px;
            font-family: inherit; font-size: .95rem; font-weight: 800;
            text-decoration: none; cursor: pointer; margin-bottom: 10px;
            transition: transform .2s, box-shadow .2s;
            box-shadow: 0 6px 20px rgba(15,118,110,.25);
        }
        .btn-go-dash:hover { transform:translateY(-2px); box-shadow:0 12px 28px rgba(15,118,110,.32); }

        .btn-logout {
            display: inline-flex; align-items: center; justify-content: center; gap: 6px;
            color: #ef4444; font-size: .85rem; font-weight: 700;
            text-decoration: none; padding: 10px 16px;
            border-radius: 12px; transition: background .2s;
            width: 100%;
        }
        .btn-logout:hover { background: #fff1f2; }

        /* ── Responsive ──────────────────────────── */
        @media (max-width: 720px) {
            .login-wrap { grid-template-columns: 1fr; max-width: 480px; }
            .brand-panel { display: none; }
            .form-panel { padding: 32px 28px 36px; }
        }

        @media (max-width: 480px) {
            body { padding: 16px 12px; }
            .form-panel { padding: 28px 20px 32px; }
            .login-wrap { border-radius: 22px; }
            .form-title { font-size: 1.3rem; }
            .form-meta-row { flex-direction: column; align-items: flex-start; }
        }

        @media (prefers-reduced-motion: reduce) {
            *, *::before, *::after { animation-duration:.01ms !important; transition-duration:.01ms !important; }
        }

        /* ── RTL overrides ───────────────────────── */
        [dir="rtl"] body { font-family: 'Cairo', sans-serif; }
        [dir="rtl"] .field-icon { left:auto; right:14px; }
        [dir="rtl"] .field-wrap input { padding-left:14px; padding-right:42px; text-align:right; }
        [dir="rtl"] .field-wrap input.has-toggle { padding-left:46px; padding-right:42px; }
        [dir="rtl"] .pw-eye { right:auto; left:12px; }
        [dir="rtl"] .back-link i { transform:scaleX(-1); }
        [dir="rtl"] .form-top-bar { flex-direction:row-reverse; }
        [dir="rtl"] .form-meta-row { flex-direction:row-reverse; }
    </style>
</head>
<body class="<?php echo htmlspecialchars(getLangBodyClass(), ENT_QUOTES, 'UTF-8'); ?>">
    <!-- Ambient blobs -->
    <div class="blob blob-1" aria-hidden="true"></div>
    <div class="blob blob-2" aria-hidden="true"></div>
    <div class="blob blob-3" aria-hidden="true"></div>

    <div class="login-wrap">

        <!-- ═══ BRAND PANEL (desktop left) ════════════════════ -->
        <div class="brand-panel" aria-hidden="true">
            <div class="accent-dot"></div>

            <div class="brand-top">
                <div class="brand-logo-wrap">
                    <i class="fas fa-tools"></i>
                </div>
                <h2 class="brand-title"><?php echo htmlspecialchars(loginSettingAr($siteSettings, 'site_name', 'site_name'), ENT_QUOTES, 'UTF-8'); ?></h2>
                <p class="brand-sub"><?php echo htmlspecialchars(t('login_subtitle'), ENT_QUOTES, 'UTF-8'); ?></p>

                <div class="brand-features">
                    <div class="feature-item">
                        <div class="feature-icon teal"><i class="fas fa-circle-check"></i></div>
                        <div class="feature-text">
                            <h4><?php echo htmlspecialchars(loginSettingAr($siteSettings, 'feature_1_title', 'login_feat1_title'), ENT_QUOTES, 'UTF-8'); ?></h4>
                            <p><?php echo htmlspecialchars(loginSettingAr($siteSettings, 'feature_1_body', 'login_feat1_body'), ENT_QUOTES, 'UTF-8'); ?></p>
                        </div>
                    </div>
                    <div class="feature-item">
                        <div class="feature-icon orange"><i class="fas fa-calendar-check"></i></div>
                        <div class="feature-text">
                            <h4><?php echo htmlspecialchars(loginSettingAr($siteSettings, 'feature_2_title', 'login_feat2_title'), ENT_QUOTES, 'UTF-8'); ?></h4>
                            <p><?php echo htmlspecialchars(loginSettingAr($siteSettings, 'feature_2_body', 'login_feat2_body'), ENT_QUOTES, 'UTF-8'); ?></p>
                        </div>
                    </div>
                    <div class="feature-item">
                        <div class="feature-icon indigo"><i class="fas fa-bolt"></i></div>
                        <div class="feature-text">
                            <h4><?php echo htmlspecialchars(loginSettingAr($siteSettings, 'feature_3_title', 'login_feat3_title'), ENT_QUOTES, 'UTF-8'); ?></h4>
                            <p><?php echo htmlspecialchars(loginSettingAr($siteSettings, 'feature_3_body', 'login_feat3_body'), ENT_QUOTES, 'UTF-8'); ?></p>
                        </div>
                    </div>
                    <div class="feature-item">
                        <div class="feature-icon green"><i class="fas fa-shield-halved"></i></div>
                        <div class="feature-text">
                            <h4><?php echo htmlspecialchars(t('login_feat4_title'), ENT_QUOTES, 'UTF-8'); ?></h4>
                            <p><?php echo htmlspecialchars(t('login_feat4_body'), ENT_QUOTES, 'UTF-8'); ?></p>
                        </div>
                    </div>
                </div>
            </div>

            <div class="brand-footer">
                &copy; <?php echo date('Y'); ?> <?php echo htmlspecialchars(loginSettingAr($siteSettings, 'site_name', 'site_name'), ENT_QUOTES, 'UTF-8'); ?>
            </div>
        </div>

        <!-- ═══ FORM PANEL (right) ══════════════════════════════ -->
        <div class="form-panel">

            <!-- Top bar -->
            <div class="form-top-bar">
                <a href="home.php" class="back-link">
                    <i class="fas fa-arrow-left" aria-hidden="true"></i>
                    <?php echo htmlspecialchars(t('nav_back_home'), ENT_QUOTES, 'UTF-8'); ?>
                </a>
                <a href="<?php echo htmlspecialchars(langSwitchUrl(), ENT_QUOTES, 'UTF-8'); ?>" class="lang-pill">
                    <i class="fa-solid fa-globe" aria-hidden="true"></i>
                    <?php echo htmlspecialchars(t('lang_switch_label'), ENT_QUOTES, 'UTF-8'); ?>
                </a>
            </div>

            <?php if ($loginBlocked): ?>
            <!-- ── Already signed in ────────────── -->
            <div class="already-in">
                <div class="already-icon"><i class="fas fa-circle-check" aria-hidden="true"></i></div>
                <h2><?php echo htmlspecialchars(t('login_already_in_title'), ENT_QUOTES, 'UTF-8'); ?></h2>
                <p><?php echo htmlspecialchars(t('login_already_in_body'), ENT_QUOTES, 'UTF-8'); ?></p>
                <?php if ($activeDashboardUrl !== ''): ?>
                <a class="btn-go-dash" href="<?php echo htmlspecialchars($activeDashboardUrl, ENT_QUOTES, 'UTF-8'); ?>">
                    <i class="fas fa-gauge-high" aria-hidden="true"></i>
                    <?php echo htmlspecialchars(t('login_go_dashboard'), ENT_QUOTES, 'UTF-8'); ?>
                </a>
                <?php endif; ?>
                <a class="btn-logout" href="logout.php">
                    <i class="fas fa-right-from-bracket" aria-hidden="true"></i>
                    <?php echo htmlspecialchars(t('nav_logout'), ENT_QUOTES, 'UTF-8'); ?>
                </a>
            </div>

            <?php else: ?>
            <!-- ── Login form ───────────────────── -->

            <h1 class="form-title"><?php echo htmlspecialchars(t('login_title'), ENT_QUOTES, 'UTF-8'); ?></h1>
            <p class="form-subtitle"><?php echo htmlspecialchars(t('login_subtitle'), ENT_QUOTES, 'UTF-8'); ?></p>

            <!-- Account type tabs -->
            <div class="type-tabs" role="tablist" aria-label="Account type">
                <button
                    type="button"
                    class="type-tab <?php echo $selectedUserType === 'customer' ? 'active' : ''; ?>"
                    data-type="customer"
                    onclick="pickType(this)"
                    role="tab"
                    aria-selected="<?php echo $selectedUserType === 'customer' ? 'true' : 'false'; ?>"
                >
                    <i class="fas fa-user" aria-hidden="true"></i>
                    <?php echo htmlspecialchars(t('login_tab_customer'), ENT_QUOTES, 'UTF-8'); ?>
                </button>
                <button
                    type="button"
                    class="type-tab <?php echo $selectedUserType === 'service_provider' ? 'active' : ''; ?>"
                    data-type="service_provider"
                    onclick="pickType(this)"
                    role="tab"
                    aria-selected="<?php echo $selectedUserType === 'service_provider' ? 'true' : 'false'; ?>"
                >
                    <i class="fas fa-screwdriver-wrench" aria-hidden="true"></i>
                    <?php echo htmlspecialchars(t('login_tab_provider'), ENT_QUOTES, 'UTF-8'); ?>
                </button>
            </div>

            <!-- Server error -->
            <?php if ($errorMessage !== ''): ?>
            <div class="login-alert is-error" role="alert">
                <i class="fas fa-circle-exclamation alert-icon" aria-hidden="true"></i>
                <span><?php echo htmlspecialchars($errorMessage, ENT_QUOTES, 'UTF-8'); ?></span>
            </div>
            <?php endif; ?>

            <?php if ($successMessage !== ''): ?>
            <div class="login-alert is-success" role="status">
                <i class="fas fa-circle-check alert-icon" aria-hidden="true"></i>
                <span><?php echo htmlspecialchars($successMessage, ENT_QUOTES, 'UTF-8'); ?></span>
            </div>
            <?php endif; ?>

            <!-- Client-side alert (JS) -->
            <div id="clientAlert" class="login-alert is-error is-hidden" role="alert" aria-live="polite">
                <i class="fas fa-circle-exclamation alert-icon" aria-hidden="true"></i>
                <span id="clientAlertText"></span>
            </div>

            <form id="loginForm" method="post" action="login.php" novalidate>
                <input type="hidden" name="user_type" id="userTypeInput" value="<?php echo htmlspecialchars($selectedUserType, ENT_QUOTES, 'UTF-8'); ?>">

                <!-- Email / Phone -->
                <div class="field-group">
                    <label for="email"><?php echo htmlspecialchars(t('login_identifier'), ENT_QUOTES, 'UTF-8'); ?></label>
                    <div class="field-wrap">
                        <i class="fas fa-at field-icon" aria-hidden="true"></i>
                        <input
                            type="text"
                            id="email"
                            name="email"
                            dir="ltr"
                            value="<?php echo htmlspecialchars($identifierValue, ENT_QUOTES, 'UTF-8'); ?>"
                            placeholder="you@example.com"
                            autocomplete="username"
                            required
                        >
                    </div>
                </div>

                <!-- Password -->
                <div class="field-group">
                    <label for="password"><?php echo htmlspecialchars(t('login_password'), ENT_QUOTES, 'UTF-8'); ?></label>
                    <div class="field-wrap">
                        <i class="fas fa-lock field-icon" aria-hidden="true"></i>
                        <input
                            type="password"
                            id="password"
                            name="password"
                            class="has-toggle"
                            placeholder="••••••••"
                            autocomplete="current-password"
                            required
                        >
                        <button type="button" class="pw-eye" onclick="togglePw()" aria-label="<?php echo htmlspecialchars(t('toggle_password_visibility'), ENT_QUOTES, 'UTF-8'); ?>">
                            <i class="fas fa-eye" id="pwEyeIcon"></i>
                        </button>
                    </div>
                </div>

                <!-- Forgot password link -->
                <div class="form-meta-row">
                    <a href="forgot_password.php" class="forgot-link">
                        <?php echo htmlspecialchars(t('login_forgot'), ENT_QUOTES, 'UTF-8'); ?>
                    </a>
                </div>

                <!-- Submit -->
                <button type="submit" id="loginBtn" class="btn-login">
                    <span id="loginBtnLabel"><?php echo htmlspecialchars(t('login_button'), ENT_QUOTES, 'UTF-8'); ?></span>
                    <i class="fas fa-arrow-right btn-arrow" id="loginBtnIcon" aria-hidden="true"></i>
                </button>
            </form>

            <!-- Footer -->
            <div class="form-footer">
                <div class="footer-divider"><?php echo htmlspecialchars(t('login_no_account'), ENT_QUOTES, 'UTF-8'); ?></div>
                <p>
                    <a href="register.php">
                        <i class="fas fa-user-plus" style="margin-<?php echo isRtl() ? 'left' : 'right'; ?>:4px;" aria-hidden="true"></i>
                        <?php echo htmlspecialchars(t('login_register_link'), ENT_QUOTES, 'UTF-8'); ?>
                    </a>
                </p>
            </div>

            <?php endif; ?>
        </div><!-- /.form-panel -->
    </div><!-- /.login-wrap -->

    <script>
    (function(){
        'use strict';

        /* Account type toggle */
        window.pickType = function(btn) {
            document.querySelectorAll('.type-tab').forEach(function(b) {
                var sel = b === btn;
                b.classList.toggle('active', sel);
                b.setAttribute('aria-selected', sel ? 'true' : 'false');
            });
            var inp = document.getElementById('userTypeInput');
            if (inp) inp.value = btn.dataset.type || 'customer';
        };

        /* Password visibility toggle */
        window.togglePw = function() {
            var inp  = document.getElementById('password');
            var icon = document.getElementById('pwEyeIcon');
            if (!inp || !icon) return;
            var show = inp.type === 'password';
            inp.type      = show ? 'text' : 'password';
            icon.className = show ? 'fas fa-eye-slash' : 'fas fa-eye';
        };

        /* Alert helpers */
        var alert     = document.getElementById('clientAlert');
        var alertText = document.getElementById('clientAlertText');

        function showErr(msg) {
            if (!alert || !alertText) return;
            alertText.textContent = msg;
            alert.classList.remove('is-hidden');
            alert.scrollIntoView({ behavior:'smooth', block:'nearest' });
        }
        function clearErr() {
            if (!alert) return;
            alert.classList.add('is-hidden');
        }

        /* Client-side validation */
        var form    = document.getElementById('loginForm');
        var idInput = document.getElementById('email');
        var pwInput = document.getElementById('password');
        var emailRx = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        var phoneRx = /^[0-9+()\-\s]{7,20}$/;

        if (form) {
            form.addEventListener('invalid', function(e){ e.preventDefault(); }, true);

            form.addEventListener('submit', function(e) {
                var id = idInput ? idInput.value.trim() : '';
                var pw = pwInput ? pwInput.value        : '';
                if (idInput) idInput.value = id;

                clearErr();

                if (!id) {
                    e.preventDefault();
                    showErr('Please enter your email address or phone number.');
                    if (idInput) { idInput.classList.add('is-invalid'); idInput.focus(); }
                    return;
                }
                if (!emailRx.test(id) && !phoneRx.test(id)) {
                    e.preventDefault();
                    showErr('Please enter a valid email address or phone number.');
                    if (idInput) { idInput.classList.add('is-invalid'); idInput.focus(); }
                    return;
                }
                if (!pw) {
                    e.preventDefault();
                    showErr('Please enter your password.');
                    if (pwInput) { pwInput.classList.add('is-invalid'); pwInput.focus(); }
                    return;
                }

                /* Loading state */
                var btn   = document.getElementById('loginBtn');
                var label = document.getElementById('loginBtnLabel');
                var icon  = document.getElementById('loginBtnIcon');
                if (btn) btn.disabled = true;
                if (label) label.textContent = '<?php echo addslashes(t("login_signing_in")); ?>';
                if (icon)  icon.className    = 'fas fa-spinner fa-spin';
            });

            /* Remove is-invalid on retype */
            form.addEventListener('input', function(e) {
                e.target.classList.remove('is-invalid');
            });
        }
    }());
    </script>
</body>
</html>
