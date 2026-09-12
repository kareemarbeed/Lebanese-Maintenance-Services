<?php
declare(strict_types=1);

session_start();

require_once __DIR__ . '/db_connection.php';
require_once __DIR__ . '/site_settings.php';
require_once __DIR__ . '/auth_config.php';
require_once __DIR__ . '/lang.php';

ensureSiteSettingsTable($pdo);
$siteFavicon = resolveSiteFavicon($pdo);

$tabAccessToken = trim((string) ($_GET['tab'] ?? $_POST['tab'] ?? ''));
$userRole = '';
$userId = 0;
$userEmail = '';

if ($tabAccessToken !== '' && preg_match('/^[a-f0-9]{64}$/i', $tabAccessToken)) {
    if (isset($_SESSION['customer_tab_tokens']) && is_array($_SESSION['customer_tab_tokens'])) {
        $tokenPayload = $_SESSION['customer_tab_tokens'][$tabAccessToken] ?? null;
        if (is_array($tokenPayload)) {
            $userRole = 'customer';
            $userId = (int) ($tokenPayload['user_id'] ?? 0);
            $userEmail = (string) ($tokenPayload['user_email'] ?? '');
        }
    }
}

if ($userRole === '' && isset($_SESSION['user_type']) && is_string($_SESSION['user_type'])) {
    $userType = strtolower((string) $_SESSION['user_type']);
    if ($userType === 'customer') {
        $userRole = 'customer';
        $userId = (int) ($_SESSION['user_id'] ?? 0);
        $userEmail = (string) ($_SESSION['user_email'] ?? '');
    } elseif ($userType === 'service_provider') {
        $userRole = 'service_provider';
        $userId = (int) ($_SESSION['user_id'] ?? 0);
        $userEmail = (string) ($_SESSION['user_email'] ?? '');
    } elseif ($userType === 'admin') {
        $userRole = 'admin';
        $userId = 0;
        $userEmail = ADMIN_EMAIL;
    }
}

if ($userRole === '' || ($userRole !== 'admin' && $userId <= 0)) {
    header('Location: login.php');
    exit;
}

function isStrongPassword(string $password): bool
{
    return (bool) preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z0-9]).{8,}$/', $password);
}

$errorMessage = '';
$successMessage = '';
$oldPassword = '';
$newPassword = '';
$confirmPassword = '';

$storedPasswordHash = '';

try {
    if ($userRole === 'admin') {
        ensureSiteSettingsTable($pdo);
        $siteSettings = loadSiteSettings($pdo, ['admin_password_hash' => '']);
        $storedPasswordHash = trim((string) ($siteSettings['admin_password_hash'] ?? '')) !== ''
            ? trim((string) $siteSettings['admin_password_hash'])
            : ADMIN_PASSWORD_HASH;
    } elseif ($userRole === 'customer') {
        $statement = $pdo->prepare('SELECT password, email FROM customer WHERE customer_id = :customer_id LIMIT 1');
        $statement->execute(['customer_id' => $userId]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);

        if ($row === false) {
            header('Location: login.php');
            exit;
        }

        $storedPasswordHash = (string) ($row['password'] ?? '');
        $userEmail = $userEmail !== '' ? $userEmail : (string) ($row['email'] ?? '');
    } else {
        $statement = $pdo->prepare('SELECT password, email FROM serviceprovider WHERE provider_id = :provider_id LIMIT 1');
        $statement->execute(['provider_id' => $userId]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);

        if ($row === false) {
            header('Location: login.php');
            exit;
        }

        $storedPasswordHash = (string) ($row['password'] ?? '');
        $userEmail = $userEmail !== '' ? $userEmail : (string) ($row['email'] ?? '');
    }
} catch (PDOException $exception) {
    $errorMessage = t('change_pwd_err_load');
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $errorMessage === '') {
    $oldPassword = (string) ($_POST['old_password'] ?? '');
    $newPassword = (string) ($_POST['new_password'] ?? '');
    $confirmPassword = (string) ($_POST['confirm_password'] ?? '');

    if ($oldPassword === '') {
        $errorMessage = t('change_pwd_err_old_empty');
    } elseif ($newPassword === '') {
        $errorMessage = t('change_pwd_err_new_empty');
    } elseif ($confirmPassword === '') {
        $errorMessage = t('change_pwd_err_confirm');
    } elseif ($newPassword !== $confirmPassword) {
        $errorMessage = t('change_pwd_err_mismatch');
    } elseif (!isStrongPassword($newPassword)) {
        $errorMessage = t('change_pwd_err_weak');
    } elseif ($storedPasswordHash === '' || !password_verify($oldPassword, $storedPasswordHash)) {
        $errorMessage = t('change_pwd_err_wrong');
    } else {
        $passwordHash = password_hash($newPassword, PASSWORD_DEFAULT);
        if ($passwordHash === false) {
            $errorMessage = t('change_pwd_err_hash');
        } else {
            try {
                if ($userRole === 'admin') {
                    ensureSiteSettingsTable($pdo);
                    saveSiteSettings($pdo, ['admin_password_hash' => $passwordHash]);
                } elseif ($userRole === 'customer') {
                    $updateStatement = $pdo->prepare(
                        'UPDATE customer SET password = :password WHERE customer_id = :customer_id'
                    );
                    $updateStatement->execute([
                        'password' => $passwordHash,
                        'customer_id' => $userId,
                    ]);
                } else {
                    $updateStatement = $pdo->prepare(
                        'UPDATE serviceprovider SET password = :password WHERE provider_id = :provider_id'
                    );
                    $updateStatement->execute([
                        'password' => $passwordHash,
                        'provider_id' => $userId,
                    ]);
                }

                $successMessage = t('change_pwd_ok');
                $oldPassword = '';
                $newPassword = '';
                $confirmPassword = '';
            } catch (PDOException $exception) {
                $errorMessage = t('change_pwd_err_db');
            }
        }
    }
}

$backUrl = 'login.php';
if ($userRole === 'customer') {
    $backUrl = 'customer_dashboard.php';
    if ($tabAccessToken !== '') {
        $backUrl .= '?tab=' . urlencode($tabAccessToken);
    }
} elseif ($userRole === 'service_provider') {
    $backUrl = 'service_provider_dashboard.php';
} elseif ($userRole === 'admin') {
    $backUrl = 'admin_dashboard.php';
}

$isRtl = isRtl();
?>
<!DOCTYPE html>
<html lang="<?php echo getLang(); ?>" dir="<?php echo t('dir'); ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <?php if ($siteFavicon !== ''): ?>
        <link rel="icon" href="<?php echo htmlspecialchars($siteFavicon, ENT_QUOTES, 'UTF-8'); ?>">
    <?php endif; ?>
    <title><?php echo htmlspecialchars(t('change_pwd_title'), ENT_QUOTES, 'UTF-8'); ?> - <?php echo htmlspecialchars(t('site_name'), ENT_QUOTES, 'UTF-8'); ?></title>
    <?php echo getLangFontTag(); ?>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            min-height: 100vh;
            font-family: <?php echo htmlspecialchars(t('font_family'), ENT_QUOTES, 'UTF-8'); ?>;
            background:
                radial-gradient(circle at 8% 10%, rgba(20, 184, 166, 0.18), transparent 36%),
                radial-gradient(circle at 92% 5%, rgba(249, 115, 22, 0.18), transparent 32%),
                linear-gradient(135deg, #ecfeff 0%, #f8fafc 45%, #fff7ed 100%);
            display: flex;
            flex-direction: row;
            color: #0f172a;
        }

        .content-pane {
            flex: 1;
            min-width: 0;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 18px;
            min-height: 100vh;
        }

        @keyframes cardEntry {
            from { opacity: 0; transform: translateY(24px) scale(0.98); }
            to   { opacity: 1; transform: translateY(0) scale(1); }
        }

        .card {
            width: 100%;
            max-width: 520px;
            background: rgba(255, 255, 255, 0.95);
            border-radius: 24px;
            padding: 32px;
            box-shadow: 0 22px 48px rgba(15, 23, 42, 0.12);
            border: 1px solid rgba(15, 118, 110, 0.12);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            animation: cardEntry 0.5s cubic-bezier(0.22, 1, 0.36, 1) both;
        }

        .card h1 {
            font-size: 1.55rem;
            margin-bottom: 10px;
        }

        .card p {
            color: #475569;
            margin-bottom: 22px;
            line-height: 1.6;
        }

        .message {
            border-radius: 16px;
            padding: 14px 18px;
            margin-bottom: 18px;
            font-weight: 700;
        }

        .message.error {
            background: #fff1f2;
            border: 1px solid #fecdd3;
            color: #be123c;
        }

        .message.success {
            background: #ecfdf5;
            border: 1px solid #86efac;
            color: #166534;
        }

        .field {
            display: flex;
            flex-direction: column;
            gap: 8px;
            margin-bottom: 18px;
        }

        .field label {
            font-size: 0.9rem;
            font-weight: 700;
            color: #1f2937;
        }

        .input-wrap {
            position: relative;
        }

        .input-wrap .field-icon {
            position: absolute;
            left: 14px;
            top: 50%;
            transform: translateY(-50%);
            color: #94a3b8;
            font-size: 0.95rem;
            pointer-events: none;
            transition: color 0.2s;
        }

        .input-wrap:focus-within .field-icon { color: #0f766e; }

        .field input {
            width: 100%;
            min-height: 50px;
            border-radius: 14px;
            border: 2px solid #e5e7eb;
            padding: 12px 48px 12px 44px;
            font-family: inherit;
            font-size: 0.95rem;
            background: #fafafa;
            transition: border-color 0.25s, box-shadow 0.25s, background 0.2s;
        }

        .field input:focus {
            outline: none;
            border-color: #0f766e;
            background: #fff;
            box-shadow: 0 0 0 4px rgba(15, 118, 110, 0.13);
        }

        .field input::placeholder { color: #9ca3af; }

        .pw-toggle {
            position: absolute;
            right: 14px;
            top: 50%;
            transform: translateY(-50%);
            background: none;
            border: none;
            color: #94a3b8;
            cursor: pointer;
            font-size: 1rem;
            padding: 4px;
            transition: color 0.2s;
            display: flex;
            align-items: center;
        }

        .pw-toggle:hover { color: #0f766e; }

        .actions {
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
            align-items: center;
        }

        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            font-weight: 800;
            border-radius: 14px;
            border: none;
            cursor: pointer;
            padding: 12px 18px;
            font-size: 0.95rem;
            text-decoration: none;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }

        .btn:hover { transform: translateY(-2px); }

        .btn.primary {
            background: linear-gradient(145deg, #0f766e, #115e59);
            color: #fff;
        }

        .btn.primary:hover { box-shadow: 0 12px 28px rgba(15, 118, 110, 0.3); }

        .btn.secondary {
            background: #f8fafc;
            color: #0f172a;
            border: 1px solid #dbe2ea;
        }

        .btn.secondary:hover { box-shadow: 0 8px 18px rgba(15, 23, 42, 0.1); }

        .hint {
            font-size: 0.88rem;
            color: #64748b;
            margin-top: 6px;
            line-height: 1.5;
            margin-bottom: 18px;
        }

        @media (max-width: 640px) {
            .content-pane { padding: 12px; }
            .card { padding: 20px; }
        }

        @media (max-width: 380px) {
            .content-pane { padding: 8px; }
            .card { padding: 16px 12px; border-radius: 16px; }
            .card h1 { font-size: 1.2rem; }
        }

        /* ── Sidebar ── */
        .sidebar-toggle {
            display: none;
            position: fixed;
            top: 16px;
            <?php echo $isRtl ? 'right' : 'left'; ?>: 16px;
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
            border-<?php echo $isRtl ? 'left' : 'right'; ?>: 1px solid rgba(255, 255, 255, 0.1);
            z-index: 100;
            box-shadow: <?php echo $isRtl ? '-4px' : '4px'; ?> 0 24px rgba(15, 23, 42, 0.25);
            display: flex;
            flex-direction: column;
            padding-top: 20px;
            padding-bottom: 20px;
            overflow-x: hidden;
            overflow-y: hidden;
            min-height: 100vh;
            box-sizing: border-box;
        }

        @media (max-width: 900px) {
            .sidebar {
                position: fixed;
                <?php echo $isRtl ? 'right' : 'left'; ?>: 0;
                top: 0;
                width: min(82vw, 320px);
                height: 100vh;
                min-height: unset;
                transform: translateX(<?php echo $isRtl ? '100%' : '-100%'; ?>);
                transition: transform 0.25s ease;
            }
            .sidebar.open { transform: translateX(0); }
            .sidebar-toggle { display: inline-flex; }
            .sidebar-backdrop { display: block; }
            body.sidebar-open .sidebar-backdrop { opacity: 1; pointer-events: auto; }
            body.sidebar-open { overflow: hidden; }
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
            border: none;
            background: none;
            width: 100%;
            text-align: <?php echo $isRtl ? 'right' : 'left'; ?>;
            transition: all 0.2s ease;
            border-<?php echo $isRtl ? 'right' : 'left'; ?>: 3px solid transparent;
            cursor: pointer;
        }

        .sidebar-menu-item:hover,
        .sidebar-menu-item.active {
            background: rgba(255, 255, 255, 0.12);
            border-<?php echo $isRtl ? 'right' : 'left'; ?>-color: #22d3ee;
            color: #fff;
            <?php echo $isRtl ? 'padding-right' : 'padding-left'; ?>: 14px;
            <?php echo $isRtl ? 'margin-right' : 'margin-left'; ?>: 2px;
        }

        .sidebar-menu-item.active {
            background: rgba(255, 255, 255, 0.18);
            border-<?php echo $isRtl ? 'right' : 'left'; ?>-color: #f97316;
        }

        .sidebar-menu-item i { min-width: 20px; text-align: center; font-size: 1rem; }

        .sidebar-footer {
            padding: 16px;
            border-top: 1px solid rgba(255, 255, 255, 0.15);
            margin-top: auto;
            flex-shrink: 0;
        }

        [dir="rtl"] input { text-align: right; }
        [dir="rtl"] .input-wrap .field-icon { left: auto; right: 14px; }
        [dir="rtl"] .field input { padding-left: 48px; padding-right: 44px; }
        [dir="rtl"] .pw-toggle { right: auto; left: 14px; }
    </style>
</head>
<body class="<?php echo htmlspecialchars(getLangBodyClass(), ENT_QUOTES, 'UTF-8'); ?>">
    <?php if ($userRole !== 'admin'): ?>
    <button class="sidebar-toggle" type="button" id="sidebarToggle" aria-label="<?php echo htmlspecialchars(t('sidebar_open_label') ?: 'Open menu', ENT_QUOTES, 'UTF-8'); ?>" aria-controls="sidebar" aria-expanded="false">
        <i class="fas fa-bars" aria-hidden="true"></i>
    </button>

    <div class="sidebar-backdrop" id="sidebarBackdrop" aria-hidden="true"></div>

    <aside class="sidebar" id="sidebar" aria-label="<?php echo htmlspecialchars(t('sidebar_menu'), ENT_QUOTES, 'UTF-8'); ?>">
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
                <a href="customer_dashboard.php<?php echo $tabAccessToken !== '' ? '?tab=' . urlencode($tabAccessToken) : ''; ?>" class="sidebar-menu-item">
                    <i class="fas fa-chart-line"></i>
                    <?php echo htmlspecialchars(t('sidebar_dashboard'), ENT_QUOTES, 'UTF-8'); ?>
                </a>
                <a href="customer_requests.php<?php echo $tabAccessToken !== '' ? '?tab=' . urlencode($tabAccessToken) : ''; ?>" class="sidebar-menu-item">
                    <i class="fas fa-list-check"></i>
                    <?php echo htmlspecialchars(t('sidebar_my_requests'), ENT_QUOTES, 'UTF-8'); ?>
                </a>
                <a href="customer_dashboard.php<?php echo $tabAccessToken !== '' ? '?tab=' . urlencode($tabAccessToken) : ''; ?>#notifications" class="sidebar-menu-item">
                    <i class="fas fa-bell"></i>
                    <?php echo htmlspecialchars(t('sidebar_notifications'), ENT_QUOTES, 'UTF-8'); ?>
                </a>
                <a href="messages.php<?php echo $tabAccessToken !== '' ? '?tab=' . urlencode($tabAccessToken) : ''; ?>" class="sidebar-menu-item">
                    <i class="fas fa-comments"></i>
                    <?php echo htmlspecialchars(t('sidebar_messages'), ENT_QUOTES, 'UTF-8'); ?>
                </a>
                <a href="change_password.php<?php echo $tabAccessToken !== '' ? '?tab=' . urlencode($tabAccessToken) : ''; ?>" class="sidebar-menu-item active">
                    <i class="fas fa-key"></i>
                    <?php echo htmlspecialchars(t('sidebar_change_password'), ENT_QUOTES, 'UTF-8'); ?>
                </a>
                <a href="customer_dashboard.php<?php echo $tabAccessToken !== '' ? '?tab=' . urlencode($tabAccessToken) . '#profile-edit' : ''; ?>" class="sidebar-menu-item">
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
                <a href="messages.php" class="sidebar-menu-item">
                    <i class="fas fa-comments"></i>
                    <?php echo htmlspecialchars(t('sidebar_messages'), ENT_QUOTES, 'UTF-8'); ?>
                </a>
                <a href="change_password.php" class="sidebar-menu-item active">
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
    <?php endif; ?>

    <div class="content-pane">
    <article class="card">
        <h1><?php echo htmlspecialchars(t('change_pwd_title'), ENT_QUOTES, 'UTF-8'); ?></h1>
        <p><?php echo htmlspecialchars(t('change_pwd_subtitle'), ENT_QUOTES, 'UTF-8'); ?></p>

        <?php if ($errorMessage !== ''): ?>
            <div class="message error" role="alert"><?php echo htmlspecialchars($errorMessage, ENT_QUOTES, 'UTF-8'); ?></div>
        <?php endif; ?>

        <?php if ($successMessage !== ''): ?>
            <div class="message success" role="status"><?php echo htmlspecialchars($successMessage, ENT_QUOTES, 'UTF-8'); ?></div>
        <?php endif; ?>

        <form method="post" action="change_password.php<?php echo $userRole === 'customer' && $tabAccessToken !== '' ? '?tab=' . urlencode($tabAccessToken) : ''; ?>">
            <?php if ($userRole === 'customer' && $tabAccessToken !== ''): ?>
                <input type="hidden" name="tab" value="<?php echo htmlspecialchars($tabAccessToken, ENT_QUOTES, 'UTF-8'); ?>">
            <?php endif; ?>

            <div class="field">
                <label for="old_password"><?php echo htmlspecialchars(t('change_pwd_current_label'), ENT_QUOTES, 'UTF-8'); ?></label>
                <div class="input-wrap">
                    <i class="fas fa-lock field-icon" aria-hidden="true"></i>
                    <input id="old_password" name="old_password" type="password" autocomplete="current-password"
                        placeholder="<?php echo htmlspecialchars(t('change_pwd_current_ph'), ENT_QUOTES, 'UTF-8'); ?>" required>
                    <button type="button" class="pw-toggle" onclick="togglePw('old_password','icon-old')" aria-label="<?php echo htmlspecialchars(t('toggle_password_visibility'), ENT_QUOTES, 'UTF-8'); ?>">
                        <i class="fas fa-eye" id="icon-old"></i>
                    </button>
                </div>
            </div>
            <div class="field">
                <label for="new_password"><?php echo htmlspecialchars(t('change_pwd_new_label'), ENT_QUOTES, 'UTF-8'); ?></label>
                <div class="input-wrap">
                    <i class="fas fa-key field-icon" aria-hidden="true"></i>
                    <input id="new_password" name="new_password" type="password" autocomplete="new-password"
                        placeholder="<?php echo htmlspecialchars(t('change_pwd_new_ph'), ENT_QUOTES, 'UTF-8'); ?>" required>
                    <button type="button" class="pw-toggle" onclick="togglePw('new_password','icon-new')" aria-label="<?php echo htmlspecialchars(t('toggle_password_visibility'), ENT_QUOTES, 'UTF-8'); ?>">
                        <i class="fas fa-eye" id="icon-new"></i>
                    </button>
                </div>
            </div>
            <div class="field">
                <label for="confirm_password"><?php echo htmlspecialchars(t('change_pwd_confirm_label'), ENT_QUOTES, 'UTF-8'); ?></label>
                <div class="input-wrap">
                    <i class="fas fa-shield-halved field-icon" aria-hidden="true"></i>
                    <input id="confirm_password" name="confirm_password" type="password" autocomplete="new-password"
                        placeholder="<?php echo htmlspecialchars(t('change_pwd_confirm_ph'), ENT_QUOTES, 'UTF-8'); ?>" required>
                    <button type="button" class="pw-toggle" onclick="togglePw('confirm_password','icon-confirm')" aria-label="<?php echo htmlspecialchars(t('toggle_password_visibility'), ENT_QUOTES, 'UTF-8'); ?>">
                        <i class="fas fa-eye" id="icon-confirm"></i>
                    </button>
                </div>
            </div>

            <p class="hint"><?php echo htmlspecialchars(t('change_pwd_hint'), ENT_QUOTES, 'UTF-8'); ?></p>

            <div class="actions">
                <button type="submit" class="btn primary">
                    <i class="fas fa-key" aria-hidden="true"></i>
                    <?php echo htmlspecialchars(t('change_pwd_save'), ENT_QUOTES, 'UTF-8'); ?>
                </button>
                <a class="btn secondary" href="<?php echo htmlspecialchars($backUrl, ENT_QUOTES, 'UTF-8'); ?>">
                    <i class="fas fa-<?php echo $isRtl ? 'arrow-right' : 'arrow-left'; ?>" aria-hidden="true"></i>
                    <?php echo htmlspecialchars(t('change_pwd_back'), ENT_QUOTES, 'UTF-8'); ?>
                </a>
            </div>
        </form>
    </article>
    </div><!-- /.content-pane -->

    <?php if ($userRole !== 'admin'): ?>
    <script>
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
    <?php endif; ?>
    <script>
        function togglePw(inputId, iconId) {
            var input = document.getElementById(inputId);
            var icon  = document.getElementById(iconId);
            if (!input || !icon) return;
            if (input.type === 'password') {
                input.type = 'text';
                icon.classList.replace('fa-eye', 'fa-eye-slash');
            } else {
                input.type = 'password';
                icon.classList.replace('fa-eye-slash', 'fa-eye');
            }
        }
    </script>
</body>
</html>
