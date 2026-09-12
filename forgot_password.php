<?php
declare(strict_types=1);

session_start();

require_once __DIR__ . '/db_connection.php';
require_once __DIR__ . '/password_reset_store.php';
require_once __DIR__ . '/mailer.php';
require_once __DIR__ . '/site_settings.php';
require_once __DIR__ . '/lang.php';

ensureSiteSettingsTable($pdo);
$siteFavicon = resolveSiteFavicon($pdo);

ensurePasswordResetTable($pdo);

if (!isset($_SESSION['forgot_password_csrf']) || !is_string($_SESSION['forgot_password_csrf'])) {
    $_SESSION['forgot_password_csrf'] = bin2hex(random_bytes(32));
}

$errorMessage = '';
$successMessage = '';
$emailValue = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $postedCsrfToken = (string) ($_POST['csrf_token'] ?? '');
    $emailValue = trim((string) ($_POST['email'] ?? ''));

    if (!hash_equals($_SESSION['forgot_password_csrf'], $postedCsrfToken)) {
        $errorMessage = t('err_invalid_token') ?: 'Invalid request token. Please refresh the page and try again.';
    } elseif (!filter_var($emailValue, FILTER_VALIDATE_EMAIL)) {
        $errorMessage = t('err_invalid_email') ?: 'Please enter a valid email address.';
    } else {
        try {
            $userType = '';
            $accountLookup = $pdo->prepare('SELECT customer_id FROM customer WHERE email = :email LIMIT 1');
            $accountLookup->execute(['email' => $emailValue]);
            if ($accountLookup->fetchColumn() !== false) {
                $userType = 'customer';
            } else {
                $providerLookup = $pdo->prepare('SELECT provider_id FROM serviceprovider WHERE email = :email LIMIT 1');
                $providerLookup->execute(['email' => $emailValue]);
                if ($providerLookup->fetchColumn() !== false) {
                    $userType = 'service_provider';
                }
            }

            if ($userType !== '') {
                $rawToken = bin2hex(random_bytes(32));
                $tokenHash = hash('sha256', $rawToken);
                $expiresAt = (new DateTime('+1 hour'))->format('Y-m-d H:i:s');

                createPasswordReset($pdo, $emailValue, $userType, $tokenHash, $expiresAt);

                $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
                $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
                $basePath = rtrim(str_replace('\\', '/', dirname($_SERVER['PHP_SELF'])), '/');
                $resetLink = $scheme . '://' . $host . $basePath . '/reset_password.php?token=' . urlencode($rawToken);

                if (!sendPasswordResetEmail($emailValue, $resetLink)) {
                    $errorMessage = t('forgot_send_failed') ?: 'Unable to send reset email. Please configure SMTP settings and try again.';
                } else {
                    $successMessage = t('forgot_sent_ok') ?: 'If an account exists for that email, a reset link has been sent.';
                }
            } else {
                $successMessage = t('forgot_sent_ok') ?: 'If an account exists for that email, a reset link has been sent.';
            }
        } catch (Throwable $exception) {
            $errorMessage = t('forgot_send_failed') ?: 'Unable to send reset email right now. Please try again later.';
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
    <title><?php echo htmlspecialchars(t('forgot_title'), ENT_QUOTES, 'UTF-8'); ?> - <?php echo htmlspecialchars(t('site_name'), ENT_QUOTES, 'UTF-8'); ?></title>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <?php if (isRtl()): ?>
    <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <?php endif; ?>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: 'Plus Jakarta Sans', sans-serif;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            background:
                radial-gradient(circle at 15% 10%, rgba(20, 184, 166, 0.18), transparent 40%),
                radial-gradient(circle at 85% 80%, rgba(249, 115, 22, 0.16), transparent 38%),
                linear-gradient(130deg, #ecfeff, #f8fafc 45%, #fff7ed);
            padding: 20px;
        }

        .shape {
            position: fixed;
            border-radius: 999px;
            filter: blur(80px);
            z-index: -1;
            animation: drift 18s ease-in-out infinite;
        }
        .shape.one { width:320px;height:320px;top:-90px;left:-80px;background:rgba(20,184,166,.32); }
        .shape.two { width:420px;height:420px;right:-120px;bottom:-140px;background:rgba(251,146,60,.26);animation-delay:-9s; }

        @keyframes drift {
            0%,100% { transform:translate(0,0) scale(1); }
            33% { transform:translate(32px,-22px) scale(1.05); }
            66% { transform:translate(-28px,26px) scale(.95); }
        }

        .card {
            width: 100%;
            max-width: 460px;
            background: rgba(255, 255, 255, 0.95);
            border-radius: 28px;
            padding: 40px 36px;
            box-shadow: 0 24px 56px rgba(15, 23, 42, 0.14);
            border: 1px solid rgba(15, 118, 110, 0.1);
            animation: cardIn 0.5s cubic-bezier(0.22, 1, 0.36, 1);
        }

        @keyframes cardIn {
            from { opacity: 0; transform: translateY(24px) scale(0.97); }
            to   { opacity: 1; transform: translateY(0) scale(1); }
        }

        .card-icon {
            width: 72px;
            height: 72px;
            border-radius: 20px;
            background: linear-gradient(145deg, #0f766e, #115e59);
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 22px;
            box-shadow: 0 14px 32px rgba(15, 118, 110, 0.3);
        }

        .card-icon i { font-size: 1.8rem; color: #fff; }

        .card h1 {
            font-size: 1.55rem;
            color: #042f2e;
            margin-bottom: 8px;
            font-weight: 800;
            text-align: center;
        }

        .card > p {
            font-size: 0.9rem;
            color: #475569;
            margin-bottom: 24px;
            line-height: 1.55;
            text-align: center;
        }

        .message {
            border-radius: 14px;
            padding: 13px 15px;
            font-size: 0.9rem;
            font-weight: 700;
            margin-bottom: 20px;
            display: flex;
            align-items: flex-start;
            gap: 10px;
        }

        .message.error  { background: #fff1f2; border: 1px solid #fecdd3; color: #be123c; }
        .message.success{ background: #ecfdf5; border: 1px solid #86efac; color: #166534; }

        .field { display: flex; flex-direction: column; gap: 8px; margin-bottom: 20px; }

        .field label { font-size: 0.9rem; font-weight: 700; color: #1f2937; }

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
            padding: 12px 14px 12px 44px;
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

        .actions { display: flex; flex-direction: column; gap: 12px; }

        .btn-primary {
            min-height: 50px;
            border-radius: 14px;
            border: none;
            font-family: inherit;
            font-size: 0.97rem;
            font-weight: 800;
            cursor: pointer;
            color: #fff;
            background: linear-gradient(145deg, #0f766e, #115e59);
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 9px;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
            position: relative;
            overflow: hidden;
        }

        .btn-primary::before {
            content: '';
            position: absolute;
            top: 0; left: -100%; width: 100%; height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.18), transparent);
            transition: left 0.5s ease;
        }

        .btn-primary:hover { transform: translateY(-2px); box-shadow: 0 14px 30px rgba(15, 118, 110, 0.32); }
        .btn-primary:hover::before { left: 100%; }
        .btn-primary:active { transform: translateY(0); }

        .link {
            text-align: center;
            font-size: 0.88rem;
            color: #0f766e;
            text-decoration: none;
            font-weight: 700;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 6px;
            transition: color 0.2s, background 0.2s;
            padding: 8px;
            border-radius: 10px;
        }

        .link:hover { color: #115e59; background: rgba(15, 118, 110, 0.06); }

        @media (max-width: 500px) { .card { padding: 28px 20px; border-radius: 22px; } }

        @media (max-width: 380px) {
            body { padding: 12px; }
            .card { padding: 22px 14px; border-radius: 18px; }
            .card h1 { font-size: 1.3rem; }
        }

        @media (prefers-reduced-motion: reduce) {
            .shape { animation: none; }
        }

        [dir="rtl"] body { font-family: 'Cairo', sans-serif; }
        [dir="rtl"] .input-wrap .field-icon { left: auto; right: 14px; }
        [dir="rtl"] .field input { padding-left: 14px; padding-right: 44px; text-align: right; }
    </style>
</head>
<body class="<?php echo htmlspecialchars(getLangBodyClass(), ENT_QUOTES, 'UTF-8'); ?>">
    <div class="shape one" aria-hidden="true"></div>
    <div class="shape two" aria-hidden="true"></div>

    <div class="card">
        <div class="card-icon" aria-hidden="true"><i class="fas fa-key"></i></div>
        <h1><?php echo htmlspecialchars(t('forgot_title'), ENT_QUOTES, 'UTF-8'); ?></h1>
        <p><?php echo htmlspecialchars(t('forgot_subtitle'), ENT_QUOTES, 'UTF-8'); ?></p>

        <?php if ($errorMessage !== ''): ?>
            <div class="message error" role="alert">
                <i class="fas fa-circle-xmark" aria-hidden="true"></i>
                <span><?php echo htmlspecialchars($errorMessage, ENT_QUOTES, 'UTF-8'); ?></span>
            </div>
        <?php endif; ?>

        <?php if ($successMessage !== ''): ?>
            <div class="message success" role="status">
                <i class="fas fa-circle-check" aria-hidden="true"></i>
                <span><?php echo htmlspecialchars($successMessage, ENT_QUOTES, 'UTF-8'); ?></span>
            </div>
        <?php endif; ?>

        <form method="post" action="forgot_password.php" novalidate>
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['forgot_password_csrf'], ENT_QUOTES, 'UTF-8'); ?>">

            <div class="field">
                <label for="email"><?php echo htmlspecialchars(t('forgot_email'), ENT_QUOTES, 'UTF-8'); ?></label>
                <div class="input-wrap">
                    <i class="fas fa-envelope field-icon" aria-hidden="true"></i>
                    <input type="email" id="email" name="email" dir="ltr"
                        placeholder="you@example.com"
                        autocomplete="email"
                        required
                        value="<?php echo htmlspecialchars($emailValue, ENT_QUOTES, 'UTF-8'); ?>">
                </div>
            </div>

            <div class="actions">
                <button class="btn-primary" type="submit" id="forgotBtn">
                    <i class="fas fa-paper-plane" aria-hidden="true"></i>
                    <span id="forgotBtnLabel"><?php echo htmlspecialchars(t('forgot_button'), ENT_QUOTES, 'UTF-8'); ?></span>
                </button>
                <a class="link" href="login.php">
                    <i class="fas fa-<?php echo isRtl() ? 'arrow-right' : 'arrow-left'; ?>" aria-hidden="true"></i>
                    <?php echo htmlspecialchars(t('forgot_back_login'), ENT_QUOTES, 'UTF-8'); ?>
                </a>
            </div>
        </form>
    </div>

    <script>
        var form = document.querySelector('form');
        if (form) {
            form.addEventListener('submit', function () {
                var btn = document.getElementById('forgotBtn');
                var lbl = document.getElementById('forgotBtnLabel');
                if (btn && lbl) {
                    btn.disabled = true;
                    lbl.textContent = '<?php echo addslashes(t('login_signing_in') ?: 'Sending…'); ?>';
                    btn.querySelector('i').className = 'fas fa-spinner fa-spin';
                }
            });
        }
    </script>
</body>
</html>
