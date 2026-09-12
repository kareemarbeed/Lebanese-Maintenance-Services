<?php
declare(strict_types=1);

session_start();

require_once __DIR__ . '/db_connection.php';
require_once __DIR__ . '/email_verification_store.php';
require_once __DIR__ . '/mailer.php';
require_once __DIR__ . '/site_settings.php';
require_once __DIR__ . '/lang.php';

ensureEmailVerificationTable($pdo);
ensureSiteSettingsTable($pdo);
$siteSettings = loadSiteSettings($pdo, ['site_favicon' => '']);
$siteFavicon  = trim((string) ($siteSettings['site_favicon'] ?? ''));

/*
 * Guard: only accessible when a pending verification is waiting.
 * Redirect to register if the session has no pending email.
 */
$pendingEmail = trim((string) ($_SESSION['verify_pending_email'] ?? ''));
$pendingType  = (string) ($_SESSION['verify_pending_type'] ?? '');

if ($pendingEmail === '' || !in_array($pendingType, ['customer', 'service_provider'], true)) {
    header('Location: register.php');
    exit;
}

/*
 * Issue a tab-scoped access token for customers (mirrors register.php / login.php).
 */
function issueCustomerTabAccessToken(int $userId, string $userEmail): string
{
    if (!isset($_SESSION['customer_tab_tokens']) || !is_array($_SESSION['customer_tab_tokens'])) {
        $_SESSION['customer_tab_tokens'] = [];
    }

    $tabToken = bin2hex(random_bytes(32));

    $_SESSION['customer_tab_tokens'][$tabToken] = [
        'user_id'    => $userId,
        'user_email' => $userEmail,
        'issued_at'  => time(),
    ];

    if (count($_SESSION['customer_tab_tokens']) > 25) {
        uasort($_SESSION['customer_tab_tokens'], static function (array $l, array $r): int {
            return ((int) ($l['issued_at'] ?? 0)) <=> ((int) ($r['issued_at'] ?? 0));
        });
        $_SESSION['customer_tab_tokens'] = array_slice($_SESSION['customer_tab_tokens'], -25, null, true);
    }

    return $tabToken;
}

function resetSessionForRole(string $role): void
{
    $savedLang = $_SESSION['lang'] ?? 'en';

    if (session_status() === PHP_SESSION_ACTIVE) {
        session_regenerate_id(true);
    }

    $_SESSION                = [];
    $_SESSION['user_type']   = $role;
    $_SESSION['lang']        = $savedLang;
}

$errorMessage   = '';
$successMessage = '';
$resendSuccess  = false;

/*
 * Show a warning banner when the initial registration email could not be sent,
 * but do not block the user — they can still resend immediately.
 */
$emailSendFailed = (bool) ($_SESSION['verify_email_send_failed'] ?? false);
unset($_SESSION['verify_email_send_failed']);

$csrfKey = 'verify_email_csrf';
if (!isset($_SESSION[$csrfKey]) || !is_string($_SESSION[$csrfKey])) {
    $_SESSION[$csrfKey] = bin2hex(random_bytes(32));
}

$codeValue = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $postedCsrf  = (string) ($_POST['csrf_token'] ?? '');
    $formAction  = (string) ($_POST['form_action'] ?? '');

    if (!hash_equals($_SESSION[$csrfKey], $postedCsrf)) {
        $errorMessage = 'Invalid request token. Please refresh the page and try again.';
    } elseif ($formAction === 'resend') {
        /*
         * Resend flow: generate a new code and send a fresh email.
         * Rate-limit is handled implicitly — createVerificationCode() invalidates the old code first.
         */
        try {
            $newCode   = createVerificationCode($pdo, $pendingEmail, $pendingType);
            $emailSent = sendVerificationEmail($pendingEmail, $newCode);

            if ($emailSent) {
                $resendSuccess  = true;
                $successMessage = t('verify_resent');
            } else {
                $errorMessage = t('verify_send_failed');
            }
        } catch (PDOException) {
            $errorMessage = t('verify_send_failed');
        }
    } elseif ($formAction === 'verify') {
        $codeValue = trim((string) ($_POST['code'] ?? ''));

        if ($codeValue === '') {
            $errorMessage = t('verify_enter_code');
        } elseif (!preg_match('/^\d{6}$/', $codeValue)) {
            $errorMessage = t('verify_invalid_code');
        } else {
            try {
                $result = verifyEmailCode($pdo, $pendingEmail, $pendingType, $codeValue);

                if ($result === 'ok') {
                    if ($pendingType === 'service_provider') {
                        $pdo->prepare(
                            'UPDATE serviceprovider SET is_verified = 1 WHERE email = :email LIMIT 1'
                        )->execute(['email' => $pendingEmail]);

                        $providerId = (int) ($_SESSION['verify_pending_provider_id'] ?? 0);

                        if ($providerId <= 0) {
                            $stmt = $pdo->prepare('SELECT provider_id FROM serviceprovider WHERE email = :email LIMIT 1');
                            $stmt->execute(['email' => $pendingEmail]);
                            $providerId = (int) ($stmt->fetchColumn() ?: 0);
                        }

                        unset(
                            $_SESSION['verify_pending_email'],
                            $_SESSION['verify_pending_type'],
                            $_SESSION['verify_pending_provider_id']
                        );

                        resetSessionForRole('service_provider');
                        $_SESSION['user_id']     = $providerId;
                        $_SESSION['user_email']  = $pendingEmail;
                        $_SESSION['remember_me'] = false;

                        header('Location: service_provider_dashboard.php');
                        exit;
                    }

                    $pdo->prepare(
                        'UPDATE customer SET is_verified = 1 WHERE email = :email LIMIT 1'
                    )->execute(['email' => $pendingEmail]);

                    $customerId = (int) ($_SESSION['verify_pending_customer_id'] ?? 0);

                    if ($customerId <= 0) {
                        $stmt = $pdo->prepare('SELECT customer_id FROM customer WHERE email = :email LIMIT 1');
                        $stmt->execute(['email' => $pendingEmail]);
                        $customerId = (int) ($stmt->fetchColumn() ?: 0);
                    }

                    unset(
                        $_SESSION['verify_pending_email'],
                        $_SESSION['verify_pending_type'],
                        $_SESSION['verify_pending_customer_id']
                    );

                    resetSessionForRole('customer');
                    $_SESSION['user_id']     = $customerId;
                    $_SESSION['user_email']  = $pendingEmail;
                    $_SESSION['remember_me'] = false;

                    $tabToken = issueCustomerTabAccessToken($customerId, $pendingEmail);
                    header('Location: customer_dashboard.php?tab=' . urlencode($tabToken));
                    exit;
                } elseif ($result === 'expired') {
                    $errorMessage = t('verify_code_expired');
                } else {
                    $errorMessage = t('verify_wrong_code');
                }
            } catch (PDOException) {
                $errorMessage = t('verify_generic_error');
            }
        }
    }
}

/*
 * Mask the email address for display: show first 3 chars then **** then @domain.
 */
$maskedEmail = '';
$atPos = strpos($pendingEmail, '@');
if ($atPos !== false) {
    $local  = substr($pendingEmail, 0, $atPos);
    $domain = substr($pendingEmail, $atPos);
    $visible = mb_substr($local, 0, min(3, mb_strlen($local)));
    $maskedEmail = $visible . str_repeat('*', max(2, mb_strlen($local) - 3)) . $domain;
} else {
    $maskedEmail = $pendingEmail;
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
    <title><?php echo htmlspecialchars(t('verify_title'), ENT_QUOTES, 'UTF-8'); ?> – <?php echo htmlspecialchars(t('site_name'), ENT_QUOTES, 'UTF-8'); ?></title>
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
            padding: 20px;
            background:
                radial-gradient(circle at 20% 20%, rgba(15, 118, 110, 0.2), transparent 45%),
                radial-gradient(circle at 80% 80%, rgba(249, 115, 22, 0.18), transparent 40%),
                linear-gradient(135deg, #ecfeff, #f8fafc 45%, #fff7ed);
        }

        .shape {
            position: fixed;
            border-radius: 999px;
            filter: blur(80px);
            z-index: -1;
            animation: drift 18s ease-in-out infinite;
        }
        .shape.one { width:300px;height:300px;top:-80px;left:-70px;background:rgba(20,184,166,.35); }
        .shape.two { width:400px;height:400px;right:-110px;bottom:-120px;background:rgba(251,146,60,.3);animation-delay:-9s; }

        @keyframes drift {
            0%,100% { transform:translate(0,0) scale(1); }
            33% { transform:translate(30px,-20px) scale(1.05); }
            66% { transform:translate(-25px,25px) scale(.95); }
        }

        .card {
            width: 100%;
            max-width: 460px;
            background: rgba(255,255,255,.93);
            backdrop-filter: blur(18px);
            border: 1px solid rgba(255,255,255,.65);
            border-radius: 28px;
            padding: 40px 38px;
            box-shadow: 0 24px 56px rgba(15,23,42,.14);
            animation: cardIn .55s cubic-bezier(.22,1,.36,1);
        }

        @keyframes cardIn {
            from { opacity:0; transform:translateY(24px) scale(.98); }
            to   { opacity:1; transform:translateY(0) scale(1); }
        }

        .card-icon {
            width: 72px;
            height: 72px;
            border-radius: 20px;
            background: linear-gradient(145deg, #0f766e, #115e59);
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 20px;
            box-shadow: 0 14px 30px rgba(15,118,110,.3);
        }
        .card-icon i { font-size: 1.9rem; color: #fff; }

        h1 {
            font-size: 1.55rem;
            font-weight: 800;
            color: #042f2e;
            text-align: center;
            margin-bottom: 8px;
        }

        .subtitle {
            color: #4b5563;
            font-size: .93rem;
            text-align: center;
            margin-bottom: 24px;
            line-height: 1.5;
        }

        .email-display {
            display: inline-block;
            font-weight: 700;
            color: #0f766e;
            word-break: break-all;
        }

        .message {
            border-radius: 14px;
            padding: 12px 15px;
            font-size: .9rem;
            font-weight: 700;
            margin-bottom: 18px;
        }
        .message.error   { background:#fff1f2;border:1px solid #fecdd3;color:#be123c; }
        .message.success { background:#ecfdf5;border:1px solid #a7f3d0;color:#065f46; }
        .message.warning { background:#fffbeb;border:1px solid #fde68a;color:#92400e; }

        .code-group {
            margin-bottom: 20px;
        }
        .code-group label {
            display: block;
            font-size: .88rem;
            font-weight: 700;
            color: #1f2937;
            margin-bottom: 8px;
        }

        /* Six individual digit boxes */
        .code-boxes {
            display: flex;
            gap: 10px;
            justify-content: center;
            margin-bottom: 6px;
        }

        .code-box {
            width: 52px;
            height: 58px;
            border: 2.5px solid #d1d5db;
            border-radius: 14px;
            background: #fff;
            font-size: 1.6rem;
            font-weight: 800;
            text-align: center;
            color: #042f2e;
            transition: border-color .2s, box-shadow .2s;
            caret-color: #0f766e;
        }
        .code-box:focus {
            outline: none;
            border-color: #0f766e;
            box-shadow: 0 0 0 4px rgba(15,118,110,.14);
        }

        /* Hidden real input that stores the full 6-digit value */
        #codeHidden { display: none; }

        .expiry-hint {
            font-size: .78rem;
            color: #6b7280;
            text-align: center;
            margin-top: 4px;
        }

        .btn-primary {
            width: 100%;
            min-height: 50px;
            border: none;
            border-radius: 14px;
            background: linear-gradient(145deg, #0f766e, #115e59);
            color: #fff;
            font-size: 1rem;
            font-weight: 800;
            font-family: inherit;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 9px;
            transition: transform .2s, box-shadow .2s;
            margin-bottom: 14px;
        }
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 12px 26px rgba(15,118,110,.32);
        }
        .btn-primary:active { transform: translateY(0); }

        .btn-secondary {
            width: 100%;
            min-height: 44px;
            border: 2px solid #d1d5db;
            border-radius: 14px;
            background: #fff;
            color: #374151;
            font-size: .93rem;
            font-weight: 700;
            font-family: inherit;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            transition: border-color .2s, background .2s;
        }
        .btn-secondary:hover {
            border-color: #0f766e;
            background: rgba(15,118,110,.05);
            color: #0f766e;
        }

        .divider {
            text-align: center;
            color: #9ca3af;
            font-size: .82rem;
            margin: 14px 0;
        }

        .back-link {
            display: block;
            text-align: center;
            margin-top: 18px;
            font-size: .85rem;
            color: #94a3b8;
            text-decoration: none;
            font-weight: 600;
        }
        .back-link:hover { color: #0f766e; }

        @media (max-width: 480px) {
            .card { padding: 28px 20px; border-radius: 22px; }
            .code-box { width: 44px; height: 50px; font-size: 1.4rem; }
        }

        @media (prefers-reduced-motion: reduce) {
            *,*::before,*::after {
                animation-duration:.01ms!important;
                transition-duration:.01ms!important;
            }
        }

        [dir="rtl"] body { font-family: 'Cairo', sans-serif; }
    </style>
</head>
<body class="<?php echo htmlspecialchars(getLangBodyClass(), ENT_QUOTES, 'UTF-8'); ?>">
    <div class="shape one" aria-hidden="true"></div>
    <div class="shape two" aria-hidden="true"></div>

    <div class="card">
        <div class="card-icon">
            <i class="fas fa-envelope-open-text"></i>
        </div>

        <h1><?php echo htmlspecialchars(t('verify_title'), ENT_QUOTES, 'UTF-8'); ?></h1>
        <p class="subtitle">
            <?php echo htmlspecialchars(t('verify_subtitle_before'), ENT_QUOTES, 'UTF-8'); ?>
            <span class="email-display"><?php echo htmlspecialchars($maskedEmail, ENT_QUOTES, 'UTF-8'); ?></span>
            <?php echo htmlspecialchars(t('verify_subtitle_after'), ENT_QUOTES, 'UTF-8'); ?>
        </p>

        <?php if ($emailSendFailed): ?>
            <div class="message warning">
                <i class="fas fa-triangle-exclamation"></i>
                <?php echo htmlspecialchars(t('verify_send_failed'), ENT_QUOTES, 'UTF-8'); ?>
            </div>
        <?php endif; ?>

        <?php if ($errorMessage !== ''): ?>
            <div class="message error" role="alert">
                <i class="fas fa-circle-xmark"></i>
                <?php echo htmlspecialchars($errorMessage, ENT_QUOTES, 'UTF-8'); ?>
            </div>
        <?php endif; ?>

        <?php if ($successMessage !== ''): ?>
            <div class="message success" role="status">
                <i class="fas fa-circle-check"></i>
                <?php echo htmlspecialchars($successMessage, ENT_QUOTES, 'UTF-8'); ?>
            </div>
        <?php endif; ?>

        <!-- Code entry form -->
        <form id="verifyForm" method="post" action="verify_email.php" novalidate>
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars((string) $_SESSION[$csrfKey], ENT_QUOTES, 'UTF-8'); ?>">
            <input type="hidden" name="form_action" value="verify">
            <input type="hidden" name="code" id="codeHidden" value="<?php echo htmlspecialchars($codeValue, ENT_QUOTES, 'UTF-8'); ?>">

            <div class="code-group">
                <label><?php echo htmlspecialchars(t('verify_code_label'), ENT_QUOTES, 'UTF-8'); ?></label>
                <div class="code-boxes" aria-label="Verification code digits">
                    <?php for ($i = 0; $i < 6; $i++): ?>
                        <input
                            type="text"
                            inputmode="numeric"
                            pattern="\d"
                            maxlength="1"
                            class="code-box"
                            autocomplete="<?php echo $i === 0 ? 'one-time-code' : 'off'; ?>"
                            aria-label="Digit <?php echo $i + 1; ?>"
                            value="<?php echo isset($codeValue[$i]) ? htmlspecialchars($codeValue[$i], ENT_QUOTES, 'UTF-8') : ''; ?>"
                        >
                    <?php endfor; ?>
                </div>
                <p class="expiry-hint"><i class="fas fa-clock"></i> <?php echo htmlspecialchars(t('verify_expiry_hint'), ENT_QUOTES, 'UTF-8'); ?></p>
            </div>

            <button type="submit" class="btn-primary">
                <i class="fas fa-shield-halved"></i>
                <?php echo htmlspecialchars(t('verify_button'), ENT_QUOTES, 'UTF-8'); ?>
            </button>
        </form>

        <div class="divider"><?php echo htmlspecialchars(t('lbl_or'), ENT_QUOTES, 'UTF-8'); ?></div>

        <!-- Resend code form -->
        <form method="post" action="verify_email.php">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars((string) $_SESSION[$csrfKey], ENT_QUOTES, 'UTF-8'); ?>">
            <input type="hidden" name="form_action" value="resend">
            <button type="submit" class="btn-secondary">
                <i class="fas fa-rotate-right"></i>
                <?php echo htmlspecialchars(t('verify_resend'), ENT_QUOTES, 'UTF-8'); ?>
            </button>
        </form>

        <a href="register.php" class="back-link">
            <i class="fas fa-arrow-left"></i>
            <?php echo htmlspecialchars(t('verify_back_register'), ENT_QUOTES, 'UTF-8'); ?>
        </a>
    </div>

    <script>
        (function () {
            var boxes  = document.querySelectorAll('.code-box');
            var hidden = document.getElementById('codeHidden');
            var form   = document.getElementById('verifyForm');

            function sync() {
                var val = '';
                boxes.forEach(function (b) { val += (b.value.replace(/\D/g, '').slice(-1) || ''); });
                if (hidden) hidden.value = val;
            }

            boxes.forEach(function (box, idx) {
                box.addEventListener('input', function (e) {
                    // Accept only digits; clean multi-char pastes
                    var digits = e.target.value.replace(/\D/g, '');
                    if (digits.length > 1) {
                        // Paste: distribute digits across remaining boxes
                        for (var j = 0; j < digits.length && idx + j < boxes.length; j++) {
                            boxes[idx + j].value = digits[j];
                        }
                        var next = idx + digits.length;
                        if (next < boxes.length) boxes[next].focus();
                        else boxes[boxes.length - 1].blur();
                    } else {
                        box.value = digits;
                        if (digits && idx < boxes.length - 1) boxes[idx + 1].focus();
                    }
                    sync();
                });

                box.addEventListener('keydown', function (e) {
                    if (e.key === 'Backspace' && !box.value && idx > 0) {
                        boxes[idx - 1].value = '';
                        boxes[idx - 1].focus();
                        sync();
                    }
                    if (e.key === 'ArrowLeft'  && idx > 0)                boxes[idx - 1].focus();
                    if (e.key === 'ArrowRight' && idx < boxes.length - 1) boxes[idx + 1].focus();
                    // Submit on Enter when all filled
                    if (e.key === 'Enter') { sync(); if (form) form.submit(); }
                });
            });

            // On submit, collect final values then validate client-side
            if (form) {
                form.addEventListener('submit', function (e) {
                    sync();
                    if (!hidden || hidden.value.length !== 6) {
                        e.preventDefault();
                        boxes[0].focus();
                    }
                });
            }

            // Auto-focus first empty box on page load
            for (var i = 0; i < boxes.length; i++) {
                if (!boxes[i].value) { boxes[i].focus(); break; }
            }
        })();
    </script>
</body>
</html>
