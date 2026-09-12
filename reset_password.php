<?php
declare(strict_types=1);

session_start();

require_once __DIR__ . '/db_connection.php';
require_once __DIR__ . '/password_reset_store.php';
require_once __DIR__ . '/site_settings.php';
require_once __DIR__ . '/lang.php';

ensurePasswordResetTable($pdo);

ensureSiteSettingsTable($pdo);
$siteFavicon = resolveSiteFavicon($pdo);

$errorMessage = '';
$successMessage = '';
$passwordValue = '';
$confirmPasswordValue = '';

function isStrongResetPassword(string $password): bool
{
    return (bool) preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z0-9]).{8,}$/', $password);
}

$token = trim((string) ($_GET['token'] ?? $_POST['token'] ?? ''));
if ($token === '') {
    $errorMessage = t('reset_err_invalid_token') ?: 'Invalid or missing reset token.';
}

$resetRow = null;
$tokenError = false; // true only for link-level errors (invalid/expired/used token)

if ($errorMessage === '') {
    $tokenHash = hash('sha256', $token);
    $resetRow = findPasswordReset($pdo, $tokenHash);

    if ($resetRow === null) {
        $errorMessage = t('reset_err_invalid') ?: 'This reset link is invalid.';
        $tokenError = true;
    } elseif ($resetRow['used_at'] !== null) {
        $errorMessage = t('reset_err_used') ?: 'This reset link has already been used.';
        $tokenError = true;
    } else {
        $expiresAt = strtotime($resetRow['expires_at']);
        if ($expiresAt === false || $expiresAt < time()) {
            $errorMessage = t('reset_err_expired') ?: 'This reset link has expired.';
            $tokenError = true;
        }
    }
}

if ($errorMessage !== '' && !$tokenError) {
    // should not happen but guard anyway
}

/*
 * Handle password update submissions.
 * Only reached when token is valid (tokenError = false).
 */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !$tokenError && $resetRow !== null) {
    $passwordValue = (string) ($_POST['password'] ?? '');
    $confirmPasswordValue = (string) ($_POST['confirm_password'] ?? '');

    if ($passwordValue === '') {
        $errorMessage = t('reset_err_empty') ?: 'Please enter a new password.';
    } elseif (!isStrongResetPassword($passwordValue)) {
        $errorMessage = t('reset_err_weak') ?: 'Password must be at least 8 characters and include uppercase, lowercase, number, and special character.';
    } elseif ($passwordValue !== $confirmPasswordValue) {
        $errorMessage = t('reset_err_mismatch') ?: 'Password confirmation does not match.';
    } else {
        $passwordHash = password_hash($passwordValue, PASSWORD_DEFAULT);
        if ($passwordHash === false) {
            $errorMessage = t('reset_err_hash') ?: 'Unable to update password right now. Please try again.';
        } else {
            try {
                if ($resetRow['user_type'] === 'customer') {
                    $updateStatement = $pdo->prepare(
                        'UPDATE customer SET password = :password WHERE email = :email'
                    );
                } else {
                    $updateStatement = $pdo->prepare(
                        'UPDATE serviceprovider SET password = :password WHERE email = :email'
                    );
                }

                $updateStatement->execute([
                    'password' => $passwordHash,
                    'email'    => $resetRow['user_email'],
                ]);

                markPasswordResetUsed($pdo, (int) $resetRow['reset_id']);
                $successMessage = t('reset_success') ?: 'Your password has been updated. You can now log in.';
            } catch (PDOException $exception) {
                $errorMessage = t('reset_err_db') ?: 'Unable to update password right now. Please try again.';
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
    <title><?php echo htmlspecialchars(t('reset_title'), ENT_QUOTES, 'UTF-8'); ?> - <?php echo htmlspecialchars(t('site_name'), ENT_QUOTES, 'UTF-8'); ?></title>
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

        .field { display: flex; flex-direction: column; gap: 8px; margin-bottom: 18px; }

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
            justify-content: center;
        }

        .pw-toggle:hover { color: #0f766e; }

        /* Password strength */
        .pw-strength { margin-top: 6px; display: none; }
        .pw-strength.visible { display: block; }
        .pw-bar { height: 4px; border-radius: 999px; background: #e5e7eb; overflow: hidden; margin-bottom: 4px; }
        .pw-fill { height: 100%; border-radius: 999px; transition: width 0.3s, background 0.3s; width: 0; }
        .pw-label { font-size: 0.76rem; font-weight: 700; }
        .pw-label.weak   { color: #ef4444; }
        .pw-label.fair   { color: #f97316; }
        .pw-label.good   { color: #eab308; }
        .pw-label.strong { color: #22c55e; }

        .actions { display: flex; flex-direction: column; gap: 12px; margin-top: 6px; }

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
            transition: color 0.2s;
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
            .btn-primary { transition: none; }
        }

        [dir="rtl"] body { font-family: 'Cairo', sans-serif; }
        [dir="rtl"] .input-wrap .field-icon { left: auto; right: 14px; }
        [dir="rtl"] .field input { padding-left: 48px; padding-right: 44px; text-align: right; }
        [dir="rtl"] .pw-toggle { right: auto; left: 14px; }
    </style>
</head>
<body class="<?php echo htmlspecialchars(getLangBodyClass(), ENT_QUOTES, 'UTF-8'); ?>">
    <div class="shape one" aria-hidden="true"></div>
    <div class="shape two" aria-hidden="true"></div>

    <div class="card">
        <div class="card-icon" aria-hidden="true"><i class="fas fa-shield-halved"></i></div>
        <h1><?php echo htmlspecialchars(t('reset_title'), ENT_QUOTES, 'UTF-8'); ?></h1>
        <p><?php echo htmlspecialchars(t('reset_subtitle'), ENT_QUOTES, 'UTF-8'); ?></p>

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

        <?php if ($successMessage === '' && !$tokenError): ?>
            <!-- Form shown for valid tokens (even when validation errors occur) -->
            <form method="post" action="reset_password.php" novalidate>
                <input type="hidden" name="token" value="<?php echo htmlspecialchars($token, ENT_QUOTES, 'UTF-8'); ?>">

                <div class="field">
                    <label for="password"><?php echo htmlspecialchars(t('reset_new_password'), ENT_QUOTES, 'UTF-8'); ?></label>
                    <div class="input-wrap">
                        <i class="fas fa-lock field-icon" aria-hidden="true"></i>
                        <input type="password" id="password" name="password"
                            placeholder="••••••••"
                            autocomplete="new-password"
                            oninput="updatePwStrength(this.value)"
                            required>
                        <button type="button" class="pw-toggle" onclick="togglePw('password','icon-pw')" aria-label="<?php echo htmlspecialchars(t('toggle_password_visibility'), ENT_QUOTES, 'UTF-8'); ?>">
                            <i class="fas fa-eye" id="icon-pw"></i>
                        </button>
                    </div>
                    <div id="pwStrength" class="pw-strength">
                        <div class="pw-bar"><div id="pwFill" class="pw-fill"></div></div>
                        <span id="pwLabel" class="pw-label"></span>
                    </div>
                </div>

                <div class="field">
                    <label for="confirm_password"><?php echo htmlspecialchars(t('reset_confirm'), ENT_QUOTES, 'UTF-8'); ?></label>
                    <div class="input-wrap">
                        <i class="fas fa-shield-halved field-icon" aria-hidden="true"></i>
                        <input type="password" id="confirm_password" name="confirm_password"
                            placeholder="••••••••"
                            autocomplete="new-password"
                            required>
                        <button type="button" class="pw-toggle" onclick="togglePw('confirm_password','icon-confirm')" aria-label="<?php echo htmlspecialchars(t('toggle_password_visibility'), ENT_QUOTES, 'UTF-8'); ?>">
                            <i class="fas fa-eye" id="icon-confirm"></i>
                        </button>
                    </div>
                </div>

                <div class="actions">
                    <button class="btn-primary" type="submit" id="resetBtn">
                        <i class="fas fa-check" aria-hidden="true"></i>
                        <span id="resetBtnLabel"><?php echo htmlspecialchars(t('reset_button'), ENT_QUOTES, 'UTF-8'); ?></span>
                    </button>
                    <a class="link" href="login.php">
                        <i class="fas fa-<?php echo isRtl() ? 'arrow-right' : 'arrow-left'; ?>" aria-hidden="true"></i>
                        <?php echo htmlspecialchars(t('forgot_back_login'), ENT_QUOTES, 'UTF-8'); ?>
                    </a>
                </div>
            </form>
        <?php else: ?>
            <div class="actions">
                <a class="link" href="login.php">
                    <i class="fas fa-<?php echo isRtl() ? 'arrow-right' : 'arrow-left'; ?>" aria-hidden="true"></i>
                    <?php echo htmlspecialchars(t('forgot_back_login'), ENT_QUOTES, 'UTF-8'); ?>
                </a>
            </div>
        <?php endif; ?>
    </div>

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

        function updatePwStrength(val) {
            var container = document.getElementById('pwStrength');
            var fill  = document.getElementById('pwFill');
            var label = document.getElementById('pwLabel');
            if (!container || !fill || !label) return;
            if (!val) { container.classList.remove('visible'); return; }
            container.classList.add('visible');
            var score = [val.length>=8, /[A-Z]/.test(val), /[a-z]/.test(val), /\d/.test(val), /[^a-zA-Z0-9]/.test(val)].filter(Boolean).length;
            var map = [[25,'#ef4444','weak','Weak'],[50,'#f97316','fair','Fair'],[75,'#eab308','good','Good'],[100,'#22c55e','strong','Strong']];
            var entry = score<=2?map[0]:score===3?map[1]:score===4?map[2]:map[3];
            fill.style.width = entry[0]+'%';
            fill.style.background = entry[1];
            label.className = 'pw-label '+entry[2];
            label.textContent = entry[3];
        }

        var resetForm = document.querySelector('form');
        if (resetForm) {
            resetForm.addEventListener('submit', function(e) {
                var pw  = document.getElementById('password');
                var cpw = document.getElementById('confirm_password');
                if (pw && pw.value === '') { e.preventDefault(); pw.focus(); return; }
                if (cpw && cpw.value === '') { e.preventDefault(); cpw.focus(); return; }
                var btn = document.getElementById('resetBtn');
                var lbl = document.getElementById('resetBtnLabel');
                if (btn && lbl) {
                    btn.disabled = true;
                    lbl.textContent = '<?php echo addslashes(t('login_signing_in') ?: 'Updating…'); ?>';
                    btn.querySelector('i').className = 'fas fa-spinner fa-spin';
                }
            });
        }
    </script>
</body>
</html>
