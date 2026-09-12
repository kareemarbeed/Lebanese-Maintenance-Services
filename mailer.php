<?php
declare(strict_types=1);

/*
 * Start/resume session safely for consistent session availability.
 */
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

require_once __DIR__ . '/mail_settings.php';

/*
 * Send a 6-digit email verification code to a newly registered user.
 * Code expires in 10 minutes.
 */
function sendVerificationEmail(string $toEmail, string $code): bool
{
    $subject = 'Your verification code – Lebanese Maintenance Services';
    $body    = "Welcome to Lebanese Maintenance Services!\n\n"
             . "Your email verification code is:\n\n"
             . "    $code\n\n"
             . "Enter this code on the verification page. It expires in 10 minutes.\n"
             . "If you did not register, you can safely ignore this email.";

    return sendMailMessage($toEmail, $subject, $body);
}

/*
 * Send a password reset email with either SMTP or PHP mail().
 */
function sendPasswordResetEmail(string $toEmail, string $resetLink): bool
{
    $subject = 'Reset your password';
    $body = "We received a request to reset your password.\n\n"
        . "Use the link below to set a new password (valid for 1 hour):\n"
        . $resetLink . "\n\n"
        . "If you did not request this, you can ignore this email.";

    return sendMailMessage($toEmail, $subject, $body);
}

/*
 * Dispatch the email using the configured transport.
 */
function sendMailMessage(string $toEmail, string $subject, string $body): bool
{
    $fromEmail = SMTP_FROM_EMAIL !== '' ? SMTP_FROM_EMAIL : 'no-reply@localhost';
    $fromName = SMTP_FROM_NAME !== '' ? SMTP_FROM_NAME : 'Support';

    if (MAIL_TRANSPORT === 'smtp' && SMTP_HOST !== '') {
        return sendViaSmtp($fromEmail, $fromName, $toEmail, $subject, $body);
    }

    return sendViaMail($fromEmail, $fromName, $toEmail, $subject, $body);
}

/*
 * Use PHP's mail() as a fallback for configured local mail servers.
 */
function sendViaMail(string $fromEmail, string $fromName, string $toEmail, string $subject, string $body): bool
{
    $headers = [];
    $headers[] = 'From: ' . $fromName . ' <' . $fromEmail . '>';
    $headers[] = 'MIME-Version: 1.0';
    $headers[] = 'Content-Type: text/plain; charset=UTF-8';

    return @mail($toEmail, $subject, $body, implode("\r\n", $headers));
}

/*
 * Send mail via SMTP with optional STARTTLS and AUTH LOGIN.
 */
function sendViaSmtp(string $fromEmail, string $fromName, string $toEmail, string $subject, string $body): bool
{
    $host = SMTP_HOST;
    $port = SMTP_PORT;
    $username = SMTP_USERNAME;
    $password = SMTP_PASSWORD;
    $encryption = strtolower(SMTP_ENCRYPTION);

    $targetHost = $host;
    if ($encryption === 'ssl') {
        $targetHost = 'ssl://' . $host;
    }

    $socket = @fsockopen($targetHost, $port, $errno, $errstr, 15);
    if (!$socket) {
        return false;
    }

    $expect = function (array $codes) use ($socket): bool {
        $response = '';
        while (!feof($socket)) {
            $line = fgets($socket, 512);
            if ($line === false) {
                break;
            }
            $response .= $line;
            if (isset($line[3]) && $line[3] === ' ') {
                break;
            }
        }

        $statusCode = (int) substr(trim($response), 0, 3);
        return in_array($statusCode, $codes, true);
    };

    $send = function (string $command) use ($socket): void {
        fwrite($socket, $command . "\r\n");
    };

    if (!$expect([220])) {
        fclose($socket);
        return false;
    }

    $send('EHLO localhost');
    if (!$expect([250])) {
        fclose($socket);
        return false;
    }

    if ($encryption === 'tls') {
        $send('STARTTLS');
        if (!$expect([220])) {
            fclose($socket);
            return false;
        }

        if (!stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT)) {
            fclose($socket);
            return false;
        }

        $send('EHLO localhost');
        if (!$expect([250])) {
            fclose($socket);
            return false;
        }
    }

    if ($username !== '' && $password !== '') {
        $send('AUTH LOGIN');
        if (!$expect([334])) {
            fclose($socket);
            return false;
        }
        $send(base64_encode($username));
        if (!$expect([334])) {
            fclose($socket);
            return false;
        }
        $send(base64_encode($password));
        if (!$expect([235])) {
            fclose($socket);
            return false;
        }
    }

    $send('MAIL FROM:<' . $fromEmail . '>');
    if (!$expect([250])) {
        fclose($socket);
        return false;
    }

    $send('RCPT TO:<' . $toEmail . '>');
    if (!$expect([250, 251])) {
        fclose($socket);
        return false;
    }

    $send('DATA');
    if (!$expect([354])) {
        fclose($socket);
        return false;
    }

    $headers = [];
    $headers[] = 'From: ' . $fromName . ' <' . $fromEmail . '>';
    $headers[] = 'To: ' . $toEmail;
    $headers[] = 'Subject: ' . $subject;
    $headers[] = 'MIME-Version: 1.0';
    $headers[] = 'Content-Type: text/plain; charset=UTF-8';

    $message = implode("\r\n", $headers) . "\r\n\r\n" . $body;
    $message = str_replace("\n.", "\n..", $message);

    $send($message . "\r\n.");
    if (!$expect([250])) {
        fclose($socket);
        return false;
    }

    $send('QUIT');
    fclose($socket);

    return true;
}
