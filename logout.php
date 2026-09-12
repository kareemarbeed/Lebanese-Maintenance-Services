<?php
declare(strict_types=1);

session_start();

$savedLang = (string) ($_SESSION['lang'] ?? 'en');

$_SESSION = [];

if (ini_get('session.use_cookies')) {
    $cookieParams = session_get_cookie_params();
    setcookie(
        session_name(),
        '',
        time() - 42000,
        $cookieParams['path'],
        $cookieParams['domain'],
        $cookieParams['secure'],
        $cookieParams['httponly']
    );
}

session_destroy();

$redirect = 'login.php';
if ($savedLang !== '' && $savedLang !== 'en') {
    $redirect .= '?lang=' . urlencode($savedLang);
}

header('Location: ' . $redirect);
exit;
