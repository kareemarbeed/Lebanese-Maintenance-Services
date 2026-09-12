<?php
declare(strict_types=1);

/*
 * Language loader. Call initLang() once at the top of each page.
 * Use t($key) to retrieve a translated string.
 * Language is stored in $_SESSION['lang'] and toggled via ?lang=ar / ?lang=en.
 */

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

function initLang(): void
{
    $allowed = ['en', 'ar'];

    if (isset($_GET['lang']) && in_array($_GET['lang'], $allowed, true)) {
        $_SESSION['lang'] = $_GET['lang'];
    }

    if (!isset($_SESSION['lang']) || !in_array($_SESSION['lang'], $allowed, true)) {
        $_SESSION['lang'] = 'en';
    }
}

function getLang(): string
{
    $allowed = ['en', 'ar'];
    if (isset($_GET['lang']) && in_array($_GET['lang'], $allowed, true)) {
        return (string) $_GET['lang'];
    }
    return (string) ($_SESSION['lang'] ?? 'en');
}

function getTranslations(): array
{
    static $translations = [];
    $lang = getLang();

    if (!isset($translations[$lang])) {
        $file = __DIR__ . '/lang/' . $lang . '.php';
        $translations[$lang] = file_exists($file) ? (require $file) : [];

        if ($lang !== 'en') {
            $enFile = __DIR__ . '/lang/en.php';
            if (file_exists($enFile)) {
                $translations['en'] = $translations['en'] ?? (require $enFile);
            }
        }
    }

    return $translations[$lang];
}

function t(string $key, array $params = []): string
{
    $translations = getTranslations();
    $value = $translations[$key] ?? null;

    if ($value === null && getLang() !== 'en') {
        static $en = null;
        if ($en === null) {
            $enFile = __DIR__ . '/lang/en.php';
            $en = file_exists($enFile) ? (require $enFile) : [];
        }
        $value = $en[$key] ?? $key;
    }

    $value = $value ?? $key;

    foreach ($params as $placeholder => $replacement) {
        $value = str_replace('{' . $placeholder . '}', (string) $replacement, $value);
    }

    return $value;
}

function isRtl(): bool
{
    return getLang() === 'ar';
}

function langSwitchUrl(string $currentUrl = ''): string
{
    $lang = getLang();
    $target = $lang === 'en' ? 'ar' : 'en';

    $parsed = parse_url($currentUrl ?: $_SERVER['REQUEST_URI'] ?? '');
    $path = $parsed['path'] ?? '';
    parse_str($parsed['query'] ?? '', $queryParams);
    $queryParams['lang'] = $target;
    unset($queryParams['lang']);
    $queryParams = array_merge($queryParams, ['lang' => $target]);

    return $path . '?' . http_build_query($queryParams);
}

function langUrl(string $url): string
{
    $lang = getLang();
    if ($lang === 'en') return $url;
    $sep = (strpos($url, '?') !== false) ? '&' : '?';
    return $url . $sep . 'lang=' . urlencode($lang);
}

function getLangFontTag(): string
{
    $url = t('font_url');
    return '<link href="' . htmlspecialchars($url, ENT_QUOTES, 'UTF-8') . '" rel="stylesheet">';
}

function getLangBodyClass(): string
{
    return isRtl() ? 'lang-ar rtl' : 'lang-en ltr';
}

initLang();

function toArabicNumerals(string $str): string
{
    if (getLang() !== 'ar') return $str;
    return strtr($str, ['0'=>'٠','1'=>'١','2'=>'٢','3'=>'٣','4'=>'٤',
                         '5'=>'٥','6'=>'٦','7'=>'٧','8'=>'٨','9'=>'٩']);
}

function fromArabicNumerals(string $str): string
{
    return strtr($str, ['٠'=>'0','١'=>'1','٢'=>'2','٣'=>'3','٤'=>'4',
                         '٥'=>'5','٦'=>'6','٧'=>'7','٨'=>'8','٩'=>'9']);
}

/*
 * When Arabic is active, register an output-buffer callback that injects a
 * small script before </body> on every page.  The script converts Western
 * digits to Eastern-Arabic numerals in all text nodes (server-rendered and
 * dynamically added) and skips form controls so values stay submittable.
 */
if (getLang() === 'ar') {
    ob_start(function ($buffer) {
        $script = '<script>(function(){'
            . 'var m={"0":"٠","1":"١","2":"٢","3":"٣","4":"٤","5":"٥","6":"٦","7":"٧","8":"٨","9":"٩"};'
            . 'var skip={SCRIPT:1,STYLE:1,INPUT:1,TEXTAREA:1,SELECT:1,OPTION:1};'
            . 'function conv(n){'
            .   'if(n.nodeType===3){if(/\d/.test(n.nodeValue))n.nodeValue=n.nodeValue.replace(/\d/g,function(d){return m[d];});}'
            .   'else if(n.nodeType===1&&!skip[n.nodeName]){if(n.classList&&n.classList.contains("no-ar-numerals"))return;n.childNodes.forEach(conv);}'
            . '}'
            . 'function run(){'
            .   'conv(document.body);'
            .   'if(window.MutationObserver){'
            .     'new MutationObserver(function(ms){'
            .       'ms.forEach(function(mt){mt.addedNodes.forEach(conv);});'
            .     '}).observe(document.body,{childList:true,subtree:true});'
            .   '}'
            . '}'
            . 'document.readyState==="loading"?document.addEventListener("DOMContentLoaded",run):run();'
            . '})();</script>';
        $pos = strrpos((string) $buffer, '</body>');
        return $pos !== false
            ? substr((string) $buffer, 0, $pos) . $script . substr((string) $buffer, $pos)
            : $buffer;
    });
}
