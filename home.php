<?php
declare(strict_types=1);

/*
 * Start/resume session safely for consistent session availability.
 */
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

/*
 * Public home page driven by admin-managed site settings.
 */
require_once __DIR__ . '/db_connection.php';
require_once __DIR__ . '/site_settings.php';
require_once __DIR__ . '/service_categories.php';
require_once __DIR__ . '/lang.php';

ensureSiteSettingsTable($pdo);

$defaults = [
    'site_name' => 'Lebanese Maintenance Services',
    'site_tagline' => 'Trusted home services in one place',
    'hero_title' => 'Book skilled professionals for every home fix',
    'hero_subtitle' => 'Compare verified providers, pick a time, and track your request from one dashboard.',
    'primary_cta_text' => 'Get Started',
    'support_email' => 'support@example.com',
    'support_phone' => '+961 70 000 000',
    'facebook_url' => '',
    'instagram_url' => '',
    'linkedin_url' => '',
    'site_favicon' => '',
    'highlight_images' => '[]',
    'pinned_provider_id' => '0',
    'pinned_review_id' => '0',
    'feature_1_title' => 'Verified Providers',
    'feature_1_body' => 'Every provider is reviewed by our admin team before appearing to customers.',
    'feature_2_title' => 'Smart Scheduling',
    'feature_2_body' => 'Pick multiple slots and let providers confirm the time that works best.',
    'feature_3_title' => 'Transparent Pricing',
    'feature_3_body' => 'See estimated and final pricing in one place with no guesswork.',
    'footer_note' => 'Built for reliable home maintenance across Lebanon.',
    'site_name_ar'    => '',
    'site_tagline_ar' => '',
    'hero_title_ar'   => '',
    'hero_subtitle_ar'=> '',
    'primary_cta_text_ar' => '',
    'feature_1_title_ar' => '',
    'feature_1_body_ar'  => '',
    'feature_2_title_ar' => '',
    'feature_2_body_ar'  => '',
    'feature_3_title_ar' => '',
    'feature_3_body_ar'  => '',
    'footer_note_ar'     => '',
];

$settings = loadSiteSettings($pdo, $defaults);

/*
 * Pick Arabic variant for a setting key when Arabic is active, with lang-file fallback.
 * Priority: admin-set Arabic → lang-file Arabic translation → admin-set English value.
 */
function settingAr(array $settings, string $key): string {
    static $tKeyMap = [
        'site_name'         => 'site_name',
        'hero_title'        => 'home_hero_title',
        'hero_subtitle'     => 'home_hero_subtitle',
        'primary_cta_text'  => 'home_cta_start',
        'feature_1_title'   => 'home_feat1_title',
        'feature_1_body'    => 'home_feat1_body',
        'feature_2_title'   => 'home_feat2_title',
        'feature_2_body'    => 'home_feat2_body',
        'feature_3_title'   => 'home_feat3_title',
        'feature_3_body'    => 'home_feat3_body',
        'footer_note'       => 'home_footer_note',
    ];
    if (getLang() === 'ar') {
        $arVal = trim((string) ($settings[$key . '_ar'] ?? ''));
        if ($arVal !== '') return $arVal;
        if (isset($tKeyMap[$key])) {
            $tVal = t($tKeyMap[$key]);
            if ($tVal !== $tKeyMap[$key]) return $tVal;
        }
    }
    return (string) ($settings[$key] ?? '');
}

/*
 * Current site favicon used in browser tabs.
 */
$siteFavicon = trim((string) ($settings['site_favicon'] ?? ''));

try {
    $categories = ensureServiceCategories($pdo);
} catch (PDOException $exception) {
    $categories = [];
}

/*
 * Admin-chosen pinned provider and review IDs.
 */
$pinnedProviderId = max(0, (int) ($settings['pinned_provider_id'] ?? 0));
$pinnedReviewId   = max(0, (int) ($settings['pinned_review_id'] ?? 0));

/*
 * Fetch the admin-pinned provider row (if set) for a guaranteed first slide.
 */
$pinnedProviderSlide = null;
if ($pinnedProviderId > 0) {
    try {
        $pinnedProviderStmt = $pdo->prepare(
            'SELECT sp.provider_id,
                    sp.name,
                    sp.photo,
                    COALESCE(AVG(sr.rating), 0) AS average_rating,
                    COUNT(sr.rating) AS rating_count,
                    GROUP_CONCAT(DISTINCT sc.name ORDER BY sc.name SEPARATOR \', \') AS service_names
             FROM serviceprovider sp
             LEFT JOIN appointmentslot asl ON sp.provider_id = asl.serviceprovider_id
             LEFT JOIN servicerequest sr   ON sr.slot_id = asl.slot_id AND sr.rating IS NOT NULL
             LEFT JOIN providedservices ps ON sp.provider_id = ps.provider_id
             LEFT JOIN servicecategory sc  ON ps.category_id = sc.category_id
             WHERE sp.provider_id = :provider_id
             GROUP BY sp.provider_id, sp.name, sp.photo'
        );
        $pinnedProviderStmt->execute(['provider_id' => $pinnedProviderId]);
        $pinnedProviderRow = $pinnedProviderStmt->fetch(PDO::FETCH_ASSOC);
        if (is_array($pinnedProviderRow)) {
            $ppRatingCount = (int) ($pinnedProviderRow['rating_count'] ?? 0);
            $ppRating = $ppRatingCount > 0
                ? number_format((float) ($pinnedProviderRow['average_rating'] ?? 0), 1)
                : null;
            $pinnedProviderSlide = [
                'type'    => 'provider',
                'label'   => buildSlideLabel('provider'),
                'title'   => (string) ($pinnedProviderRow['name'] ?? 'Featured Provider'),
                'text'    => trim((string) ($pinnedProviderRow['service_names'] ?? '')) !== ''
                    ? (string) $pinnedProviderRow['service_names']
                    : 'Verified home services for every need.',
                'image'   => normalizeProviderPhotoPath((string) ($pinnedProviderRow['photo'] ?? '')),
                'meta'    => $ppRating !== null
                    ? ($ppRating . ' / 5 · ' . $ppRatingCount . ' reviews')
                    : 'Featured provider',
                'badge'   => 'Provider',
                'initials' => buildProviderInitials((string) ($pinnedProviderRow['name'] ?? '')),
            ];
        }
    } catch (PDOException $exception) {
        $pinnedProviderSlide = null;
    }
}

/*
 * Fetch the admin-pinned review row (if set) for a guaranteed first slide.
 */
$pinnedReviewSlide = null;
if ($pinnedReviewId > 0) {
    try {
        $pinnedReviewStmt = $pdo->prepare(
            'SELECT sr.review,
                    sr.rating,
                    COALESCE(c.name, \'Customer\') AS customer_name,
                    sp.name AS provider_name
             FROM servicerequest sr
             INNER JOIN appointmentslot asl ON sr.slot_id = asl.slot_id
             INNER JOIN serviceprovider sp  ON asl.serviceprovider_id = sp.provider_id
             LEFT  JOIN customer c          ON sr.customer_id = c.customer_id
             WHERE sr.request_id = :request_id AND sr.rating IS NOT NULL
             LIMIT 1'
        );
        $pinnedReviewStmt->execute(['request_id' => $pinnedReviewId]);
        $pinnedReviewRow = $pinnedReviewStmt->fetch(PDO::FETCH_ASSOC);
        if (is_array($pinnedReviewRow)) {
            $prText = trim((string) ($pinnedReviewRow['review'] ?? ''));
            if ($prText === '') {
                $prText = 'Customer rated the service highly.';
            }
            if (mb_strlen($prText) > 140) {
                $prText = mb_substr($prText, 0, 140) . '...';
            }
            $pinnedReviewSlide = [
                'type'     => 'review',
                'label'    => buildSlideLabel('review'),
                'title'    => (string) ($pinnedReviewRow['customer_name'] ?? 'Customer'),
                'text'     => $prText,
                'image'    => '',
                'meta'     => 'About ' . (string) ($pinnedReviewRow['provider_name'] ?? 'Our Provider')
                    . ' · ' . (int) ($pinnedReviewRow['rating'] ?? 5) . '/5',
                'badge'    => 'Review',
                'initials' => buildProviderInitials((string) ($pinnedReviewRow['customer_name'] ?? 'Customer')),
            ];
        }
    } catch (PDOException $exception) {
        $pinnedReviewSlide = null;
    }
}

/*
 * Decode and normalize admin-managed highlight images.
 */
$highlightImages = [];
$highlightImagesRaw = trim((string) ($settings['highlight_images'] ?? ''));
if ($highlightImagesRaw !== '') {
    $decodedImages = json_decode($highlightImagesRaw, true);
    if (is_array($decodedImages)) {
        foreach ($decodedImages as $imagePath) {
            if (!is_string($imagePath)) {
                continue;
            }
            $imagePath = trim($imagePath);
            if ($imagePath === '') {
                continue;
            }
            $highlightImages[] = $imagePath;
        }
    }
}

/*
 * Normalize provider photo paths and initials for the highlights reel.
 */
function normalizeProviderPhotoPath(string $photoPath): string
{
    $photoPath = trim($photoPath);
    if ($photoPath === '') {
        return '';
    }

    if (stripos($photoPath, 'uploads/') === 0 || stripos($photoPath, 'http') === 0) {
        return $photoPath;
    }

    return 'uploads/provider_photos/' . ltrim($photoPath, '/');
}

function normalizeHighlightImagePath(string $photoPath): string
{
    $photoPath = trim($photoPath);
    if ($photoPath === '') {
        return '';
    }

    if (stripos($photoPath, 'uploads/') === 0 || stripos($photoPath, 'http') === 0) {
        return $photoPath;
    }

    return 'uploads/highlight_photos/' . ltrim($photoPath, '/');
}

if (count($highlightImages) > 0) {
    $highlightImages = array_values(
        array_filter(
            array_map('normalizeHighlightImagePath', $highlightImages),
            static function (string $imagePath): bool {
                return $imagePath !== '';
            }
        )
    );
}

function buildProviderInitials(string $name): string
{
    $name = trim($name);
    if ($name === '') {
        return 'SP';
    }

    $parts = preg_split('/\s+/', $name);
    $initials = '';

    foreach ($parts as $part) {
        if ($part === '') {
            continue;
        }

        $initials .= strtoupper(mb_substr($part, 0, 1));
        if (mb_strlen($initials) >= 2) {
            break;
        }
    }

    return $initials !== '' ? $initials : 'SP';
}

function buildSlideLabel(string $type): string
{
    if ($type === 'image') {
        return 'Featured Image';
    }

    if ($type === 'provider') {
        return 'Service Provider';
    }

    return 'Customer Review';
}

/*
 * Build slideshow from admin-pinned provider, admin-pinned review, and highlight images only.
 */
$slideshowSlides = [];

if ($pinnedProviderSlide !== null) {
    $slideshowSlides[] = $pinnedProviderSlide;
}
if ($pinnedReviewSlide !== null) {
    $slideshowSlides[] = $pinnedReviewSlide;
}

foreach ($highlightImages as $index => $imagePath) {
    $slideshowSlides[] = [
        'type'  => 'image',
        'label' => buildSlideLabel('image'),
        'title' => 'Featured image ' . (string) ($index + 1),
        'text'  => 'Admin-managed highlight image.',
        'image' => $imagePath,
        'meta'  => '',
        'badge' => 'Gallery',
    ];
}

shuffle($slideshowSlides);

if (count($slideshowSlides) === 0) {
    $slideshowSlides = [
        [
            'type'  => 'image',
            'label' => buildSlideLabel('image'),
            'title' => 'Welcome',
            'text'  => 'Use the admin panel to feature a provider and a review here.',
            'image' => '',
            'meta'  => '',
            'badge' => 'Gallery',
        ],
    ];
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
    <title><?php echo htmlspecialchars(settingAr($settings, 'site_name'), ENT_QUOTES, 'UTF-8'); ?></title>
    <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=Manrope:wght@400;500;600;700&display=swap" rel="stylesheet">
    <?php if (isRtl()): ?>
    <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <?php endif; ?>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        /*
         * Home page layout tokens and base styles.
         */
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root {
            --ink: #0f172a;
            --muted: #475569;
            --brand: #0f766e;
            --brand-deep: #115e59;
            --accent: #f97316;
            --surface: #ffffff;
            --line: rgba(15, 23, 42, 0.08);
        }

        body {
            font-family: <?php echo isRtl() ? "'Cairo', sans-serif" : "'Manrope', sans-serif"; ?>;
            color: var(--ink);
            min-height: 100vh;
            background:
                radial-gradient(circle at 10% 10%, rgba(14, 165, 233, 0.18), transparent 38%),
                radial-gradient(circle at 85% 15%, rgba(249, 115, 22, 0.2), transparent 40%),
                linear-gradient(135deg, #f8fafc, #ecfeff 45%, #fff7ed);
            padding: 24px 16px 40px;
        }

        @keyframes fadeSlideUp {
            from { opacity: 0; transform: translateY(22px); }
            to   { opacity: 1; transform: translateY(0); }
        }

        header,
        .hero,
        .feature-grid,
        .category-panel {
            animation: fadeSlideUp 0.5s cubic-bezier(0.22, 1, 0.36, 1) both;
        }

        .feature-grid { animation-delay: 0.08s; }
        .category-panel { animation-delay: 0.14s; }

        .shell {
            max-width: 1200px;
            margin: 0 auto;
            display: flex;
            flex-direction: column;
            gap: 24px;
        }

        header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            flex-wrap: wrap;
        }

        .logo {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .logo-mark {
            width: 48px;
            height: 48px;
            border-radius: 14px;
            background: linear-gradient(140deg, var(--brand), var(--brand-deep));
            display: flex;
            align-items: center;
            justify-content: center;
            color: #fff;
            font-weight: 700;
            font-family: 'Space Grotesk', sans-serif;
            box-shadow: 0 12px 24px rgba(15, 118, 110, 0.2);
        }

        .logo-text h1 {
            font-family: 'Space Grotesk', sans-serif;
            font-size: 1.5rem;
            margin-bottom: 4px;
        }

        .logo-text span {
            font-size: 0.9rem;
            color: var(--muted);
        }

        .header-actions {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }

        .btn {
            padding: 10px 16px;
            border-radius: 999px;
            font-weight: 700;
            text-decoration: none;
            border: 1px solid var(--line);
            color: var(--ink);
            background: var(--surface);
            transition: transform 0.2s ease, box-shadow 0.2s ease;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }

        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 18px rgba(15, 23, 42, 0.1);
        }

        .btn.primary {
            background: linear-gradient(140deg, var(--brand), var(--brand-deep));
            color: #fff;
            border: none;
        }

        .btn.primary:hover {
            box-shadow: 0 10px 24px rgba(15, 118, 110, 0.35);
        }

        .hero {
            display: grid;
            grid-template-columns: minmax(0, 1.1fr) minmax(0, 0.9fr);
            gap: 20px;
            align-items: center;
        }

        .hero-card {
            background: rgba(255, 255, 255, 0.9);
            border-radius: 24px;
            padding: 24px;
            box-shadow: 0 18px 40px rgba(15, 23, 42, 0.1);
            border: 1px solid rgba(255, 255, 255, 0.8);
        }

        .hero-card h2 {
            font-family: 'Space Grotesk', sans-serif;
            font-size: 2.2rem;
            margin-bottom: 12px;
        }

        .hero-card p {
            color: var(--muted);
            font-size: 1rem;
            line-height: 1.6;
            margin-bottom: 18px;
        }

        .hero-actions {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }

        .hero-cta {
            padding: 12px 22px;
            border-radius: 14px;
            border: none;
            background: linear-gradient(140deg, var(--brand), var(--brand-deep));
            color: #fff;
            font-weight: 700;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }

        .hero-cta:hover {
            transform: translateY(-3px);
            box-shadow: 0 14px 30px rgba(15, 118, 110, 0.38);
        }

        .hero-secondary {
            padding: 12px 22px;
            border-radius: 14px;
            border: 1px solid var(--line);
            color: var(--ink);
            text-decoration: none;
            background: #fff;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }

        .hero-secondary:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(15, 23, 42, 0.1);
        }

        .feature-grid {
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: 16px;
        }

        /* When nested inside .hero right column, stack cards vertically */
        .hero .feature-grid {
            grid-template-columns: 1fr;
        }

        .feature-card {
            background: #fff;
            border-radius: 18px;
            padding: 20px;
            border: 1px solid var(--line);
            box-shadow: 0 12px 28px rgba(15, 23, 42, 0.08);
            transition: transform 0.22s ease, box-shadow 0.22s ease;
        }

        .feature-card:hover {
            transform: translateY(-4px);
            box-shadow: 0 20px 40px rgba(15, 23, 42, 0.13);
        }

        .feature-icon {
            width: 44px;
            height: 44px;
            border-radius: 12px;
            background: linear-gradient(140deg, rgba(15, 118, 110, 0.12), rgba(15, 118, 110, 0.06));
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--brand);
            font-size: 1.1rem;
            margin-bottom: 12px;
        }

        .feature-card h3 {
            font-family: 'Space Grotesk', sans-serif;
            font-size: 1.05rem;
            margin-bottom: 8px;
        }

        .feature-card p {
            color: var(--muted);
            font-size: 0.92rem;
            line-height: 1.5;
        }

        .category-panel {
            background: rgba(255, 255, 255, 0.92);
            border-radius: 22px;
            padding: 20px;
            border: 1px solid rgba(255, 255, 255, 0.85);
            box-shadow: 0 16px 34px rgba(15, 23, 42, 0.09);
        }

        .category-panel h3 {
            font-family: 'Space Grotesk', sans-serif;
            font-size: 1.2rem;
            margin-bottom: 12px;
        }

        .category-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 12px;
        }

        .category-card {
            border: 1px solid var(--line);
            border-radius: 14px;
            padding: 14px;
            background: #fff;
            transition: transform 0.2s ease, box-shadow 0.2s ease, border-color 0.2s ease;
            cursor: pointer;
            text-decoration: none;
            display: block;
            color: inherit;
        }

        .category-card:hover {
            transform: translateY(-3px);
            box-shadow: 0 12px 26px rgba(15, 23, 42, 0.1);
            border-color: var(--brand);
            background: linear-gradient(135deg, #f0fdfa, #fff);
        }

        .category-card h4 {
            font-size: 0.95rem;
            margin-bottom: 6px;
            color: var(--ink);
        }

        .category-card p {
            font-size: 0.85rem;
            color: var(--muted);
            line-height: 1.4;
        }

        .category-card .cat-cta {
            display: inline-flex;
            align-items: center;
            gap: 4px;
            margin-top: 8px;
            font-size: 0.78rem;
            font-weight: 700;
            color: var(--brand);
            opacity: 0;
            transform: translateY(4px);
            transition: opacity 0.2s ease, transform 0.2s ease;
        }

        .category-card:hover .cat-cta {
            opacity: 1;
            transform: translateY(0);
        }

        /*
         * Highlight slideshow at the top of the home page.
         */
        .highlight-showcase {
            display: grid;
            gap: 12px;
        }

        .showcase-slider {
            position: relative;
            height: 400px;
            border-radius: 26px;
            overflow: hidden;
            background: #0f172a;
            box-shadow: 0 18px 40px rgba(15, 23, 42, 0.18);
        }

        .showcase-slide {
            position: absolute;
            inset: 0;
            opacity: 0;
            transform: translateY(8px) scale(1.01);
            transition: opacity 0.6s ease, transform 0.6s ease;
            display: grid;
            background: linear-gradient(140deg, rgba(15, 23, 42, 0.94), rgba(15, 118, 110, 0.92));
        }

        .showcase-slide.is-active {
            opacity: 1;
            transform: translateY(0) scale(1);
            z-index: 1;
        }

        .slide-stage {
            width: 100%;
            height: 100%;
            display: grid;
            place-items: stretch;
            overflow: hidden;
        }

        .slide-card {
            width: 100%;
            height: 100%;
            padding: 28px;
            color: #fff;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .slide-image-card {
            position: relative;
            display: flex;
            align-items: stretch;
            padding: 0;
            width: 100%;
            height: 100%;
        }

        .slide-grid {
            width: 100%;
            height: 100%;
            display: grid;
            place-items: center;
            gap: 14px;
            text-align: center;
        }

        .slide-tag {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 8px 14px;
            border-radius: 999px;
            border: 1px solid rgba(255, 255, 255, 0.2);
            background: rgba(255, 255, 255, 0.1);
            font-size: 0.78rem;
            letter-spacing: 0.3px;
            text-transform: uppercase;
        }

        .slide-icon img {
            width: 100%;
            height: 100%;
            object-fit: cover;
            display: block;
        }

        .slide-image-card .slide-media {
            width: 100%;
            height: 100%;
            object-fit: cover;
            object-position: center;
            display: block;
            flex: 1;
            min-width: 0;
            min-height: 0;
        }

        .slide-avatar,
        .slide-icon {
            width: 76px;
            height: 76px;
            border-radius: 22px;
            display: grid;
            place-items: center;
            overflow: hidden;
            box-shadow: 0 14px 28px rgba(15, 23, 42, 0.2);
        }

        .slide-avatar {
            background: linear-gradient(140deg, rgba(249, 115, 22, 0.9), rgba(15, 118, 110, 0.9));
            color: #fff;
            font-family: 'Space Grotesk', sans-serif;
            font-size: 1.15rem;
            font-weight: 700;
        }

        .slide-avatar img {
            width: 100%;
            height: 100%;
            object-fit: cover;
            object-position: center top;
            display: block;
            border-radius: 22px;
        }

        .slide-avatar i {
            font-size: 2rem;
            opacity: 0.95;
        }

        .slide-name {
            font-family: 'Space Grotesk', sans-serif;
            font-size: 2rem;
            line-height: 1.1;
        }

        .slide-copy {
            max-width: 42rem;
            color: rgba(255, 255, 255, 0.9);
            font-size: 0.98rem;
            line-height: 1.6;
        }

        .slide-quote {
            max-width: 48rem;
            font-size: 1.2rem;
            line-height: 1.55;
            font-style: italic;
        }

        .slide-meta-line {
            font-size: 0.84rem;
            color: rgba(255, 255, 255, 0.76);
        }

        .showcase-controls {
            display: flex;
            justify-content: center;
            gap: 8px;
        }

        .showcase-dot {
            width: 10px;
            height: 10px;
            border-radius: 999px;
            border: none;
            background: rgba(15, 23, 42, 0.2);
            cursor: pointer;
            transition: transform 0.2s ease, background 0.2s ease;
        }

        .showcase-dot.is-active {
            background: var(--accent);
            transform: scale(1.2);
        }

        /*
         * Footer layout with social links.
         */
        footer {
            text-align: center;
            color: var(--muted);
            font-size: 0.86rem;
            margin-top: 12px;
            display: grid;
            gap: 8px;
        }

        .footer-row {
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            justify-content: center;
            gap: 14px;
        }

        .social-links {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
        }

        .social-link {
            width: 36px;
            height: 36px;
            border-radius: 12px;
            border: 1px solid var(--line);
            background: #ffffff;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            color: #0f172a;
            text-decoration: none;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }

        .social-link:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 18px rgba(15, 23, 42, 0.12);
            border-color: var(--brand);
            color: var(--brand);
        }

        .footer-divider {
            height: 1px;
            background: var(--line);
            margin: 4px 0;
        }

        @media (max-width: 900px) {
            .hero {
                grid-template-columns: 1fr;
            }

            .feature-grid {
                grid-template-columns: repeat(3, minmax(0, 1fr));
            }

            .showcase-slider {
                height: 300px;
            }

            .slide-card {
                padding: 20px;
            }

            .slide-name {
                font-size: 1.6rem;
            }

            .slide-quote {
                font-size: 1.05rem;
            }
        }

        @media (max-width: 600px) {
            .shell {
                padding: 10px 10px 24px;
                gap: 16px;
            }

            .header {
                padding: 12px 14px;
                border-radius: 16px;
            }

            .header-brand h1 {
                font-size: 1.1rem;
            }

            .header-nav {
                gap: 6px;
            }

            .hero-content {
                padding: 24px 16px;
            }

            .hero-title {
                font-size: 1.9rem;
            }

            .hero-subtitle {
                font-size: 0.93rem;
            }

            .hero-actions {
                flex-direction: column;
                align-items: stretch;
            }

            .hero-actions .btn {
                width: 100%;
                justify-content: center;
            }

            .feature-grid {
                grid-template-columns: 1fr;
            }

            .category-panel {
                padding: 16px;
                border-radius: 16px;
            }

            .category-grid {
                grid-template-columns: repeat(2, 1fr);
            }

            .review-card {
                padding: 16px;
            }

            .footer-grid {
                grid-template-columns: 1fr;
                gap: 14px;
            }

            .showcase-slider {
                height: 220px;
            }

            .slide-name {
                font-size: 1.35rem;
            }
        }

        @media (max-width: 380px) {
            .showcase-slider {
                height: 180px;
            }

            .slide-name {
                font-size: 1.15rem;
            }

            .slide-quote {
                font-size: 0.88rem;
            }

            .category-grid {
                grid-template-columns: 1fr;
            }

            .hero-title {
                font-size: 1.65rem;
            }

            .header-brand h1 {
                font-size: 1rem;
            }
        }

        @media (prefers-reduced-motion: reduce) {
            .showcase-slide {
                transition: none;
            }

            .showcase-dot {
                transition: none;
            }
        }

        /* RTL overrides */
        [dir="rtl"] .header-actions { flex-direction: row-reverse; }
        [dir="rtl"] .hero-actions   { flex-direction: row-reverse; }
        [dir="rtl"] .logo           { flex-direction: row-reverse; }
        [dir="rtl"] .feature-icon   { margin-left: auto; margin-right: 0; }
        [dir="rtl"] .btn i, [dir="rtl"] .hero-cta i, [dir="rtl"] .hero-secondary i { transform: scaleX(-1); }
        [dir="rtl"] .lang-btn i     { transform: none; }
    </style>
</head>
<body class="<?php echo htmlspecialchars(getLangBodyClass(), ENT_QUOTES, 'UTF-8'); ?>">
    <!-- Main page shell -->
    <div class="shell">
        <header>
            <div class="logo">
                <div class="logo-mark">LM</div>
                <div class="logo-text">
                    <h1><?php echo htmlspecialchars(settingAr($settings, 'site_name'), ENT_QUOTES, 'UTF-8'); ?></h1>
                    <span><?php echo htmlspecialchars(settingAr($settings, 'site_tagline'), ENT_QUOTES, 'UTF-8'); ?></span>
                </div>
            </div>
            <div class="header-actions">
                <a class="btn" href="<?php echo htmlspecialchars(langSwitchUrl(), ENT_QUOTES, 'UTF-8'); ?>" style="gap:6px;">
                    <i class="fa-solid fa-globe"></i><?php echo htmlspecialchars(t('lang_switch_label'), ENT_QUOTES, 'UTF-8'); ?>
                </a>
                <a class="btn" href="<?php echo htmlspecialchars(langUrl('login.php'), ENT_QUOTES, 'UTF-8'); ?>"><?php echo htmlspecialchars(t('nav_login'), ENT_QUOTES, 'UTF-8'); ?></a>
                <a class="btn primary" href="<?php echo htmlspecialchars(langUrl('register.php'), ENT_QUOTES, 'UTF-8'); ?>"><?php echo htmlspecialchars(t('home_cta_start'), ENT_QUOTES, 'UTF-8'); ?></a>
            </div>
        </header>

        <!-- Highlight slideshow featuring admin images, top ratings, and latest reviews -->
        <section class="highlight-showcase" aria-label="Highlights slideshow">
            <div class="showcase-slider" data-slide-count="<?php echo count($slideshowSlides); ?>">
                <?php foreach ($slideshowSlides as $index => $slide): ?>
                    <article class="showcase-slide <?php echo $index === 0 ? 'is-active' : ''; ?>" data-slide-index="<?php echo (int) $index; ?>">
                        <div class="slide-stage">
                            <?php if ($slide['type'] === 'image'): ?>
                                <div class="slide-card slide-image-card">
                                    <?php if ($slide['image'] !== ''): ?>
                                        <img class="slide-media" src="<?php echo htmlspecialchars($slide['image'], ENT_QUOTES, 'UTF-8'); ?>" alt="<?php echo htmlspecialchars($slide['title'], ENT_QUOTES, 'UTF-8'); ?>">
                                    <?php else: ?>
                                        <div class="slide-grid">
                                            <span class="slide-tag"><i class="fas fa-image" aria-hidden="true"></i> <?php echo htmlspecialchars($slide['label'], ENT_QUOTES, 'UTF-8'); ?></span>
                                            <h3 class="slide-name"><?php echo htmlspecialchars($slide['title'], ENT_QUOTES, 'UTF-8'); ?></h3>
                                            <p class="slide-copy"><?php echo htmlspecialchars($slide['text'], ENT_QUOTES, 'UTF-8'); ?></p>
                                        </div>
                                    <?php endif; ?>
                                </div>
                            <?php elseif ($slide['type'] === 'provider'): ?>
                                <div class="slide-card">
                                    <div class="slide-grid">
                                        <span class="slide-tag"><i class="fas fa-star" aria-hidden="true"></i> <?php echo htmlspecialchars($slide['badge'], ENT_QUOTES, 'UTF-8'); ?></span>
                                        <div class="slide-avatar">
                                            <?php if (!empty($slide['image'])): ?>
                                                <img src="<?php echo htmlspecialchars($slide['image'], ENT_QUOTES, 'UTF-8'); ?>" alt="<?php echo htmlspecialchars($slide['title'], ENT_QUOTES, 'UTF-8'); ?>">
                                            <?php else: ?>
                                                <?php echo htmlspecialchars((string) ($slide['initials'] ?? 'SP'), ENT_QUOTES, 'UTF-8'); ?>
                                            <?php endif; ?>
                                        </div>
                                        <h3 class="slide-name"><?php echo htmlspecialchars($slide['title'], ENT_QUOTES, 'UTF-8'); ?></h3>
                                        <p class="slide-copy"><?php echo htmlspecialchars($slide['text'], ENT_QUOTES, 'UTF-8'); ?></p>
                                        <p class="slide-meta-line"><?php echo htmlspecialchars($slide['meta'], ENT_QUOTES, 'UTF-8'); ?></p>
                                    </div>
                                </div>
                            <?php else: ?>
                                <div class="slide-card">
                                    <div class="slide-grid">
                                        <span class="slide-tag"><i class="fas fa-quote-left" aria-hidden="true"></i> <?php echo htmlspecialchars($slide['badge'], ENT_QUOTES, 'UTF-8'); ?></span>
                                        <div class="slide-avatar">
                                            <?php if (!empty($slide['image'])): ?>
                                                <img src="<?php echo htmlspecialchars($slide['image'], ENT_QUOTES, 'UTF-8'); ?>" alt="<?php echo htmlspecialchars($slide['title'], ENT_QUOTES, 'UTF-8'); ?>">
                                            <?php else: ?>
                                                <?php echo htmlspecialchars((string) ($slide['initials'] ?? 'C'), ENT_QUOTES, 'UTF-8'); ?>
                                            <?php endif; ?>
                                        </div>
                                        <h3 class="slide-name"><?php echo htmlspecialchars($slide['title'], ENT_QUOTES, 'UTF-8'); ?></h3>
                                        <p class="slide-quote">&ldquo;<?php echo htmlspecialchars($slide['text'], ENT_QUOTES, 'UTF-8'); ?>&rdquo;</p>
                                        <p class="slide-meta-line"><?php echo htmlspecialchars($slide['meta'], ENT_QUOTES, 'UTF-8'); ?></p>
                                    </div>
                                </div>
                            <?php endif; ?>
                        </div>
                    </article>
                <?php endforeach; ?>
            </div>
            <div class="showcase-controls" role="tablist" aria-label="Slide controls">
                <?php foreach ($slideshowSlides as $index => $slide): ?>
                    <button
                        type="button"
                        class="showcase-dot <?php echo $index === 0 ? 'is-active' : ''; ?>"
                        data-slide-target="<?php echo (int) $index; ?>"
                        aria-label="Show slide <?php echo (int) ($index + 1); ?>"
                    ></button>
                <?php endforeach; ?>
            </div>
        </section>

        <section class="hero">
            <div class="hero-card">
                <h2><?php echo htmlspecialchars(settingAr($settings, 'hero_title'), ENT_QUOTES, 'UTF-8'); ?></h2>
                <p><?php echo htmlspecialchars(settingAr($settings, 'hero_subtitle'), ENT_QUOTES, 'UTF-8'); ?></p>
                <div class="hero-actions">
                    <a class="hero-cta" href="<?php echo htmlspecialchars(langUrl('register.php'), ENT_QUOTES, 'UTF-8'); ?>"><i class="fas fa-arrow-right" aria-hidden="true"></i><?php echo htmlspecialchars(settingAr($settings, 'primary_cta_text'), ENT_QUOTES, 'UTF-8'); ?></a>
                    <a class="hero-secondary" href="<?php echo htmlspecialchars(langUrl('login.php'), ENT_QUOTES, 'UTF-8'); ?>"><i class="fas fa-sign-in-alt" aria-hidden="true"></i><?php echo htmlspecialchars(t('home_cta_login'), ENT_QUOTES, 'UTF-8'); ?></a>
                </div>
            </div>
            <div class="feature-grid">
                <article class="feature-card">
                    <div class="feature-icon" aria-hidden="true"><i class="fas fa-shield-halved"></i></div>
                    <h3><?php echo htmlspecialchars(settingAr($settings, 'feature_1_title'), ENT_QUOTES, 'UTF-8'); ?></h3>
                    <p><?php echo htmlspecialchars(settingAr($settings, 'feature_1_body'), ENT_QUOTES, 'UTF-8'); ?></p>
                </article>
                <article class="feature-card">
                    <div class="feature-icon" aria-hidden="true"><i class="fas fa-calendar-check"></i></div>
                    <h3><?php echo htmlspecialchars(settingAr($settings, 'feature_2_title'), ENT_QUOTES, 'UTF-8'); ?></h3>
                    <p><?php echo htmlspecialchars(settingAr($settings, 'feature_2_body'), ENT_QUOTES, 'UTF-8'); ?></p>
                </article>
                <article class="feature-card">
                    <div class="feature-icon" aria-hidden="true"><i class="fas fa-tag"></i></div>
                    <h3><?php echo htmlspecialchars(settingAr($settings, 'feature_3_title'), ENT_QUOTES, 'UTF-8'); ?></h3>
                    <p><?php echo htmlspecialchars(settingAr($settings, 'feature_3_body'), ENT_QUOTES, 'UTF-8'); ?></p>
                </article>
            </div>
        </section>

        <section class="category-panel">
            <h3><?php echo htmlspecialchars(t('home_categories_title'), ENT_QUOTES, 'UTF-8'); ?></h3>
            <div class="category-grid">
                <?php if (count($categories) === 0): ?>
                    <p><?php echo htmlspecialchars(t('lbl_no_results'), ENT_QUOTES, 'UTF-8'); ?></p>
                <?php else: ?>
                    <?php foreach ($categories as $category): ?>
                        <a class="category-card" href="<?php echo htmlspecialchars(langUrl('register.php'), ENT_QUOTES, 'UTF-8'); ?>">
                            <h4><?php echo htmlspecialchars(tCategory($category, 'name'), ENT_QUOTES, 'UTF-8'); ?></h4>
                            <p><?php echo htmlspecialchars(tCategory($category, 'description') !== '' ? tCategory($category, 'description') : t('home_category_no_desc'), ENT_QUOTES, 'UTF-8'); ?></p>
                            <span class="cat-cta"><i class="fas fa-arrow-right" aria-hidden="true"></i> <?php echo htmlspecialchars(t('home_cta_start'), ENT_QUOTES, 'UTF-8'); ?></span>
                        </a>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>
        </section>

        <footer>
            <div class="footer-row">
                <div><?php echo htmlspecialchars(t('home_support_label'), ENT_QUOTES, 'UTF-8'); ?>: <span class="no-ar-numerals" dir="ltr"><?php echo htmlspecialchars($settings['support_email'], ENT_QUOTES, 'UTF-8'); ?></span> | <span dir="ltr" style="unicode-bidi: isolate-override;"><?php echo htmlspecialchars($settings['support_phone'], ENT_QUOTES, 'UTF-8'); ?></span></div>
                <?php if ($settings['facebook_url'] !== '' || $settings['instagram_url'] !== '' || $settings['linkedin_url'] !== ''): ?>
                    <div class="social-links" aria-label="Social media">
                        <?php if ($settings['facebook_url'] !== ''): ?>
                            <a class="social-link" href="<?php echo htmlspecialchars($settings['facebook_url'], ENT_QUOTES, 'UTF-8'); ?>" target="_blank" rel="noopener" aria-label="Facebook">
                                <i class="fab fa-facebook-f" aria-hidden="true"></i>
                            </a>
                        <?php endif; ?>
                        <?php if ($settings['instagram_url'] !== ''): ?>
                            <a class="social-link" href="<?php echo htmlspecialchars($settings['instagram_url'], ENT_QUOTES, 'UTF-8'); ?>" target="_blank" rel="noopener" aria-label="Instagram">
                                <i class="fab fa-instagram" aria-hidden="true"></i>
                            </a>
                        <?php endif; ?>
                        <?php if ($settings['linkedin_url'] !== ''): ?>
                            <a class="social-link" href="<?php echo htmlspecialchars($settings['linkedin_url'], ENT_QUOTES, 'UTF-8'); ?>" target="_blank" rel="noopener" aria-label="LinkedIn">
                                <i class="fab fa-linkedin-in" aria-hidden="true"></i>
                            </a>
                        <?php endif; ?>
                    </div>
                <?php endif; ?>
            </div>
            <div><?php echo htmlspecialchars(settingAr($settings, 'footer_note'), ENT_QUOTES, 'UTF-8'); ?></div>
        </footer>
    </div>

    <script>
        /*
         * Auto-rotate the highlight slideshow with manual controls.
         */
        (function () {
            var slider = document.querySelector('.showcase-slider');
            var slides = Array.prototype.slice.call(document.querySelectorAll('.showcase-slide'));
            var dots = Array.prototype.slice.call(document.querySelectorAll('.showcase-dot'));
            var prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
            var currentIndex = 0;
            var rotationMs = 6000;
            var rotationTimer = null;

            if (!slider || slides.length === 0) {
                return;
            }

            function setActive(index) {
                slides.forEach(function (slide, slideIndex) {
                    slide.classList.toggle('is-active', slideIndex === index);
                });
                dots.forEach(function (dot, dotIndex) {
                    dot.classList.toggle('is-active', dotIndex === index);
                });
            }

            function goTo(index) {
                currentIndex = (index + slides.length) % slides.length;
                setActive(currentIndex);
            }

            function startRotation() {
                if (rotationTimer) {
                    window.clearInterval(rotationTimer);
                }

                var intervalMs = prefersReducedMotion ? 9000 : rotationMs;
                rotationTimer = window.setInterval(function () {
                    goTo(currentIndex + 1);
                }, intervalMs);
            }

            dots.forEach(function (dot) {
                dot.addEventListener('click', function () {
                    var targetIndex = parseInt(dot.getAttribute('data-slide-target') || '0', 10);
                    goTo(targetIndex);
                    startRotation();
                });
            });

            startRotation();
        })();
    </script>

</body>
</html>
