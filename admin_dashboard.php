<?php
declare(strict_types=1);

/*
 * Start/resume session for admin-only access enforcement.
 */
session_start();

/*
 * Shared PDO connection for admin read/write operations.
 */
require_once __DIR__ . '/db_connection.php';

/*
 * JSON-backed verification store for admin-controlled provider status.
 */
require_once __DIR__ . '/verification_store.php';

/*
 * JSON-backed suspension store for admin-controlled account status.
 */
require_once __DIR__ . '/suspension_store.php';

/*
 * Service category helpers for admin management.
 */
require_once __DIR__ . '/service_categories.php';

/*
 * Site settings helpers for admin-managed home page content.
 */
require_once __DIR__ . '/site_settings.php';
require_once __DIR__ . '/admin_chat_store.php';
require_once __DIR__ . '/lang.php';

// Compute absolute base path before any redirect so guards work under clean URLs too.
$appBase = rtrim(str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'])), '/');

/*
 * Restrict this page to authenticated admin sessions.
 */
if (!isset($_SESSION['user_type']) || (string) $_SESSION['user_type'] !== 'admin') {
    header('Location: ' . $appBase . '/login.php');
    exit;
}

/*
 * Admin identity details used in the header.
 */
$adminEmail = (string) ($_SESSION['user_email'] ?? '');

/*
 * CSRF token dedicated to admin actions on this dashboard.
 */
if (!isset($_SESSION['admin_dashboard_csrf']) || !is_string($_SESSION['admin_dashboard_csrf'])) {
    $_SESSION['admin_dashboard_csrf'] = bin2hex(random_bytes(32));
}

if (!isset($_SESSION['admin_chat_csrf']) || !is_string($_SESSION['admin_chat_csrf'])) {
    $_SESSION['admin_chat_csrf'] = bin2hex(random_bytes(32));
}

ensureAdminChatTable($pdo);
$adminChatUnread = countAdminUnreadFromUsers($pdo);

/*
 * View-state status messages.
 */
$errorMessage = '';
$successMessage = '';

/*
 * Flash success message for PRG redirects.
 */
if (isset($_SESSION['admin_dashboard_flash_success']) && is_string($_SESSION['admin_dashboard_flash_success'])) {
    $successMessage = $_SESSION['admin_dashboard_flash_success'];
    unset($_SESSION['admin_dashboard_flash_success']);
}

/*
 * Load persisted provider verification state from JSON.
 */
$verifiedProviderIds = loadVerifiedProviderIds();
$verifiedProviderLookup = buildVerifiedProviderLookup($verifiedProviderIds);

/*
 * Load persisted suspension state for providers and customers.
 */
$suspendedAccountIds = loadSuspendedAccountIds();
$suspendedProviderLookup = buildSuspendedLookup((array) ($suspendedAccountIds['providers'] ?? []));
$suspendedCustomerLookup = buildSuspendedLookup((array) ($suspendedAccountIds['customers'] ?? []));

/*
 * Read toolbar filters for provider and customer sections.
 */
$providerSearchQuery = trim((string) ($_GET['provider_q'] ?? ''));
$providerVerificationFilter = strtolower(trim((string) ($_GET['provider_verification'] ?? 'all')));
if (!in_array($providerVerificationFilter, ['all', 'verified', 'unverified'], true)) {
    $providerVerificationFilter = 'all';
}

$providerStatusFilter = strtolower(trim((string) ($_GET['provider_status'] ?? 'all')));
if (!in_array($providerStatusFilter, ['all', 'active', 'suspended'], true)) {
    $providerStatusFilter = 'all';
}

$customerSearchQuery = trim((string) ($_GET['customer_q'] ?? ''));
$customerStatusFilter = strtolower(trim((string) ($_GET['customer_status'] ?? 'all')));
if (!in_array($customerStatusFilter, ['all', 'active', 'suspended'], true)) {
    $customerStatusFilter = 'all';
}

/*
 * Build reset links that preserve the other panel's filters.
 */
$providerResetQuery = http_build_query([
    'customer_q' => $customerSearchQuery,
    'customer_status' => $customerStatusFilter,
]);
$customerResetQuery = http_build_query([
    'provider_q' => $providerSearchQuery,
    'provider_status' => $providerStatusFilter,
    'provider_verification' => $providerVerificationFilter,
]);

/*
 * Admin-managed site settings used by the public home page.
 */
$siteSettingsDefaults = [
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
    'admin_password_hash' => '',
];

/*
 * Upload policy for admin-managed highlight images on the home page.
 */
const HIGHLIGHT_IMAGE_UPLOAD_DIRECTORY = __DIR__ . '/uploads/highlight_photos';
const HIGHLIGHT_IMAGE_UPLOAD_WEB_PATH = 'uploads/highlight_photos';
const HIGHLIGHT_IMAGE_MAX_BYTES = 2_097_152; // 2 MB
const HIGHLIGHT_IMAGE_MAX_COUNT = 8;

/*
 * Upload policy for the site favicon (browser tab icon).
 */
const SITE_FAVICON_UPLOAD_DIRECTORY = __DIR__ . '/uploads/site_assets';
const SITE_FAVICON_UPLOAD_WEB_PATH = 'uploads/site_assets';
const SITE_FAVICON_MAX_BYTES = 1_048_576; // 1 MB

$siteSettings = $siteSettingsDefaults;
try {
    ensureSiteSettingsTable($pdo);
    $siteSettings = loadSiteSettings($pdo, $siteSettingsDefaults);
} catch (PDOException $exception) {
    if ($errorMessage === '') {
        $errorMessage = 'Unable to load site settings right now. Please try again.';
    }
}

/*
 * Current site favicon path for browser tab icon.
 */
$siteFavicon = trim((string) ($siteSettings['site_favicon'] ?? ''));

/*
 * Current highlight image list used by the home page reel.
 */
$highlightImageList = normalizeHighlightImageList((string) ($siteSettings['highlight_images'] ?? ''));

/*
 * Load service categories for admin management.
 */
$serviceCategories = [];
try {
    $serviceCategories = ensureServiceCategories($pdo);
} catch (PDOException $exception) {
    $serviceCategories = [];
}

/*
 * All service providers available to pin on the home page.
 */
$allProviders = [];
try {
    $allProvidersStatement = $pdo->query(
        'SELECT provider_id, name FROM serviceprovider ORDER BY name ASC'
    );
    $allProviders = $allProvidersStatement ? $allProvidersStatement->fetchAll(PDO::FETCH_ASSOC) : [];
} catch (PDOException $exception) {
    $allProviders = [];
}

/*
 * All rated reviews available to pin on the home page.
 */
$allReviews = [];
try {
    $allReviewsStatement = $pdo->query(
        'SELECT sr.request_id,
                sr.rating,
                sr.review,
                COALESCE(c.name, \'Customer\') AS customer_name,
                sp.name AS provider_name
         FROM servicerequest sr
         INNER JOIN appointmentslot asl ON sr.slot_id = asl.slot_id
         INNER JOIN serviceprovider sp  ON asl.serviceprovider_id = sp.provider_id
         LEFT  JOIN customer c          ON sr.customer_id = c.customer_id
         WHERE sr.rating IS NOT NULL
         ORDER BY sr.request_id DESC'
    );
    $allReviews = $allReviewsStatement ? $allReviewsStatement->fetchAll(PDO::FETCH_ASSOC) : [];
} catch (PDOException $exception) {
    $allReviews = [];
}

$pinnedProviderId = (int) ($siteSettings['pinned_provider_id'] ?? 0);
$pinnedReviewId   = (int) ($siteSettings['pinned_review_id'] ?? 0);

/*
 * Load all service request interactions for the admin interactions panel.
 */
$allInteractions = [];
try {
    $interactionsStmt = $pdo->query(
        'SELECT
             sr.request_id,
             sr.status,
             sr.rating,
             sr.review,
             sr.estimated_price,
             sr.final_price,
             sr.image1,
             sr.image2,
             sr.image3,
             c.customer_id,
             COALESCE(c.name,  \'Unknown Customer\') AS customer_name,
             COALESCE(c.email, \'\')                 AS customer_email,
             COALESCE(c.phone, \'\')                 AS customer_phone,
             sp.provider_id,
             COALESCE(sp.name,  \'Unknown Provider\') AS provider_name,
             COALESCE(sp.email, \'\')                 AS provider_email,
             COALESCE(sp.phone, \'\')                 AS provider_phone,
             COALESCE(sc.name,  \'General Service\')  AS category_name,
             IFNULL(sc.name_ar, \'\')               AS category_name_ar,
             asl.date                                AS appointment_date,
             asl.slot                                AS appointment_time,
             (SELECT COUNT(*)
              FROM request_chat_message rcm
              WHERE rcm.request_id = sr.request_id) AS message_count
         FROM servicerequest sr
         LEFT JOIN appointmentslot asl ON sr.slot_id          = asl.slot_id
         LEFT JOIN serviceprovider sp  ON asl.serviceprovider_id = sp.provider_id
         LEFT JOIN customer c          ON sr.customer_id       = c.customer_id
         LEFT JOIN servicecategory sc  ON sr.category_id       = sc.category_id
         ORDER BY sr.request_id DESC
         LIMIT 500'
    );
    if ($interactionsStmt !== false) {
        while ($row = $interactionsStmt->fetch(PDO::FETCH_ASSOC)) {
            $allInteractions[] = $row;
        }
    }
} catch (PDOException) {
    $allInteractions = [];
}

/*
 * Confirm that a service provider exists before running admin updates.
 */
function serviceProviderExists(PDO $pdo, int $providerId): bool
{
    $statement = $pdo->prepare('SELECT provider_id FROM serviceprovider WHERE provider_id = :provider_id LIMIT 1');
    $statement->execute(['provider_id' => $providerId]);

    return $statement->fetchColumn() !== false;
}

/*
 * Confirm a service request with a rating exists (used for pinned review validation).
 */
function ratedReviewExists(PDO $pdo, int $requestId): bool
{
    $statement = $pdo->prepare(
        'SELECT request_id FROM servicerequest WHERE request_id = :request_id AND rating IS NOT NULL LIMIT 1'
    );
    $statement->execute(['request_id' => $requestId]);

    return $statement->fetchColumn() !== false;
}

/*
 * Confirm that a customer exists before running admin updates.
 */
function customerExists(PDO $pdo, int $customerId): bool
{
    $statement = $pdo->prepare('SELECT customer_id FROM customer WHERE customer_id = :customer_id LIMIT 1');
    $statement->execute(['customer_id' => $customerId]);

    return $statement->fetchColumn() !== false;
}

/*
 * Confirm that a service category exists before admin updates.
 */
function serviceCategoryExists(PDO $pdo, int $categoryId): bool
{
    $statement = $pdo->prepare('SELECT category_id FROM servicecategory WHERE category_id = :category_id LIMIT 1');
    $statement->execute(['category_id' => $categoryId]);

    return $statement->fetchColumn() !== false;
}

/*
 * Check if a service category is referenced by providers or requests.
 */
function serviceCategoryInUse(PDO $pdo, int $categoryId): bool
{
    $providerCheck = $pdo->prepare('SELECT provider_id FROM providedservices WHERE category_id = :category_id LIMIT 1');
    $providerCheck->execute(['category_id' => $categoryId]);
    if ($providerCheck->fetchColumn() !== false) {
        return true;
    }

    $requestCheck = $pdo->prepare('SELECT request_id FROM servicerequest WHERE category_id = :category_id LIMIT 1');
    $requestCheck->execute(['category_id' => $categoryId]);

    return $requestCheck->fetchColumn() !== false;
}

/*
 * Check if a dashboard card matches the supplied search query.
 */
function matchesAdminSearch(string $query, array $fields): bool
{
    $query = trim($query);
    if ($query === '') {
        return true;
    }

    $normalizedQuery = mb_strtolower($query);
    $normalizedFields = mb_strtolower(implode(' ', $fields));

    return strpos($normalizedFields, $normalizedQuery) !== false;
}

/*
 * Normalize highlight image JSON into a clean array of web paths.
 */
function normalizeHighlightImageList(string $rawValue): array
{
    $rawValue = trim($rawValue);
    if ($rawValue === '') {
        return [];
    }

    $decoded = json_decode($rawValue, true);
    if (!is_array($decoded)) {
        return [];
    }

    $images = [];
    foreach ($decoded as $imagePath) {
        if (!is_string($imagePath)) {
            continue;
        }

        $imagePath = trim($imagePath);
        if ($imagePath === '') {
            continue;
        }

        $images[] = $imagePath;
    }

    return $images;
}

/*
 * Validate admin highlight image uploads and return normalized metadata.
 */
function validateHighlightImageUploads(?array $filePayload): array
{
    if ($filePayload === null || !is_array($filePayload)) {
        return [];
    }

    $names = (array) ($filePayload['name'] ?? []);
    $errors = (array) ($filePayload['error'] ?? []);
    $tmpNames = (array) ($filePayload['tmp_name'] ?? []);
    $sizes = (array) ($filePayload['size'] ?? []);

    $allowedMimeMap = [
        'image/jpeg' => 'jpg',
        'image/png' => 'png',
        'image/webp' => 'webp',
    ];

    $finfoResource = finfo_open(FILEINFO_MIME_TYPE);
    if ($finfoResource === false) {
        throw new RuntimeException('Unable to validate highlight images right now.');
    }

    $validatedUploads = [];

    try {
        foreach ($errors as $index => $error) {
            $uploadError = (int) $error;
            if ($uploadError === UPLOAD_ERR_NO_FILE) {
                continue;
            }

            if ($uploadError !== UPLOAD_ERR_OK) {
                throw new RuntimeException('One or more highlight images could not be uploaded.');
            }

            $temporaryPath = (string) ($tmpNames[$index] ?? '');
            if ($temporaryPath === '' || !is_uploaded_file($temporaryPath)) {
                throw new RuntimeException('Highlight image upload could not be verified.');
            }

            $fileSize = (int) ($sizes[$index] ?? 0);
            if ($fileSize <= 0 || $fileSize > HIGHLIGHT_IMAGE_MAX_BYTES) {
                throw new RuntimeException('Each highlight image must be between 1 byte and 2 MB.');
            }

            $mimeType = finfo_file($finfoResource, $temporaryPath);
            if (!is_string($mimeType) || !array_key_exists($mimeType, $allowedMimeMap)) {
                throw new RuntimeException('Highlight images must be JPG, PNG, or WEBP.');
            }

            $validatedUploads[] = [
                'tmp_name' => $temporaryPath,
                'extension' => $allowedMimeMap[$mimeType],
                'original_name' => (string) ($names[$index] ?? ''),
            ];
        }
    } finally {
        finfo_close($finfoResource);
    }

    return $validatedUploads;
}

/*
 * Persist highlight images to disk and return web + absolute paths.
 */
function storeHighlightImages(array $uploads): array
{
    if (count($uploads) === 0) {
        return ['web_paths' => [], 'moved_files' => []];
    }

    if (!is_dir(HIGHLIGHT_IMAGE_UPLOAD_DIRECTORY)) {
        $created = mkdir(HIGHLIGHT_IMAGE_UPLOAD_DIRECTORY, 0755, true);
        if (!$created && !is_dir(HIGHLIGHT_IMAGE_UPLOAD_DIRECTORY)) {
            throw new RuntimeException('Unable to prepare highlight image storage.');
        }
    }

    $storedPaths = [];
    $movedFiles = [];

    foreach ($uploads as $upload) {
        $fileExtension = (string) ($upload['extension'] ?? '');
        $tmpName = (string) ($upload['tmp_name'] ?? '');
        $generatedName = 'highlight_' . date('Ymd_His') . '_' . bin2hex(random_bytes(8)) . '.' . $fileExtension;
        $absoluteDestination = HIGHLIGHT_IMAGE_UPLOAD_DIRECTORY . DIRECTORY_SEPARATOR . $generatedName;

        if (!move_uploaded_file($tmpName, $absoluteDestination)) {
            throw new RuntimeException('Unable to save highlight images. Please try again.');
        }

        $storedPaths[] = HIGHLIGHT_IMAGE_UPLOAD_WEB_PATH . '/' . $generatedName;
        $movedFiles[] = $absoluteDestination;
    }

    return ['web_paths' => $storedPaths, 'moved_files' => $movedFiles];
}

/*
 * Safely remove stored highlight images within the upload directory.
 */
function deleteHighlightImage(string $photoPath): void
{
    $photoPath = trim($photoPath);
    if ($photoPath === '') {
        return;
    }

    $baseDirectory = realpath(HIGHLIGHT_IMAGE_UPLOAD_DIRECTORY);
    if ($baseDirectory === false) {
        return;
    }

    $normalized = str_replace('\\', '/', $photoPath);
    if (strpos($normalized, '..') !== false) {
        return;
    }

    $absolutePath = realpath(__DIR__ . '/' . $normalized);
    if ($absolutePath === false) {
        $absolutePath = __DIR__ . '/' . $normalized;
    }

    if (strpos($absolutePath, $baseDirectory) !== 0) {
        return;
    }

    if (is_file($absolutePath)) {
        @unlink($absolutePath);
    }
}

/*
 * Validate the uploaded favicon file and return normalized metadata.
 */
function validateSiteFaviconUpload(?array $filePayload): ?array
{
    if ($filePayload === null || !is_array($filePayload)) {
        return null;
    }

    $uploadError = (int) ($filePayload['error'] ?? UPLOAD_ERR_NO_FILE);
    if ($uploadError === UPLOAD_ERR_NO_FILE) {
        return null;
    }

    if ($uploadError !== UPLOAD_ERR_OK) {
        throw new RuntimeException('Site icon upload failed. Please try again.');
    }

    $temporaryPath = (string) ($filePayload['tmp_name'] ?? '');
    if ($temporaryPath === '' || !is_uploaded_file($temporaryPath)) {
        throw new RuntimeException('Uploaded site icon could not be verified. Please upload again.');
    }

    $fileSize = (int) ($filePayload['size'] ?? 0);
    if ($fileSize <= 0 || $fileSize > SITE_FAVICON_MAX_BYTES) {
        throw new RuntimeException('Site icon must be between 1 byte and 1 MB.');
    }

    $allowedMimeMap = [
        'image/png' => 'png',
        'image/jpeg' => 'jpg',
        'image/webp' => 'webp',
        'image/x-icon' => 'ico',
        'image/vnd.microsoft.icon' => 'ico',
    ];

    $finfoResource = finfo_open(FILEINFO_MIME_TYPE);
    if ($finfoResource === false) {
        throw new RuntimeException('Unable to validate the site icon right now.');
    }

    try {
        $mimeType = finfo_file($finfoResource, $temporaryPath);
        if (!is_string($mimeType) || !array_key_exists($mimeType, $allowedMimeMap)) {
            throw new RuntimeException('Site icon must be PNG, JPG, WEBP, or ICO.');
        }
    } finally {
        finfo_close($finfoResource);
    }

    return [
        'tmp_name' => $temporaryPath,
        'extension' => $allowedMimeMap[$mimeType],
    ];
}

/*
 * Persist the validated favicon upload and return web/absolute paths.
 */
function storeSiteFavicon(array $iconInfo): array
{
    if (!is_dir(SITE_FAVICON_UPLOAD_DIRECTORY)) {
        $created = mkdir(SITE_FAVICON_UPLOAD_DIRECTORY, 0755, true);
        if (!$created && !is_dir(SITE_FAVICON_UPLOAD_DIRECTORY)) {
            throw new RuntimeException('Unable to prepare site icon storage.');
        }
    }

    $fileExtension = (string) ($iconInfo['extension'] ?? '');
    $tmpName = (string) ($iconInfo['tmp_name'] ?? '');
    $generatedName = 'favicon_' . date('Ymd_His') . '_' . bin2hex(random_bytes(6)) . '.' . $fileExtension;
    $absoluteDestination = SITE_FAVICON_UPLOAD_DIRECTORY . DIRECTORY_SEPARATOR . $generatedName;

    if (!move_uploaded_file($tmpName, $absoluteDestination)) {
        throw new RuntimeException('Unable to save the site icon. Please try again.');
    }

    return [
        'web_path' => SITE_FAVICON_UPLOAD_WEB_PATH . '/' . $generatedName,
        'absolute_path' => $absoluteDestination,
    ];
}

/*
 * Safely remove a stored site favicon file.
 */
function deleteSiteFavicon(string $iconPath): void
{
    $iconPath = trim($iconPath);
    if ($iconPath === '') {
        return;
    }

    $baseDirectory = realpath(SITE_FAVICON_UPLOAD_DIRECTORY);
    if ($baseDirectory === false) {
        return;
    }

    $normalized = str_replace('\\', '/', $iconPath);
    if (strpos($normalized, '..') !== false) {
        return;
    }

    $absolutePath = realpath(__DIR__ . '/' . $normalized);
    if ($absolutePath === false) {
        $absolutePath = __DIR__ . '/' . $normalized;
    }

    if (strpos($absolutePath, $baseDirectory) !== 0) {
        return;
    }

    if (is_file($absolutePath)) {
        @unlink($absolutePath);
    }
}



/*
 * Handle admin actions for provider verification and account suspensions.
 */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $postedCsrfToken = (string) ($_POST['csrf_token'] ?? '');
    $action = trim((string) ($_POST['action'] ?? ''));
    $providerId = (int) ($_POST['provider_id'] ?? 0);
    $customerId = (int) ($_POST['customer_id'] ?? 0);
    $categoryId = (int) ($_POST['category_id'] ?? 0);
    $categoryName = trim((string) ($_POST['category_name'] ?? ''));
    $categoryDescription = trim((string) ($_POST['category_description'] ?? ''));

    if (!hash_equals($_SESSION['admin_dashboard_csrf'], $postedCsrfToken)) {
        $errorMessage = 'Invalid request token. Please refresh the page and try again.';
    } elseif ($action === 'verify_provider' || $action === 'unverify_provider') {
        if ($providerId <= 0) {
            $errorMessage = 'Please select a valid service provider.';
        } elseif (!serviceProviderExists($pdo, $providerId)) {
            $errorMessage = 'Service provider not found.';
        } else {
            $isVerifying = $action === 'verify_provider';

            $updatedLookup = $verifiedProviderLookup;

            if ($isVerifying) {
                $updatedLookup[$providerId] = true;
            } else {
                unset($updatedLookup[$providerId]);
            }

            if (!saveVerifiedProviderIds(array_keys($updatedLookup))) {
                $errorMessage = 'Unable to update verification status right now.';
            } else {
                $verifiedProviderLookup = $updatedLookup;
                $_SESSION['admin_dashboard_flash_success'] = $isVerifying
                    ? 'Service provider verified successfully.'
                    : 'Service provider marked as unverified.';
                $redirectQs = http_build_query([
                    'provider_q'            => trim((string) ($_POST['redirect_provider_q'] ?? '')),
                    'provider_status'       => trim((string) ($_POST['redirect_provider_status'] ?? 'all')),
                    'provider_verification' => trim((string) ($_POST['redirect_provider_verification'] ?? 'all')),
                    'customer_q'            => trim((string) ($_POST['redirect_customer_q'] ?? '')),
                    'customer_status'       => trim((string) ($_POST['redirect_customer_status'] ?? 'all')),
                ]);
                header('Location: ' . $appBase . '/admin_dashboard.php' . ($redirectQs ? '?' . $redirectQs : '') . '#service-providers');
                exit;
            }
        }
    } elseif ($action === 'suspend_provider' || $action === 'unsuspend_provider') {
        if ($providerId <= 0) {
            $errorMessage = 'Please select a valid service provider.';
        } elseif (!serviceProviderExists($pdo, $providerId)) {
            $errorMessage = 'Service provider not found.';
        } else {
            $isSuspending = $action === 'suspend_provider';
            $updatedProviderLookup = $suspendedProviderLookup;

            if ($isSuspending) {
                $updatedProviderLookup[$providerId] = true;
            } else {
                unset($updatedProviderLookup[$providerId]);
            }

            $saveResult = saveSuspendedAccountIds([
                'customers' => array_keys($suspendedCustomerLookup),
                'providers' => array_keys($updatedProviderLookup),
            ]);

            if (!$saveResult) {
                $errorMessage = 'Unable to update suspension status right now.';
            } else {
                $suspendedProviderLookup = $updatedProviderLookup;
                $_SESSION['admin_dashboard_flash_success'] = $isSuspending
                    ? 'Service provider suspended successfully.'
                    : 'Service provider unsuspended successfully.';
                $redirectQs = http_build_query([
                    'provider_q'            => trim((string) ($_POST['redirect_provider_q'] ?? '')),
                    'provider_status'       => trim((string) ($_POST['redirect_provider_status'] ?? 'all')),
                    'provider_verification' => trim((string) ($_POST['redirect_provider_verification'] ?? 'all')),
                    'customer_q'            => trim((string) ($_POST['redirect_customer_q'] ?? '')),
                    'customer_status'       => trim((string) ($_POST['redirect_customer_status'] ?? 'all')),
                ]);
                header('Location: ' . $appBase . '/admin_dashboard.php' . ($redirectQs ? '?' . $redirectQs : '') . '#service-providers');
                exit;
            }
        }
    } elseif ($action === 'suspend_customer' || $action === 'unsuspend_customer') {
        if ($customerId <= 0) {
            $errorMessage = 'Please select a valid customer.';
        } elseif (!customerExists($pdo, $customerId)) {
            $errorMessage = 'Customer not found.';
        } else {
            $isSuspending = $action === 'suspend_customer';
            $updatedCustomerLookup = $suspendedCustomerLookup;

            if ($isSuspending) {
                $updatedCustomerLookup[$customerId] = true;
            } else {
                unset($updatedCustomerLookup[$customerId]);
            }

            $saveResult = saveSuspendedAccountIds([
                'customers' => array_keys($updatedCustomerLookup),
                'providers' => array_keys($suspendedProviderLookup),
            ]);

            if (!$saveResult) {
                $errorMessage = 'Unable to update suspension status right now.';
            } else {
                $suspendedCustomerLookup = $updatedCustomerLookup;
                $_SESSION['admin_dashboard_flash_success'] = $isSuspending
                    ? 'Customer suspended successfully.'
                    : 'Customer unsuspended successfully.';
                $redirectQs = http_build_query([
                    'provider_q'            => trim((string) ($_POST['redirect_provider_q'] ?? '')),
                    'provider_status'       => trim((string) ($_POST['redirect_provider_status'] ?? 'all')),
                    'provider_verification' => trim((string) ($_POST['redirect_provider_verification'] ?? 'all')),
                    'customer_q'            => trim((string) ($_POST['redirect_customer_q'] ?? '')),
                    'customer_status'       => trim((string) ($_POST['redirect_customer_status'] ?? 'all')),
                ]);
                header('Location: ' . $appBase . '/admin_dashboard.php' . ($redirectQs ? '?' . $redirectQs : '') . '#customers');
                exit;
            }
        }
    } elseif ($action === 'update_site_settings') {
        $siteSettingsInput = [
            'site_name' => trim((string) ($_POST['site_name'] ?? '')),
            'site_tagline' => trim((string) ($_POST['site_tagline'] ?? '')),
            'hero_title' => trim((string) ($_POST['hero_title'] ?? '')),
            'hero_subtitle' => trim((string) ($_POST['hero_subtitle'] ?? '')),
            'primary_cta_text' => trim((string) ($_POST['primary_cta_text'] ?? '')),
            'support_email' => trim((string) ($_POST['support_email'] ?? '')),
            'support_phone' => trim((string) ($_POST['support_phone'] ?? '')),
            'facebook_url' => trim((string) ($_POST['facebook_url'] ?? '')),
            'instagram_url' => trim((string) ($_POST['instagram_url'] ?? '')),
            'linkedin_url' => trim((string) ($_POST['linkedin_url'] ?? '')),
            'site_favicon' => (string) ($siteSettings['site_favicon'] ?? ''),
            'highlight_images' => (string) ($siteSettings['highlight_images'] ?? '[]'),
            'pinned_provider_id' => (string) max(0, (int) ($_POST['pinned_provider_id'] ?? 0)),
            'pinned_review_id' => (string) max(0, (int) ($_POST['pinned_review_id'] ?? 0)),
            'feature_1_title' => trim((string) ($_POST['feature_1_title'] ?? '')),
            'feature_1_body' => trim((string) ($_POST['feature_1_body'] ?? '')),
            'feature_2_title' => trim((string) ($_POST['feature_2_title'] ?? '')),
            'feature_2_body' => trim((string) ($_POST['feature_2_body'] ?? '')),
            'feature_3_title' => trim((string) ($_POST['feature_3_title'] ?? '')),
            'feature_3_body' => trim((string) ($_POST['feature_3_body'] ?? '')),
            'footer_note' => trim((string) ($_POST['footer_note'] ?? '')),
            'site_name_ar'    => trim((string) ($_POST['site_name_ar'] ?? '')),
            'site_tagline_ar' => trim((string) ($_POST['site_tagline_ar'] ?? '')),
            'hero_title_ar'   => trim((string) ($_POST['hero_title_ar'] ?? '')),
            'hero_subtitle_ar'=> trim((string) ($_POST['hero_subtitle_ar'] ?? '')),
            'primary_cta_text_ar' => trim((string) ($_POST['primary_cta_text_ar'] ?? '')),
            'feature_1_title_ar' => trim((string) ($_POST['feature_1_title_ar'] ?? '')),
            'feature_1_body_ar'  => trim((string) ($_POST['feature_1_body_ar'] ?? '')),
            'feature_2_title_ar' => trim((string) ($_POST['feature_2_title_ar'] ?? '')),
            'feature_2_body_ar'  => trim((string) ($_POST['feature_2_body_ar'] ?? '')),
            'feature_3_title_ar' => trim((string) ($_POST['feature_3_title_ar'] ?? '')),
            'feature_3_body_ar'  => trim((string) ($_POST['feature_3_body_ar'] ?? '')),
            'footer_note_ar'     => trim((string) ($_POST['footer_note_ar'] ?? '')),
        ];

        if ($siteSettingsInput['site_name'] === '') {
            $errorMessage = 'Site name is required.';
        } elseif ($siteSettingsInput['hero_title'] === '') {
            $errorMessage = 'Hero title is required.';
        } elseif ($siteSettingsInput['support_email'] !== ''
            && !filter_var($siteSettingsInput['support_email'], FILTER_VALIDATE_EMAIL)
        ) {
            $errorMessage = 'Please enter a valid support email address.';
        } elseif ($siteSettingsInput['facebook_url'] !== ''
            && !filter_var($siteSettingsInput['facebook_url'], FILTER_VALIDATE_URL)
        ) {
            $errorMessage = 'Please enter a valid Facebook URL.';
        } elseif ($siteSettingsInput['instagram_url'] !== ''
            && !filter_var($siteSettingsInput['instagram_url'], FILTER_VALIDATE_URL)
        ) {
            $errorMessage = 'Please enter a valid Instagram URL.';
        } elseif ($siteSettingsInput['linkedin_url'] !== ''
            && !filter_var($siteSettingsInput['linkedin_url'], FILTER_VALIDATE_URL)
        ) {
            $errorMessage = 'Please enter a valid LinkedIn URL.';
        } elseif (mb_strlen($siteSettingsInput['site_name']) > 120) {
            $errorMessage = 'Site name must be 120 characters or fewer.';
        } elseif (mb_strlen($siteSettingsInput['hero_title']) > 200) {
            $errorMessage = 'Hero title must be 200 characters or fewer.';
        } elseif ((int) $siteSettingsInput['pinned_provider_id'] > 0
            && !serviceProviderExists($pdo, (int) $siteSettingsInput['pinned_provider_id'])
        ) {
            $errorMessage = 'The selected featured provider no longer exists.';
        } elseif ((int) $siteSettingsInput['pinned_review_id'] > 0
            && !ratedReviewExists($pdo, (int) $siteSettingsInput['pinned_review_id'])
        ) {
            $errorMessage = 'The selected featured review no longer exists.';
        } else {
            /*
             * Merge existing highlight images with upload/removal changes.
             */
            $highlightImages = normalizeHighlightImageList((string) ($siteSettings['highlight_images'] ?? ''));
            $imagesToRemove = array_values(
                array_intersect(
                    $highlightImages,
                    array_map('trim', (array) ($_POST['remove_highlight_images'] ?? []))
                )
            );
            $highlightImages = array_values(array_diff($highlightImages, $imagesToRemove));
            $movedHighlightFiles = [];
            $existingFaviconPath = trim((string) ($siteSettings['site_favicon'] ?? ''));
            $removeFavicon = isset($_POST['remove_site_favicon']);
            $movedFaviconFile = '';

            try {
                $highlightUploads = validateHighlightImageUploads($_FILES['highlight_images'] ?? null);
                if (count($highlightUploads) > 0) {
                    $storedHighlightImages = storeHighlightImages($highlightUploads);
                    $highlightImages = array_merge($highlightImages, $storedHighlightImages['web_paths']);
                    $movedHighlightFiles = $storedHighlightImages['moved_files'];
                }

                if (count($highlightImages) > HIGHLIGHT_IMAGE_MAX_COUNT) {
                    $highlightImages = array_slice($highlightImages, 0, HIGHLIGHT_IMAGE_MAX_COUNT);
                }

                $encodedHighlights = json_encode($highlightImages, JSON_UNESCAPED_SLASHES);
                $siteSettingsInput['highlight_images'] = is_string($encodedHighlights) ? $encodedHighlights : '[]';
            } catch (RuntimeException $exception) {
                $errorMessage = $exception->getMessage();
            }

            /*
             * Apply favicon upload/removal updates for the browser tab icon.
             */
            if ($errorMessage === '') {
                try {
                    $faviconUpload = validateSiteFaviconUpload($_FILES['site_favicon'] ?? null);
                    $updatedFaviconPath = $existingFaviconPath;

                    if ($faviconUpload !== null) {
                        $storedIcon = storeSiteFavicon($faviconUpload);
                        $updatedFaviconPath = (string) ($storedIcon['web_path'] ?? '');
                        $movedFaviconFile = (string) ($storedIcon['absolute_path'] ?? '');
                    }

                    if ($removeFavicon) {
                        $updatedFaviconPath = '';
                    }

                    $siteSettingsInput['site_favicon'] = $updatedFaviconPath;
                } catch (RuntimeException $exception) {
                    $errorMessage = $exception->getMessage();
                }
            }

            try {
                if ($errorMessage !== '') {
                    throw new RuntimeException($errorMessage);
                }

                saveSiteSettings($pdo, $siteSettingsInput);
                foreach ($imagesToRemove as $imagePath) {
                    deleteHighlightImage($imagePath);
                }
                if ($existingFaviconPath !== '' && $existingFaviconPath !== $siteSettingsInput['site_favicon']) {
                    deleteSiteFavicon($existingFaviconPath);
                }
                $_SESSION['admin_dashboard_flash_success'] = 'Site settings updated successfully.';
                header('Location: ' . $appBase . '/admin_dashboard.php#site-settings');
                exit;
            } catch (RuntimeException $exception) {
                foreach ($movedHighlightFiles as $filePath) {
                    if (is_string($filePath) && $filePath !== '' && is_file($filePath)) {
                        @unlink($filePath);
                    }
                }
                if ($movedFaviconFile !== '' && is_file($movedFaviconFile)) {
                    @unlink($movedFaviconFile);
                }
                if ($errorMessage === '') {
                    $errorMessage = $exception->getMessage();
                }
            } catch (PDOException $exception) {
                foreach ($movedHighlightFiles as $filePath) {
                    if (is_string($filePath) && $filePath !== '' && is_file($filePath)) {
                        @unlink($filePath);
                    }
                }
                if ($movedFaviconFile !== '' && is_file($movedFaviconFile)) {
                    @unlink($movedFaviconFile);
                }
                $errorMessage = 'Unable to update site settings right now.';
            }
        }
    } elseif ($action === 'create_category') {
        $categoryNameAr = trim((string) ($_POST['category_name_ar'] ?? ''));
        $categoryDescAr = trim((string) ($_POST['category_description_ar'] ?? ''));
        if ($categoryName === '') {
            $errorMessage = 'Please enter a category name.';
        } elseif (mb_strlen($categoryName) > 200) {
            $errorMessage = 'Category name must be 200 characters or fewer.';
        } elseif (mb_strlen($categoryDescription) > 1000) {
            $errorMessage = 'Category description must be 1000 characters or fewer.';
        } else {
            try {
                migrateServiceCategoryArabicColumns($pdo);
                $insertStatement = $pdo->prepare(
                    'INSERT INTO servicecategory (name, description, name_ar, description_ar)
                     VALUES (:name, :description, :name_ar, :description_ar)'
                );
                $insertStatement->execute([
                    'name'           => $categoryName,
                    'description'    => $categoryDescription,
                    'name_ar'        => $categoryNameAr,
                    'description_ar' => $categoryDescAr,
                ]);

                $_SESSION['admin_dashboard_flash_success'] = 'Category created successfully.';
                header('Location: ' . $appBase . '/admin_dashboard.php#service-categories');
                exit;
            } catch (PDOException $exception) {
                $errorMessage = 'Unable to create the category right now.';
            }
        }
    } elseif ($action === 'update_category') {
        $categoryNameAr = trim((string) ($_POST['category_name_ar'] ?? ''));
        $categoryDescAr = trim((string) ($_POST['category_description_ar'] ?? ''));
        if ($categoryId <= 0) {
            $errorMessage = 'Please select a valid category.';
        } elseif (!serviceCategoryExists($pdo, $categoryId)) {
            $errorMessage = 'Category not found.';
        } elseif ($categoryName === '') {
            $errorMessage = 'Please enter a category name.';
        } elseif (mb_strlen($categoryName) > 200) {
            $errorMessage = 'Category name must be 200 characters or fewer.';
        } elseif (mb_strlen($categoryDescription) > 1000) {
            $errorMessage = 'Category description must be 1000 characters or fewer.';
        } else {
            try {
                migrateServiceCategoryArabicColumns($pdo);
                $updateStatement = $pdo->prepare(
                    'UPDATE servicecategory
                     SET name = :name,
                         description = :description,
                         name_ar = :name_ar,
                         description_ar = :description_ar
                     WHERE category_id = :category_id'
                );
                $updateStatement->execute([
                    'name'           => $categoryName,
                    'description'    => $categoryDescription,
                    'name_ar'        => $categoryNameAr,
                    'description_ar' => $categoryDescAr,
                    'category_id'    => $categoryId,
                ]);

                $_SESSION['admin_dashboard_flash_success'] = 'Category updated successfully.';
                header('Location: ' . $appBase . '/admin_dashboard.php#service-categories');
                exit;
            } catch (PDOException $exception) {
                $errorMessage = 'Unable to update the category right now.';
            }
        }
    } elseif ($action === 'delete_category') {
        if ($categoryId <= 0) {
            $errorMessage = 'Please select a valid category.';
        } elseif (!serviceCategoryExists($pdo, $categoryId)) {
            $errorMessage = 'Category not found.';
        } elseif (serviceCategoryInUse($pdo, $categoryId)) {
            $errorMessage = 'Category cannot be deleted because it is already in use.';
        } else {
            try {
                $deleteStatement = $pdo->prepare('DELETE FROM servicecategory WHERE category_id = :category_id');
                $deleteStatement->execute(['category_id' => $categoryId]);

                $_SESSION['admin_dashboard_flash_success'] = 'Category deleted successfully.';
                header('Location: ' . $appBase . '/admin_dashboard.php#service-categories');
                exit;
            } catch (PDOException $exception) {
                $errorMessage = 'Unable to delete the category right now.';
            }
        }
    } elseif ($action === 'approve_cat_request' || $action === 'reject_cat_request') {
        $catRequestId = (int) ($_POST['cat_request_id'] ?? 0);
        $catAdminNotes = trim((string) ($_POST['admin_notes'] ?? ''));
        if ($catRequestId <= 0) {
            $errorMessage = t('admin_cat_err_not_found');
        } else {
            try {
                $pdo->exec(
                    "CREATE TABLE IF NOT EXISTS category_requests (
                        request_id INT AUTO_INCREMENT PRIMARY KEY,
                        provider_id INT NOT NULL,
                        category_name VARCHAR(200) NOT NULL,
                        category_info TEXT,
                        status ENUM('pending','approved','rejected') NOT NULL DEFAULT 'pending',
                        admin_notes TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
                );

                $catReqRow = $pdo->prepare('SELECT * FROM category_requests WHERE request_id = :id LIMIT 1');
                $catReqRow->execute(['id' => $catRequestId]);
                $catReqData = $catReqRow->fetch();

                if (!$catReqData) {
                    $errorMessage = t('admin_cat_err_not_found');
                } else {
                    $newStatus = ($action === 'approve_cat_request') ? 'approved' : 'rejected';

                    if ($action === 'approve_cat_request') {
                        migrateServiceCategoryArabicColumns($pdo);
                        $approveNameAr = trim((string) ($_POST['category_name_ar'] ?? ''));
                        $approveDescAr = trim((string) ($_POST['category_description_ar'] ?? ''));
                        $insCategory = $pdo->prepare(
                            'INSERT INTO servicecategory (name, description, name_ar, description_ar)
                             VALUES (:name, :description, :name_ar, :description_ar)'
                        );
                        $insCategory->execute([
                            'name'           => (string) $catReqData['category_name'],
                            'description'    => (string) ($catReqData['category_info'] ?? ''),
                            'name_ar'        => $approveNameAr,
                            'description_ar' => $approveDescAr,
                        ]);
                    }

                    $updReq = $pdo->prepare(
                        'UPDATE category_requests SET status = :status, admin_notes = :notes WHERE request_id = :id'
                    );
                    $updReq->execute([
                        'status' => $newStatus,
                        'notes'  => $catAdminNotes,
                        'id'     => $catRequestId,
                    ]);

                    $flashMsg = $action === 'approve_cat_request'
                        ? t('admin_cat_ok_approved')
                        : t('admin_cat_ok_rejected');
                    $_SESSION['admin_dashboard_flash_success'] = $flashMsg;
                    header('Location: ' . $appBase . '/admin_dashboard.php#service-categories');
                    exit;
                }
            } catch (PDOException $exception) {
                $errorMessage = t('admin_cat_err_db');
            }
        }
    } elseif ($action === 'approve_location_request' || $action === 'reject_location_request') {
        $locRequestId = (int) ($_POST['location_request_id'] ?? 0);
        if ($locRequestId <= 0) {
            $errorMessage = t('admin_loc_err_not_found');
        } else {
            try {
                $locRow = $pdo->prepare(
                    'SELECT * FROM provider_location_requests WHERE id = :id AND status = \'pending\' LIMIT 1'
                );
                $locRow->execute(['id' => $locRequestId]);
                $locData = $locRow->fetch();

                if (!$locData) {
                    $errorMessage = t('admin_loc_err_not_found');
                } else {
                    $locProviderId = (int) $locData['provider_id'];
                    if ($action === 'approve_location_request') {
                        // Update provider location to the requested value
                        $pdo->prepare(
                            'UPDATE serviceprovider
                             SET location = :loc, pending_location = \'\', location_change_status = \'none\'
                             WHERE provider_id = :pid'
                        )->execute(['loc' => (string) $locData['requested_location'], 'pid' => $locProviderId]);

                        $pdo->prepare(
                            'UPDATE provider_location_requests SET status = \'approved\' WHERE id = :id'
                        )->execute(['id' => $locRequestId]);

                        $_SESSION['admin_dashboard_flash_success'] = t('admin_loc_ok_approved');
                    } else {
                        // Reject — restore status on provider
                        $pdo->prepare(
                            'UPDATE serviceprovider
                             SET pending_location = \'\', location_change_status = \'none\'
                             WHERE provider_id = :pid'
                        )->execute(['pid' => $locProviderId]);

                        $pdo->prepare(
                            'UPDATE provider_location_requests SET status = \'rejected\' WHERE id = :id'
                        )->execute(['id' => $locRequestId]);

                        $_SESSION['admin_dashboard_flash_success'] = t('admin_loc_ok_rejected');
                    }
                    header('Location: ' . $appBase . '/admin_dashboard.php#location-requests');
                    exit;
                }
            } catch (PDOException $exception) {
                $errorMessage = t('admin_loc_err_db');
            }
        }
    } else {
        $errorMessage = 'Unknown admin action requested.';
    }
}

/*
 * Data collections used by the admin dashboard view.
 */
$serviceProviders = [];
$customers = [];
$providerCount = 0;
$verifiedProviderCount = 0;
$customerCount = 0;

try {
    /*
     * Load service provider summaries for verification and suspension controls.
     */
    $providerStatement = $pdo->prepare(
        'SELECT
            sp.provider_id,
            sp.name,
            sp.email,
            sp.phone,
            COUNT(DISTINCT ps.category_id) AS service_count,
            COUNT(DISTINCT sr.request_id) AS request_count
         FROM serviceprovider sp
         LEFT JOIN providedservices ps
            ON sp.provider_id = ps.provider_id
         LEFT JOIN appointmentslot asl
            ON sp.provider_id = asl.serviceprovider_id
         LEFT JOIN servicerequest sr
            ON sr.slot_id = asl.slot_id
         GROUP BY sp.provider_id, sp.name, sp.email, sp.phone
         ORDER BY sp.name ASC'
    );
    $providerStatement->execute();

    while ($row = $providerStatement->fetch()) {
        $providerId = (int) $row['provider_id'];
        $isVerified = isset($verifiedProviderLookup[$providerId]);
        $isSuspended = isset($suspendedProviderLookup[$providerId]);
        if ($isVerified) {
            $verifiedProviderCount += 1;
        }

        $serviceProviders[] = [
            'provider_id' => $providerId,
            'name' => (string) $row['name'],
            'email' => (string) ($row['email'] ?? ''),
            'phone' => (string) ($row['phone'] ?? ''),
            'service_count' => (int) ($row['service_count'] ?? 0),
            'request_count' => (int) ($row['request_count'] ?? 0),
            'is_verified' => $isVerified,
            'is_suspended' => $isSuspended,
        ];
    }

    /*
     * Present verified providers first, then sort by name for readability.
     */
    usort(
        $serviceProviders,
        static function (array $left, array $right): int {
            if ($left['is_verified'] === $right['is_verified']) {
                return strcasecmp($left['name'], $right['name']);
            }

            return $left['is_verified'] ? -1 : 1;
        }
    );

    /*
     * Load customer summaries for suspension controls.
     */
    $customerStatement = $pdo->prepare(
        'SELECT
            c.customer_id,
            c.name,
            c.email,
            c.phone,
            COUNT(sr.request_id) AS request_count
         FROM customer c
         LEFT JOIN servicerequest sr
            ON sr.customer_id = c.customer_id
         GROUP BY c.customer_id, c.name, c.email, c.phone
         ORDER BY c.name ASC'
    );
    $customerStatement->execute();

    while ($row = $customerStatement->fetch()) {
        $customerIdValue = (int) $row['customer_id'];
        $isSuspended = isset($suspendedCustomerLookup[$customerIdValue]);
        $customers[] = [
            'customer_id' => $customerIdValue,
            'name' => (string) $row['name'],
            'email' => (string) ($row['email'] ?? ''),
            'phone' => (string) ($row['phone'] ?? ''),
            'request_count' => (int) ($row['request_count'] ?? 0),
            'is_suspended' => $isSuspended,
        ];
    }

    /*
     * Emit JSON suggestions for live search inputs in the admin toolbars.
     */
    $suggestMode = strtolower(trim((string) ($_GET['suggest'] ?? '')));
    if (in_array($suggestMode, ['providers', 'customers'], true)) {
        $query = trim((string) ($_GET['query'] ?? ''));
        $normalizedQuery = mb_strtolower($query);
        $suggestions = [];
        $seenSuggestions = [];

        if ($normalizedQuery !== '') {
            if ($suggestMode === 'providers') {
                foreach ($serviceProviders as $provider) {
                    if ($providerVerificationFilter === 'verified' && !$provider['is_verified']) {
                        continue;
                    }

                    if ($providerVerificationFilter === 'unverified' && $provider['is_verified']) {
                        continue;
                    }

                    if ($providerStatusFilter === 'active' && $provider['is_suspended']) {
                        continue;
                    }

                    if ($providerStatusFilter === 'suspended' && !$provider['is_suspended']) {
                        continue;
                    }

                    if (!matchesAdminSearch($query, [$provider['name'], $provider['email'], $provider['phone']])) {
                        continue;
                    }

                    foreach ([$provider['name'], $provider['email'], $provider['phone']] as $candidate) {
                        $candidate = trim((string) $candidate);
                        if ($candidate === '') {
                            continue;
                        }

                        if (strpos(mb_strtolower($candidate), $normalizedQuery) === false) {
                            continue;
                        }

                        if (isset($seenSuggestions[$candidate])) {
                            continue;
                        }

                        $seenSuggestions[$candidate] = true;
                        $suggestions[] = $candidate;

                        if (count($suggestions) >= 12) {
                            break 2;
                        }
                    }
                }
            } else {
                foreach ($customers as $customer) {
                    if ($customerStatusFilter === 'active' && $customer['is_suspended']) {
                        continue;
                    }

                    if ($customerStatusFilter === 'suspended' && !$customer['is_suspended']) {
                        continue;
                    }

                    if (!matchesAdminSearch($query, [$customer['name'], $customer['email'], $customer['phone']])) {
                        continue;
                    }

                    foreach ([$customer['name'], $customer['email'], $customer['phone']] as $candidate) {
                        $candidate = trim((string) $candidate);
                        if ($candidate === '') {
                            continue;
                        }

                        if (strpos(mb_strtolower($candidate), $normalizedQuery) === false) {
                            continue;
                        }

                        if (isset($seenSuggestions[$candidate])) {
                            continue;
                        }

                        $seenSuggestions[$candidate] = true;
                        $suggestions[] = $candidate;

                        if (count($suggestions) >= 12) {
                            break 2;
                        }
                    }
                }
            }
        }

        header('Content-Type: application/json; charset=UTF-8');
        echo json_encode([
            'ok' => true,
            'suggestions' => $suggestions,
        ]);
        exit;
    }

    $providerCount = count($serviceProviders);
    $customerCount = count($customers);

    /*
     * Apply toolbar filters to the rendered provider and customer lists.
     */
    $serviceProviders = array_values(
        array_filter(
            $serviceProviders,
            static function (array $provider) use ($providerSearchQuery, $providerVerificationFilter, $providerStatusFilter): bool {
                if ($providerVerificationFilter === 'verified' && !$provider['is_verified']) {
                    return false;
                }

                if ($providerVerificationFilter === 'unverified' && $provider['is_verified']) {
                    return false;
                }

                if ($providerStatusFilter === 'active' && $provider['is_suspended']) {
                    return false;
                }

                if ($providerStatusFilter === 'suspended' && !$provider['is_suspended']) {
                    return false;
                }

                return matchesAdminSearch(
                    $providerSearchQuery,
                    [$provider['name'], $provider['email'], $provider['phone']]
                );
            }
        )
    );

    $customers = array_values(
        array_filter(
            $customers,
            static function (array $customer) use ($customerSearchQuery, $customerStatusFilter): bool {
                if ($customerStatusFilter === 'active' && $customer['is_suspended']) {
                    return false;
                }

                if ($customerStatusFilter === 'suspended' && !$customer['is_suspended']) {
                    return false;
                }

                return matchesAdminSearch(
                    $customerSearchQuery,
                    [$customer['name'], $customer['email'], $customer['phone']]
                );
            }
        )
    );
} catch (PDOException $exception) {
    if ($errorMessage === '') {
        $errorMessage = 'Unable to load admin data right now. Please try again.';
    }
}

/*
 * Load all pending category requests from providers.
 */
$allCategoryRequests = [];
try {
    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS category_requests (
            request_id INT AUTO_INCREMENT PRIMARY KEY,
            provider_id INT NOT NULL,
            category_name VARCHAR(200) NOT NULL,
            category_info TEXT,
            status ENUM('pending','approved','rejected') NOT NULL DEFAULT 'pending',
            admin_notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
    );

    $allCatReqStmt = $pdo->query(
        'SELECT cr.request_id, cr.provider_id, cr.category_name, cr.category_info,
                cr.status, cr.admin_notes, cr.created_at,
                sp.name AS provider_name, sp.email AS provider_email
         FROM category_requests cr
         LEFT JOIN serviceprovider sp ON cr.provider_id = sp.provider_id
         ORDER BY cr.status = \'pending\' DESC, cr.created_at DESC'
    );

    if ($allCatReqStmt) {
        while ($catRow = $allCatReqStmt->fetch()) {
            $allCategoryRequests[] = [
                'request_id'     => (int) $catRow['request_id'],
                'provider_id'    => (int) $catRow['provider_id'],
                'category_name'  => (string) $catRow['category_name'],
                'category_info'  => (string) ($catRow['category_info'] ?? ''),
                'status'         => (string) $catRow['status'],
                'admin_notes'    => (string) ($catRow['admin_notes'] ?? ''),
                'created_at'     => (string) $catRow['created_at'],
                'provider_name'  => (string) ($catRow['provider_name'] ?? ''),
                'provider_email' => (string) ($catRow['provider_email'] ?? ''),
            ];
        }
    }
} catch (PDOException $exception) {
    // Non-fatal: table may not exist yet
}

/*
 * Load provider location change requests (all, newest pending first).
 */
$allLocationRequests = [];
$pendingLocationCount = 0;
try {
    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS provider_location_requests (
            id INT AUTO_INCREMENT PRIMARY KEY,
            provider_id INT NOT NULL,
            current_location VARCHAR(255) NOT NULL DEFAULT '',
            requested_location VARCHAR(255) NOT NULL,
            status ENUM('pending','approved','rejected') NOT NULL DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
    );

    $locReqStmt = $pdo->query(
        'SELECT plr.id, plr.provider_id, plr.current_location, plr.requested_location,
                plr.status, plr.created_at,
                sp.name AS provider_name, sp.email AS provider_email
         FROM provider_location_requests plr
         LEFT JOIN serviceprovider sp ON plr.provider_id = sp.provider_id
         ORDER BY plr.status = \'pending\' DESC, plr.created_at DESC
         LIMIT 200'
    );
    if ($locReqStmt) {
        while ($locRow = $locReqStmt->fetch()) {
            $allLocationRequests[] = [
                'id'                 => (int) $locRow['id'],
                'provider_id'        => (int) $locRow['provider_id'],
                'current_location'   => (string) ($locRow['current_location'] ?? ''),
                'requested_location' => (string) $locRow['requested_location'],
                'status'             => (string) $locRow['status'],
                'created_at'         => (string) $locRow['created_at'],
                'provider_name'      => (string) ($locRow['provider_name'] ?? ''),
                'provider_email'     => (string) ($locRow['provider_email'] ?? ''),
            ];
            if ((string) $locRow['status'] === 'pending') {
                $pendingLocationCount++;
            }
        }
    }
} catch (PDOException $exception) {
    // Non-fatal
}

/*
 * Reviews section: global stats + paginated, searchable, sortable review list.
 */
$reviewSectionSort   = strtolower(trim((string) ($_GET['rev_sort'] ?? 'newest')));
if (!in_array($reviewSectionSort, ['newest', 'highest', 'lowest'], true)) {
    $reviewSectionSort = 'newest';
}
$reviewSectionStars  = (int) ($_GET['rev_stars'] ?? 0);
if ($reviewSectionStars < 0 || $reviewSectionStars > 5) {
    $reviewSectionStars = 0;
}
$reviewSectionSearch = trim((string) ($_GET['rev_q'] ?? ''));
$reviewSectionPage   = max(1, (int) ($_GET['rev_page'] ?? 1));
$reviewsPerPage      = 15;
$reviewSectionOffset = ($reviewSectionPage - 1) * $reviewsPerPage;

$reviewSortClause = match($reviewSectionSort) {
    'highest' => 'sr.rating DESC, asl.date DESC',
    'lowest'  => 'sr.rating ASC, asl.date DESC',
    default   => 'asl.date DESC, sr.request_id DESC',
};

$reviewStatsTotals    = 0;
$reviewStatsAvg       = 0.0;
$reviewStatsFiveStar  = 0;
$reviewSectionRows    = [];
$reviewSectionTotal   = 0;

try {
    // Global stats
    $statsStmt = $pdo->query(
        'SELECT COUNT(*) AS total,
                IFNULL(ROUND(AVG(sr.rating),1),0) AS avg_rating,
                SUM(CASE WHEN sr.rating=5 THEN 1 ELSE 0 END) AS five_star
         FROM servicerequest sr
         WHERE sr.rating IS NOT NULL'
    );
    if ($statsStmt) {
        $statsRow = $statsStmt->fetch(PDO::FETCH_ASSOC);
        $reviewStatsTotals   = (int) ($statsRow['total'] ?? 0);
        $reviewStatsAvg      = (float) ($statsRow['avg_rating'] ?? 0.0);
        $reviewStatsFiveStar = (int) ($statsRow['five_star'] ?? 0);
    }

    // Build WHERE clauses
    $revWhere = 'WHERE sr.rating IS NOT NULL';
    $revParams = [];
    if ($reviewSectionStars > 0) {
        $revWhere .= ' AND sr.rating = :stars';
        $revParams['stars'] = $reviewSectionStars;
    }
    if ($reviewSectionSearch !== '') {
        $revWhere .= ' AND (sp.name LIKE :sq OR c.name LIKE :sq2 OR sr.review LIKE :sq3)';
        $revParams['sq']  = '%' . $reviewSectionSearch . '%';
        $revParams['sq2'] = '%' . $reviewSectionSearch . '%';
        $revParams['sq3'] = '%' . $reviewSectionSearch . '%';
    }

    // Count
    $countStmt = $pdo->prepare(
        "SELECT COUNT(*) AS n
         FROM servicerequest sr
         INNER JOIN appointmentslot asl ON sr.slot_id = asl.slot_id
         INNER JOIN serviceprovider sp  ON asl.serviceprovider_id = sp.provider_id
         LEFT  JOIN customer c          ON sr.customer_id = c.customer_id
         $revWhere"
    );
    $countStmt->execute($revParams);
    $reviewSectionTotal = (int) ($countStmt->fetchColumn() ?? 0);

    // Rows
    $rowStmt = $pdo->prepare(
        "SELECT sr.request_id,
                sr.rating,
                IFNULL(sr.review,'') AS review,
                asl.date AS appointment_date,
                COALESCE(c.name,'Customer') AS customer_name,
                c.customer_id,
                COALESCE(sp.name,'Provider') AS provider_name,
                sp.provider_id
         FROM servicerequest sr
         INNER JOIN appointmentslot asl ON sr.slot_id = asl.slot_id
         INNER JOIN serviceprovider sp  ON asl.serviceprovider_id = sp.provider_id
         LEFT  JOIN customer c          ON sr.customer_id = c.customer_id
         $revWhere
         ORDER BY $reviewSortClause
         LIMIT :lim OFFSET :off"
    );
    foreach ($revParams as $k => $v) {
        $rowStmt->bindValue(':' . $k, $v);
    }
    $rowStmt->bindValue(':lim', $reviewsPerPage, PDO::PARAM_INT);
    $rowStmt->bindValue(':off', $reviewSectionOffset, PDO::PARAM_INT);
    $rowStmt->execute();
    $reviewSectionRows = $rowStmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException) {
    $reviewSectionRows  = [];
    $reviewSectionTotal = 0;
}

$reviewSectionPages = $reviewSectionTotal > 0 ? (int) ceil($reviewSectionTotal / $reviewsPerPage) : 0;

function adminReviewPageUrl(int $page, string $sort, int $stars, string $search): string
{
    $params = ['rev_page' => $page, 'rev_sort' => $sort];
    if ($stars > 0) $params['rev_stars'] = $stars;
    if ($search !== '') $params['rev_q'] = $search;
    return 'admin_dashboard.php?' . http_build_query($params) . '#reviews';
}

function adminReviewStarHtml(int $rating): string
{
    $html = '';
    for ($i = 1; $i <= 5; $i++) {
        $html .= $i <= $rating
            ? '<i class="fa-solid fa-star" style="color:#f59e0b;font-size:.85rem;"></i>'
            : '<i class="fa-regular fa-star" style="color:#d1d5db;font-size:.85rem;"></i>';
    }
    return $html;
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
    <title><?php echo htmlspecialchars(t('admin_title'), ENT_QUOTES, 'UTF-8'); ?> - <?php echo htmlspecialchars(t('site_name'), ENT_QUOTES, 'UTF-8'); ?></title>
    <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&display=swap" rel="stylesheet">
    <?php if (isRtl()): ?>
    <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <?php endif; ?>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        /*
         * Global reset and color tokens.
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
            --surface: #f8fafc;
            --card: rgba(255, 255, 255, 0.94);
            --line: rgba(15, 23, 42, 0.08);
            --success: #16a34a;
            --warning: #f59e0b;
            --danger: #ef4444;
        }

        html,
        body {
            width: 100%;
            overflow-x: hidden;
            height: 100%;
        }

        body {
            font-family: 'Space Grotesk', sans-serif;
            color: var(--ink);
            min-height: 100vh;
            background:
                radial-gradient(circle at 8% 12%, rgba(15, 118, 110, 0.18), transparent 38%),
                radial-gradient(circle at 92% 8%, rgba(249, 115, 22, 0.2), transparent 35%),
                linear-gradient(135deg, #f8fafc, #ecfeff 55%, #fff7ed);
            display: flex;
            flex-direction: row;
        }

        /*
         * Ambient background highlights for visual depth.
         */
        .glow {
            position: fixed;
            border-radius: 999px;
            filter: blur(90px);
            opacity: 0.8;
            z-index: -1;
            animation: floatGlow 16s ease-in-out infinite;
        }

        .glow.one {
            width: 340px;
            height: 340px;
            top: -120px;
            left: -80px;
            background: rgba(20, 184, 166, 0.4);
        }

        .glow.two {
            width: 420px;
            height: 420px;
            right: -120px;
            bottom: -140px;
            background: rgba(251, 146, 60, 0.35);
            animation-delay: -6s;
        }

        @keyframes floatGlow {
            0%, 100% {
                transform: translate(0, 0) scale(1);
            }
            50% {
                transform: translate(30px, -20px) scale(1.05);
            }
        }

        /*
         * Page shell for layout consistency.
         * Adjusted for sidebar layout - sidebar takes 15%, main content takes 85%.
         */
        .shell {
            width: calc(100% - 15%);
            margin: 0 0 0 15%;
            max-width: none;
            display: flex;
            flex-direction: column;
            gap: 18px;
            animation: pageIn 0.6s ease;
            padding: 28px 16px 40px;
            overflow-y: auto;
        }

        @keyframes pageIn {
            from {
                opacity: 0;
                transform: translateY(18px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        /*
         * Header strip with admin identity and logout.
         */
        .topbar {
            background: var(--card);
            border-radius: 24px;
            padding: 18px 20px;
            border: 1px solid rgba(255, 255, 255, 0.8);
            box-shadow: 0 16px 40px rgba(15, 23, 42, 0.1);
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 12px;
        }

        .brand h1 {
            font-size: 1.6rem;
            font-weight: 700;
            letter-spacing: -0.5px;
        }

        .brand p {
            color: var(--muted);
            font-size: 0.95rem;
        }

        .topbar-actions {
            display: flex;
            align-items: center;
            gap: 10px;
            flex-wrap: wrap;
        }

        .chip {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 8px 14px;
            border-radius: 999px;
            background: rgba(15, 118, 110, 0.12);
            color: var(--brand-deep);
            font-weight: 600;
            font-size: 0.9rem;
        }

        /*
         * Reusable button styles.
         */
        .btn {
            border: none;
            border-radius: 14px;
            padding: 10px 16px;
            font-family: inherit;
            font-size: 0.92rem;
            font-weight: 600;
            cursor: pointer;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }

        .btn.primary {
            background: linear-gradient(140deg, var(--brand), var(--brand-deep));
            color: #fff;
            box-shadow: 0 10px 20px rgba(15, 118, 110, 0.2);
        }

        .btn.ghost {
            background: #fff;
            color: var(--ink);
            border: 1px solid var(--line);
        }

        .btn.warn {
            background: rgba(245, 158, 11, 0.14);
            color: #92400e;
            border: 1px solid rgba(245, 158, 11, 0.3);
        }

        .btn.danger {
            background: rgba(239, 68, 68, 0.12);
            color: #b91c1c;
            border: 1px solid rgba(239, 68, 68, 0.3);
        }

        .btn:hover {
            transform: translateY(-1px);
        }

        /*
         * Feedback banners for admin actions.
         */
        .feedback {
            border-radius: 16px;
            border: 1px solid;
            padding: 12px 16px;
            font-weight: 600;
            font-size: 0.95rem;
        }

        .feedback.error {
            background: rgba(239, 68, 68, 0.12);
            border-color: rgba(239, 68, 68, 0.32);
            color: #b91c1c;
        }

        .feedback.success {
            background: rgba(16, 185, 129, 0.14);
            border-color: rgba(16, 185, 129, 0.3);
            color: #047857;
        }

        /*
         * Summary metric cards.
         */
        .metrics {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 12px;
        }

        .panel {
            display: none;
        }

        .panel:target {
            display: flex;
        }

        /*
         * Quick navigation to separate admin sections.
         */
        .section-nav {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
        }

        .section-nav a {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 8px 14px;
            border-radius: 999px;
            border: 1px solid var(--line);
            background: #fff;
            color: var(--ink);
            text-decoration: none;
            font-size: 0.88rem;
            font-weight: 700;
        }

        .metric-card {
            border-radius: 18px;
            padding: 16px 18px;
            display: flex;
            align-items: center;
            gap: 14px;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }

        .metric-card:hover {
            transform: translateY(-3px);
            box-shadow: 0 10px 28px rgba(15, 23, 42, 0.12);
        }

        .metric-card.blue   { background: linear-gradient(135deg,#eff6ff,#dbeafe); border: 1.5px solid #93c5fd; }
        .metric-card.teal   { background: linear-gradient(135deg,#f0fdfa,#ccfbf1); border: 1.5px solid #99f6e4; }
        .metric-card.violet { background: linear-gradient(135deg,#f5f3ff,#ede9fe); border: 1.5px solid #c4b5fd; }
        .metric-card.amber  { background: linear-gradient(135deg,#fff7ed,#ffedd5); border: 1.5px solid #fed7aa; }
        .metric-card.rose   { background: linear-gradient(135deg,#fff1f2,#ffe4e6); border: 1.5px solid #fecdd3; }

        .metric-icon {
            width: 48px;
            height: 48px;
            border-radius: 14px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.15rem;
            flex-shrink: 0;
        }

        .metric-card.blue   .metric-icon { background: rgba(37,99,235,.15);  color: #2563eb; }
        .metric-card.teal   .metric-icon { background: rgba(15,118,110,.15); color: #0f766e; }
        .metric-card.violet .metric-icon { background: rgba(124,58,237,.15); color: #7c3aed; }
        .metric-card.amber  .metric-icon { background: rgba(249,115,22,.15); color: #ea580c; }
        .metric-card.rose   .metric-icon { background: rgba(225,29,72,.15);  color: #e11d48; }

        .metric-card h3 {
            font-size: 0.74rem;
            color: #64748b;
            font-weight: 600;
            margin-bottom: 3px;
            text-transform: uppercase;
            letter-spacing: 0.4px;
        }

        .metric-card p {
            font-size: 1.6rem;
            font-weight: 800;
            color: #0f172a;
            line-height: 1;
        }

        /*
         * Section panels for providers and customers.
         */
        .panel {
            background: var(--card);
            border-radius: 26px;
            padding: 22px;
            border: 1px solid rgba(255, 255, 255, 0.9);
            box-shadow: 0 18px 38px rgba(15, 23, 42, 0.08);
            flex-direction: column;
            gap: 16px;
        }

        /*
         * Site settings and category management forms.
         */
        .settings-form,
        .category-form {
            display: grid;
            gap: 12px;
        }

        .settings-grid {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 12px;
        }

        .settings-field {
            display: flex;
            flex-direction: column;
            gap: 6px;
        }

        .settings-field label {
            font-size: 0.86rem;
            font-weight: 700;
            color: #0f172a;
        }

        .settings-field input,
        .settings-field textarea {
            min-height: 44px;
            border-radius: 12px;
            border: 1px solid var(--line);
            padding: 10px 12px;
            font-family: inherit;
            font-size: 0.9rem;
            background: #fff;
            color: var(--ink);
        }

        .settings-field textarea {
            min-height: 90px;
            resize: vertical;
        }

        .settings-field input:focus,
        .settings-field textarea:focus {
            outline: none;
            border-color: rgba(15, 118, 110, 0.55);
            box-shadow: 0 0 0 3px rgba(15, 118, 110, 0.12);
        }

        .settings-hint {
            font-size: 0.78rem;
            color: var(--muted);
            line-height: 1.4;
        }

        .highlight-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 10px;
        }

        .highlight-card {
            border: 1px solid var(--line);
            border-radius: 14px;
            padding: 8px;
            background: #fff;
            display: grid;
            gap: 6px;
            align-items: center;
        }

        .highlight-card img {
            width: 100%;
            height: 110px;
            object-fit: cover;
            border-radius: 10px;
            display: block;
        }

        .highlight-card span {
            font-size: 0.75rem;
            font-weight: 700;
            color: var(--muted);
        }

        /* ── Admin services: stats bar ─────────────────────────────── */
        .admin-svc-stats {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 12px;
            margin-bottom: 22px;
        }
        .admin-svc-stat {
            border-radius: 16px; padding: 14px 16px;
            display: flex; align-items: center; gap: 12px;
            transition: transform .15s;
        }
        .admin-svc-stat:hover { transform: translateY(-2px); }
        .admin-svc-stat.blue   { background: linear-gradient(135deg,#eff6ff,#e0effe); border: 1px solid #93c5fd; }
        .admin-svc-stat.violet { background: linear-gradient(135deg,#f5f3ff,#ede9fe); border: 1px solid #c4b5fd; }
        .admin-svc-stat.rose   { background: linear-gradient(135deg,#fff1f2,#ffe4e6); border: 1px solid #fecdd3; }
        .admin-svc-stat-icon {
            width: 42px; height: 42px; border-radius: 12px; flex-shrink: 0;
            display: flex; align-items: center; justify-content: center; font-size: 1.05rem;
        }
        .admin-svc-stat-icon.blue   { background: linear-gradient(145deg,#2563eb,#1d4ed8); color: #fff; }
        .admin-svc-stat-icon.violet { background: linear-gradient(145deg,#7c3aed,#6d28d9); color: #fff; }
        .admin-svc-stat-icon.rose   { background: linear-gradient(145deg,#e11d48,#be123c); color: #fff; }
        .admin-svc-stat-value { font-size: 1.5rem; font-weight: 800; color: #0f172a; line-height: 1; }
        .admin-svc-stat-label { font-size: .7rem; font-weight: 600; color: #64748b; margin-top: 3px; text-transform: uppercase; letter-spacing: .3px; }

        /* ── Add category form card ─────────────────────────────────── */
        .admin-cat-add-card {
            background: linear-gradient(135deg,#f8fafc,#f1f5f9);
            border: 1px solid #e2e8f0; border-radius: 18px;
            padding: 20px 22px; margin-bottom: 22px;
        }
        .admin-cat-add-card h3 {
            font-size: .95rem; font-weight: 800; color: #0f172a;
            margin: 0 0 14px; display: flex; align-items: center; gap: 8px;
        }
        .admin-cat-add-card h3 i { color: #0f766e; }

        /* ── Category cards ─────────────────────────────────────────── */
        .category-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 14px;
        }
        .category-card {
            border: 1px solid var(--line); border-radius: 18px;
            padding: 0; background: #fff; overflow: hidden;
            transition: box-shadow .15s, transform .15s;
            display: flex; flex-direction: column;
        }
        .category-card:hover { box-shadow: 0 6px 20px rgba(15,23,42,.08); transform: translateY(-2px); }
        .cat-card-header {
            display: flex; align-items: center; gap: 12px;
            padding: 16px 18px 12px;
            border-bottom: 1px solid #f1f5f9;
        }
        .cat-card-avatar {
            width: 44px; height: 44px; border-radius: 12px; flex-shrink: 0;
            display: flex; align-items: center; justify-content: center;
            font-size: 1.2rem; font-weight: 800; color: #fff;
            background: linear-gradient(135deg,#0f766e,#14b8a6);
        }
        .cat-card-title { font-size: .95rem; font-weight: 800; color: #0f172a; }
        .cat-card-title-ar { font-size: .82rem; color: #64748b; direction: rtl; margin-top: 2px; }
        .cat-card-body { padding: 12px 18px; flex: 1; }
        .cat-card-desc { font-size: .8rem; color: #64748b; line-height: 1.4; }
.category-actions { display: flex; flex-wrap: wrap; gap: 8px; }

        /* ── Category search ────────────────────────────────────────── */
        .admin-cat-search-wrap { position: relative; margin-bottom: 16px; }
        .admin-cat-search-icon {
            position: absolute; top: 50%; transform: translateY(-50%);
            left: 14px; color: #94a3b8; font-size: .88rem; pointer-events: none;
        }
        [dir="rtl"] .admin-cat-search-icon { left: auto; right: 14px; }
        .admin-cat-search-input {
            width: 100%; min-height: 44px;
            border: 2px solid #e2e8f0; border-radius: 12px;
            padding: 9px 12px 9px 40px; font-family: inherit;
            font-size: .9rem; color: #0f172a; background: #fff;
            transition: border-color .2s, box-shadow .2s;
        }
        [dir="rtl"] .admin-cat-search-input { padding: 9px 40px 9px 12px; }
        .admin-cat-search-input:focus {
            outline: none; border-color: #0f766e;
            box-shadow: 0 0 0 4px rgba(15,118,110,.1);
        }

        /* ── Category card collapsible edit ────────────────────────── */
        .cat-edit-form { display: none; }
        .cat-edit-form.cat-edit-open { display: block; }

        @media (max-width: 640px) {
            .admin-svc-stats { grid-template-columns: 1fr; }
            .category-grid   { grid-template-columns: 1fr; }
        }

        /* ── Category request cards (admin) ─────────────────────────── */
        .admin-cat-req-card {
            background: #fff; border: 1px solid #e2e8f0; border-radius: 16px;
            padding: 18px 20px; transition: box-shadow .15s;
        }
        .admin-cat-req-card.pending { border-left: 4px solid #f59e0b; }
        .admin-cat-req-card.approved { border-left: 4px solid #22c55e; }
        .admin-cat-req-card.rejected { border-left: 4px solid #ef4444; }
        [dir="rtl"] .admin-cat-req-card.pending   { border-left: none; border-right: 4px solid #f59e0b; }
        [dir="rtl"] .admin-cat-req-card.approved  { border-left: none; border-right: 4px solid #22c55e; }
        [dir="rtl"] .admin-cat-req-card.rejected  { border-left: none; border-right: 4px solid #ef4444; }
        .admin-cat-req-card:hover { box-shadow: 0 4px 16px rgba(15,23,42,.07); }

        .panel-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 10px;
        }

        .panel-header h2 {
            font-size: 1.3rem;
            font-weight: 700;
        }

        .panel-header p {
            color: var(--muted);
            font-size: 0.92rem;
        }

        /*
         * Panel toolbars for search and filtering controls.
         */
        .panel-toolbar {
            display: flex;
            flex-direction: column;
            gap: 10px;
        }

        .toolbar-form {
            display: grid;
            grid-template-columns: 1.2fr minmax(160px, 0.7fr) minmax(160px, 0.7fr) auto;
            gap: 10px;
            align-items: center;
        }

        .toolbar-form.compact {
            grid-template-columns: 1.2fr minmax(160px, 0.7fr) auto;
        }

        .toolbar-field {
            position: relative;
        }

        .toolbar-field i {
            position: absolute;
            left: 12px;
            top: 50%;
            transform: translateY(-50%);
            color: #64748b;
            font-size: 0.9rem;
            pointer-events: none;
        }

        .toolbar-field input,
        .toolbar-field select {
            width: 100%;
            min-height: 44px;
            border-radius: 14px;
            border: 1px solid var(--line);
            padding: 9px 12px 9px 36px;
            font-family: inherit;
            font-size: 0.9rem;
            background: #fff;
            color: var(--ink);
        }

        [dir="rtl"] .toolbar-field i {
            left: auto;
            right: 12px;
        }

        [dir="rtl"] .toolbar-field input,
        [dir="rtl"] .toolbar-field select {
            padding: 9px 36px 9px 12px;
            text-align: right;
        }

        .toolbar-field input:focus,
        .toolbar-field select:focus {
            outline: none;
            border-color: rgba(15, 118, 110, 0.55);
            box-shadow: 0 0 0 3px rgba(15, 118, 110, 0.12);
        }

        .card-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
            gap: 14px;
        }

        .card {
            border: 1px solid var(--line);
            border-radius: 20px;
            padding: 16px;
            background: #fff;
            display: flex;
            flex-direction: column;
            gap: 12px;
        }

        .card-header {
            display: flex;
            align-items: flex-start;
            justify-content: space-between;
            gap: 10px;
        }

        .card-header h3 {
            font-size: 1.05rem;
            font-weight: 700;
        }

        .status {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 6px 12px;
            border-radius: 999px;
            font-size: 0.78rem;
            font-weight: 700;
        }

        .status-stack {
            display: flex;
            flex-direction: column;
            align-items: flex-end;
            gap: 6px;
        }

        .status.verified {
            background: rgba(16, 185, 129, 0.14);
            color: #047857;
        }

        .status.unverified {
            background: rgba(245, 158, 11, 0.14);
            color: #92400e;
        }

        .status.active {
            background: rgba(16, 185, 129, 0.14);
            color: #047857;
        }

        .status.suspended {
            background: rgba(239, 68, 68, 0.14);
            color: #b91c1c;
        }

        .status.customer {
            background: rgba(59, 130, 246, 0.14);
            color: #1d4ed8;
        }

        .meta {
            display: grid;
            gap: 6px;
            font-size: 0.9rem;
            color: var(--muted);
        }

        .meta strong {
            color: var(--ink);
            font-weight: 600;
        }

        .card-actions {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
        }

        .empty-state {
            padding: 18px;
            border-radius: 18px;
            border: 1px dashed var(--line);
            color: var(--muted);
            text-align: center;
            background: rgba(255, 255, 255, 0.8);
        }

        @media (max-width: 720px) {
            .topbar {
                flex-direction: column;
                align-items: flex-start;
            }

            .toolbar-form {
                grid-template-columns: 1fr;
            }

            .settings-grid,
            .category-grid {
                grid-template-columns: 1fr;
            }

            .card-actions {
                flex-direction: column;
                align-items: stretch;
            }

            .btn {
                width: 100%;
            }
        }

        @media (max-width: 480px) {
            body {
                padding: 12px 10px 24px;
                gap: 12px;
            }

            .topbar {
                padding: 12px;
                border-radius: 16px;
            }

            .topbar h1 {
                font-size: 1.1rem;
            }

            .panel {
                padding: 14px;
                border-radius: 16px;
            }

            .card {
                border-radius: 16px;
            }

            /* Reviews filter: stack all controls full-width on phones */
            #reviewsFilterForm .toolbar-field,
            #reviewsFilterForm .btn {
                flex: 1 1 100%;
                min-width: 0;
                width: 100%;
            }

            /* Panel header: allow title and actions to stack */
            .panel-header {
                flex-wrap: wrap;
            }
        }

        /*
         * Mobile sidebar toggle button and backdrop overlay.
         */
        .sidebar-toggle {
            display: none;
            position: fixed;
            top: 16px;
            left: 16px;
            z-index: 120;
            width: 46px;
            height: 46px;
            border-radius: 14px;
            border: 1px solid rgba(15, 23, 42, 0.12);
            background: #fff;
            color: var(--ink);
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

        /*
         * Sidebar navigation with permanent display on left side.
         * Always visible, taking 15% of the page width.
         */
        .sidebar {
            position: relative;
            left: 0;
            top: 0;
            height: 100vh;
            width: 15%;
            min-width: 180px;
            background: linear-gradient(180deg, rgba(15, 118, 110, 0.98), rgba(17, 94, 89, 0.98));
            backdrop-filter: blur(16px);
            border-right: 1px solid rgba(255, 255, 255, 0.1);
            transform: none;
            transition: none;
            z-index: 100;
            box-shadow: 4px 0 24px rgba(15, 23, 42, 0.25);
            display: flex;
            flex-direction: column;
            padding-top: 20px;
            padding-bottom: 20px;
            overflow: hidden;
            box-sizing: border-box;
        }

        .sidebar.open {
            transform: none;
        }

        @media (max-width: 1100px) {
            .sidebar {
                position: fixed;
                left: 0;
                top: 0;
                width: min(82vw, 320px);
                height: 100vh;
                transform: translateX(-100%);
                transition: transform 0.25s ease;
            }

            .sidebar.open {
                transform: translateX(0);
            }

            .sidebar-toggle {
                display: inline-flex;
            }

            .sidebar-backdrop {
                display: block;
            }

            body.sidebar-open .sidebar-backdrop {
                opacity: 1;
                pointer-events: auto;
            }

            .shell {
                width: 100%;
                margin-left: 0;
            }

            .topbar {
                padding-left: 56px;
            }

            [dir="rtl"] .sidebar {
                left: auto;
                right: 0;
                transform: translateX(100%);
            }

            [dir="rtl"] .sidebar.open {
                transform: translateX(0);
            }

            [dir="rtl"] .sidebar-toggle {
                left: auto;
                right: 16px;
            }

            [dir="rtl"] .topbar {
                padding-left: 0;
                padding-right: 56px;
            }
        }

        @media (max-width: 900px) {
            /*
             * Stack toolbar controls for smaller screens.
             */
            .toolbar-form,
            .toolbar-form.compact {
                grid-template-columns: 1fr;
            }

            .panel-toolbar .btn {
                width: 100%;
            }
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

        .sidebar-user-details {
            flex: 1;
            min-width: 0;
        }

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
            overflow-x: hidden;
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
            cursor: pointer;
            border: none;
            background: none;
            width: 100%;
            text-align: left;
            transition: all 0.2s ease;
            border-left: 3px solid transparent;
        }

        .sidebar-menu-item:hover {
            background: rgba(255, 255, 255, 0.12);
            border-left-color: #22d3ee;
            color: #fff;
            padding-left: 14px;
            transform: translateX(2px);
        }

        .sidebar-menu-item i {
            min-width: 20px;
            text-align: center;
            font-size: 1rem;
        }

        .sidebar-footer {
            padding: 16px;
            border-top: 1px solid rgba(255, 255, 255, 0.15);
            margin-top: auto;
            flex-shrink: 0;
        }

        /*
         * Adjust main content when sidebar is open to account for fixed positioning.
         */
        body.sidebar-open {
            overflow: hidden;
        }
        [dir="rtl"] body { font-family: 'Cairo', sans-serif; }
        [dir="rtl"] .sidebar { right: 0; left: auto; border-right: none; border-left: 1px solid rgba(255,255,255,.15); }
        [dir="rtl"] input, [dir="rtl"] textarea, [dir="rtl"] select { text-align: right; }

        .admin-chat-link {
            display: inline-flex; align-items: center; gap: 8px;
            padding: 10px 18px; border-radius: 12px; text-decoration: none;
            background: linear-gradient(135deg, #0f766e, #115e59); color: #fff;
            font-weight: 700; font-size: .9rem; transition: filter .2s;
        }
        .admin-chat-link:hover { filter: brightness(1.06); }
        .admin-chat-unread {
            background: #ef4444; color: #fff; border-radius: 999px;
            font-size: .7rem; font-weight: 800; padding: 1px 7px; min-width: 20px;
            text-align: center;
        }
    </style>
</head>
<body class="<?php echo htmlspecialchars(getLangBodyClass(), ENT_QUOTES, 'UTF-8'); ?>">
    <!-- Mobile sidebar toggle control -->
    <button class="sidebar-toggle" type="button" id="sidebarToggle" aria-label="Open navigation menu" aria-controls="sidebar" aria-expanded="false">
        <i class="fas fa-bars" aria-hidden="true"></i>
    </button>

    <!-- Mobile sidebar backdrop to dismiss the menu -->
    <div class="sidebar-backdrop" id="sidebarBackdrop" aria-hidden="true"></div>

    <aside class="sidebar" id="sidebar" aria-label="Navigation menu">
        <div class="sidebar-header">
            <h2><?php echo htmlspecialchars(t('admin_nav_menu'), ENT_QUOTES, 'UTF-8'); ?></h2>
        </div>

        <div class="sidebar-user-info">
            <div class="sidebar-user-badge">
                <i class="fas fa-shield"></i>
            </div>
            <div class="sidebar-user-details">
                <div class="sidebar-user-id"><?php echo htmlspecialchars(t('admin_nav_admin'), ENT_QUOTES, 'UTF-8'); ?></div>
                <div class="sidebar-user-email no-ar-numerals" dir="ltr"><?php echo htmlspecialchars($adminEmail !== '' ? $adminEmail : t('sidebar_no_email'), ENT_QUOTES, 'UTF-8'); ?></div>
            </div>
        </div>

        <nav class="sidebar-menu">
            <?php $dash = htmlspecialchars($appBase, ENT_QUOTES, 'UTF-8') . '/admin_dashboard.php'; ?>
            <a href="<?php echo $dash; ?>" class="sidebar-menu-item">
                <i class="fas fa-chart-line"></i>
                <?php echo htmlspecialchars(t('sidebar_dashboard'), ENT_QUOTES, 'UTF-8'); ?>
            </a>
            <a href="<?php echo $dash; ?>#service-providers" class="sidebar-menu-item">
                <i class="fas fa-person-wrench"></i>
                <?php echo htmlspecialchars(t('admin_nav_providers'), ENT_QUOTES, 'UTF-8'); ?>
            </a>
            <a href="<?php echo $dash; ?>#customers" class="sidebar-menu-item">
                <i class="fas fa-users"></i>
                <?php echo htmlspecialchars(t('admin_nav_customers'), ENT_QUOTES, 'UTF-8'); ?>
            </a>
            <a href="<?php echo $dash; ?>#interactions" class="sidebar-menu-item">
                <i class="fas fa-arrows-left-right-to-line"></i>
                <?php echo htmlspecialchars(t('admin_nav_interactions'), ENT_QUOTES, 'UTF-8'); ?>
            </a>
            <a href="<?php echo $dash; ?>#service-categories" class="sidebar-menu-item">
                <i class="fas fa-layer-group"></i>
                <?php echo htmlspecialchars(t('admin_nav_categories'), ENT_QUOTES, 'UTF-8'); ?>
            </a>
            <a href="<?php echo $dash; ?>#reviews" class="sidebar-menu-item">
                <i class="fa-solid fa-star" aria-hidden="true"></i>
                <?php echo htmlspecialchars(t('admin_nav_reviews'), ENT_QUOTES, 'UTF-8'); ?>
            </a>
            <a href="<?php echo $dash; ?>#location-requests" class="sidebar-menu-item" style="position:relative;">
                <i class="fas fa-map-marker-alt"></i>
                <?php echo htmlspecialchars(t('admin_nav_location_requests'), ENT_QUOTES, 'UTF-8'); ?>
                <?php if ($pendingLocationCount > 0): ?>
                    <span style="position:absolute;top:6px;<?php echo isRtl()?'left':'right'; ?>:10px;background:#ef4444;color:#fff;font-size:.7rem;font-weight:700;border-radius:999px;min-width:18px;height:18px;display:inline-flex;align-items:center;justify-content:center;padding:0 4px;"><?php echo $pendingLocationCount; ?></span>
                <?php endif; ?>
            </a>
            <a href="<?php echo $dash; ?>#site-settings" class="sidebar-menu-item">
                <i class="fas fa-sliders"></i>
                <?php echo htmlspecialchars(t('admin_settings'), ENT_QUOTES, 'UTF-8'); ?>
            </a>
            <a href="change_password.php" class="sidebar-menu-item">
                <i class="fas fa-key"></i>
                <?php echo htmlspecialchars(t('sidebar_change_password'), ENT_QUOTES, 'UTF-8'); ?>
            </a>
        </nav>

        <div class="sidebar-footer">
            <a href="logout.php" class="sidebar-menu-item">
                <i class="fas fa-right-from-bracket"></i>
                <?php echo htmlspecialchars(t('admin_nav_logout'), ENT_QUOTES, 'UTF-8'); ?>
            </a>
        </div>
    </aside>

    <span class="glow one" aria-hidden="true"></span>
    <span class="glow two" aria-hidden="true"></span>

    <div class="shell">
        <!-- Admin header section -->
        <header class="topbar">
            <div class="brand">
                <h1><?php echo htmlspecialchars(t('admin_title'), ENT_QUOTES, 'UTF-8'); ?></h1>
                <p><?php echo htmlspecialchars(t('admin_chat_mgmt_sub'), ENT_QUOTES, 'UTF-8'); ?></p>
            </div>
            <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
                <a href="admin_chat.php" class="admin-chat-link">
                    <i class="fa-solid fa-comments"></i>
                    <?php echo htmlspecialchars(t('admin_live_chat'), ENT_QUOTES, 'UTF-8'); ?>
                    <span class="admin-chat-unread" id="adminChatBadge"<?php if ($adminChatUnread <= 0) echo ' style="display:none"'; ?>><?php echo $adminChatUnread > 0 ? (int) $adminChatUnread : ''; ?></span>
                </a>
                <a href="<?php echo htmlspecialchars(langSwitchUrl(), ENT_QUOTES, 'UTF-8'); ?>"
                   style="display:inline-flex;align-items:center;gap:6px;font-size:.82rem;font-weight:700;color:#0f766e;text-decoration:none;border:1.5px solid #dbe2ea;padding:6px 14px;border-radius:999px;background:#fff;white-space:nowrap;">
                    <i class="fa-solid fa-globe"></i><?php echo htmlspecialchars(t('lang_switch_label'), ENT_QUOTES, 'UTF-8'); ?>
                </a>
            </div>
        </header>

        <!-- Status feedback messages -->
        <?php if ($errorMessage !== ''): ?>
            <div class="feedback error"><?php echo htmlspecialchars($errorMessage, ENT_QUOTES, 'UTF-8'); ?></div>
        <?php elseif ($successMessage !== ''): ?>
            <div class="feedback success"><?php echo htmlspecialchars($successMessage, ENT_QUOTES, 'UTF-8'); ?></div>
        <?php endif; ?>

        <!-- Summary metrics -->
        <section class="metrics" aria-label="Admin summary">
            <div class="metric-card blue">
                <div class="metric-icon"><i class="fas fa-user-tie" aria-hidden="true"></i></div>
                <div>
                    <h3><?php echo htmlspecialchars(t('admin_providers'), ENT_QUOTES, 'UTF-8'); ?></h3>
                    <p><?php echo (int) $providerCount; ?></p>
                </div>
            </div>
            <div class="metric-card teal">
                <div class="metric-icon"><i class="fas fa-badge-check" aria-hidden="true"></i></div>
                <div>
                    <h3><?php echo htmlspecialchars(t('prov_verified_badge'), ENT_QUOTES, 'UTF-8'); ?> <?php echo htmlspecialchars(t('admin_providers'), ENT_QUOTES, 'UTF-8'); ?></h3>
                    <p><?php echo (int) $verifiedProviderCount; ?></p>
                </div>
            </div>
            <div class="metric-card violet">
                <div class="metric-icon"><i class="fas fa-users" aria-hidden="true"></i></div>
                <div>
                    <h3><?php echo htmlspecialchars(t('admin_customers'), ENT_QUOTES, 'UTF-8'); ?></h3>
                    <p><?php echo (int) $customerCount; ?></p>
                </div>
            </div>
            <?php if ($adminChatUnread > 0): ?>
            <div class="metric-card rose" style="cursor:pointer;" onclick="window.location='admin_chat.php'">
                <div class="metric-icon"><i class="fas fa-comments" aria-hidden="true"></i></div>
                <div>
                    <h3><?php echo htmlspecialchars(t('admin_live_chat'), ENT_QUOTES, 'UTF-8'); ?></h3>
                    <p><?php echo $adminChatUnread; ?> <span style="font-size:.75rem;font-weight:600;"><?php echo htmlspecialchars(t('admin_chat_badge'), ENT_QUOTES, 'UTF-8'); ?></span></p>
                </div>
            </div>
            <?php endif; ?>
        </section>

        <!-- Home Page Settings Section -->
        <section id="site-settings" class="panel">
            <div class="panel-header">
                <div>
                    <h2>Home Page Settings</h2>
                    <p>Control the public home page messaging and contact details.</p>
                </div>
                <a class="btn ghost" href="home.php" target="_blank">Preview Home</a>
            </div>

            <form class="settings-form" method="post" action="<?php echo htmlspecialchars($appBase, ENT_QUOTES, 'UTF-8'); ?>/admin_dashboard.php#site-settings" enctype="multipart/form-data">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['admin_dashboard_csrf'], ENT_QUOTES, 'UTF-8'); ?>">
                <input type="hidden" name="action" value="update_site_settings">

                <div class="settings-grid">
                    <div class="settings-field">
                        <label for="site_name">Site name</label>
                        <input id="site_name" name="site_name" type="text" value="<?php echo htmlspecialchars($siteSettings['site_name'], ENT_QUOTES, 'UTF-8'); ?>" required>
                    </div>
                    <div class="settings-field">
                        <label for="site_tagline">Site tagline</label>
                        <input id="site_tagline" name="site_tagline" type="text" value="<?php echo htmlspecialchars($siteSettings['site_tagline'], ENT_QUOTES, 'UTF-8'); ?>">
                    </div>
                    <div class="settings-field">
                        <label for="primary_cta_text">Primary CTA text</label>
                        <input id="primary_cta_text" name="primary_cta_text" type="text" value="<?php echo htmlspecialchars($siteSettings['primary_cta_text'], ENT_QUOTES, 'UTF-8'); ?>">
                    </div>
                    <div class="settings-field">
                        <label for="support_email">Support email</label>
                        <input id="support_email" name="support_email" type="email" dir="ltr" value="<?php echo htmlspecialchars($siteSettings['support_email'], ENT_QUOTES, 'UTF-8'); ?>">
                    </div>
                    <div class="settings-field">
                        <label for="support_phone">Support phone</label>
                        <input id="support_phone" name="support_phone" type="text" dir="ltr" value="<?php echo htmlspecialchars($siteSettings['support_phone'], ENT_QUOTES, 'UTF-8'); ?>">
                    </div>
                    <div class="settings-field">
                        <label for="hero_title">Hero title</label>
                        <input id="hero_title" name="hero_title" type="text" value="<?php echo htmlspecialchars($siteSettings['hero_title'], ENT_QUOTES, 'UTF-8'); ?>" required>
                    </div>
                </div>

                <div class="settings-field">
                    <label for="hero_subtitle">Hero subtitle</label>
                    <textarea id="hero_subtitle" name="hero_subtitle"><?php echo htmlspecialchars($siteSettings['hero_subtitle'], ENT_QUOTES, 'UTF-8'); ?></textarea>
                </div>

                <!-- Social links for home page footer icons -->
                <div class="settings-grid">
                    <div class="settings-field">
                        <label for="facebook_url">Facebook URL</label>
                        <input id="facebook_url" name="facebook_url" type="url" placeholder="https://facebook.com/yourpage" value="<?php echo htmlspecialchars($siteSettings['facebook_url'], ENT_QUOTES, 'UTF-8'); ?>">
                    </div>
                    <div class="settings-field">
                        <label for="instagram_url">Instagram URL</label>
                        <input id="instagram_url" name="instagram_url" type="url" placeholder="https://instagram.com/yourprofile" value="<?php echo htmlspecialchars($siteSettings['instagram_url'], ENT_QUOTES, 'UTF-8'); ?>">
                    </div>
                    <div class="settings-field">
                        <label for="linkedin_url">LinkedIn URL</label>
                        <input id="linkedin_url" name="linkedin_url" type="url" placeholder="https://linkedin.com/company/yourpage" value="<?php echo htmlspecialchars($siteSettings['linkedin_url'], ENT_QUOTES, 'UTF-8'); ?>">
                    </div>
                </div>

                <!-- Site favicon upload used in browser tabs -->
                <div class="settings-field">
                    <label for="site_favicon">Site icon (browser tab)</label>
                    <input id="site_favicon" name="site_favicon" type="file" accept="image/png,image/jpeg,image/webp,image/x-icon,image/vnd.microsoft.icon">
                    <p class="settings-hint">Upload PNG, JPG, WEBP, or ICO. Max 1 MB.</p>
                </div>
                <?php if (!empty($siteSettings['site_favicon'])): ?>
                    <div class="settings-field">
                        <label>Current site icon</label>
                        <div class="highlight-grid">
                            <label class="highlight-card">
                                <img src="<?php echo htmlspecialchars($siteSettings['site_favicon'], ENT_QUOTES, 'UTF-8'); ?>" alt="Site icon preview">
                                <span>Remove current icon</span>
                                <input type="checkbox" name="remove_site_favicon" value="1">
                            </label>
                        </div>
                    </div>
                <?php endif; ?>

                <!-- Highlight images used in the animated home page reel -->
                <div class="settings-field">
                    <label for="highlight_images">Highlight photos</label>
                    <input id="highlight_images" name="highlight_images[]" type="file" accept="image/jpeg,image/png,image/webp" multiple>
                    <p class="settings-hint">Upload up to <?php echo (int) HIGHLIGHT_IMAGE_MAX_COUNT; ?> images (JPG, PNG, or WEBP). Max 2 MB each. Recommended size: 1200 × 400 px (landscape).</p>
                </div>
                <?php if (count($highlightImageList) > 0): ?>
                    <div class="settings-field">
                        <label>Current highlight photos</label>
                        <div class="highlight-grid">
                            <?php foreach ($highlightImageList as $imagePath): ?>
                                <label class="highlight-card">
                                    <img src="<?php echo htmlspecialchars($imagePath, ENT_QUOTES, 'UTF-8'); ?>" alt="Highlight image preview">
                                    <span>Remove this photo</span>
                                    <input type="checkbox" name="remove_highlight_images[]" value="<?php echo htmlspecialchars($imagePath, ENT_QUOTES, 'UTF-8'); ?>">
                                </label>
                            <?php endforeach; ?>
                        </div>
                    </div>
                <?php endif; ?>

                <div class="settings-grid">
                    <div class="settings-field">
                        <label for="feature_1_title">Feature 1 title</label>
                        <input id="feature_1_title" name="feature_1_title" type="text" value="<?php echo htmlspecialchars($siteSettings['feature_1_title'], ENT_QUOTES, 'UTF-8'); ?>">
                    </div>
                    <div class="settings-field">
                        <label for="feature_2_title">Feature 2 title</label>
                        <input id="feature_2_title" name="feature_2_title" type="text" value="<?php echo htmlspecialchars($siteSettings['feature_2_title'], ENT_QUOTES, 'UTF-8'); ?>">
                    </div>
                    <div class="settings-field">
                        <label for="feature_3_title">Feature 3 title</label>
                        <input id="feature_3_title" name="feature_3_title" type="text" value="<?php echo htmlspecialchars($siteSettings['feature_3_title'], ENT_QUOTES, 'UTF-8'); ?>">
                    </div>
                    <div class="settings-field">
                        <label for="footer_note">Footer note</label>
                        <input id="footer_note" name="footer_note" type="text" value="<?php echo htmlspecialchars($siteSettings['footer_note'], ENT_QUOTES, 'UTF-8'); ?>">
                    </div>
                </div>

                <div class="settings-grid">
                    <div class="settings-field">
                        <label for="feature_1_body">Feature 1 body</label>
                        <textarea id="feature_1_body" name="feature_1_body"><?php echo htmlspecialchars($siteSettings['feature_1_body'], ENT_QUOTES, 'UTF-8'); ?></textarea>
                    </div>
                    <div class="settings-field">
                        <label for="feature_2_body">Feature 2 body</label>
                        <textarea id="feature_2_body" name="feature_2_body"><?php echo htmlspecialchars($siteSettings['feature_2_body'], ENT_QUOTES, 'UTF-8'); ?></textarea>
                    </div>
                    <div class="settings-field">
                        <label for="feature_3_body">Feature 3 body</label>
                        <textarea id="feature_3_body" name="feature_3_body"><?php echo htmlspecialchars($siteSettings['feature_3_body'], ENT_QUOTES, 'UTF-8'); ?></textarea>
                    </div>
                </div>

                <!-- Pinned provider and review for the home page slideshow -->
                <div class="settings-grid">
                    <div class="settings-field">
                        <label for="pinned_provider_id">Featured service provider</label>
                        <select id="pinned_provider_id" name="pinned_provider_id">
                            <option value="0">— None —</option>
                            <?php foreach ($allProviders as $providerOption): ?>
                                <?php $optProviderId = (int) ($providerOption['provider_id'] ?? 0); ?>
                                <option value="<?php echo $optProviderId; ?>" <?php echo $pinnedProviderId === $optProviderId ? 'selected' : ''; ?>>
                                    <?php echo htmlspecialchars((string) ($providerOption['name'] ?? ''), ENT_QUOTES, 'UTF-8'); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                        <p class="settings-hint">This provider's slide will appear first in the homepage slideshow.</p>
                    </div>
                    <div class="settings-field">
                        <label for="pinned_review_id">Featured review / testimonial</label>
                        <select id="pinned_review_id" name="pinned_review_id">
                            <option value="0">— None —</option>
                            <?php foreach ($allReviews as $reviewOption): ?>
                                <?php
                                $optReviewId     = (int) ($reviewOption['request_id'] ?? 0);
                                $optCustomerName = (string) ($reviewOption['customer_name'] ?? 'Customer');
                                $optProviderName = (string) ($reviewOption['provider_name'] ?? '');
                                $optRating       = (int) ($reviewOption['rating'] ?? 0);
                                $optReviewSnip   = trim((string) ($reviewOption['review'] ?? ''));
                                if (mb_strlen($optReviewSnip) > 60) {
                                    $optReviewSnip = mb_substr($optReviewSnip, 0, 60) . '…';
                                }
                                $optLabel = $optCustomerName
                                    . ($optProviderName !== '' ? ' → ' . $optProviderName : '')
                                    . ' (' . $optRating . '/5)'
                                    . ($optReviewSnip !== '' ? ' — "' . $optReviewSnip . '"' : '');
                                ?>
                                <option value="<?php echo $optReviewId; ?>" <?php echo $pinnedReviewId === $optReviewId ? 'selected' : ''; ?>>
                                    <?php echo htmlspecialchars($optLabel, ENT_QUOTES, 'UTF-8'); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                        <p class="settings-hint">This review will appear first in the homepage slideshow.</p>
                    </div>
                </div>

                <!-- Arabic content section for bilingual homepage -->
                <hr style="margin:24px 0;border:none;border-top:1px solid #e2e8f0;">
                <h3 style="font-size:1rem;font-weight:700;margin-bottom:14px;color:#0f766e;">
                    <i class="fas fa-language" aria-hidden="true"></i>
                    <?php echo htmlspecialchars(t('admin_settings_ar_section'), ENT_QUOTES, 'UTF-8'); ?>
                </h3>
                <div class="settings-grid">
                    <div class="settings-field">
                        <label for="site_name_ar"><?php echo htmlspecialchars(t('admin_settings_site_name_ar'), ENT_QUOTES, 'UTF-8'); ?></label>
                        <input id="site_name_ar" name="site_name_ar" type="text" dir="rtl"
                            value="<?php echo htmlspecialchars($siteSettings['site_name_ar'] ?? '', ENT_QUOTES, 'UTF-8'); ?>"
                            placeholder="اسم الموقع بالعربية">
                    </div>
                    <div class="settings-field">
                        <label for="site_tagline_ar"><?php echo htmlspecialchars(t('admin_settings_tagline_ar'), ENT_QUOTES, 'UTF-8'); ?></label>
                        <input id="site_tagline_ar" name="site_tagline_ar" type="text" dir="rtl"
                            value="<?php echo htmlspecialchars($siteSettings['site_tagline_ar'] ?? '', ENT_QUOTES, 'UTF-8'); ?>"
                            placeholder="شعار الموقع بالعربية">
                    </div>
                    <div class="settings-field">
                        <label for="hero_title_ar"><?php echo htmlspecialchars(t('admin_settings_hero_title_ar'), ENT_QUOTES, 'UTF-8'); ?></label>
                        <input id="hero_title_ar" name="hero_title_ar" type="text" dir="rtl"
                            value="<?php echo htmlspecialchars($siteSettings['hero_title_ar'] ?? '', ENT_QUOTES, 'UTF-8'); ?>"
                            placeholder="عنوان البانر الرئيسي بالعربية">
                    </div>
                    <div class="settings-field">
                        <label for="primary_cta_text_ar"><?php echo htmlspecialchars(t('admin_settings_cta_ar'), ENT_QUOTES, 'UTF-8'); ?></label>
                        <input id="primary_cta_text_ar" name="primary_cta_text_ar" type="text" dir="rtl"
                            value="<?php echo htmlspecialchars($siteSettings['primary_cta_text_ar'] ?? '', ENT_QUOTES, 'UTF-8'); ?>"
                            placeholder="نص الزر بالعربية">
                    </div>
                </div>
                <div class="settings-field">
                    <label for="hero_subtitle_ar"><?php echo htmlspecialchars(t('admin_settings_hero_sub_ar'), ENT_QUOTES, 'UTF-8'); ?></label>
                    <textarea id="hero_subtitle_ar" name="hero_subtitle_ar" dir="rtl"
                        placeholder="وصف البانر الرئيسي بالعربية"><?php echo htmlspecialchars($siteSettings['hero_subtitle_ar'] ?? '', ENT_QUOTES, 'UTF-8'); ?></textarea>
                </div>

                <div class="settings-grid" style="margin-top:16px;">
                    <div class="settings-field">
                        <label for="feature_1_title_ar"><?php echo htmlspecialchars(t('admin_settings_feat1_title_ar'), ENT_QUOTES, 'UTF-8'); ?></label>
                        <input id="feature_1_title_ar" name="feature_1_title_ar" type="text" dir="rtl"
                            value="<?php echo htmlspecialchars($siteSettings['feature_1_title_ar'] ?? '', ENT_QUOTES, 'UTF-8'); ?>"
                            placeholder="عنوان الميزة الأولى">
                    </div>
                    <div class="settings-field">
                        <label for="feature_1_body_ar"><?php echo htmlspecialchars(t('admin_settings_feat1_body_ar'), ENT_QUOTES, 'UTF-8'); ?></label>
                        <input id="feature_1_body_ar" name="feature_1_body_ar" type="text" dir="rtl"
                            value="<?php echo htmlspecialchars($siteSettings['feature_1_body_ar'] ?? '', ENT_QUOTES, 'UTF-8'); ?>"
                            placeholder="وصف الميزة الأولى">
                    </div>
                    <div class="settings-field">
                        <label for="feature_2_title_ar"><?php echo htmlspecialchars(t('admin_settings_feat2_title_ar'), ENT_QUOTES, 'UTF-8'); ?></label>
                        <input id="feature_2_title_ar" name="feature_2_title_ar" type="text" dir="rtl"
                            value="<?php echo htmlspecialchars($siteSettings['feature_2_title_ar'] ?? '', ENT_QUOTES, 'UTF-8'); ?>"
                            placeholder="عنوان الميزة الثانية">
                    </div>
                    <div class="settings-field">
                        <label for="feature_2_body_ar"><?php echo htmlspecialchars(t('admin_settings_feat2_body_ar'), ENT_QUOTES, 'UTF-8'); ?></label>
                        <input id="feature_2_body_ar" name="feature_2_body_ar" type="text" dir="rtl"
                            value="<?php echo htmlspecialchars($siteSettings['feature_2_body_ar'] ?? '', ENT_QUOTES, 'UTF-8'); ?>"
                            placeholder="وصف الميزة الثانية">
                    </div>
                    <div class="settings-field">
                        <label for="feature_3_title_ar"><?php echo htmlspecialchars(t('admin_settings_feat3_title_ar'), ENT_QUOTES, 'UTF-8'); ?></label>
                        <input id="feature_3_title_ar" name="feature_3_title_ar" type="text" dir="rtl"
                            value="<?php echo htmlspecialchars($siteSettings['feature_3_title_ar'] ?? '', ENT_QUOTES, 'UTF-8'); ?>"
                            placeholder="عنوان الميزة الثالثة">
                    </div>
                    <div class="settings-field">
                        <label for="feature_3_body_ar"><?php echo htmlspecialchars(t('admin_settings_feat3_body_ar'), ENT_QUOTES, 'UTF-8'); ?></label>
                        <input id="feature_3_body_ar" name="feature_3_body_ar" type="text" dir="rtl"
                            value="<?php echo htmlspecialchars($siteSettings['feature_3_body_ar'] ?? '', ENT_QUOTES, 'UTF-8'); ?>"
                            placeholder="وصف الميزة الثالثة">
                    </div>
                    <div class="settings-field">
                        <label for="footer_note_ar"><?php echo htmlspecialchars(t('admin_settings_footer_note_ar'), ENT_QUOTES, 'UTF-8'); ?></label>
                        <input id="footer_note_ar" name="footer_note_ar" type="text" dir="rtl"
                            value="<?php echo htmlspecialchars($siteSettings['footer_note_ar'] ?? '', ENT_QUOTES, 'UTF-8'); ?>"
                            placeholder="ملاحظة التذييل بالعربية">
                    </div>
                </div>

                <button class="btn primary" type="submit">
                    <i class="fa-solid fa-floppy-disk" aria-hidden="true"></i>
                    Save Home Settings
                </button>
            </form>
        </section>

        <!-- Service category management section -->
        <section id="service-categories" class="panel" style="flex-direction:column;">
            <?php
                $pendingCatReqsCount = count(array_filter($allCategoryRequests, static fn($r) => $r['status'] === 'pending'));
                $catColors = ['#0f766e','#4f46e5','#d97706','#dc2626','#7c3aed','#0284c7','#059669','#db2777'];
            ?>

            <!-- Panel header -->
            <div class="panel-header">
                <div>
                    <h2><?php echo htmlspecialchars(t('admin_cat_title'), ENT_QUOTES, 'UTF-8'); ?></h2>
                    <p class="panel-lead"><?php echo htmlspecialchars(t('admin_cat_lead'), ENT_QUOTES, 'UTF-8'); ?></p>
                </div>
                <?php if ($pendingCatReqsCount > 0): ?>
                    <span class="status unverified" style="font-size:.85rem;">
                        <i class="fas fa-clock"></i>
                        <?php echo $pendingCatReqsCount; ?> <?php echo htmlspecialchars(t('admin_loc_pending'), ENT_QUOTES, 'UTF-8'); ?>
                    </span>
                <?php endif; ?>
            </div>

            <!-- Stats bar -->
            <div class="admin-svc-stats">
                <div class="admin-svc-stat blue">
                    <div class="admin-svc-stat-icon blue"><i class="fas fa-layer-group" aria-hidden="true"></i></div>
                    <div>
                        <div class="admin-svc-stat-value"><?php echo count($serviceCategories); ?></div>
                        <div class="admin-svc-stat-label"><?php echo htmlspecialchars(t('admin_cat_stat_total'), ENT_QUOTES, 'UTF-8'); ?></div>
                    </div>
                </div>
                <div class="admin-svc-stat violet">
                    <div class="admin-svc-stat-icon violet"><i class="fas fa-clock" aria-hidden="true"></i></div>
                    <div>
                        <div class="admin-svc-stat-value"><?php echo $pendingCatReqsCount; ?></div>
                        <div class="admin-svc-stat-label"><?php echo htmlspecialchars(t('admin_cat_stat_pending'), ENT_QUOTES, 'UTF-8'); ?></div>
                    </div>
                </div>
                <div class="admin-svc-stat rose">
                    <div class="admin-svc-stat-icon rose"><i class="fas fa-users" aria-hidden="true"></i></div>
                    <div>
                        <div class="admin-svc-stat-value"><?php echo $providerCount; ?></div>
                        <div class="admin-svc-stat-label"><?php echo htmlspecialchars(t('admin_cat_stat_providers'), ENT_QUOTES, 'UTF-8'); ?></div>
                    </div>
                </div>
            </div>

            <!-- Add category form -->
            <div class="admin-cat-add-card">
                <h3><i class="fas fa-circle-plus" aria-hidden="true"></i> <?php echo htmlspecialchars(t('admin_cat_add_title'), ENT_QUOTES, 'UTF-8'); ?></h3>
                <form class="category-form" method="post" action="<?php echo htmlspecialchars($appBase, ENT_QUOTES, 'UTF-8'); ?>/admin_dashboard.php#service-categories">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['admin_dashboard_csrf'], ENT_QUOTES, 'UTF-8'); ?>">
                    <input type="hidden" name="action" value="create_category">
                    <div class="settings-grid">
                        <div class="settings-field">
                            <label for="category_name"><?php echo htmlspecialchars(t('admin_cat_name_en_label'), ENT_QUOTES, 'UTF-8'); ?></label>
                            <input id="category_name" name="category_name" type="text" placeholder="<?php echo htmlspecialchars(t('admin_cat_name_en_ph'), ENT_QUOTES, 'UTF-8'); ?>" required>
                        </div>
                        <div class="settings-field">
                            <label for="category_name_ar"><?php echo htmlspecialchars(t('admin_cat_name_ar_label'), ENT_QUOTES, 'UTF-8'); ?></label>
                            <input id="category_name_ar" name="category_name_ar" type="text" placeholder="<?php echo htmlspecialchars(t('admin_cat_name_ar_ph'), ENT_QUOTES, 'UTF-8'); ?>" dir="rtl">
                        </div>
                        <div class="settings-field">
                            <label for="category_description"><?php echo htmlspecialchars(t('admin_cat_desc_en_label'), ENT_QUOTES, 'UTF-8'); ?></label>
                            <textarea id="category_description" name="category_description" placeholder="<?php echo htmlspecialchars(t('admin_cat_desc_en_ph'), ENT_QUOTES, 'UTF-8'); ?>"></textarea>
                        </div>
                        <div class="settings-field">
                            <label for="category_description_ar"><?php echo htmlspecialchars(t('admin_cat_desc_ar_label'), ENT_QUOTES, 'UTF-8'); ?></label>
                            <textarea id="category_description_ar" name="category_description_ar" placeholder="<?php echo htmlspecialchars(t('admin_cat_desc_ar_ph'), ENT_QUOTES, 'UTF-8'); ?>" dir="rtl"></textarea>
                        </div>
                    </div>
                    <button class="btn primary" type="submit" style="margin-top:4px;">
                        <i class="fa-solid fa-plus" aria-hidden="true"></i>
                        <?php echo htmlspecialchars(t('admin_cat_add_btn'), ENT_QUOTES, 'UTF-8'); ?>
                    </button>
                </form>
            </div>

            <!-- Category search -->
            <?php if (count($serviceCategories) > 0): ?>
                <div class="admin-cat-search-wrap">
                    <i class="fas fa-search admin-cat-search-icon" aria-hidden="true"></i>
                    <input type="text" id="adminCatSearch" class="admin-cat-search-input"
                        placeholder="<?php echo htmlspecialchars(t('admin_cat_search_ph'), ENT_QUOTES, 'UTF-8'); ?>"
                        autocomplete="off">
                </div>
            <?php endif; ?>

            <!-- Category grid -->
            <div class="category-grid" id="adminCatGrid">
                <?php if (count($serviceCategories) === 0): ?>
                    <div class="empty-state" style="grid-column:1/-1;"><?php echo htmlspecialchars(t('admin_cat_empty'), ENT_QUOTES, 'UTF-8'); ?></div>
                <?php else: ?>
                    <?php foreach ($serviceCategories as $catIndex => $category): ?>
                        <?php
                            $categoryId   = (int) $category['category_id'];
                            $catInitial   = mb_strtoupper(mb_substr((string) $category['name'], 0, 1));
                            $catColor     = $catColors[$catIndex % count($catColors)];
                            $catNameLower = mb_strtolower((string) $category['name'] . ' ' . ($category['description'] ?? ''));
                        ?>
                        <div class="category-card" data-cat-name="<?php echo htmlspecialchars($catNameLower, ENT_QUOTES, 'UTF-8'); ?>">
                            <div class="cat-card-header">
                                <div class="cat-card-avatar" style="background:linear-gradient(135deg,<?php echo htmlspecialchars($catColor, ENT_QUOTES, 'UTF-8'); ?>,<?php echo htmlspecialchars($catColor, ENT_QUOTES, 'UTF-8'); ?>cc);">
                                    <?php echo htmlspecialchars($catInitial, ENT_QUOTES, 'UTF-8'); ?>
                                </div>
                                <div style="min-width:0;">
                                    <div class="cat-card-title"><?php echo htmlspecialchars($category['name'], ENT_QUOTES, 'UTF-8'); ?></div>
                                    <?php if (!empty($category['name_ar'])): ?>
                                        <div class="cat-card-title-ar"><?php echo htmlspecialchars($category['name_ar'], ENT_QUOTES, 'UTF-8'); ?></div>
                                    <?php endif; ?>
                                </div>
                            </div>

                            <?php if (!empty($category['description'])): ?>
                                <div class="cat-card-body">
                                    <p class="cat-card-desc"><?php echo htmlspecialchars(mb_substr($category['description'], 0, 100) . (mb_strlen($category['description']) > 100 ? '…' : ''), ENT_QUOTES, 'UTF-8'); ?></p>
                                </div>
                            <?php endif; ?>

                            <!-- Edit form (collapsible) -->
                            <div class="cat-card-body" style="padding-top:0;">
                                <button type="button" class="btn ghost" style="font-size:.8rem;padding:5px 12px;width:100%;"
                                    onclick="this.closest('.category-card').querySelector('.cat-edit-form').classList.toggle('cat-edit-open')">
                                    <i class="fas fa-pen" aria-hidden="true"></i>
                                    <?php echo htmlspecialchars(t('admin_cat_edit_toggle'), ENT_QUOTES, 'UTF-8'); ?>
                                </button>
                                <div class="cat-edit-form" style="margin-top:12px;" id="cat-edit-<?php echo $categoryId; ?>">
                                    <form class="category-form" method="post" action="<?php echo htmlspecialchars($appBase, ENT_QUOTES, 'UTF-8'); ?>/admin_dashboard.php#service-categories">
                                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['admin_dashboard_csrf'], ENT_QUOTES, 'UTF-8'); ?>">
                                        <input type="hidden" name="action" value="update_category">
                                        <input type="hidden" name="category_id" value="<?php echo $categoryId; ?>">
                                        <div class="settings-field" style="margin-bottom:8px;">
                                            <label for="category-name-<?php echo $categoryId; ?>"><?php echo htmlspecialchars(t('admin_cat_name_en_label'), ENT_QUOTES, 'UTF-8'); ?></label>
                                            <input id="category-name-<?php echo $categoryId; ?>" name="category_name" type="text" value="<?php echo htmlspecialchars($category['name'], ENT_QUOTES, 'UTF-8'); ?>" required>
                                        </div>
                                        <div class="settings-field" style="margin-bottom:8px;">
                                            <label for="category-name-ar-<?php echo $categoryId; ?>"><?php echo htmlspecialchars(t('admin_cat_name_ar_label'), ENT_QUOTES, 'UTF-8'); ?></label>
                                            <input id="category-name-ar-<?php echo $categoryId; ?>" name="category_name_ar" type="text" value="<?php echo htmlspecialchars($category['name_ar'] ?? '', ENT_QUOTES, 'UTF-8'); ?>" dir="rtl" placeholder="<?php echo htmlspecialchars(t('admin_cat_name_ar_ph'), ENT_QUOTES, 'UTF-8'); ?>">
                                        </div>
                                        <div class="settings-field" style="margin-bottom:8px;">
                                            <label for="category-desc-<?php echo $categoryId; ?>"><?php echo htmlspecialchars(t('admin_cat_desc_en_label'), ENT_QUOTES, 'UTF-8'); ?></label>
                                            <textarea id="category-desc-<?php echo $categoryId; ?>" name="category_description"><?php echo htmlspecialchars($category['description'], ENT_QUOTES, 'UTF-8'); ?></textarea>
                                        </div>
                                        <div class="settings-field" style="margin-bottom:10px;">
                                            <label for="category-desc-ar-<?php echo $categoryId; ?>"><?php echo htmlspecialchars(t('admin_cat_desc_ar_label'), ENT_QUOTES, 'UTF-8'); ?></label>
                                            <textarea id="category-desc-ar-<?php echo $categoryId; ?>" name="category_description_ar" dir="rtl" placeholder="<?php echo htmlspecialchars(t('admin_cat_desc_ar_ph'), ENT_QUOTES, 'UTF-8'); ?>"><?php echo htmlspecialchars($category['description_ar'] ?? '', ENT_QUOTES, 'UTF-8'); ?></textarea>
                                        </div>
                                        <div class="category-actions">
                                            <button class="btn primary" type="submit">
                                                <i class="fa-solid fa-floppy-disk" aria-hidden="true"></i>
                                                <?php echo htmlspecialchars(t('admin_cat_save_btn'), ENT_QUOTES, 'UTF-8'); ?>
                                            </button>
                                        </div>
                                    </form>
                                </div>
                            </div>

                        </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>

            <!-- Provider Category Requests sub-section -->
            <div style="margin-top:32px;border-top:2px solid #e2e8f0;padding-top:24px;">
                <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;margin-bottom:16px;">
                    <div>
                        <h3 style="font-size:1.05rem;font-weight:800;margin:0 0 3px;color:#0f172a;"><?php echo htmlspecialchars(t('admin_cat_req_title'), ENT_QUOTES, 'UTF-8'); ?></h3>
                        <p style="font-size:.86rem;color:#64748b;margin:0;"><?php echo htmlspecialchars(t('admin_cat_req_lead'), ENT_QUOTES, 'UTF-8'); ?></p>
                    </div>
                    <?php if ($pendingCatReqsCount > 0): ?>
                        <span style="display:inline-flex;align-items:center;gap:6px;background:#fef9c3;color:#92400e;border:1px solid #fde68a;border-radius:999px;padding:4px 13px;font-size:.82rem;font-weight:700;">
                            <i class="fas fa-clock"></i>
                            <?php echo $pendingCatReqsCount; ?> <?php echo htmlspecialchars(t('admin_loc_pending'), ENT_QUOTES, 'UTF-8'); ?>
                        </span>
                    <?php endif; ?>
                </div>

                <?php if (empty($allCategoryRequests)): ?>
                    <div class="empty-state"><?php echo htmlspecialchars(t('admin_cat_req_empty'), ENT_QUOTES, 'UTF-8'); ?></div>
                <?php else: ?>
                    <div style="display:flex;flex-direction:column;gap:14px;">
                        <?php foreach ($allCategoryRequests as $catReq): ?>
                            <?php
                                $reqStatus   = $catReq['status'];
                                $statusBg    = '#f1f5f9'; $statusColor = '#475569'; $statusIcon = 'fa-clock';
                                if ($reqStatus === 'approved') { $statusBg = '#dcfce7'; $statusColor = '#166534'; $statusIcon = 'fa-circle-check'; }
                                if ($reqStatus === 'rejected') { $statusBg = '#fee2e2'; $statusColor = '#991b1b'; $statusIcon = 'fa-circle-xmark'; }
                                $statusLabel = t('cat_req_status_' . $reqStatus);
                            ?>
                            <div class="admin-cat-req-card <?php echo htmlspecialchars($reqStatus, ENT_QUOTES, 'UTF-8'); ?>">
                                <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:10px;flex-wrap:wrap;gap:8px;">
                                    <div>
                                        <p style="font-weight:800;font-size:.98rem;color:#0f172a;margin:0 0 3px;"><?php echo htmlspecialchars($catReq['category_name'], ENT_QUOTES, 'UTF-8'); ?></p>
                                        <p style="font-size:.83rem;color:#64748b;margin:0;">
                                            <i class="fas fa-user" aria-hidden="true"></i>
                                            <?php echo htmlspecialchars($catReq['provider_name'] ?: '#' . $catReq['provider_id'], ENT_QUOTES, 'UTF-8'); ?>
                                            <?php if ($catReq['provider_email'] !== ''): ?>
                                                <span dir="ltr">(<?php echo htmlspecialchars($catReq['provider_email'], ENT_QUOTES, 'UTF-8'); ?>)</span>
                                            <?php endif; ?>
                                        </p>
                                    </div>
                                    <span style="display:inline-flex;align-items:center;gap:5px;background:<?php echo $statusBg; ?>;color:<?php echo $statusColor; ?>;padding:4px 12px;border-radius:999px;font-size:.8rem;font-weight:700;white-space:nowrap;">
                                        <i class="fas <?php echo $statusIcon; ?>" aria-hidden="true"></i>
                                        <?php echo htmlspecialchars($statusLabel, ENT_QUOTES, 'UTF-8'); ?>
                                    </span>
                                </div>

                                <?php if ($catReq['category_info'] !== ''): ?>
                                    <p style="font-size:.86rem;color:#374151;margin-bottom:12px;background:#f8fafc;border-radius:8px;padding:8px 12px;">
                                        <strong><?php echo htmlspecialchars(t('admin_cat_req_info'), ENT_QUOTES, 'UTF-8'); ?>:</strong>
                                        <?php echo htmlspecialchars($catReq['category_info'], ENT_QUOTES, 'UTF-8'); ?>
                                    </p>
                                <?php endif; ?>

                                <?php if ($reqStatus === 'pending'): ?>
                                    <div style="display:flex;gap:12px;flex-wrap:wrap;margin-top:12px;padding-top:12px;border-top:1px solid #f1f5f9;">
                                        <!-- Approve form -->
                                        <form method="post" action="<?php echo htmlspecialchars($appBase, ENT_QUOTES, 'UTF-8'); ?>/admin_dashboard.php#service-categories" style="flex:1;min-width:220px;display:grid;gap:8px;">
                                            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['admin_dashboard_csrf'], ENT_QUOTES, 'UTF-8'); ?>">
                                            <input type="hidden" name="action" value="approve_cat_request">
                                            <input type="hidden" name="cat_request_id" value="<?php echo (int) $catReq['request_id']; ?>">
                                            <div class="settings-field">
                                                <label><?php echo htmlspecialchars(t('admin_cat_name_ar_label'), ENT_QUOTES, 'UTF-8'); ?></label>
                                                <input type="text" name="category_name_ar" dir="rtl" placeholder="<?php echo htmlspecialchars(t('admin_cat_name_ar_ph'), ENT_QUOTES, 'UTF-8'); ?>">
                                            </div>
                                            <div class="settings-field">
                                                <label><?php echo htmlspecialchars(t('admin_cat_req_notes_label'), ENT_QUOTES, 'UTF-8'); ?></label>
                                                <input type="text" name="admin_notes" placeholder="<?php echo htmlspecialchars(t('admin_cat_req_notes_ph'), ENT_QUOTES, 'UTF-8'); ?>">
                                            </div>
                                            <button type="submit" class="btn primary" style="align-self:flex-start;">
                                                <i class="fas fa-check" aria-hidden="true"></i>
                                                <?php echo htmlspecialchars(t('admin_cat_req_approve'), ENT_QUOTES, 'UTF-8'); ?>
                                            </button>
                                        </form>

                                        <!-- Reject form -->
                                        <form method="post" action="<?php echo htmlspecialchars($appBase, ENT_QUOTES, 'UTF-8'); ?>/admin_dashboard.php#service-categories" style="flex:1;min-width:180px;display:grid;gap:8px;align-content:end;">
                                            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['admin_dashboard_csrf'], ENT_QUOTES, 'UTF-8'); ?>">
                                            <input type="hidden" name="action" value="reject_cat_request">
                                            <input type="hidden" name="cat_request_id" value="<?php echo (int) $catReq['request_id']; ?>">
                                            <div class="settings-field">
                                                <label><?php echo htmlspecialchars(t('admin_cat_req_notes_label'), ENT_QUOTES, 'UTF-8'); ?></label>
                                                <input type="text" name="admin_notes" placeholder="<?php echo htmlspecialchars(t('admin_cat_req_notes_ph'), ENT_QUOTES, 'UTF-8'); ?>">
                                            </div>
                                            <button type="submit" class="btn danger" style="align-self:flex-start;">
                                                <i class="fas fa-xmark" aria-hidden="true"></i>
                                                <?php echo htmlspecialchars(t('admin_cat_req_reject'), ENT_QUOTES, 'UTF-8'); ?>
                                            </button>
                                        </form>
                                    </div>
                                <?php elseif ($catReq['admin_notes'] !== ''): ?>
                                    <p style="font-size:.82rem;color:#374151;margin-top:8px;font-style:italic;">
                                        <i class="fas fa-comment-dots" aria-hidden="true"></i>
                                        <strong><?php echo htmlspecialchars(t('cat_req_admin_notes'), ENT_QUOTES, 'UTF-8'); ?></strong>
                                        <?php echo htmlspecialchars($catReq['admin_notes'], ENT_QUOTES, 'UTF-8'); ?>
                                    </p>
                                <?php endif; ?>
                            </div>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>
            </div>
        </section>

        <!-- Service provider management section -->
        <section id="service-providers" class="panel">
            <div class="panel-header">
                <div>
                    <h2><?php echo htmlspecialchars(t('admin_providers'), ENT_QUOTES, 'UTF-8'); ?></h2>
                    <p><?php echo htmlspecialchars(t('admin_providers_lead'), ENT_QUOTES, 'UTF-8'); ?></p>
                </div>
            </div>

            <!-- Provider toolbar with search and status filters -->
            <div class="panel-toolbar" aria-label="Provider toolbar">
                <form class="toolbar-form" method="get" action="<?php echo htmlspecialchars($appBase, ENT_QUOTES, 'UTF-8'); ?>/admin_dashboard.php#service-providers" role="search">
                    <input type="hidden" name="customer_q" value="<?php echo htmlspecialchars($customerSearchQuery, ENT_QUOTES, 'UTF-8'); ?>">
                    <input type="hidden" name="customer_status" value="<?php echo htmlspecialchars($customerStatusFilter, ENT_QUOTES, 'UTF-8'); ?>">

                    <div class="toolbar-field">
                        <i class="fa-solid fa-magnifying-glass" aria-hidden="true"></i>
                        <input
                            type="search"
                            name="provider_q"
                            value="<?php echo htmlspecialchars($providerSearchQuery, ENT_QUOTES, 'UTF-8'); ?>"
                            placeholder="<?php echo htmlspecialchars(t('admin_search_provider_ph'), ENT_QUOTES, 'UTF-8'); ?>"
                            autocomplete="off"
                            list="providerSuggestions"
                            data-suggest="providers"
                        >
                        <datalist id="providerSuggestions"></datalist>
                    </div>

                    <div class="toolbar-field">
                        <i class="fa-solid fa-shield-halved" aria-hidden="true"></i>
                        <select name="provider_verification">
                            <option value="all" <?php echo $providerVerificationFilter === 'all' ? 'selected' : ''; ?>><?php echo htmlspecialchars(t('admin_filter_all_verification'), ENT_QUOTES, 'UTF-8'); ?></option>
                            <option value="verified" <?php echo $providerVerificationFilter === 'verified' ? 'selected' : ''; ?>><?php echo htmlspecialchars(t('admin_filter_verified_only'), ENT_QUOTES, 'UTF-8'); ?></option>
                            <option value="unverified" <?php echo $providerVerificationFilter === 'unverified' ? 'selected' : ''; ?>><?php echo htmlspecialchars(t('admin_filter_unverified_only'), ENT_QUOTES, 'UTF-8'); ?></option>
                        </select>
                    </div>

                    <div class="toolbar-field">
                        <i class="fa-solid fa-user-lock" aria-hidden="true"></i>
                        <select name="provider_status">
                            <option value="all" <?php echo $providerStatusFilter === 'all' ? 'selected' : ''; ?>><?php echo htmlspecialchars(t('admin_filter_all_statuses'), ENT_QUOTES, 'UTF-8'); ?></option>
                            <option value="active" <?php echo $providerStatusFilter === 'active' ? 'selected' : ''; ?>><?php echo htmlspecialchars(t('admin_filter_active_only'), ENT_QUOTES, 'UTF-8'); ?></option>
                            <option value="suspended" <?php echo $providerStatusFilter === 'suspended' ? 'selected' : ''; ?>><?php echo htmlspecialchars(t('admin_filter_suspended_only'), ENT_QUOTES, 'UTF-8'); ?></option>
                        </select>
                    </div>

                    <a class="btn ghost" href="<?php echo htmlspecialchars($appBase, ENT_QUOTES, 'UTF-8'); ?>/admin_dashboard.php<?php echo $providerResetQuery !== '' ? '?' . htmlspecialchars($providerResetQuery, ENT_QUOTES, 'UTF-8') : ''; ?>#service-providers">
                        <i class="fa-solid fa-rotate-left" aria-hidden="true"></i>
                        <?php echo htmlspecialchars(t('admin_reset_btn'), ENT_QUOTES, 'UTF-8'); ?>
                    </a>
                </form>
            </div>

            <?php if (count($serviceProviders) === 0): ?>
                <div class="empty-state">
                    <?php if ($providerSearchQuery !== ''): ?>
                        <?php echo htmlspecialchars(t('admin_no_providers_match'), ENT_QUOTES, 'UTF-8'); ?>
                    <?php else: ?>
                        <?php echo htmlspecialchars(t('admin_no_providers'), ENT_QUOTES, 'UTF-8'); ?>
                    <?php endif; ?>
                </div>
            <?php else: ?>
                <div class="card-grid">
                    <?php foreach ($serviceProviders as $provider): ?>
                        <article class="card">
                            <div class="card-header">
                                <div>
                                    <h3><?php echo htmlspecialchars($provider['name'], ENT_QUOTES, 'UTF-8'); ?></h3>
                                    <div class="meta">
                                        <div><strong><?php echo htmlspecialchars(t('admin_lbl_email'), ENT_QUOTES, 'UTF-8'); ?></strong> <span class="no-ar-numerals" dir="ltr"><?php echo htmlspecialchars($provider['email'], ENT_QUOTES, 'UTF-8'); ?></span></div>
                                        <div><strong><?php echo htmlspecialchars(t('admin_lbl_phone'), ENT_QUOTES, 'UTF-8'); ?></strong> <span dir="ltr"><?php echo htmlspecialchars($provider['phone'], ENT_QUOTES, 'UTF-8'); ?></span></div>
                                        <div><strong><?php echo htmlspecialchars(t('admin_lbl_services'), ENT_QUOTES, 'UTF-8'); ?></strong> <?php echo (int) $provider['service_count']; ?></div>
                                        <div><strong><?php echo htmlspecialchars(t('admin_lbl_requests'), ENT_QUOTES, 'UTF-8'); ?></strong> <?php echo (int) $provider['request_count']; ?></div>
                                    </div>
                                </div>
                                <div class="status-stack">
                                    <span class="status <?php echo $provider['is_verified'] ? 'verified' : 'unverified'; ?>">
                                        <i class="fa-solid <?php echo $provider['is_verified'] ? 'fa-circle-check' : 'fa-circle-exclamation'; ?>" aria-hidden="true"></i>
                                        <?php echo htmlspecialchars($provider['is_verified'] ? t('admin_status_verified') : t('admin_status_unverified'), ENT_QUOTES, 'UTF-8'); ?>
                                    </span>
                                    <span class="status <?php echo $provider['is_suspended'] ? 'suspended' : 'active'; ?>">
                                        <i class="fa-solid <?php echo $provider['is_suspended'] ? 'fa-user-lock' : 'fa-user-check'; ?>" aria-hidden="true"></i>
                                        <?php echo htmlspecialchars($provider['is_suspended'] ? t('admin_status_suspended') : t('admin_status_active'), ENT_QUOTES, 'UTF-8'); ?>
                                    </span>
                                </div>
                            </div>

                            <div class="card-actions">
                                <a class="btn ghost" href="<?php echo htmlspecialchars($appBase, ENT_QUOTES, 'UTF-8'); ?>/admin/user/provider/<?php echo (int) $provider['provider_id']; ?>" style="background:rgba(15,118,110,.08);color:#0f766e;border-color:rgba(15,118,110,.2);">
                                    <i class="fa-solid fa-id-card" aria-hidden="true"></i>
                                    <?php echo htmlspecialchars(t('admin_profile_view'), ENT_QUOTES, 'UTF-8'); ?>
                                </a>
                                <?php if ($provider['is_verified']): ?>
                                    <form method="post" action="<?php echo htmlspecialchars($appBase, ENT_QUOTES, 'UTF-8'); ?>/admin_dashboard.php">
                                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['admin_dashboard_csrf'], ENT_QUOTES, 'UTF-8'); ?>">
                                        <input type="hidden" name="action" value="unverify_provider">
                                        <input type="hidden" name="provider_id" value="<?php echo (int) $provider['provider_id']; ?>">
                                        <input type="hidden" name="redirect_provider_q" value="<?php echo htmlspecialchars($providerSearchQuery, ENT_QUOTES, 'UTF-8'); ?>">
                                        <input type="hidden" name="redirect_provider_status" value="<?php echo htmlspecialchars($providerStatusFilter, ENT_QUOTES, 'UTF-8'); ?>">
                                        <input type="hidden" name="redirect_provider_verification" value="<?php echo htmlspecialchars($providerVerificationFilter, ENT_QUOTES, 'UTF-8'); ?>">
                                        <input type="hidden" name="redirect_customer_q" value="<?php echo htmlspecialchars($customerSearchQuery, ENT_QUOTES, 'UTF-8'); ?>">
                                        <input type="hidden" name="redirect_customer_status" value="<?php echo htmlspecialchars($customerStatusFilter, ENT_QUOTES, 'UTF-8'); ?>">
                                        <button class="btn warn" type="submit"><i class="fa-solid fa-ban" aria-hidden="true"></i><?php echo htmlspecialchars(t('admin_unverify'), ENT_QUOTES, 'UTF-8'); ?></button>
                                    </form>
                                <?php else: ?>
                                    <form method="post" action="<?php echo htmlspecialchars($appBase, ENT_QUOTES, 'UTF-8'); ?>/admin_dashboard.php">
                                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['admin_dashboard_csrf'], ENT_QUOTES, 'UTF-8'); ?>">
                                        <input type="hidden" name="action" value="verify_provider">
                                        <input type="hidden" name="provider_id" value="<?php echo (int) $provider['provider_id']; ?>">
                                        <input type="hidden" name="redirect_provider_q" value="<?php echo htmlspecialchars($providerSearchQuery, ENT_QUOTES, 'UTF-8'); ?>">
                                        <input type="hidden" name="redirect_provider_status" value="<?php echo htmlspecialchars($providerStatusFilter, ENT_QUOTES, 'UTF-8'); ?>">
                                        <input type="hidden" name="redirect_provider_verification" value="<?php echo htmlspecialchars($providerVerificationFilter, ENT_QUOTES, 'UTF-8'); ?>">
                                        <input type="hidden" name="redirect_customer_q" value="<?php echo htmlspecialchars($customerSearchQuery, ENT_QUOTES, 'UTF-8'); ?>">
                                        <input type="hidden" name="redirect_customer_status" value="<?php echo htmlspecialchars($customerStatusFilter, ENT_QUOTES, 'UTF-8'); ?>">
                                        <button class="btn primary" type="submit"><i class="fa-solid fa-circle-check" aria-hidden="true"></i><?php echo htmlspecialchars(t('admin_verify'), ENT_QUOTES, 'UTF-8'); ?></button>
                                    </form>
                                <?php endif; ?>

                                <?php if ($provider['is_suspended']): ?>
                                    <form method="post" action="<?php echo htmlspecialchars($appBase, ENT_QUOTES, 'UTF-8'); ?>/admin_dashboard.php">
                                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['admin_dashboard_csrf'], ENT_QUOTES, 'UTF-8'); ?>">
                                        <input type="hidden" name="action" value="unsuspend_provider">
                                        <input type="hidden" name="provider_id" value="<?php echo (int) $provider['provider_id']; ?>">
                                        <input type="hidden" name="redirect_provider_q" value="<?php echo htmlspecialchars($providerSearchQuery, ENT_QUOTES, 'UTF-8'); ?>">
                                        <input type="hidden" name="redirect_provider_status" value="<?php echo htmlspecialchars($providerStatusFilter, ENT_QUOTES, 'UTF-8'); ?>">
                                        <input type="hidden" name="redirect_provider_verification" value="<?php echo htmlspecialchars($providerVerificationFilter, ENT_QUOTES, 'UTF-8'); ?>">
                                        <input type="hidden" name="redirect_customer_q" value="<?php echo htmlspecialchars($customerSearchQuery, ENT_QUOTES, 'UTF-8'); ?>">
                                        <input type="hidden" name="redirect_customer_status" value="<?php echo htmlspecialchars($customerStatusFilter, ENT_QUOTES, 'UTF-8'); ?>">
                                        <button class="btn primary" type="submit" data-confirm="<?php echo htmlspecialchars(t('admin_unsuspend_prov_confirm'), ENT_QUOTES, 'UTF-8'); ?>">
                                            <i class="fa-solid fa-unlock" aria-hidden="true"></i><?php echo htmlspecialchars(t('admin_unsuspend'), ENT_QUOTES, 'UTF-8'); ?>
                                        </button>
                                    </form>
                                <?php else: ?>
                                    <form method="post" action="<?php echo htmlspecialchars($appBase, ENT_QUOTES, 'UTF-8'); ?>/admin_dashboard.php">
                                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['admin_dashboard_csrf'], ENT_QUOTES, 'UTF-8'); ?>">
                                        <input type="hidden" name="action" value="suspend_provider">
                                        <input type="hidden" name="provider_id" value="<?php echo (int) $provider['provider_id']; ?>">
                                        <input type="hidden" name="redirect_provider_q" value="<?php echo htmlspecialchars($providerSearchQuery, ENT_QUOTES, 'UTF-8'); ?>">
                                        <input type="hidden" name="redirect_provider_status" value="<?php echo htmlspecialchars($providerStatusFilter, ENT_QUOTES, 'UTF-8'); ?>">
                                        <input type="hidden" name="redirect_provider_verification" value="<?php echo htmlspecialchars($providerVerificationFilter, ENT_QUOTES, 'UTF-8'); ?>">
                                        <input type="hidden" name="redirect_customer_q" value="<?php echo htmlspecialchars($customerSearchQuery, ENT_QUOTES, 'UTF-8'); ?>">
                                        <input type="hidden" name="redirect_customer_status" value="<?php echo htmlspecialchars($customerStatusFilter, ENT_QUOTES, 'UTF-8'); ?>">
                                        <button class="btn warn" type="submit" data-confirm="<?php echo htmlspecialchars(t('admin_suspend_prov_confirm'), ENT_QUOTES, 'UTF-8'); ?>">
                                            <i class="fa-solid fa-user-lock" aria-hidden="true"></i><?php echo htmlspecialchars(t('admin_suspend'), ENT_QUOTES, 'UTF-8'); ?>
                                        </button>
                                    </form>
                                <?php endif; ?>
                            </div>
                        </article>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
        </section>

        <!-- Customer management section -->
        <section id="customers" class="panel">
            <div class="panel-header">
                <div>
                    <h2><?php echo htmlspecialchars(t('admin_customers'), ENT_QUOTES, 'UTF-8'); ?></h2>
                    <p><?php echo htmlspecialchars(t('admin_customers_lead'), ENT_QUOTES, 'UTF-8'); ?></p>
                </div>
            </div>

            <!-- Customer toolbar with search and status filters -->
            <div class="panel-toolbar" aria-label="Customer toolbar">
                <form class="toolbar-form compact" method="get" action="<?php echo htmlspecialchars($appBase, ENT_QUOTES, 'UTF-8'); ?>/admin_dashboard.php#customers" role="search">
                    <input type="hidden" name="provider_q" value="<?php echo htmlspecialchars($providerSearchQuery, ENT_QUOTES, 'UTF-8'); ?>">
                    <input type="hidden" name="provider_status" value="<?php echo htmlspecialchars($providerStatusFilter, ENT_QUOTES, 'UTF-8'); ?>">
                    <input type="hidden" name="provider_verification" value="<?php echo htmlspecialchars($providerVerificationFilter, ENT_QUOTES, 'UTF-8'); ?>">

                    <div class="toolbar-field">
                        <i class="fa-solid fa-magnifying-glass" aria-hidden="true"></i>
                        <input
                            type="search"
                            name="customer_q"
                            value="<?php echo htmlspecialchars($customerSearchQuery, ENT_QUOTES, 'UTF-8'); ?>"
                            placeholder="<?php echo htmlspecialchars(t('admin_search_customer_ph'), ENT_QUOTES, 'UTF-8'); ?>"
                            autocomplete="off"
                            list="customerSuggestions"
                            data-suggest="customers"
                        >
                        <datalist id="customerSuggestions"></datalist>
                    </div>

                    <div class="toolbar-field">
                        <i class="fa-solid fa-user-lock" aria-hidden="true"></i>
                        <select name="customer_status">
                            <option value="all" <?php echo $customerStatusFilter === 'all' ? 'selected' : ''; ?>><?php echo htmlspecialchars(t('admin_filter_all_statuses'), ENT_QUOTES, 'UTF-8'); ?></option>
                            <option value="active" <?php echo $customerStatusFilter === 'active' ? 'selected' : ''; ?>><?php echo htmlspecialchars(t('admin_filter_active_only'), ENT_QUOTES, 'UTF-8'); ?></option>
                            <option value="suspended" <?php echo $customerStatusFilter === 'suspended' ? 'selected' : ''; ?>><?php echo htmlspecialchars(t('admin_filter_suspended_only'), ENT_QUOTES, 'UTF-8'); ?></option>
                        </select>
                    </div>

                    <a class="btn ghost" href="<?php echo htmlspecialchars($appBase, ENT_QUOTES, 'UTF-8'); ?>/admin_dashboard.php<?php echo $customerResetQuery !== '' ? '?' . htmlspecialchars($customerResetQuery, ENT_QUOTES, 'UTF-8') : ''; ?>#customers">
                        <i class="fa-solid fa-rotate-left" aria-hidden="true"></i>
                        <?php echo htmlspecialchars(t('admin_reset_btn'), ENT_QUOTES, 'UTF-8'); ?>
                    </a>
                </form>
            </div>

            <?php if (count($customers) === 0): ?>
                <div class="empty-state">
                    <?php if ($customerSearchQuery !== ''): ?>
                        <?php echo htmlspecialchars(t('admin_no_customers_match'), ENT_QUOTES, 'UTF-8'); ?>
                    <?php else: ?>
                        <?php echo htmlspecialchars(t('admin_no_customers'), ENT_QUOTES, 'UTF-8'); ?>
                    <?php endif; ?>
                </div>
            <?php else: ?>
                <div class="card-grid">
                    <?php foreach ($customers as $customer): ?>
                        <article class="card">
                            <div class="card-header">
                                <div>
                                    <h3><?php echo htmlspecialchars($customer['name'], ENT_QUOTES, 'UTF-8'); ?></h3>
                                    <div class="meta">
                                        <div><strong><?php echo htmlspecialchars(t('admin_lbl_email'), ENT_QUOTES, 'UTF-8'); ?></strong> <span class="no-ar-numerals" dir="ltr"><?php echo htmlspecialchars($customer['email'], ENT_QUOTES, 'UTF-8'); ?></span></div>
                                        <div><strong><?php echo htmlspecialchars(t('admin_lbl_phone'), ENT_QUOTES, 'UTF-8'); ?></strong> <span dir="ltr"><?php echo htmlspecialchars($customer['phone'], ENT_QUOTES, 'UTF-8'); ?></span></div>
                                        <div><strong><?php echo htmlspecialchars(t('admin_lbl_requests'), ENT_QUOTES, 'UTF-8'); ?></strong> <?php echo (int) $customer['request_count']; ?></div>
                                    </div>
                                </div>
                                <div class="status-stack">
                                    <span class="status customer"><i class="fa-solid fa-user" aria-hidden="true"></i><?php echo htmlspecialchars(t('admin_status_customer_lbl'), ENT_QUOTES, 'UTF-8'); ?></span>
                                    <span class="status <?php echo $customer['is_suspended'] ? 'suspended' : 'active'; ?>">
                                        <i class="fa-solid <?php echo $customer['is_suspended'] ? 'fa-user-lock' : 'fa-user-check'; ?>" aria-hidden="true"></i>
                                        <?php echo htmlspecialchars($customer['is_suspended'] ? t('admin_status_suspended') : t('admin_status_active'), ENT_QUOTES, 'UTF-8'); ?>
                                    </span>
                                </div>
                            </div>

                            <div class="card-actions">
                                <a class="btn ghost" href="<?php echo htmlspecialchars($appBase, ENT_QUOTES, 'UTF-8'); ?>/admin/user/customer/<?php echo (int) $customer['customer_id']; ?>" style="background:rgba(15,118,110,.08);color:#0f766e;border-color:rgba(15,118,110,.2);">
                                    <i class="fa-solid fa-id-card" aria-hidden="true"></i>
                                    <?php echo htmlspecialchars(t('admin_profile_view'), ENT_QUOTES, 'UTF-8'); ?>
                                </a>
                                <?php if ($customer['is_suspended']): ?>
                                    <form method="post" action="<?php echo htmlspecialchars($appBase, ENT_QUOTES, 'UTF-8'); ?>/admin_dashboard.php">
                                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['admin_dashboard_csrf'], ENT_QUOTES, 'UTF-8'); ?>">
                                        <input type="hidden" name="action" value="unsuspend_customer">
                                        <input type="hidden" name="customer_id" value="<?php echo (int) $customer['customer_id']; ?>">
                                        <input type="hidden" name="redirect_provider_q" value="<?php echo htmlspecialchars($providerSearchQuery, ENT_QUOTES, 'UTF-8'); ?>">
                                        <input type="hidden" name="redirect_provider_status" value="<?php echo htmlspecialchars($providerStatusFilter, ENT_QUOTES, 'UTF-8'); ?>">
                                        <input type="hidden" name="redirect_provider_verification" value="<?php echo htmlspecialchars($providerVerificationFilter, ENT_QUOTES, 'UTF-8'); ?>">
                                        <input type="hidden" name="redirect_customer_q" value="<?php echo htmlspecialchars($customerSearchQuery, ENT_QUOTES, 'UTF-8'); ?>">
                                        <input type="hidden" name="redirect_customer_status" value="<?php echo htmlspecialchars($customerStatusFilter, ENT_QUOTES, 'UTF-8'); ?>">
                                        <button class="btn primary" type="submit" data-confirm="<?php echo htmlspecialchars(t('admin_unsuspend_cust_confirm'), ENT_QUOTES, 'UTF-8'); ?>">
                                            <i class="fa-solid fa-unlock" aria-hidden="true"></i><?php echo htmlspecialchars(t('admin_unsuspend'), ENT_QUOTES, 'UTF-8'); ?>
                                        </button>
                                    </form>
                                <?php else: ?>
                                    <form method="post" action="<?php echo htmlspecialchars($appBase, ENT_QUOTES, 'UTF-8'); ?>/admin_dashboard.php">
                                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['admin_dashboard_csrf'], ENT_QUOTES, 'UTF-8'); ?>">
                                        <input type="hidden" name="action" value="suspend_customer">
                                        <input type="hidden" name="customer_id" value="<?php echo (int) $customer['customer_id']; ?>">
                                        <input type="hidden" name="redirect_provider_q" value="<?php echo htmlspecialchars($providerSearchQuery, ENT_QUOTES, 'UTF-8'); ?>">
                                        <input type="hidden" name="redirect_provider_status" value="<?php echo htmlspecialchars($providerStatusFilter, ENT_QUOTES, 'UTF-8'); ?>">
                                        <input type="hidden" name="redirect_provider_verification" value="<?php echo htmlspecialchars($providerVerificationFilter, ENT_QUOTES, 'UTF-8'); ?>">
                                        <input type="hidden" name="redirect_customer_q" value="<?php echo htmlspecialchars($customerSearchQuery, ENT_QUOTES, 'UTF-8'); ?>">
                                        <input type="hidden" name="redirect_customer_status" value="<?php echo htmlspecialchars($customerStatusFilter, ENT_QUOTES, 'UTF-8'); ?>">
                                        <button class="btn warn" type="submit" data-confirm="<?php echo htmlspecialchars(t('admin_suspend_cust_confirm'), ENT_QUOTES, 'UTF-8'); ?>">
                                            <i class="fa-solid fa-user-lock" aria-hidden="true"></i><?php echo htmlspecialchars(t('admin_suspend'), ENT_QUOTES, 'UTF-8'); ?>
                                        </button>
                                    </form>
                                <?php endif; ?>
                            </div>
                        </article>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
        </section>

        <!-- Location change requests panel -->
        <section id="location-requests" class="panel" style="flex-direction:column;">
            <div class="panel-header">
                <div>
                    <h2><?php echo htmlspecialchars(t('admin_loc_title'), ENT_QUOTES, 'UTF-8'); ?></h2>
                    <p class="panel-lead"><?php echo htmlspecialchars(t('admin_loc_lead'), ENT_QUOTES, 'UTF-8'); ?></p>
                </div>
                <?php if ($pendingLocationCount > 0): ?>
                    <span class="status unverified" style="font-size:.85rem;">
                        <i class="fas fa-clock"></i>
                        <?php echo $pendingLocationCount; ?> <?php echo htmlspecialchars(t('admin_loc_pending'), ENT_QUOTES, 'UTF-8'); ?>
                    </span>
                <?php endif; ?>
            </div>

            <?php if (count($allLocationRequests) === 0): ?>
                <p class="empty-state"><?php echo htmlspecialchars(t('admin_loc_empty'), ENT_QUOTES, 'UTF-8'); ?></p>
            <?php else: ?>
                <div style="overflow-x:auto;margin-top:4px;">
                    <table style="width:100%;border-collapse:collapse;font-size:.9rem;">
                        <thead>
                            <tr style="border-bottom:2px solid rgba(15,23,42,.08);">
                                <th style="padding:10px 12px;text-align:<?php echo isRtl()?'right':'left';?>;font-weight:700;color:#475569;"><?php echo htmlspecialchars(t('admin_loc_provider'), ENT_QUOTES, 'UTF-8'); ?></th>
                                <th style="padding:10px 12px;text-align:<?php echo isRtl()?'right':'left';?>;font-weight:700;color:#475569;"><?php echo htmlspecialchars(t('admin_loc_current'), ENT_QUOTES, 'UTF-8'); ?></th>
                                <th style="padding:10px 12px;text-align:<?php echo isRtl()?'right':'left';?>;font-weight:700;color:#475569;"><?php echo htmlspecialchars(t('admin_loc_requested'), ENT_QUOTES, 'UTF-8'); ?></th>
                                <th style="padding:10px 12px;text-align:<?php echo isRtl()?'right':'left';?>;font-weight:700;color:#475569;"><?php echo htmlspecialchars(t('admin_loc_date'), ENT_QUOTES, 'UTF-8'); ?></th>
                                <th style="padding:10px 12px;text-align:<?php echo isRtl()?'right':'left';?>;font-weight:700;color:#475569;"><?php echo htmlspecialchars(t('admin_loc_status'), ENT_QUOTES, 'UTF-8'); ?></th>
                                <th style="padding:10px 12px;"></th>
                            </tr>
                        </thead>
                        <tbody>
                        <?php foreach ($allLocationRequests as $locReq): ?>
                            <tr style="border-bottom:1px solid rgba(15,23,42,.06);<?php echo $locReq['status']==='pending'?'background:rgba(254,249,195,.4);':''; ?>">
                                <td style="padding:10px 12px;">
                                    <div style="font-weight:600;color:#0f172a;"><?php echo htmlspecialchars($locReq['provider_name'], ENT_QUOTES, 'UTF-8'); ?></div>
                                    <div style="font-size:.8rem;color:#64748b;" dir="ltr"><?php echo htmlspecialchars($locReq['provider_email'], ENT_QUOTES, 'UTF-8'); ?></div>
                                </td>
                                <td style="padding:10px 12px;color:#475569;"><?php echo htmlspecialchars($locReq['current_location'] ?: '—', ENT_QUOTES, 'UTF-8'); ?></td>
                                <td style="padding:10px 12px;font-weight:600;color:#0f172a;"><?php echo htmlspecialchars($locReq['requested_location'], ENT_QUOTES, 'UTF-8'); ?></td>
                                <td style="padding:10px 12px;color:#64748b;font-size:.82rem;" dir="ltr"><?php echo htmlspecialchars(substr($locReq['created_at'], 0, 10), ENT_QUOTES, 'UTF-8'); ?></td>
                                <td style="padding:10px 12px;">
                                    <?php if ($locReq['status'] === 'pending'): ?>
                                        <span style="display:inline-flex;align-items:center;gap:5px;background:#fef9c3;color:#92400e;border:1px solid #fde68a;border-radius:999px;padding:3px 10px;font-size:.8rem;font-weight:700;">
                                            <i class="fas fa-clock"></i> <?php echo htmlspecialchars(t('admin_loc_pending'), ENT_QUOTES, 'UTF-8'); ?>
                                        </span>
                                    <?php elseif ($locReq['status'] === 'approved'): ?>
                                        <span style="display:inline-flex;align-items:center;gap:5px;background:#dcfce7;color:#166534;border:1px solid #bbf7d0;border-radius:999px;padding:3px 10px;font-size:.8rem;font-weight:700;">
                                            <i class="fas fa-check"></i> <?php echo htmlspecialchars(t('admin_loc_approved'), ENT_QUOTES, 'UTF-8'); ?>
                                        </span>
                                    <?php else: ?>
                                        <span style="display:inline-flex;align-items:center;gap:5px;background:#fee2e2;color:#991b1b;border:1px solid #fecaca;border-radius:999px;padding:3px 10px;font-size:.8rem;font-weight:700;">
                                            <i class="fas fa-times"></i> <?php echo htmlspecialchars(t('admin_loc_rejected'), ENT_QUOTES, 'UTF-8'); ?>
                                        </span>
                                    <?php endif; ?>
                                </td>
                                <td style="padding:10px 12px;">
                                    <?php if ($locReq['status'] === 'pending'): ?>
                                        <div style="display:flex;gap:6px;flex-wrap:wrap;">
                                            <form method="post" style="display:inline;">
                                                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['admin_dashboard_csrf'], ENT_QUOTES, 'UTF-8'); ?>">
                                                <input type="hidden" name="action" value="approve_location_request">
                                                <input type="hidden" name="location_request_id" value="<?php echo (int) $locReq['id']; ?>">
                                                <button type="submit" class="btn primary" style="padding:6px 14px;font-size:.82rem;border-radius:10px;">
                                                    <i class="fas fa-check"></i> <?php echo htmlspecialchars(t('admin_loc_approve'), ENT_QUOTES, 'UTF-8'); ?>
                                                </button>
                                            </form>
                                            <form method="post" style="display:inline;">
                                                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['admin_dashboard_csrf'], ENT_QUOTES, 'UTF-8'); ?>">
                                                <input type="hidden" name="action" value="reject_location_request">
                                                <input type="hidden" name="location_request_id" value="<?php echo (int) $locReq['id']; ?>">
                                                <button type="submit" class="btn danger" style="padding:6px 14px;font-size:.82rem;border-radius:10px;" data-confirm="<?php echo htmlspecialchars(t('admin_loc_reject') . '?', ENT_QUOTES, 'UTF-8'); ?>">
                                                    <i class="fas fa-times"></i> <?php echo htmlspecialchars(t('admin_loc_reject'), ENT_QUOTES, 'UTF-8'); ?>
                                                </button>
                                            </form>
                                        </div>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            <?php endif; ?>
        </section>

        <!-- Reviews & Ratings section -->
        <section id="reviews" class="panel" style="flex-direction:column;">
            <div class="panel-header">
                <div>
                    <h2><?php echo htmlspecialchars(t('admin_reviews_title'), ENT_QUOTES, 'UTF-8'); ?></h2>
                    <p><?php echo htmlspecialchars(t('admin_reviews_lead'), ENT_QUOTES, 'UTF-8'); ?></p>
                </div>
            </div>

            <!-- Stats chips -->
            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-top:4px;">
                <div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:16px;padding:14px 18px;">
                    <div style="font-size:.75rem;font-weight:800;color:#15803d;text-transform:uppercase;letter-spacing:.05em;margin-bottom:4px;"><?php echo htmlspecialchars(t('admin_reviews_total'), ENT_QUOTES, 'UTF-8'); ?></div>
                    <div style="font-size:1.9rem;font-weight:800;color:#0f172a;"><?php echo $reviewStatsTotals; ?></div>
                </div>
                <div style="background:#fffbeb;border:1px solid #fde68a;border-radius:16px;padding:14px 18px;">
                    <div style="font-size:.75rem;font-weight:800;color:#b45309;text-transform:uppercase;letter-spacing:.05em;margin-bottom:4px;"><?php echo htmlspecialchars(t('admin_reviews_avg'), ENT_QUOTES, 'UTF-8'); ?></div>
                    <div style="font-size:1.9rem;font-weight:800;color:#0f172a;display:flex;align-items:center;gap:7px;">
                        <?php echo number_format($reviewStatsAvg, 1); ?>
                        <i class="fa-solid fa-star" style="font-size:1.2rem;color:#f59e0b;"></i>
                    </div>
                </div>
                <div style="background:#eff6ff;border:1px solid #bfdbfe;border-radius:16px;padding:14px 18px;">
                    <div style="font-size:.75rem;font-weight:800;color:#1d4ed8;text-transform:uppercase;letter-spacing:.05em;margin-bottom:4px;"><?php echo htmlspecialchars(t('admin_reviews_five_star'), ENT_QUOTES, 'UTF-8'); ?></div>
                    <div style="font-size:1.9rem;font-weight:800;color:#0f172a;"><?php echo $reviewStatsFiveStar; ?></div>
                </div>
            </div>

            <!-- Search, sort, star filter toolbar -->
            <form id="reviewsFilterForm" method="get" action="<?php echo htmlspecialchars($appBase, ENT_QUOTES, 'UTF-8'); ?>/admin_dashboard.php" style="display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-top:6px;">
                <input type="hidden" name="provider_q" value="<?php echo htmlspecialchars($providerSearchQuery, ENT_QUOTES, 'UTF-8'); ?>">
                <input type="hidden" name="customer_q" value="<?php echo htmlspecialchars($customerSearchQuery, ENT_QUOTES, 'UTF-8'); ?>">
                <input type="hidden" name="customer_status" value="<?php echo htmlspecialchars($customerStatusFilter, ENT_QUOTES, 'UTF-8'); ?>">
                <input type="hidden" name="provider_status" value="<?php echo htmlspecialchars($providerStatusFilter, ENT_QUOTES, 'UTF-8'); ?>">
                <input type="hidden" name="provider_verification" value="<?php echo htmlspecialchars($providerVerificationFilter, ENT_QUOTES, 'UTF-8'); ?>">
                <div class="toolbar-field" style="flex:1;min-width:200px;">
                    <i class="fa-solid fa-magnifying-glass"></i>
                    <input type="search" name="rev_q" value="<?php echo htmlspecialchars($reviewSectionSearch, ENT_QUOTES, 'UTF-8'); ?>" placeholder="<?php echo htmlspecialchars(t('admin_reviews_search_ph'), ENT_QUOTES, 'UTF-8'); ?>" autocomplete="off">
                </div>
                <div class="toolbar-field" style="min-width:160px;">
                    <i class="fa-solid fa-arrow-up-wide-short"></i>
                    <select name="rev_sort">
                        <option value="newest" <?php echo $reviewSectionSort==='newest' ? 'selected' : ''; ?>><?php echo htmlspecialchars(t('admin_reviews_sort_newest'), ENT_QUOTES, 'UTF-8'); ?></option>
                        <option value="highest" <?php echo $reviewSectionSort==='highest' ? 'selected' : ''; ?>><?php echo htmlspecialchars(t('admin_reviews_sort_highest'), ENT_QUOTES, 'UTF-8'); ?></option>
                        <option value="lowest" <?php echo $reviewSectionSort==='lowest' ? 'selected' : ''; ?>><?php echo htmlspecialchars(t('admin_reviews_sort_lowest'), ENT_QUOTES, 'UTF-8'); ?></option>
                    </select>
                </div>
                <div class="toolbar-field" style="min-width:150px;">
                    <i class="fa-solid fa-star"></i>
                    <select name="rev_stars">
                        <option value="0" <?php echo $reviewSectionStars===0 ? 'selected' : ''; ?>><?php echo htmlspecialchars(t('admin_reviews_filter_all'), ENT_QUOTES, 'UTF-8'); ?></option>
                        <option value="5" <?php echo $reviewSectionStars===5 ? 'selected' : ''; ?>><?php echo htmlspecialchars(t('admin_reviews_filter_5'), ENT_QUOTES, 'UTF-8'); ?></option>
                        <option value="4" <?php echo $reviewSectionStars===4 ? 'selected' : ''; ?>><?php echo htmlspecialchars(t('admin_reviews_filter_4'), ENT_QUOTES, 'UTF-8'); ?></option>
                        <option value="3" <?php echo $reviewSectionStars===3 ? 'selected' : ''; ?>><?php echo htmlspecialchars(t('admin_reviews_filter_3'), ENT_QUOTES, 'UTF-8'); ?></option>
                        <option value="2" <?php echo $reviewSectionStars===2 ? 'selected' : ''; ?>><?php echo htmlspecialchars(t('admin_reviews_filter_2'), ENT_QUOTES, 'UTF-8'); ?></option>
                        <option value="1" <?php echo $reviewSectionStars===1 ? 'selected' : ''; ?>><?php echo htmlspecialchars(t('admin_reviews_filter_1'), ENT_QUOTES, 'UTF-8'); ?></option>
                    </select>
                </div>
                <a href="<?php echo htmlspecialchars($appBase, ENT_QUOTES, 'UTF-8'); ?>/admin_dashboard.php#reviews" class="btn ghost">
                    <i class="fa-solid fa-rotate-left"></i>
                    <?php echo htmlspecialchars(t('admin_reset_btn'), ENT_QUOTES, 'UTF-8'); ?>
                </a>
            </form>

            <?php if ($reviewSectionTotal === 0): ?>
                <div class="empty-state" style="margin-top:8px;"><?php echo htmlspecialchars(t('admin_reviews_empty'), ENT_QUOTES, 'UTF-8'); ?></div>
            <?php else: ?>
                <div style="overflow-x:auto;margin-top:6px;">
                    <table style="width:100%;border-collapse:collapse;font-size:.9rem;">
                        <thead>
                            <tr style="border-bottom:2px solid rgba(15,23,42,.08);">
                                <th style="padding:10px 12px;text-align:<?php echo isRtl()?'right':'left';?>;font-weight:700;color:#475569;"><?php echo htmlspecialchars(t('admin_reviews_provider'), ENT_QUOTES, 'UTF-8'); ?></th>
                                <th style="padding:10px 12px;text-align:<?php echo isRtl()?'right':'left';?>;font-weight:700;color:#475569;"><?php echo htmlspecialchars(t('admin_reviews_customer'), ENT_QUOTES, 'UTF-8'); ?></th>
                                <th style="padding:10px 12px;text-align:<?php echo isRtl()?'right':'left';?>;font-weight:700;color:#475569;"><?php echo htmlspecialchars(t('admin_reviews_rating'), ENT_QUOTES, 'UTF-8'); ?></th>
                                <th style="padding:10px 12px;text-align:<?php echo isRtl()?'right':'left';?>;font-weight:700;color:#475569;"><?php echo htmlspecialchars(t('admin_reviews_comment'), ENT_QUOTES, 'UTF-8'); ?></th>
                                <th style="padding:10px 12px;text-align:<?php echo isRtl()?'right':'left';?>;font-weight:700;color:#475569;"><?php echo htmlspecialchars(t('admin_reviews_date'), ENT_QUOTES, 'UTF-8'); ?></th>
                                <th style="padding:10px 12px;"></th>
                            </tr>
                        </thead>
                        <tbody>
                        <?php foreach ($reviewSectionRows as $revRow): ?>
                            <tr style="border-bottom:1px solid rgba(15,23,42,.05);">
                                <td style="padding:10px 12px;">
                                    <a href="<?php echo htmlspecialchars($appBase, ENT_QUOTES, 'UTF-8'); ?>/admin/user/provider/<?php echo (int)$revRow['provider_id']; ?>" style="font-weight:600;color:#0f766e;text-decoration:none;">
                                        <?php echo htmlspecialchars((string)$revRow['provider_name'], ENT_QUOTES, 'UTF-8'); ?>
                                    </a>
                                </td>
                                <td style="padding:10px 12px;">
                                    <a href="<?php echo htmlspecialchars($appBase, ENT_QUOTES, 'UTF-8'); ?>/admin/user/customer/<?php echo (int)$revRow['customer_id']; ?>" style="font-weight:600;color:#0f172a;text-decoration:none;">
                                        <?php echo htmlspecialchars((string)$revRow['customer_name'], ENT_QUOTES, 'UTF-8'); ?>
                                    </a>
                                </td>
                                <td style="padding:10px 12px;white-space:nowrap;">
                                    <?php echo adminReviewStarHtml((int)$revRow['rating']); ?>
                                </td>
                                <td style="padding:10px 12px;max-width:260px;">
                                    <?php
                                        $revComment = trim((string)$revRow['review']);
                                        if ($revComment !== '') {
                                            $preview = mb_strlen($revComment) > 120 ? mb_substr($revComment, 0, 120) . '…' : $revComment;
                                            echo '<span style="color:#334155;font-size:.86rem;">' . htmlspecialchars($preview, ENT_QUOTES, 'UTF-8') . '</span>';
                                        } else {
                                            echo '<span style="color:#94a3b8;font-style:italic;font-size:.86rem;">' . htmlspecialchars(t('admin_reviews_no_comment'), ENT_QUOTES, 'UTF-8') . '</span>';
                                        }
                                    ?>
                                </td>
                                <td style="padding:10px 12px;color:#64748b;font-size:.82rem;white-space:nowrap;" dir="ltr">
                                    <?php echo htmlspecialchars(substr((string)$revRow['appointment_date'], 0, 10), ENT_QUOTES, 'UTF-8'); ?>
                                </td>
                                <td style="padding:10px 12px;white-space:nowrap;">
                                    <a href="<?php echo htmlspecialchars($appBase, ENT_QUOTES, 'UTF-8'); ?>/admin/user/provider/<?php echo (int)$revRow['provider_id']; ?>" class="btn ghost" style="padding:5px 12px;font-size:.8rem;border-radius:9px;">
                                        <i class="fa-solid fa-arrow-up-right-from-square"></i>
                                    </a>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>

                <?php if ($reviewSectionPages > 1): ?>
                    <div style="display:flex;justify-content:center;gap:8px;flex-wrap:wrap;margin-top:12px;">
                        <?php if ($reviewSectionPage > 1): ?>
                            <a href="<?php echo htmlspecialchars(adminReviewPageUrl($reviewSectionPage - 1, $reviewSectionSort, $reviewSectionStars, $reviewSectionSearch), ENT_QUOTES, 'UTF-8'); ?>" class="btn ghost" style="padding:7px 14px;font-size:.86rem;">
                                <i class="fa-solid fa-chevron-left"></i>
                                <?php echo htmlspecialchars(t('admin_reviews_prev'), ENT_QUOTES, 'UTF-8'); ?>
                            </a>
                        <?php endif; ?>
                        <span style="display:inline-flex;align-items:center;padding:7px 14px;font-size:.86rem;color:#64748b;font-weight:600;">
                            <?php echo htmlspecialchars(t('admin_reviews_page'), ENT_QUOTES, 'UTF-8'); ?> <?php echo $reviewSectionPage; ?> / <?php echo $reviewSectionPages; ?>
                        </span>
                        <?php if ($reviewSectionPage < $reviewSectionPages): ?>
                            <a href="<?php echo htmlspecialchars(adminReviewPageUrl($reviewSectionPage + 1, $reviewSectionSort, $reviewSectionStars, $reviewSectionSearch), ENT_QUOTES, 'UTF-8'); ?>" class="btn ghost" style="padding:7px 14px;font-size:.86rem;">
                                <?php echo htmlspecialchars(t('admin_reviews_next'), ENT_QUOTES, 'UTF-8'); ?>
                                <i class="fa-solid fa-chevron-right"></i>
                            </a>
                        <?php endif; ?>
                    </div>
                <?php endif; ?>
            <?php endif; ?>
        </section>

        <!-- Interactions panel: all requests between customers and service providers -->
        <section id="interactions" class="panel" style="flex-direction:column;">
            <div class="panel-header">
                <div>
                    <h2><?php echo htmlspecialchars(t('admin_interactions_title'), ENT_QUOTES, 'UTF-8'); ?></h2>
                    <p><?php echo htmlspecialchars(t('admin_interactions_lead'), ENT_QUOTES, 'UTF-8'); ?></p>
                </div>
                <span style="font-size:.82rem;font-weight:700;color:#64748b;"><?php echo count($allInteractions); ?> <?php echo htmlspecialchars(t('admin_interactions_count'), ENT_QUOTES, 'UTF-8'); ?></span>
            </div>

            <?php if (empty($allInteractions)): ?>
                <p style="font-size:.9rem;color:#64748b;padding:20px 0;"><?php echo htmlspecialchars(t('admin_interactions_empty'), ENT_QUOTES, 'UTF-8'); ?></p>
            <?php else: ?>
                <div class="toolbar-field" style="margin-bottom:14px;max-width:360px;">
                    <i class="fa-solid fa-magnifying-glass" aria-hidden="true"></i>
                    <input type="text" id="interactionSearch"
                        placeholder="<?php echo htmlspecialchars(t('admin_interactions_search_ph'), ENT_QUOTES, 'UTF-8'); ?>"
                        autocomplete="off"
                        aria-label="<?php echo htmlspecialchars(t('admin_interactions_search_ph'), ENT_QUOTES, 'UTF-8'); ?>">
                </div>
                <div style="display:flex;flex-direction:column;gap:16px;margin-top:8px;" id="interactionsList">
                    <?php foreach ($allInteractions as $ia): ?>
                        <?php
                            $iaStatus = (string) ($ia['status'] ?? 'Pending');
                            $statusColors = [
                                'Pending'   => ['#fff7ed','#9a3412','#fdba74'],
                                'Confirmed' => ['#ecfdf5','#065f46','#86efac'],
                                'Completed' => ['#dbeafe','#1e40af','#93c5fd'],
                                'Cancelled' => ['#fee2e2','#991b1b','#fca5a5'],
                            ];
                            [$sc_bg, $sc_text, $sc_border] = $statusColors[$iaStatus] ?? ['#f8fafc','#334155','#cbd5e1'];
                            $iaImages = array_filter([(string)($ia['image1']??''), (string)($ia['image2']??''), (string)($ia['image3']??'')]);
                            $iaDate = !empty($ia['appointment_date']) ? $ia['appointment_date'] : '';
                            $iaTime = !empty($ia['appointment_time']) ? substr((string)$ia['appointment_time'], 0, 5) : '';
                            $iaId   = (int) $ia['request_id'];
                            $iaMsgCount = (int)($ia['message_count'] ?? 0);
                        ?>
                        <article style="background:#fff;border:1px solid #e2e8f0;border-radius:16px;padding:0;overflow:hidden;box-shadow:0 4px 14px rgba(15,23,42,.05);" data-search="<?php echo htmlspecialchars(strtolower(implode(' ', [$iaId, $ia['customer_name'] ?? '', $ia['customer_email'] ?? '', $ia['customer_phone'] ?? '', $ia['provider_name'] ?? '', $ia['provider_email'] ?? '', $ia['provider_phone'] ?? '', $ia['category_name'] ?? '', $iaStatus])), ENT_QUOTES, 'UTF-8'); ?>">
                            <!-- Header bar -->
                            <div style="display:flex;align-items:center;justify-content:space-between;padding:12px 16px;background:#f8fafc;border-bottom:1px solid #e2e8f0;flex-wrap:wrap;gap:8px;">
                                <div style="display:flex;align-items:center;gap:10px;">
                                    <span style="font-size:.75rem;font-weight:800;color:#64748b;letter-spacing:.04em;">REQ #<?php echo $iaId; ?></span>
                                    <span style="background:<?php echo $sc_bg; ?>;color:<?php echo $sc_text; ?>;border:1px solid <?php echo $sc_border; ?>;padding:2px 9px;border-radius:20px;font-size:.73rem;font-weight:800;"><?php echo htmlspecialchars(t('req_status_' . strtolower($iaStatus)), ENT_QUOTES, 'UTF-8'); ?></span>
                                    <?php if (!empty($ia['category_name'])): ?>
                                        <?php
                                            $iaCatDisplay = (isRtl() && !empty($ia['category_name_ar']))
                                                ? $ia['category_name_ar']
                                                : $ia['category_name'];
                                        ?>
                                        <span style="font-size:.78rem;font-weight:700;color:#334155;background:#f1f5f9;padding:2px 9px;border-radius:20px;border:1px solid #e2e8f0;"><?php echo htmlspecialchars($iaCatDisplay, ENT_QUOTES, 'UTF-8'); ?></span>
                                    <?php endif; ?>
                                </div>
                                <div style="display:flex;align-items:center;gap:8px;">
                                    <?php if ($iaDate !== ''): ?>
                                        <span style="font-size:.78rem;color:#64748b;"><i class="fas fa-calendar-alt" style="margin-right:4px;"></i><?php echo htmlspecialchars($iaDate . ($iaTime !== '' ? ' ' . $iaTime : ''), ENT_QUOTES, 'UTF-8'); ?></span>
                                    <?php endif; ?>
                                    <button onclick="toggleInteraction(<?php echo $iaId; ?>)" style="font-size:.76rem;font-weight:700;color:#0f766e;background:#ecfdf5;border:1px solid #86efac;border-radius:8px;padding:4px 10px;cursor:pointer;">
                                        <i class="fas fa-chevron-down" id="chevron-<?php echo $iaId; ?>"></i> <?php echo htmlspecialchars(t('admin_interactions_details'), ENT_QUOTES, 'UTF-8'); ?>
                                    </button>
                                </div>
                            </div>

                            <!-- Collapsed summary row -->
                            <div style="display:grid;grid-template-columns:1fr 1fr;gap:0;padding:12px 16px;">
                                <div style="border-right:1px solid #f1f5f9;padding-right:16px;">
                                    <p style="font-size:.72rem;font-weight:800;color:#94a3b8;text-transform:uppercase;letter-spacing:.04em;margin-bottom:4px;"><?php echo htmlspecialchars(t('admin_interactions_customer'), ENT_QUOTES, 'UTF-8'); ?></p>
                                    <p style="font-size:.9rem;font-weight:700;color:#0f172a;"><?php echo htmlspecialchars((string)($ia['customer_name'] ?? 'Unknown'), ENT_QUOTES, 'UTF-8'); ?></p>
                                    <p style="font-size:.78rem;color:#64748b;" dir="ltr"><?php echo htmlspecialchars((string)($ia['customer_email'] ?? ''), ENT_QUOTES, 'UTF-8'); ?></p>
                                    <?php if (!empty($ia['customer_phone'])): ?>
                                        <p style="font-size:.78rem;color:#64748b;" dir="ltr"><?php echo htmlspecialchars((string)$ia['customer_phone'], ENT_QUOTES, 'UTF-8'); ?></p>
                                    <?php endif; ?>
                                </div>
                                <div style="padding-left:16px;">
                                    <p style="font-size:.72rem;font-weight:800;color:#94a3b8;text-transform:uppercase;letter-spacing:.04em;margin-bottom:4px;"><?php echo htmlspecialchars(t('admin_interactions_provider'), ENT_QUOTES, 'UTF-8'); ?></p>
                                    <p style="font-size:.9rem;font-weight:700;color:#0f172a;"><?php echo htmlspecialchars((string)($ia['provider_name'] ?? 'Unknown'), ENT_QUOTES, 'UTF-8'); ?></p>
                                    <p style="font-size:.78rem;color:#64748b;" dir="ltr"><?php echo htmlspecialchars((string)($ia['provider_email'] ?? ''), ENT_QUOTES, 'UTF-8'); ?></p>
                                    <?php if (!empty($ia['provider_phone'])): ?>
                                        <p style="font-size:.78rem;color:#64748b;" dir="ltr"><?php echo htmlspecialchars((string)$ia['provider_phone'], ENT_QUOTES, 'UTF-8'); ?></p>
                                    <?php endif; ?>
                                </div>
                            </div>

                            <!-- Expandable detail block -->
                            <div id="detail-<?php echo $iaId; ?>" style="display:none;border-top:1px solid #f1f5f9;padding:14px 16px;background:#fafafa;">
                                <?php if (!empty($ia['description'])): ?>
                                    <div style="margin-bottom:12px;">
                                        <p style="font-size:.76rem;font-weight:800;color:#94a3b8;text-transform:uppercase;margin-bottom:4px;"><?php echo htmlspecialchars(t('admin_interactions_desc'), ENT_QUOTES, 'UTF-8'); ?></p>
                                        <p style="font-size:.88rem;color:#334155;line-height:1.5;"><?php echo nl2br(htmlspecialchars((string)($ia['description'] ?? ''), ENT_QUOTES, 'UTF-8')); ?></p>
                                    </div>
                                <?php endif; ?>

                                <!-- Pricing -->
                                <?php if ($ia['estimated_price'] !== null || $ia['final_price'] !== null): ?>
                                    <div style="display:flex;gap:16px;margin-bottom:12px;flex-wrap:wrap;">
                                        <?php if ($ia['estimated_price'] !== null): ?>
                                            <div style="background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:8px 12px;">
                                                <p style="font-size:.72rem;font-weight:800;color:#94a3b8;text-transform:uppercase;"><?php echo htmlspecialchars(t('req_price_estimated'), ENT_QUOTES, 'UTF-8'); ?></p>
                                                <p style="font-size:.92rem;font-weight:800;color:#0f766e;">$<?php echo number_format((float)$ia['estimated_price'], 2); ?></p>
                                            </div>
                                        <?php endif; ?>
                                        <?php if ($ia['final_price'] !== null): ?>
                                            <div style="background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:8px 12px;">
                                                <p style="font-size:.72rem;font-weight:800;color:#94a3b8;text-transform:uppercase;"><?php echo htmlspecialchars(t('req_price_final'), ENT_QUOTES, 'UTF-8'); ?></p>
                                                <p style="font-size:.92rem;font-weight:800;color:#1e40af;">$<?php echo number_format((float)$ia['final_price'], 2); ?></p>
                                            </div>
                                        <?php endif; ?>
                                    </div>
                                <?php endif; ?>

                                <!-- Rating & review -->
                                <?php if ($ia['rating'] !== null): ?>
                                    <div style="margin-bottom:12px;">
                                        <p style="font-size:.76rem;font-weight:800;color:#94a3b8;text-transform:uppercase;margin-bottom:4px;"><?php echo htmlspecialchars(t('req_rating_label'), ENT_QUOTES, 'UTF-8'); ?></p>
                                        <div style="display:flex;align-items:center;gap:6px;">
                                            <?php for ($s = 1; $s <= 5; $s++): ?>
                                                <i class="fas fa-star" style="color:<?php echo $s <= (int)$ia['rating'] ? '#f59e0b' : '#cbd5e1'; ?>;font-size:.9rem;"></i>
                                            <?php endfor; ?>
                                            <span style="font-size:.82rem;color:#64748b;">(<?php echo (int)$ia['rating']; ?>/5)</span>
                                        </div>
                                        <?php if (!empty($ia['review'])): ?>
                                            <p style="font-size:.84rem;color:#334155;margin-top:4px;font-style:italic;">"<?php echo htmlspecialchars((string)$ia['review'], ENT_QUOTES, 'UTF-8'); ?>"</p>
                                        <?php endif; ?>
                                    </div>
                                <?php endif; ?>

                                <!-- Images -->
                                <?php if (!empty($iaImages)): ?>
                                    <div style="margin-bottom:12px;">
                                        <p style="font-size:.76rem;font-weight:800;color:#94a3b8;text-transform:uppercase;margin-bottom:6px;"><?php echo htmlspecialchars(t('admin_interactions_images'), ENT_QUOTES, 'UTF-8'); ?></p>
                                        <div style="display:flex;gap:8px;flex-wrap:wrap;">
                                            <?php foreach ($iaImages as $imgPath): ?>
                                                <a href="<?php echo htmlspecialchars($imgPath, ENT_QUOTES, 'UTF-8'); ?>" target="_blank" style="display:block;width:72px;height:72px;border-radius:10px;overflow:hidden;border:1px solid #e2e8f0;">
                                                    <img src="<?php echo htmlspecialchars($imgPath, ENT_QUOTES, 'UTF-8'); ?>" alt="Request image" style="width:100%;height:100%;object-fit:cover;">
                                                </a>
                                            <?php endforeach; ?>
                                        </div>
                                    </div>
                                <?php endif; ?>

                                <!-- Messages link -->
                                <div style="display:flex;align-items:center;gap:10px;padding-top:8px;border-top:1px solid #e2e8f0;">
                                    <span style="font-size:.82rem;color:#64748b;"><i class="fas fa-comments" style="margin-right:5px;"></i><?php echo $iaMsgCount; ?> <?php echo htmlspecialchars(t('admin_interactions_msgs'), ENT_QUOTES, 'UTF-8'); ?></span>
                                    <?php if ($iaMsgCount > 0): ?>
                                        <button onclick="loadInteractionMessages(<?php echo $iaId; ?>, this)" style="font-size:.76rem;font-weight:700;color:#0f766e;background:#ecfdf5;border:1px solid #86efac;border-radius:8px;padding:4px 10px;cursor:pointer;"><?php echo htmlspecialchars(t('admin_interactions_view_msgs'), ENT_QUOTES, 'UTF-8'); ?></button>
                                    <?php endif; ?>
                                </div>
                                <div id="msgs-<?php echo $iaId; ?>" style="display:none;margin-top:10px;max-height:320px;overflow-y:auto;display:none;flex-direction:column;gap:6px;background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:10px;"></div>
                            </div>
                        </article>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
        </section>

    </div>

    <script>
        /*
         * Live search for service category cards.
         */
        (function () {
            var input = document.getElementById('adminCatSearch');
            var grid  = document.getElementById('adminCatGrid');
            if (!input || !grid) return;
            input.addEventListener('input', function () {
                var q = input.value.trim().toLowerCase();
                var cards = grid.querySelectorAll('.category-card');
                cards.forEach(function (card) {
                    var name = (card.dataset.catName || '').toLowerCase();
                    card.style.display = (q === '' || name.indexOf(q) !== -1) ? '' : 'none';
                });
            });
        })();

        /*
         * Confirmation prompts for suspension actions.
         */
        document.querySelectorAll('[data-confirm]').forEach((button) => {
            button.addEventListener('click', (event) => {
                const message = button.getAttribute('data-confirm');
                if (message && !window.confirm(message)) {
                    event.preventDefault();
                }
            });
        });

        /*
         * Live search suggestions and auto-submit for provider/customer toolbars.
         */
        (function () {
            var toolbarForms = document.querySelectorAll('.toolbar-form');
            if (!toolbarForms.length) {
                return;
            }

            function attachLiveSearch(formElement) {
                var searchInput = formElement.querySelector('input[type="search"][data-suggest]');
                if (!searchInput) {
                    return;
                }

                var datalistId = searchInput.getAttribute('list') || '';
                var datalist = datalistId ? document.getElementById(datalistId) : null;
                var debounceTimer = null;

                function clearSuggestions() {
                    if (datalist) {
                        datalist.innerHTML = '';
                    }
                }

                function updateSuggestions() {
                    var query = (searchInput.value || '').trim();
                    clearSuggestions();

                    if (!datalist || query.length < 1) {
                        return;
                    }

                    var params = new URLSearchParams(new FormData(formElement));
                    params.set('suggest', searchInput.getAttribute('data-suggest'));
                    params.set('query', query);

                    fetch('admin_dashboard.php?' + params.toString())
                        .then(function (response) { return response.json(); })
                        .then(function (payload) {
                            if (!payload || !payload.ok || !Array.isArray(payload.suggestions)) {
                                return;
                            }

                            payload.suggestions.forEach(function (suggestion) {
                                var option = document.createElement('option');
                                option.value = suggestion;
                                datalist.appendChild(option);
                            });
                        })
                        .catch(function () {
                            return;
                        });
                }

                function navigateForm() {
                    var action = formElement.getAttribute('action') || '';
                    var hashIndex = action.indexOf('#');
                    var hash = hashIndex !== -1 ? action.substring(hashIndex) : '';
                    var base = hashIndex !== -1 ? action.substring(0, hashIndex) : action;
                    var params = new URLSearchParams(new FormData(formElement));
                    try {
                        sessionStorage.setItem('adminSearchFocusName', searchInput.name || '');
                        sessionStorage.setItem('adminSearchFocusValue', searchInput.value || '');
                    } catch (e) {}
                    window.location.href = base + '?' + params.toString() + hash;
                }

                function scheduleSubmit() {
                    if (debounceTimer) {
                        window.clearTimeout(debounceTimer);
                    }

                    debounceTimer = window.setTimeout(navigateForm, 800);
                }

                searchInput.addEventListener('input', function () {
                    updateSuggestions();
                    scheduleSubmit();
                });

                searchInput.addEventListener('keydown', function (e) {
                    if (e.key === 'Enter') {
                        if (debounceTimer) {
                            window.clearTimeout(debounceTimer);
                            debounceTimer = null;
                        }
                        navigateForm();
                    }
                });

                formElement.querySelectorAll('select').forEach(function (selectElement) {
                    selectElement.addEventListener('change', navigateForm);
                });
            }

            toolbarForms.forEach(function (formElement) {
                attachLiveSearch(formElement);
            });

            /* Restore focus to the search input after a filter navigation */
            (function () {
                var focusName = '';
                try { focusName = sessionStorage.getItem('adminSearchFocusName') || ''; } catch (e) {}
                if (!focusName) return;
                try { sessionStorage.removeItem('adminSearchFocusName'); sessionStorage.removeItem('adminSearchFocusValue'); } catch (e) {}
                var target = document.querySelector('input[type="search"][name="' + focusName + '"]');
                if (!target) return;
                target.focus();
                var len = target.value.length;
                try { target.setSelectionRange(len, len); } catch (e) {}
            })();
        })();

        /*
         * Mobile sidebar toggle behavior with backdrop support.
         */
        (function () {
            var sidebar = document.getElementById('sidebar');
            var toggleButton = document.getElementById('sidebarToggle');
            var backdrop = document.getElementById('sidebarBackdrop');

            if (!sidebar || !toggleButton || !backdrop) {
                return;
            }

            function setSidebarState(isOpen) {
                sidebar.classList.toggle('open', isOpen);
                document.body.classList.toggle('sidebar-open', isOpen);
                toggleButton.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
                toggleButton.setAttribute('aria-label', isOpen ? 'Close navigation menu' : 'Open navigation menu');
            }

            toggleButton.addEventListener('click', function () {
                setSidebarState(!sidebar.classList.contains('open'));
            });

            backdrop.addEventListener('click', function () {
                setSidebarState(false);
            });

            document.querySelectorAll('.sidebar-menu a, .sidebar-footer a').forEach(function (link) {
                link.addEventListener('click', function () {
                    if (window.innerWidth <= 900) {
                        setSidebarState(false);
                    }
                });
            });

            window.addEventListener('resize', function () {
                if (window.innerWidth > 900) {
                    setSidebarState(false);
                }
            });

            document.addEventListener('keydown', function (e) {
                if (e.key === 'Escape' && sidebar.classList.contains('open')) {
                    setSidebarState(false);
                }
            });
        })();
        /*
         * Poll admin chat unread count every 15s and update the badge in the topbar.
         */
        (function () {
            var badge = document.getElementById('adminChatBadge');
            if (!badge) return;

            function pollAdminChatUnread() {
                fetch('admin_chat_api.php?action=unread_count', { credentials: 'same-origin' })
                    .then(function (r) { return r.json(); })
                    .then(function (d) {
                        if (!d || !d.ok) return;
                        var count = parseInt(d.count || 0, 10);
                        if (count > 0) {
                            badge.textContent = String(count);
                            badge.style.display = '';
                        } else {
                            badge.style.display = 'none';
                        }
                    })
                    .catch(function () {});
            }

            setInterval(pollAdminChatUnread, 15000);
        })();

        /*
         * Live search / filter for the interactions list.
         */
        (function () {
            var input = document.getElementById('interactionSearch');
            var list  = document.getElementById('interactionsList');
            if (!input || !list) return;
            input.addEventListener('input', function () {
                var q = input.value.trim().toLowerCase();
                list.querySelectorAll('article').forEach(function (article) {
                    var text = (article.dataset.search || '').toLowerCase();
                    article.style.display = (q === '' || text.indexOf(q) !== -1) ? '' : 'none';
                });
            });
        })();

        /*
         * Reviews filter: auto-submit on select change and debounced text input.
         * Uses window.location.href instead of form.submit() so the #reviews hash
         * is preserved — without it the :target CSS rule hides the panel on reload.
         */
        (function () {
            var form = document.getElementById('reviewsFilterForm');
            if (!form) return;
            var debounceTimer = null;

            function submitReviewsFilter() {
                var params = new URLSearchParams();
                new FormData(form).forEach(function (val, key) {
                    params.append(key, val);
                });
                window.location.href = form.action + '?' + params.toString() + '#reviews';
            }

            form.addEventListener('submit', function (e) {
                e.preventDefault();
                if (debounceTimer) clearTimeout(debounceTimer);
                submitReviewsFilter();
            });

            form.querySelectorAll('select').forEach(function (sel) {
                sel.addEventListener('change', submitReviewsFilter);
            });

            var searchInput = form.querySelector('input[type="search"]');
            if (searchInput) {
                searchInput.addEventListener('input', function () {
                    if (debounceTimer) clearTimeout(debounceTimer);
                    debounceTimer = setTimeout(submitReviewsFilter, 420);
                });
            }
        })();

        /*
         * Interaction card expand/collapse toggle.
         */
        function toggleInteraction(id) {
            var detail  = document.getElementById('detail-' + id);
            var chevron = document.getElementById('chevron-' + id);
            if (!detail) return;
            var isOpen = detail.style.display !== 'none' && detail.style.display !== '';
            detail.style.display  = isOpen ? 'none' : 'block';
            if (chevron) {
                chevron.style.transform = isOpen ? '' : 'rotate(180deg)';
                chevron.style.transition = 'transform .2s';
            }
        }

        /*
         * Load and render chat messages for a request inside the admin interactions panel.
         */
        var _iaMsgsI18n = {
            view:     <?php echo json_encode(t('admin_interactions_view_msgs')); ?>,
            hide:     <?php echo json_encode(t('admin_interactions_hide_msgs')); ?>,
            loading:  <?php echo json_encode(t('lbl_loading')); ?>,
            noMsgs:   <?php echo json_encode(t('admin_interactions_no_msgs')); ?>,
            msgsErr:  <?php echo json_encode(t('admin_interactions_msgs_err')); ?>,
            provider: <?php echo json_encode(t('admin_interactions_provider')); ?>,
            customer: <?php echo json_encode(t('admin_interactions_customer')); ?>,
        };

        function loadInteractionMessages(requestId, btn) {
            var container = document.getElementById('msgs-' + requestId);
            if (!container) return;

            var isVisible = container.style.display === 'flex';
            if (isVisible) {
                container.style.display = 'none';
                btn.textContent = _iaMsgsI18n.view;
                return;
            }

            btn.disabled = true;
            btn.textContent = _iaMsgsI18n.loading;

            fetch('chat_api.php?action=fetch&request_id=' + encodeURIComponent(requestId) + '&since_id=0', {
                credentials: 'same-origin'
            })
            .then(function (r) { return r.json(); })
            .then(function (data) {
                container.innerHTML = '';
                var messages = (data && Array.isArray(data.messages)) ? data.messages : (Array.isArray(data) ? data : []);
                if (!messages.length) {
                    container.innerHTML = '<p style="font-size:.84rem;color:#64748b;padding:6px 0;">' + _iaMsgsI18n.noMsgs + '</p>';
                } else {
                    messages.forEach(function (msg) {
                        var bubble = document.createElement('div');
                        var isProvider = String(msg.sender_role || '').toLowerCase() === 'provider';
                        bubble.style.cssText = 'padding:8px 12px;border-radius:12px;font-size:.84rem;max-width:85%;' +
                            (isProvider
                                ? 'background:#ecfdf5;border:1px solid #86efac;align-self:flex-end;'
                                : 'background:#f0f9ff;border:1px solid #bae6fd;align-self:flex-start;');
                        var sender = document.createElement('span');
                        sender.style.cssText = 'font-size:.72rem;font-weight:800;color:#64748b;display:block;margin-bottom:2px;';
                        sender.textContent = (isProvider ? _iaMsgsI18n.provider : _iaMsgsI18n.customer) +
                            (msg.created_at ? ' · ' + new Date(String(msg.created_at).replace(' ', 'T'))
                                .toLocaleString([], {month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'}) : '');
                        bubble.appendChild(sender);
                        if (msg.image_path) {
                            var img = document.createElement('img');
                            img.src = String(msg.image_path);
                            img.alt = 'image';
                            img.style.cssText = 'max-width:160px;border-radius:8px;display:block;margin-top:4px;';
                            bubble.appendChild(img);
                        } else {
                            var text = document.createElement('span');
                            text.textContent = String(msg.message || '');
                            bubble.appendChild(text);
                        }
                        container.appendChild(bubble);
                    });
                }
                container.style.display = 'flex';
                container.style.flexDirection = 'column';
                container.style.gap = '6px';
                container.scrollTop = container.scrollHeight;
                btn.textContent = _iaMsgsI18n.hide;
                btn.disabled = false;
            })
            .catch(function () {
                container.innerHTML = '<p style="font-size:.84rem;color:#ef4444;padding:6px 0;">' + _iaMsgsI18n.msgsErr + '</p>';
                container.style.display = 'flex';
                btn.disabled = false;
                btn.textContent = _iaMsgsI18n.view;
            });
        }
    </script>
</body>
</html>
