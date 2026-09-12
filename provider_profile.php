<?php
declare(strict_types=1);

/*
 * Start/resume session so we can enforce protected access and CSRF validation.
 */
session_start();

$appBase = rtrim(str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'])), '/');

/*
 * Allow admin sessions to review provider profiles without customer tab tokens.
 */
$isAdminViewer = isset($_SESSION['user_type']) && (string) $_SESSION['user_type'] === 'admin';
$adminEmail = $isAdminViewer ? (string) ($_SESSION['user_email'] ?? '') : '';

/*
 * Shared PDO connection used by profile reads and service request writes.
 */
require_once __DIR__ . '/db_connection.php';
require_once __DIR__ . '/site_settings.php';
require_once __DIR__ . '/lang.php';
require_once __DIR__ . '/service_categories.php';

ensureSiteSettingsTable($pdo);
$siteFavicon = resolveSiteFavicon($pdo);

/*
 * JSON-backed verification store for provider status display.
 */
require_once __DIR__ . '/verification_store.php';

/*
 * JSON-backed suspension store for provider status display.
 */
require_once __DIR__ . '/suspension_store.php';

/*
 * Build lookup map so verification checks are fast during rendering.
 */
$verifiedProviderLookup = buildVerifiedProviderLookup(loadVerifiedProviderIds());

/*
 * Build lookup map for suspended providers.
 */
$suspendedAccountIds = loadSuspendedAccountIds();
$suspendedProviderLookup = buildSuspendedLookup((array) ($suspendedAccountIds['providers'] ?? []));

/*
 * Enforce tab-scoped access token for protected customer pages.
 * Without a valid token in URL/form payload, this page redirects to login.
 */
$tabAccessToken = '';
$activeTabSession = null;
if (!$isAdminViewer) {
    $tabAccessToken = trim((string) ($_GET['tab'] ?? $_POST['tab'] ?? ''));
    if (!preg_match('/^[a-f0-9]{64}$/', $tabAccessToken)) {
        header('Location: ' . $appBase . '/login.php');
        exit;
    }

    /*
     * Resolve active tab identity from the session token registry.
     * This decouples protected access from shared browser-cookie sessions.
     */
    if (isset($_SESSION['customer_tab_tokens']) && is_array($_SESSION['customer_tab_tokens'])) {
        $tokenPayload = $_SESSION['customer_tab_tokens'][$tabAccessToken] ?? null;
        if (is_array($tokenPayload)) {
            $activeTabSession = $tokenPayload;
        }
    }

    if (!is_array($activeTabSession)) {
        header('Location: ' . $appBase . '/login.php');
        exit;
    }
}

/*
 * Upload policy constants for service request problem images.
 * Images are stored as web paths in servicerequest.image1/image2/image3.
 */
const SERVICE_REQUEST_UPLOAD_DIRECTORY = __DIR__ . '/uploads/service_requests';
const SERVICE_REQUEST_UPLOAD_WEB_PATH = 'uploads/service_requests';
const SERVICE_REQUEST_MAX_IMAGE_BYTES = 5_242_880; // 5 MB

/*
 * Limit the number of appointment slots a customer can propose per request.
 */
const MAX_REQUEST_SLOT_CHOICES = 3;

/*
 * Validate and normalize uploaded images from request form fields.
 * Returns an associative map (image1/image2/image3) with validated upload metadata.
 */
function validateAndCollectProblemImages(array $files): array
{
    /*
     * Accepted MIME set with matching extension to control stored file format.
     */
    $allowedMimeMap = [
        'image/jpeg' => 'jpg',
        'image/png' => 'png',
        'image/webp' => 'webp',
    ];

    $normalizedUploads = [
        'image1' => null,
        'image2' => null,
        'image3' => null,
    ];

    $hasAtLeastOneImage = false;

    $finfoResource = finfo_open(FILEINFO_MIME_TYPE);
    if ($finfoResource === false) {
        throw new RuntimeException('Unable to validate uploaded images right now.');
    }

    try {
        foreach (array_keys($normalizedUploads) as $fieldName) {
            $filePayload = $files[$fieldName] ?? null;

            if (!is_array($filePayload)) {
                continue;
            }

            $uploadError = (int) ($filePayload['error'] ?? UPLOAD_ERR_NO_FILE);
            if ($uploadError === UPLOAD_ERR_NO_FILE) {
                continue;
            }

            $hasAtLeastOneImage = true;

            if ($uploadError !== UPLOAD_ERR_OK) {
                throw new RuntimeException('One or more uploaded images are invalid. Please try again.');
            }

            $temporaryPath = (string) ($filePayload['tmp_name'] ?? '');
            if ($temporaryPath === '' || !is_uploaded_file($temporaryPath)) {
                throw new RuntimeException('Uploaded image data could not be verified. Please upload again.');
            }

            $fileSize = (int) ($filePayload['size'] ?? 0);
            if ($fileSize <= 0 || $fileSize > SERVICE_REQUEST_MAX_IMAGE_BYTES) {
                throw new RuntimeException('Each image must be between 1 byte and 5 MB.');
            }

            $mimeType = finfo_file($finfoResource, $temporaryPath);
            if (!is_string($mimeType) || !array_key_exists($mimeType, $allowedMimeMap)) {
                throw new RuntimeException('Only JPG, PNG, and WEBP images are allowed.');
            }

            $normalizedUploads[$fieldName] = [
                'tmp_name' => $temporaryPath,
                'extension' => $allowedMimeMap[$mimeType],
            ];
        }
    } finally {
        finfo_close($finfoResource);
    }

    if (!$hasAtLeastOneImage) {
        throw new RuntimeException('Please upload at least one image of the problem.');
    }

    return $normalizedUploads;
}

/*
 * Persist validated uploads to disk and return relative DB paths plus absolute file paths.
 * Absolute paths are used for cleanup if later database insert fails.
 */
function storeValidatedProblemImages(array $validatedUploads): array
{
    $storedPaths = [
        'image1' => null,
        'image2' => null,
        'image3' => null,
    ];
    $movedAbsoluteFiles = [];

    if (!is_dir(SERVICE_REQUEST_UPLOAD_DIRECTORY)) {
        $created = mkdir(SERVICE_REQUEST_UPLOAD_DIRECTORY, 0755, true);
        if (!$created && !is_dir(SERVICE_REQUEST_UPLOAD_DIRECTORY)) {
            throw new RuntimeException('Unable to prepare image upload storage.');
        }
    }

    foreach ($validatedUploads as $fieldName => $fileInfo) {
        if (!is_array($fileInfo)) {
            continue;
        }

        $fileExtension = (string) ($fileInfo['extension'] ?? '');
        $tmpName = (string) ($fileInfo['tmp_name'] ?? '');
        $generatedName = 'problem_' . date('Ymd_His') . '_' . bin2hex(random_bytes(10)) . '.' . $fileExtension;
        $absoluteDestination = SERVICE_REQUEST_UPLOAD_DIRECTORY . DIRECTORY_SEPARATOR . $generatedName;

        if (!move_uploaded_file($tmpName, $absoluteDestination)) {
            throw new RuntimeException('Unable to save uploaded image. Please try again.');
        }

        $storedPaths[$fieldName] = SERVICE_REQUEST_UPLOAD_WEB_PATH . '/' . $generatedName;
        $movedAbsoluteFiles[] = $absoluteDestination;
    }

    return [
        'stored_paths' => $storedPaths,
        'moved_files' => $movedAbsoluteFiles,
    ];
}

/*
 * Read currently selected provider from GET/POST while keeping value numeric and positive.
 */
$providerId = (int) ($_GET['provider_id'] ?? $_POST['provider_id'] ?? 0);
if ($providerId < 0) {
    $providerId = 0;
}

/*
 * Tab identity values used for ownership and topbar display.
 */
$customerId = 0;
$customerEmail = '';
if (!$isAdminViewer) {
    $customerId = (int) ($activeTabSession['user_id'] ?? 0);
    $customerEmail = (string) ($activeTabSession['user_email'] ?? '');

    if ($customerId <= 0) {
        header('Location: ' . $appBase . '/login.php');
        exit;
    }
}

/*
 * Keep legacy session keys aligned with the validated tab identity
 * unless another role is already active in this PHP session.
 */
$existingUserType = (string) ($_SESSION['user_type'] ?? '');
if (!$isAdminViewer && ($existingUserType === '' || $existingUserType === 'customer')) {
    $_SESSION['user_id'] = $customerId;
    $_SESSION['user_email'] = $customerEmail;
    $_SESSION['user_type'] = 'customer';
}

/*
 * Build a CSRF token dedicated to service request submissions from this page.
 */
if (!$isAdminViewer && (!isset($_SESSION['provider_request_csrf']) || !is_string($_SESSION['provider_request_csrf']))) {
    $_SESSION['provider_request_csrf'] = bin2hex(random_bytes(32));
}

/*
 * Page-level state used across validation and render cycles.
 */
$errorMessage = '';
$successMessage = '';
$selectedCategoryId = 0;
$selectedSlotIds = [];

/*
 * Read flash success message from previous PRG redirect and clear it immediately.
 */
if (isset($_SESSION['provider_request_flash_success']) && is_string($_SESSION['provider_request_flash_success'])) {
    $successMessage = $_SESSION['provider_request_flash_success'];
    unset($_SESSION['provider_request_flash_success']);
}

/*
 * Handle POST submissions for creating a new service request targeting this provider.
 */
if (!$isAdminViewer && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $postedCsrfToken = (string) ($_POST['csrf_token'] ?? '');
    $selectedCategoryId = (int) ($_POST['category_id'] ?? 0);
    $selectedSlotIds = array_values(
        array_unique(
            array_filter(
                array_map('intval', (array) ($_POST['slot_ids'] ?? [])),
                static function (int $slotId): bool {
                    return $slotId > 0;
                }
            )
        )
    );

    /*
     * Server-side validation gate for CSRF, provider, category, slot, and image uploads.
     */
    if (!hash_equals($_SESSION['provider_request_csrf'], $postedCsrfToken)) {
        $errorMessage = 'Invalid request token. Please refresh the page and try again.';
    } elseif ($providerId <= 0) {
        $errorMessage = 'Invalid service provider selection.';
    } elseif ($selectedCategoryId <= 0) {
        $errorMessage = 'Please choose a service category for your request.';
    } elseif (count($selectedSlotIds) === 0) {
        $errorMessage = 'Please choose at least one appointment slot.';
    } elseif (count($selectedSlotIds) > MAX_REQUEST_SLOT_CHOICES) {
        $errorMessage = 'Please choose no more than ' . MAX_REQUEST_SLOT_CHOICES . ' appointment slots.';
    } else {
        $uploadedFileSet = null;
        $movedAbsoluteFiles = [];

        try {
            /*
             * Confirm the selected category is offered by this provider.
             * This enforces category matching between customer requests and provider offerings.
             */
            if ($errorMessage === '') {
                $categoryMatch = $pdo->prepare(
                    'SELECT ps.category_id
                     FROM providedservices ps
                     WHERE ps.provider_id = :provider_id
                       AND ps.category_id = :category_id
                     LIMIT 1'
                );
                $categoryMatch->execute([
                    'provider_id' => $providerId,
                    'category_id' => $selectedCategoryId,
                ]);

                if ($categoryMatch->fetch() === false) {
                    $errorMessage = 'Please choose a category offered by this provider.';
                }
            }

            /*
             * Verify selected slots belong to provider, are future-dated, and not already reserved.
             */
            if ($errorMessage === '') {
                $slotPlaceholders = [];
                $slotParams = ['provider_id' => $providerId];

                foreach ($selectedSlotIds as $index => $slotId) {
                    $placeholder = 'slot_' . $index;
                    $slotPlaceholders[] = ':' . $placeholder;
                    $slotParams[$placeholder] = $slotId;
                }

                $slotValidation = $pdo->prepare(
                    "SELECT asl.slot_id
                     FROM appointmentslot asl
                     LEFT JOIN servicerequest sr
                        ON sr.slot_id = asl.slot_id
                        AND sr.status IN ('Pending', 'Confirmed', 'Completed')
                     WHERE asl.serviceprovider_id = :provider_id
                       AND asl.date >= CURDATE()
                       AND asl.slot_id IN (" . implode(', ', $slotPlaceholders) . ")
                       AND sr.request_id IS NULL"
                );
                $slotValidation->execute($slotParams);

                $availableSlotIds = $slotValidation->fetchAll(PDO::FETCH_COLUMN, 0);

                if (count($availableSlotIds) !== count($selectedSlotIds)) {
                    $errorMessage = 'One or more selected slots are no longer available. Please choose different slots.';
                }
            }

            /*
             * Validate and normalize uploaded images before any disk/database write.
             */
            if ($errorMessage === '') {
                $uploadedFileSet = validateAndCollectProblemImages($_FILES);
            }

            if ($errorMessage === '') {
                /*
                 * Wrap file move + DB insert in transaction-like flow with cleanup on failure.
                 */
                $pdo->beginTransaction();

                $storedImageResult = storeValidatedProblemImages($uploadedFileSet ?? []);
                $storedImagePaths = (array) ($storedImageResult['stored_paths'] ?? []);
                $movedAbsoluteFiles = (array) ($storedImageResult['moved_files'] ?? []);

                $insertRequest = $pdo->prepare(
                    "INSERT INTO servicerequest
                        (customer_id, category_id, slot_id, status, image1, image2, image3)
                     VALUES
                        (:customer_id, :category_id, :slot_id, 'Pending', :image1, :image2, :image3)"
                );

                foreach ($selectedSlotIds as $slotId) {
                    $insertRequest->execute([
                        'customer_id' => $customerId,
                        'category_id' => $selectedCategoryId,
                        'slot_id' => $slotId,
                        'image1' => $storedImagePaths['image1'] ?? null,
                        'image2' => $storedImagePaths['image2'] ?? null,
                        'image3' => $storedImagePaths['image3'] ?? null,
                    ]);
                }

                $pdo->commit();

                /*
                 * Redirect with flash message to prevent duplicate inserts on page refresh.
                 */
                $_SESSION['customer_requests_flash_success'] =
                    'Service request submitted with ' . count($selectedSlotIds) . ' slot option(s). The provider can now review your request.';
                header(
                    'Location: ' . $appBase . '/customer_requests.php'
                    . '?tab=' . urlencode($tabAccessToken)
                );
                exit;
            }
        } catch (Throwable $exception) {
            /*
             * Roll back DB state and remove moved image files if any part fails.
             */
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }

            foreach ($movedAbsoluteFiles as $absolutePath) {
                if (is_string($absolutePath) && $absolutePath !== '' && is_file($absolutePath)) {
                    @unlink($absolutePath);
                }
            }

            if ($errorMessage === '') {
                $errorMessage = 'Unable to submit service request right now. Please try again.';
            }
        }
    }
}

/*
 * Data sets used by profile rendering and request form options.
 */
$provider = null;
$providerServices = [];
$categoryPriceLookup = [];
$availableSlots = [];
$reviews = [];
$providerAverageRating = null;
$providerRatingCount = 0;

if ($providerId > 0) {
    try {
        /*
         * Load provider profile details and derive verification from JSON.
         */
        $providerStatement = $pdo->prepare(
            'SELECT
                sp.provider_id,
                sp.name,
                sp.phone,
                sp.email,
                sp.bio,
                sp.photo,
                IFNULL(sp.location, \'\') AS location,
                COUNT(DISTINCT ps.category_id) AS service_count
             FROM serviceprovider sp
             LEFT JOIN providedservices ps
                ON sp.provider_id = ps.provider_id
             WHERE sp.provider_id = :provider_id
             GROUP BY sp.provider_id, sp.name, sp.phone, sp.email, sp.bio, sp.photo, sp.location
             LIMIT 1'
        );
        $providerStatement->execute(['provider_id' => $providerId]);
        $providerRow = $providerStatement->fetch();

        if ($providerRow !== false) {
            $providerIdValue = (int) $providerRow['provider_id'];
            $isVerified = isset($verifiedProviderLookup[$providerIdValue]);
            $isSuspended = isset($suspendedProviderLookup[$providerIdValue]);

            /*
             * Block unverified or suspended providers from customer access.
             */
            if (!$isAdminViewer && !$isVerified) {
                $errorMessage = 'This provider is not verified yet.';
            } elseif (!$isAdminViewer && $isSuspended) {
                $errorMessage = 'This provider is currently suspended.';
            } else {
                $provider = [
                    'provider_id' => $providerIdValue,
                    'name' => (string) $providerRow['name'],
                    'phone' => (string) ($providerRow['phone'] ?? ''),
                    'email' => (string) ($providerRow['email'] ?? ''),
                    'bio' => trim((string) ($providerRow['bio'] ?? '')),
                    'photo' => (string) ($providerRow['photo'] ?? ''),
                    'location' => trim((string) ($providerRow['location'] ?? '')),
                    'service_count' => (int) ($providerRow['service_count'] ?? 0),
                    'is_verified' => $isVerified,
                    'is_suspended' => $isSuspended,
                ];

                /*
                 * Load categories and visit prices offered by this provider.
                 */
                $servicesStatement = $pdo->prepare(
                    'SELECT
                        ps.category_id,
                        ps.visit_price,
                        sc.name AS category_name,
                        sc.description AS category_description,
                        IFNULL(sc.name_ar, \'\') AS name_ar,
                        IFNULL(sc.description_ar, \'\') AS description_ar
                     FROM providedservices ps
                     INNER JOIN servicecategory sc
                        ON ps.category_id = sc.category_id
                     WHERE ps.provider_id = :provider_id
                     ORDER BY sc.name ASC'
                );
                $servicesStatement->execute(['provider_id' => $providerId]);

                while ($serviceRow = $servicesStatement->fetch()) {
                    $providerServices[] = [
                        'category_id'        => (int) $serviceRow['category_id'],
                        'visit_price'        => (float) $serviceRow['visit_price'],
                        'name'               => (string) $serviceRow['category_name'],
                        'description'        => trim((string) ($serviceRow['category_description'] ?? '')),
                        'name_ar'            => (string) ($serviceRow['name_ar'] ?? ''),
                        'description_ar'     => trim((string) ($serviceRow['description_ar'] ?? '')),
                        // kept for backward compat in existing template references
                        'category_name'      => (string) $serviceRow['category_name'],
                        'category_description' => trim((string) ($serviceRow['category_description'] ?? '')),
                    ];
                }

                foreach ($providerServices as $service) {
                    $categoryPriceLookup[(int) $service['category_id']] = (float) $service['visit_price'];
                }

                /*
                 * Load future slots that are still available for booking.
                 */
                $slotsStatement = $pdo->prepare(
                    "SELECT
                        asl.slot_id,
                        asl.date,
                        asl.slot
                     FROM appointmentslot asl
                     LEFT JOIN servicerequest sr
                        ON sr.slot_id = asl.slot_id
                        AND sr.status IN ('Pending', 'Confirmed', 'Completed')
                     WHERE asl.serviceprovider_id = :provider_id
                       AND asl.date >= CURDATE()
                       AND sr.request_id IS NULL
                     ORDER BY asl.date ASC, asl.slot ASC"
                );
                $slotsStatement->execute(['provider_id' => $providerId]);

                while ($slotRow = $slotsStatement->fetch()) {
                    $availableSlots[] = [
                        'slot_id' => (int) $slotRow['slot_id'],
                        'date' => (string) $slotRow['date'],
                        'slot' => (string) $slotRow['slot'],
                    ];
                }

                /*
                 * Load aggregate rating summary for the provider.
                 * This supports star-based reputation display in profile metadata.
                 */
                $ratingSummaryStatement = $pdo->prepare(
                    "SELECT
                        AVG(sr.rating) AS average_rating,
                        COUNT(sr.rating) AS rating_count
                     FROM servicerequest sr
                     INNER JOIN appointmentslot asl
                        ON sr.slot_id = asl.slot_id
                     WHERE asl.serviceprovider_id = :provider_id
                       AND sr.rating IS NOT NULL"
                );
                $ratingSummaryStatement->execute(['provider_id' => $providerId]);

                $ratingSummaryRow = $ratingSummaryStatement->fetch();
                $providerRatingCount = (int) ($ratingSummaryRow['rating_count'] ?? 0);
                $providerAverageRating = $providerRatingCount > 0
                    ? (float) ($ratingSummaryRow['average_rating'] ?? 0)
                    : null;

                /*
                 * Load review records with either star ratings or textual feedback.
                 */
                $reviewsStatement = $pdo->prepare(
                    "SELECT
                        sr.request_id,
                        sr.review,
                        sr.rating,
                        sr.status,
                        sr.estimated_price,
                        sr.final_price,
                        c.name AS customer_name,
                        sc.name AS category_name,
                        asl.date AS appointment_date,
                        asl.slot AS appointment_time
                     FROM servicerequest sr
                     INNER JOIN appointmentslot asl
                        ON sr.slot_id = asl.slot_id
                     LEFT JOIN customer c
                        ON sr.customer_id = c.customer_id
                     LEFT JOIN servicecategory sc
                        ON sr.category_id = sc.category_id
                     WHERE asl.serviceprovider_id = :provider_id
                             AND (
                                    sr.rating IS NOT NULL
                                    OR (sr.review IS NOT NULL AND TRIM(sr.review) <> '')
                             )
                     ORDER BY sr.request_id DESC
                     LIMIT 50"
                );
                $reviewsStatement->execute(['provider_id' => $providerId]);

                while ($reviewRow = $reviewsStatement->fetch()) {
                         $ratingRaw = $reviewRow['rating'] ?? null;
                    $reviews[] = [
                        'request_id' => (int) $reviewRow['request_id'],
                        'review' => (string) $reviewRow['review'],
                              'rating' => $ratingRaw !== null ? (int) $ratingRaw : null,
                        'status' => (string) ($reviewRow['status'] ?? ''),
                        'estimated_price' => $reviewRow['estimated_price'] !== null ? (float) $reviewRow['estimated_price'] : null,
                        'final_price' => $reviewRow['final_price'] !== null ? (float) $reviewRow['final_price'] : null,
                        'customer_name' => (string) ($reviewRow['customer_name'] ?? 'Anonymous customer'),
                        'category_name' => (string) ($reviewRow['category_name'] ?? 'General service'),
                        'appointment_date' => (string) ($reviewRow['appointment_date'] ?? ''),
                        'appointment_time' => (string) ($reviewRow['appointment_time'] ?? ''),
                    ];
                }
            }
        } else {
            if ($errorMessage === '') {
                $errorMessage = 'The selected service provider could not be found.';
            }
        }
    } catch (PDOException $exception) {
        if ($errorMessage === '') {
            $errorMessage = 'Unable to load provider profile right now. Please try again.';
        }
    }
} elseif ($errorMessage === '') {
    $errorMessage = $isAdminViewer
        ? 'Please select a service provider from the admin dashboard.'
        : 'Please select a service provider from the customer dashboard.';
}

/*
 * Translate a DB status value into the current-language label.
 */
function localizedStatus(string $status): string
{
    $map = [
        'Pending'   => 'req_status_pending',
        'Confirmed' => 'req_status_confirmed',
        'Completed' => 'req_status_completed',
        'Cancelled' => 'req_status_cancelled',
    ];
    $key = $map[$status] ?? null;
    return $key !== null ? t($key) : $status;
}

/*
 * Return a locale-aware date string for slot display.
 * Arabic output uses Arabic month/weekday names; English uses PHP's date().
 */
function localizedSlotDate(string $isoDate): string
{
    static $arDays = [
        'Sunday' => 'الأحد', 'Monday' => 'الاثنين', 'Tuesday' => 'الثلاثاء',
        'Wednesday' => 'الأربعاء', 'Thursday' => 'الخميس', 'Friday' => 'الجمعة', 'Saturday' => 'السبت',
    ];
    static $arMonths = [
        'January' => 'يناير', 'February' => 'فبراير', 'March' => 'مارس', 'April' => 'أبريل',
        'May' => 'مايو', 'June' => 'يونيو', 'July' => 'يوليو', 'August' => 'أغسطس',
        'September' => 'سبتمبر', 'October' => 'أكتوبر', 'November' => 'نوفمبر', 'December' => 'ديسمبر',
    ];
    $ts = strtotime($isoDate);
    if (getLang() !== 'ar') {
        return date('D, M j', $ts);
    }
    $day   = $arDays[date('l', $ts)]  ?? date('l', $ts);
    $month = $arMonths[date('F', $ts)] ?? date('F', $ts);
    return $day . '، ' . toArabicNumerals(date('j', $ts)) . ' ' . $month;
}

/*
 * Short date for review meta (M j → e.g. Apr 7 / أبريل 7).
 */
function localizedShortDate(string $isoDate): string
{
    static $arMonths = [
        'January' => 'يناير', 'February' => 'فبراير', 'March' => 'مارس', 'April' => 'أبريل',
        'May' => 'مايو', 'June' => 'يونيو', 'July' => 'يوليو', 'August' => 'أغسطس',
        'September' => 'سبتمبر', 'October' => 'أكتوبر', 'November' => 'نوفمبر', 'December' => 'ديسمبر',
    ];
    $ts = strtotime($isoDate);
    if (getLang() !== 'ar') {
        return date('M j', $ts);
    }
    $month = $arMonths[date('F', $ts)] ?? date('F', $ts);
    return $month . ' ' . toArabicNumerals(date('j', $ts));
}

/*
 * Build date-grouped slot map for calendar-driven filtering in the request form.
 */
$slotsByDate = [];
$selectedSlotDate = '';
foreach ($availableSlots as $slotItem) {
    $slotDate = $slotItem['date'];
    if (!isset($slotsByDate[$slotDate])) {
        $slotsByDate[$slotDate] = [];
    }

    $slotsByDate[$slotDate][] = $slotItem;

    if (count($selectedSlotIds) > 0 && in_array($slotItem['slot_id'], $selectedSlotIds, true)) {
        if ($selectedSlotDate === '') {
            $selectedSlotDate = $slotDate;
        }
    }
}

$availableDates = array_keys($slotsByDate);
if ($selectedSlotDate === '' && count($availableDates) > 0) {
    $selectedSlotDate = $availableDates[0];
}
?>
<!DOCTYPE html>
<html lang="<?php echo getLang(); ?>" dir="<?php echo t('dir'); ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <?php if ($siteFavicon !== ''): ?>
        <link rel="icon" href="<?php echo htmlspecialchars($appBase . '/' . $siteFavicon, ENT_QUOTES, 'UTF-8'); ?>">
    <?php endif; ?>
    <title><?php echo htmlspecialchars(t('prof_page_title'), ENT_QUOTES, 'UTF-8'); ?> - <?php echo htmlspecialchars(t('site_name'), ENT_QUOTES, 'UTF-8'); ?></title>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <?php if (isRtl()): ?>
    <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <?php endif; ?>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/flatpickr/dist/flatpickr.min.css">
    <style>
        /*
         * Global reset and visual tokens used consistently across profile sections.
         */
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root {
            --ink: #0f172a;
            --muted: #475569;
            --line: #dbe2ea;
            --brand: #0f766e;
            --brand-deep: #115e59;
            --accent: #ea580c;
            --surface: #f8fafc;
            --card: #ffffff;
            --success-bg: #ecfdf5;
            --success-border: #86efac;
            --success-text: #166534;
            --error-bg: #fff1f2;
            --error-border: #fecdd3;
            --error-text: #be123c;
        }

        html,
        body {
            width: 100%;
            overflow-x: hidden;
        }

        body {
            min-height: 100vh;
            font-family: 'Plus Jakarta Sans', sans-serif;
            color: var(--ink);
            background:
                radial-gradient(circle at 12% 0%, rgba(20, 184, 166, 0.16), transparent 36%),
                radial-gradient(circle at 88% 8%, rgba(251, 146, 60, 0.2), transparent 34%),
                linear-gradient(130deg, #ecfeff, #f8fafc 45%, #fff7ed);
            padding: 24px 16px 34px;
        }


        .slots-card { animation-delay: 0.05s; }
        .review-card { animation-delay: 0.1s; }
        .request-card { animation-delay: 0.1s; }

        /*
         * Constrained page shell for profile, review, and request sections.
         */
        .page-shell {
            width: 100%;
            max-width: 1080px;
            margin: 0 auto;
            display: flex;
            flex-direction: column;
            gap: 16px;
        }

        /*
         * Top navigation panel linking back to dashboard and session actions.
         */
        .topbar {
            background: rgba(255, 255, 255, 0.88);
            border: 1px solid rgba(255, 255, 255, 0.9);
            border-radius: 22px;
            padding: 16px;
            box-shadow: 0 14px 35px rgba(15, 23, 42, 0.09);
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 10px;
        }

        .topbar-links {
            display: flex;
            align-items: center;
            gap: 10px;
            flex-wrap: wrap;
        }

        .pill-link {
            min-height: 40px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            padding: 8px 14px;
            border-radius: 999px;
            text-decoration: none;
            border: 1px solid var(--line);
            background: #ffffff;
            color: #0f172a;
            font-size: 0.87rem;
            font-weight: 700;
        }

        .pill-link.primary {
            border: none;
            color: #fff;
            background: linear-gradient(145deg, var(--brand), var(--brand-deep));
        }

        .topbar-note {
            font-size: 0.82rem;
            color: var(--muted);
        }

        /*
         * Shared panel styles used by profile, reviews, and request sections.
         */
        .panel {
            background: rgba(255, 255, 255, 0.92);
            border: 1px solid rgba(255, 255, 255, 0.9);
            border-radius: 22px;
            box-shadow: 0 14px 35px rgba(15, 23, 42, 0.08);
            padding: 18px;
        }

        .panel h2 {
            font-size: 1.2rem;
            color: #042f2e;
            margin-bottom: 10px;
            font-weight: 800;
        }

        .panel p.lead {
            color: var(--muted);
            font-size: 0.92rem;
            margin-bottom: 12px;
            line-height: 1.4;
        }

        /*
         * Feedback banners for operation success and errors.
         */
        .feedback {
            border-radius: 14px;
            padding: 12px 14px;
            font-size: 0.9rem;
            font-weight: 700;
            border: 1px solid;
        }

        .feedback.error {
            background: var(--error-bg);
            border-color: var(--error-border);
            color: var(--error-text);
        }

        .feedback.success {
            background: var(--success-bg);
            border-color: var(--success-border);
            color: var(--success-text);
        }

        /*
         * Provider profile visual structure and metadata blocks.
         */
        .profile-layout {
            display: grid;
            grid-template-columns: 88px 1fr;
            gap: 14px;
            align-items: start;
        }

        .profile-photo {
            width: 88px;
            height: 88px;
            border-radius: 20px;
            overflow: hidden;
            border: 1px solid #dbe2ea;
            background: linear-gradient(135deg, #dbeafe, #e2e8f0);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.7rem;
            color: #0f172a;
        }

        .profile-photo img {
            width: 100%;
            height: 100%;
            object-fit: cover;
            display: block;
        }

        .profile-title {
            display: flex;
            align-items: center;
            gap: 10px;
            flex-wrap: wrap;
            margin-bottom: 8px;
        }

        .profile-title h1 {
            font-size: 1.3rem;
            font-weight: 800;
        }

        .badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            border-radius: 999px;
            padding: 5px 10px;
            font-size: 0.78rem;
            font-weight: 800;
            border: 1px solid;
        }

        .badge.verified {
            background: #ecfdf5;
            border-color: #86efac;
            color: #166534;
        }

        .badge.unverified {
            background: #fff7ed;
            border-color: #fdba74;
            color: #9a3412;
        }

        .profile-meta {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-bottom: 10px;
        }

        .meta-chip {
            border: 1px solid #dbe2ea;
            background: #f8fafc;
            border-radius: 999px;
            padding: 6px 10px;
            font-size: 0.8rem;
            font-weight: 700;
            color: #334155;
        }

        .profile-bio {
            font-size: 0.91rem;
            color: #334155;
            line-height: 1.5;
            margin-bottom: 12px;
        }

        .services-grid {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 10px;
        }

        .service-card {
            border: 1px solid #dbe2ea;
            border-radius: 14px;
            padding: 10px;
            background: #ffffff;
        }

        .service-card h3 {
            font-size: 0.93rem;
            color: #0f172a;
            margin-bottom: 5px;
        }

        .service-card p {
            font-size: 0.82rem;
            color: #475569;
            line-height: 1.4;
        }

        .service-card .price {
            margin-top: 8px;
            font-size: 0.82rem;
            font-weight: 800;
            color: #0f766e;
        }

        /*
         * Reviews list styling.
         */
        .reviews-list {
            display: grid;
            gap: 10px;
        }

        .review-item {
            border: 1px solid #e2e8f0;
            border-radius: 14px;
            padding: 11px;
            background: #fff;
        }

        .review-top {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 8px;
            flex-wrap: wrap;
            margin-bottom: 6px;
        }

        .review-top strong {
            font-size: 0.9rem;
            color: #0f172a;
        }

        .review-meta {
            font-size: 0.78rem;
            color: #64748b;
        }

        .review-text {
            font-size: 0.88rem;
            line-height: 1.5;
            color: #334155;
            margin-bottom: 6px;
        }

        .review-rating {
            margin-bottom: 6px;
            display: flex;
            align-items: center;
            gap: 7px;
            flex-wrap: wrap;
        }

        .review-stars {
            display: inline-flex;
            align-items: center;
            gap: 2px;
            color: #f59e0b;
            font-size: 0.9rem;
        }

        .review-stars .star.is-empty {
            color: #cbd5e1;
        }

        .review-rating-value {
            font-size: 0.8rem;
            color: #334155;
            font-weight: 700;
        }

        .review-prices {
            font-size: 0.78rem;
            color: #475569;
        }

        /*
         * Service request form layout and interactive slot selection styles.
         */
        .request-form {
            display: grid;
            gap: 12px;
        }

        .field {
            display: flex;
            flex-direction: column;
            gap: 7px;
        }

        .field label {
            font-size: 0.86rem;
            color: #1f2937;
            font-weight: 800;
        }

        .field select,
        .field input[type="date"],
        .field input.flatpickr-input,
        .field input[type="file"] {
            width: 100%;
            min-height: 46px;
            border: 2px solid #d9e2ec;
            border-radius: 12px;
            padding: 10px 12px;
            font-family: inherit;
            font-size: 0.9rem;
            background: #fff;
        }

        .field select:focus,
        .field input[type="date"]:focus,
        .field input.flatpickr-input:focus,
        .field input[type="file"]:focus {
            outline: none;
            border-color: var(--brand);
            box-shadow: 0 0 0 4px rgba(15, 118, 110, 0.12);
        }

        .field input.flatpickr-input[readonly] {
            cursor: pointer;
            background: #fff;
        }

        .flatpickr-calendar {
            border-radius: 16px;
            box-shadow: 0 18px 40px rgba(15, 23, 42, 0.14);
            border: 1px solid rgba(15, 118, 110, 0.15);
        }

        .flatpickr-day.selected,
        .flatpickr-day.selected:hover {
            background: #0f766e;
            border-color: #0f766e;
        }

        .flatpickr-day.has-slots {
            background: rgba(22, 163, 74, 0.12);
            border-color: #16a34a;
            color: #166534;
            font-weight: 700;
        }

        .flatpickr-day.has-slots:hover {
            background: rgba(22, 163, 74, 0.28);
        }

        .flatpickr-day.has-slots.selected,
        .flatpickr-day.has-slots.selected:hover {
            background: #0f766e;
            border-color: #0f766e;
            color: #fff;
        }

        .flatpickr-months .flatpickr-prev-month:hover svg,
        .flatpickr-months .flatpickr-next-month:hover svg {
            fill: #0f766e;
        }

        .hint {
            font-size: 0.78rem;
            color: #64748b;
            line-height: 1.4;
        }

        /*
         * Calendar panel showing available slot days in green.
         */
        .calendar-panel {
            border: 1px solid #dbe2ea;
            border-radius: 16px;
            padding: 12px;
            background: #fff;
            display: grid;
            gap: 10px;
        }

        .calendar-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 8px;
        }

        .calendar-title {
            font-size: 0.9rem;
            font-weight: 800;
            color: #0f172a;
        }

        .calendar-nav {
            border: 1px solid #dbe2ea;
            background: #f8fafc;
            color: #0f172a;
            width: 34px;
            height: 34px;
            border-radius: 10px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
        }

        .calendar-nav:disabled {
            opacity: 0.4;
            cursor: not-allowed;
        }

        .calendar-weekdays {
            display: grid;
            grid-template-columns: repeat(7, minmax(0, 1fr));
            gap: 6px;
            text-align: center;
            font-size: 0.72rem;
            color: #64748b;
            font-weight: 700;
        }

        .calendar-grid {
            display: grid;
            grid-template-columns: repeat(7, minmax(0, 1fr));
            gap: 6px;
        }

        .calendar-day {
            border: 1px solid #e2e8f0;
            background: #fff;
            border-radius: 10px;
            height: 38px;
            font-size: 0.8rem;
            font-weight: 700;
            color: #0f172a;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
        }

        .calendar-day.is-disabled {
            color: #94a3b8;
            background: #f8fafc;
            cursor: not-allowed;
        }

        .calendar-day.is-available {
            border-color: #16a34a;
            background: rgba(22, 163, 74, 0.12);
            color: #166534;
        }

        .calendar-day.is-selected {
            border-color: var(--brand);
            background: rgba(15, 118, 110, 0.16);
            color: #0f172a;
        }

        .calendar-empty {
            border: 1px dashed #cbd5e1;
            border-radius: 12px;
            padding: 10px;
            font-size: 0.8rem;
            color: #64748b;
            text-align: center;
            background: #f8fafc;
        }

        .slot-grid {
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: 8px;
        }

        .slot-option {
            display: block;
            border: 2px solid #d9e2ec;
            border-radius: 12px;
            background: #fff;
            padding: 10px;
            cursor: pointer;
            transition: border-color 0.2s ease, box-shadow 0.2s ease;
        }

        .slot-option:hover {
            border-color: #0f766e;
        }

        .slot-option input {
            margin-right: 8px;
        }

        .slot-option.is-hidden {
            display: none;
        }

        .slot-empty {
            display: none;
            border: 1px dashed #cbd5e1;
            border-radius: 12px;
            padding: 10px;
            font-size: 0.84rem;
            color: #475569;
            background: #f8fafc;
        }

        .slot-empty.is-visible {
            display: block;
        }

        .btn-primary {
            min-height: 48px;
            border: none;
            border-radius: 14px;
            background: linear-gradient(145deg, var(--brand), var(--brand-deep));
            color: #fff;
            font-family: inherit;
            font-size: 0.95rem;
            font-weight: 800;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
        }

        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 12px 28px rgba(15, 118, 110, 0.32);
        }

        /*
         * Responsive breakpoints for smaller layouts.
         */
        @media (max-width: 900px) {
            .slot-grid {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }

            .services-grid {
                grid-template-columns: 1fr;
            }
        }

        @media (max-width: 680px) {
            body {
                padding: 14px 10px 24px;
            }

            .topbar,
            .panel {
                border-radius: 16px;
                padding: 14px;
            }

            .profile-layout {
                grid-template-columns: 1fr;
            }

            .slot-grid {
                grid-template-columns: 1fr;
            }
        }

        @media (max-width: 480px) {
            body {
                padding: 10px 8px 20px;
            }

            .topbar,
            .panel {
                border-radius: 14px;
                padding: 12px;
            }

            .topbar h1 {
                font-size: 1.05rem;
            }

            .provider-avatar-wrap {
                width: 80px;
                height: 80px;
            }

            .provider-name {
                font-size: 1.3rem;
            }

            .btn-primary {
                width: 100%;
                justify-content: center;
            }

            .review-card {
                padding: 12px;
            }
        }

        /*
         * Honor reduced-motion preference for accessibility.
         */
        @media (prefers-reduced-motion: reduce) {
            *,
            *::before,
            *::after {
                animation-duration: 0.01ms !important;
                animation-iteration-count: 1 !important;
                transition-duration: 0.01ms !important;
                scroll-behavior: auto !important;
            }
        }

        [dir="rtl"] body { font-family: 'Cairo', sans-serif; }
        [dir="rtl"] .topbar { flex-direction: row-reverse; }
        [dir="rtl"] .topbar-links { flex-direction: row-reverse; }
        [dir="rtl"] .pill-link i { transform: scaleX(-1); }
        [dir="rtl"] .profile-layout { direction: rtl; }
        [dir="rtl"] .slot-option input { margin-right: 0; margin-left: 8px; }
    </style>
</head>
<body class="<?php echo htmlspecialchars(getLangBodyClass(), ENT_QUOTES, 'UTF-8'); ?>">
    <!-- Full page shell containing profile, reviews, and request sections -->
    <main class="page-shell">
        <!-- Header navigation and session context -->
        <section class="topbar" aria-label="<?php echo htmlspecialchars(t('prof_section_title'), ENT_QUOTES, 'UTF-8'); ?>">
            <div class="topbar-links">
                <?php if ($isAdminViewer): ?>
                    <a class="pill-link" href="<?php echo htmlspecialchars($appBase, ENT_QUOTES, 'UTF-8'); ?>/admin_dashboard.php#service-providers">
                        <i class="fas fa-arrow-left" aria-hidden="true"></i>
                        <?php echo htmlspecialchars(t('prof_back_admin'), ENT_QUOTES, 'UTF-8'); ?>
                    </a>
                <?php else: ?>
                    <a class="pill-link" href="<?php echo htmlspecialchars($appBase, ENT_QUOTES, 'UTF-8'); ?>/customer_dashboard.php?tab=<?php echo urlencode($tabAccessToken); ?>">
                        <i class="fas fa-arrow-left" aria-hidden="true"></i>
                        <?php echo htmlspecialchars(t('profile_back'), ENT_QUOTES, 'UTF-8'); ?>
                    </a>
                    <a class="pill-link" href="<?php echo htmlspecialchars($appBase, ENT_QUOTES, 'UTF-8'); ?>/customer_requests.php?tab=<?php echo urlencode($tabAccessToken); ?>">
                        <i class="fas fa-clipboard-list" aria-hidden="true"></i>
                        <?php echo htmlspecialchars(t('prof_my_requests'), ENT_QUOTES, 'UTF-8'); ?>
                    </a>
                <?php endif; ?>
            </div>
            <p class="topbar-note">
                <?php echo htmlspecialchars(t('prof_signed_in_as'), ENT_QUOTES, 'UTF-8'); ?>
                <?php if ($isAdminViewer): ?>
                    <?php echo htmlspecialchars($adminEmail !== '' ? $adminEmail : t('admin_nav_admin'), ENT_QUOTES, 'UTF-8'); ?>
                <?php else: ?>
                    <?php echo htmlspecialchars($customerEmail !== '' ? $customerEmail : (t('sidebar_customer_label') . ' #' . (string) $customerId), ENT_QUOTES, 'UTF-8'); ?>
                <?php endif; ?>
            </p>
        </section>

        <!-- Error and success banners for profile loading and request submission -->
        <?php if ($errorMessage !== ''): ?>
            <section class="feedback error" role="alert">
                <?php echo htmlspecialchars($errorMessage, ENT_QUOTES, 'UTF-8'); ?>
            </section>
        <?php endif; ?>

        <?php if ($successMessage !== ''): ?>
            <section class="feedback success" role="status">
                <?php echo htmlspecialchars($successMessage, ENT_QUOTES, 'UTF-8'); ?>
            </section>
        <?php endif; ?>

        <!-- Provider profile section with services summary -->
        <?php if ($provider !== null): ?>
            <section class="panel" aria-label="<?php echo htmlspecialchars(t('prof_section_title'), ENT_QUOTES, 'UTF-8'); ?>">
                <h2><?php echo htmlspecialchars(t('prof_section_title'), ENT_QUOTES, 'UTF-8'); ?></h2>
                <p class="lead">
                    <?php echo htmlspecialchars($isAdminViewer ? t('prof_section_lead_admin') : t('prof_section_lead_cust'), ENT_QUOTES, 'UTF-8'); ?>
                </p>

                <div class="profile-layout">
                    <div class="profile-photo">
                        <?php if ($provider['photo'] !== ''): ?>
                            <img src="<?php echo htmlspecialchars($appBase . '/' . $provider['photo'], ENT_QUOTES, 'UTF-8'); ?>" alt="<?php echo htmlspecialchars($provider['name'], ENT_QUOTES, 'UTF-8'); ?>">
                        <?php else: ?>
                            <i class="fas fa-user-gear" aria-hidden="true"></i>
                        <?php endif; ?>
                    </div>

                    <div>
                        <div class="profile-title">
                            <h1><?php echo htmlspecialchars($provider['name'], ENT_QUOTES, 'UTF-8'); ?></h1>
                            <span class="badge <?php echo $provider['is_verified'] ? 'verified' : 'unverified'; ?>">
                                <i class="fas <?php echo $provider['is_verified'] ? 'fa-circle-check' : 'fa-circle-exclamation'; ?>" aria-hidden="true"></i>
                                <?php echo htmlspecialchars($provider['is_verified'] ? t('prov_verified_badge') : t('prof_not_verified_badge'), ENT_QUOTES, 'UTF-8'); ?>
                            </span>
                        </div>

                        <div class="profile-meta">
                            <span class="meta-chip no-ar-numerals" dir="ltr">
                                <i class="fas fa-envelope" aria-hidden="true"></i>
                                <?php echo htmlspecialchars($provider['email'], ENT_QUOTES, 'UTF-8'); ?>
                            </span>
                            <span class="meta-chip" dir="ltr">
                                <i class="fas fa-phone" aria-hidden="true"></i>
                                <?php echo htmlspecialchars($provider['phone'] !== '' ? $provider['phone'] : t('prof_no_phone'), ENT_QUOTES, 'UTF-8'); ?>
                            </span>
                            <span class="meta-chip">
                                <i class="fas fa-layer-group" aria-hidden="true"></i>
                                <?php echo htmlspecialchars((string) $provider['service_count'], ENT_QUOTES, 'UTF-8'); ?> <?php echo htmlspecialchars(t('prof_categories_count'), ENT_QUOTES, 'UTF-8'); ?>
                            </span>
                            <?php if ($provider['location'] !== ''): ?>
                                <span class="meta-chip">
                                    <i class="fas fa-location-dot" aria-hidden="true"></i>
                                    <?php echo htmlspecialchars($provider['location'], ENT_QUOTES, 'UTF-8'); ?>
                                </span>
                            <?php endif; ?>
                            <span class="meta-chip">
                                <i class="fas fa-star" aria-hidden="true"></i>
                                <?php if ($providerRatingCount > 0 && $providerAverageRating !== null): ?>
                                    <?php echo htmlspecialchars(number_format((float) $providerAverageRating, 1), ENT_QUOTES, 'UTF-8'); ?><?php echo htmlspecialchars(t('prof_out_of_5'), ENT_QUOTES, 'UTF-8'); ?> (<?php echo htmlspecialchars((string) $providerRatingCount, ENT_QUOTES, 'UTF-8'); ?> <?php echo htmlspecialchars(t('prof_ratings_label'), ENT_QUOTES, 'UTF-8'); ?>)
                                <?php else: ?>
                                    <?php echo htmlspecialchars(t('prof_no_ratings'), ENT_QUOTES, 'UTF-8'); ?>
                                <?php endif; ?>
                            </span>
                        </div>

                        <p class="profile-bio">
                            <?php echo htmlspecialchars($provider['bio'] !== '' ? $provider['bio'] : t('prof_no_bio'), ENT_QUOTES, 'UTF-8'); ?>
                        </p>

                        <div class="services-grid" aria-label="<?php echo htmlspecialchars(t('profile_services'), ENT_QUOTES, 'UTF-8'); ?>">
                            <?php if (count($providerServices) > 0): ?>
                                <?php foreach ($providerServices as $service): ?>
                                    <article class="service-card">
                                        <h3><?php echo htmlspecialchars(tCategory($service, 'name'), ENT_QUOTES, 'UTF-8'); ?></h3>
                                        <p><?php echo htmlspecialchars(tCategory($service, 'description') !== '' ? tCategory($service, 'description') : t('prov_no_desc_available'), ENT_QUOTES, 'UTF-8'); ?></p>
                                        <p class="price"><?php echo htmlspecialchars(t('prof_visit_price_prefix'), ENT_QUOTES, 'UTF-8'); ?> $<?php echo htmlspecialchars(number_format($service['visit_price'], 2), ENT_QUOTES, 'UTF-8'); ?></p>
                                    </article>
                                <?php endforeach; ?>
                            <?php else: ?>
                                <article class="service-card">
                                    <h3><?php echo htmlspecialchars(t('prof_no_cats_title'), ENT_QUOTES, 'UTF-8'); ?></h3>
                                    <p><?php echo htmlspecialchars(t('prof_no_cats_desc'), ENT_QUOTES, 'UTF-8'); ?></p>
                                </article>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            </section>

            <!-- Reviews section rendered from servicerequest.review values -->
            <section class="panel" aria-label="<?php echo htmlspecialchars(t('prof_reviews_h'), ENT_QUOTES, 'UTF-8'); ?>">
                <h2><?php echo htmlspecialchars(t('prof_reviews_h'), ENT_QUOTES, 'UTF-8'); ?></h2>
                <p class="lead"><?php echo htmlspecialchars(t('prof_reviews_lead'), ENT_QUOTES, 'UTF-8'); ?></p>

                <div class="reviews-list">
                    <?php if (count($reviews) > 0): ?>
                        <?php foreach ($reviews as $review): ?>
                            <article class="review-item">
                                <div class="review-top">
                                    <strong><?php echo htmlspecialchars($review['customer_name'], ENT_QUOTES, 'UTF-8'); ?></strong>
                                    <span class="review-meta">
                                        <?php echo htmlspecialchars($review['category_name'], ENT_QUOTES, 'UTF-8'); ?> |
                                        <?php echo htmlspecialchars(localizedShortDate($review['appointment_date']) . ' ' . substr($review['appointment_time'], 0, 5), ENT_QUOTES, 'UTF-8'); ?>
                                    </span>
                                </div>

                                <p class="review-rating">
                                    <?php if ($review['rating'] !== null && $review['rating'] >= 1 && $review['rating'] <= 5): ?>
                                        <span class="review-stars" aria-label="<?php echo htmlspecialchars((string) $review['rating'] . ' ' . t('prof_out_of_5_label'), ENT_QUOTES, 'UTF-8'); ?>">
                                            <?php for ($starIndex = 1; $starIndex <= 5; $starIndex++): ?>
                                                <i class="fas fa-star star <?php echo $starIndex <= $review['rating'] ? '' : 'is-empty'; ?>" aria-hidden="true"></i>
                                            <?php endfor; ?>
                                        </span>
                                        <span class="review-rating-value"><?php echo htmlspecialchars((string) $review['rating'], ENT_QUOTES, 'UTF-8'); ?><?php echo htmlspecialchars(t('prof_out_of_5'), ENT_QUOTES, 'UTF-8'); ?></span>
                                    <?php else: ?>
                                        <span class="review-rating-value"><?php echo htmlspecialchars(t('prof_no_star_rating'), ENT_QUOTES, 'UTF-8'); ?></span>
                                    <?php endif; ?>
                                </p>

                                <p class="review-text">
                                    <?php echo $review['review'] !== ''
                                        ? nl2br(htmlspecialchars($review['review'], ENT_QUOTES, 'UTF-8'))
                                        : htmlspecialchars(t('prof_no_review_text'), ENT_QUOTES, 'UTF-8'); ?>
                                </p>


                            </article>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <article class="review-item">
                            <p class="review-text"><?php echo htmlspecialchars(t('prof_no_reviews_yet'), ENT_QUOTES, 'UTF-8'); ?></p>
                        </article>
                    <?php endif; ?>
                </div>
            </section>

            <?php if (!$isAdminViewer): ?>
                <!-- Service request form with category, calendar date, slot choice, and image uploads -->
                <section id="request-service" class="panel" aria-label="<?php echo htmlspecialchars(t('prof_request_title'), ENT_QUOTES, 'UTF-8'); ?>">
                    <h2><?php echo htmlspecialchars(t('prof_request_title'), ENT_QUOTES, 'UTF-8'); ?></h2>
                    <p class="lead"><?php echo htmlspecialchars(sprintf(t('prof_request_lead'), MAX_REQUEST_SLOT_CHOICES), ENT_QUOTES, 'UTF-8'); ?></p>

                    <form class="request-form" method="post" action="<?php echo htmlspecialchars($appBase . '/provider/' . $providerId, ENT_QUOTES, 'UTF-8'); ?>?tab=<?php echo urlencode($tabAccessToken); ?>#request-service" enctype="multipart/form-data" novalidate>
                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars((string) $_SESSION['provider_request_csrf'], ENT_QUOTES, 'UTF-8'); ?>">
                        <input type="hidden" name="provider_id" value="<?php echo htmlspecialchars((string) $providerId, ENT_QUOTES, 'UTF-8'); ?>">
                        <input type="hidden" name="tab" value="<?php echo htmlspecialchars($tabAccessToken, ENT_QUOTES, 'UTF-8'); ?>">

                        <div class="field">
                            <label for="category_id"><?php echo htmlspecialchars(t('prof_cat_label'), ENT_QUOTES, 'UTF-8'); ?></label>
                            <select id="category_id" name="category_id" required <?php echo count($providerServices) === 0 ? 'disabled aria-disabled="true"' : ''; ?>>
                                <option value=""><?php echo htmlspecialchars(t('prof_cat_choose'), ENT_QUOTES, 'UTF-8'); ?></option>
                                <?php if (count($providerServices) === 0): ?>
                                    <option value=""><?php echo htmlspecialchars(t('prof_cat_none_offered'), ENT_QUOTES, 'UTF-8'); ?></option>
                                <?php else: ?>
                                    <?php foreach ($providerServices as $service): ?>
                                        <?php
                                            $categoryId = (int) $service['category_id'];
                                            $priceLabel = ' ($' . number_format((float) $service['visit_price'], 2) . ')';
                                        ?>
                                        <option value="<?php echo htmlspecialchars((string) $categoryId, ENT_QUOTES, 'UTF-8'); ?>" <?php echo $selectedCategoryId === $categoryId ? 'selected' : ''; ?>>
                                            <?php echo htmlspecialchars(tCategory($service, 'name') . $priceLabel, ENT_QUOTES, 'UTF-8'); ?>
                                        </option>
                                    <?php endforeach; ?>
                                <?php endif; ?>
                            </select>
                        </div>

                        <div class="field">
                            <label for="slot_date_filter"><?php echo htmlspecialchars(t('prof_date_label'), ENT_QUOTES, 'UTF-8'); ?></label>
                            <input
                                type="text"
                                id="slot_date_filter"
                                value="<?php echo htmlspecialchars($selectedSlotDate, ENT_QUOTES, 'UTF-8'); ?>"
                                placeholder="<?php echo htmlspecialchars(t('prof_date_ph'), ENT_QUOTES, 'UTF-8'); ?>"
                                readonly
                            >
                            <?php if (count($availableDates) > 0): ?>
                                <p class="hint"><?php echo htmlspecialchars(t('prof_date_hint'), ENT_QUOTES, 'UTF-8'); ?></p>
                            <?php else: ?>
                                <p class="hint"><?php echo htmlspecialchars(t('prof_no_future_slots'), ENT_QUOTES, 'UTF-8'); ?></p>
                            <?php endif; ?>
                        </div>

                        <div class="field">
                            <label><?php echo htmlspecialchars(t('prof_slots_label'), ENT_QUOTES, 'UTF-8'); ?></label>
                            <p id="slotSelectionHint" class="hint"><?php echo htmlspecialchars(sprintf(t('prof_slots_hint'), MAX_REQUEST_SLOT_CHOICES), ENT_QUOTES, 'UTF-8'); ?></p>
                            <div id="slotGrid" class="slot-grid" role="group" aria-label="<?php echo htmlspecialchars(t('prof_slots_label'), ENT_QUOTES, 'UTF-8'); ?>" data-max-slots="<?php echo htmlspecialchars((string) MAX_REQUEST_SLOT_CHOICES, ENT_QUOTES, 'UTF-8'); ?>"
                                 data-selected-tpl="<?php echo htmlspecialchars(t('prof_slots_selected'), ENT_QUOTES, 'UTF-8'); ?>">
                                <?php foreach ($availableSlots as $slot): ?>
                                    <?php
                                        $slotVisible = $selectedSlotDate === '' || $selectedSlotDate === $slot['date'];
                                        $slotLabel = localizedSlotDate($slot['date']) . ' ' . t('prof_slot_at') . ' ' . substr($slot['slot'], 0, 5);
                                    ?>
                                    <label class="slot-option <?php echo $slotVisible ? '' : 'is-hidden'; ?>" data-slot-date="<?php echo htmlspecialchars($slot['date'], ENT_QUOTES, 'UTF-8'); ?>">
                                        <input
                                            type="checkbox"
                                            name="slot_ids[]"
                                            value="<?php echo htmlspecialchars((string) $slot['slot_id'], ENT_QUOTES, 'UTF-8'); ?>"
                                            <?php echo in_array($slot['slot_id'], $selectedSlotIds, true) ? 'checked' : ''; ?>
                                        >
                                        <?php echo htmlspecialchars($slotLabel, ENT_QUOTES, 'UTF-8'); ?>
                                    </label>
                                <?php endforeach; ?>
                            </div>
                            <div id="slotEmptyMessage" class="slot-empty">
                                <?php echo htmlspecialchars(t('prof_no_slots_date'), ENT_QUOTES, 'UTF-8'); ?>
                            </div>
                        </div>

                        <div class="field">
                            <label for="image1"><?php echo htmlspecialchars(t('prof_img1_label'), ENT_QUOTES, 'UTF-8'); ?></label>
                            <input type="file" id="image1" name="image1" accept="image/jpeg,image/png,image/webp" required>
                            <p class="hint"><?php echo htmlspecialchars(t('prof_img_hint'), ENT_QUOTES, 'UTF-8'); ?></p>
                        </div>

                        <div class="field">
                            <label for="image2"><?php echo htmlspecialchars(t('prof_img2_label'), ENT_QUOTES, 'UTF-8'); ?></label>
                            <input type="file" id="image2" name="image2" accept="image/jpeg,image/png,image/webp">
                        </div>

                        <div class="field">
                            <label for="image3"><?php echo htmlspecialchars(t('prof_img3_label'), ENT_QUOTES, 'UTF-8'); ?></label>
                            <input type="file" id="image3" name="image3" accept="image/jpeg,image/png,image/webp">
                            <p class="hint"><?php echo htmlspecialchars(t('prof_img_hint2'), ENT_QUOTES, 'UTF-8'); ?></p>
                        </div>

                        <button class="btn-primary" type="submit">
                            <i class="fas fa-paper-plane" aria-hidden="true"></i>
                            <?php echo htmlspecialchars(t('prof_submit'), ENT_QUOTES, 'UTF-8'); ?>
                        </button>
                    </form>
                </section>
            <?php endif; ?>
        <?php endif; ?>
    </main>

    <script src="https://cdn.jsdelivr.net/npm/flatpickr"></script>
    <?php if (getLang() === 'ar'): ?>
    <script src="https://cdn.jsdelivr.net/npm/flatpickr/dist/l10n/ar.js"></script>
    <?php endif; ?>
    <script>
        (function () {
            var slotDateInput = document.getElementById('slot_date_filter');
            var slotGrid = document.getElementById('slotGrid');
            var slotEmptyMessage = document.getElementById('slotEmptyMessage');
            var slotSelectionHint = document.getElementById('slotSelectionHint');

            if (!slotDateInput || !slotGrid || !slotEmptyMessage) {
                return;
            }

            var maxSlots = parseInt(slotGrid.getAttribute('data-max-slots') || '3', 10);
            var fpAvailableDates = <?php echo json_encode(array_values($availableDates)); ?>;

            function refreshVisibleSlots() {
                var selectedDate = slotDateInput.value;
                var visibleCount = 0;

                slotGrid.querySelectorAll('.slot-option').forEach(function (slotOption) {
                    var slotDate = slotOption.getAttribute('data-slot-date') || '';
                    var shouldShow = selectedDate === '' || slotDate === selectedDate;

                    slotOption.classList.toggle('is-hidden', !shouldShow);

                    if (shouldShow) {
                        visibleCount += 1;
                    }
                });

                slotEmptyMessage.classList.toggle('is-visible', visibleCount === 0);
            }

            function updateSlotSelectionState() {
                var selectedCount = slotGrid.querySelectorAll('input[type="checkbox"]:checked').length;

                if (slotSelectionHint) {
                    var tpl = slotGrid.getAttribute('data-selected-tpl') || 'Selected %d of %d slots.';
                    slotSelectionHint.textContent = tpl.replace('%d', selectedCount).replace('%d', maxSlots);
                }

                slotGrid.querySelectorAll('input[type="checkbox"]').forEach(function (checkbox) {
                    if (checkbox.checked) {
                        checkbox.disabled = false;
                    } else {
                        checkbox.disabled = selectedCount >= maxSlots;
                    }
                });
            }

            slotGrid.addEventListener('change', function (event) {
                if (event.target && event.target.matches('input[type="checkbox"]')) {
                    updateSlotSelectionState();
                }
            });

            var fpLocale = <?php echo getLang() === 'ar' ? '"ar"' : '"default"'; ?>;
            var arMap = {"0":"٠","1":"١","2":"٢","3":"٣","4":"٤","5":"٥","6":"٦","7":"٧","8":"٨","9":"٩"};
            function toArNums(s) { return String(s).replace(/\d/g, function(d){ return arMap[d]; }); }

            if (typeof flatpickr !== 'undefined') {
                flatpickr(slotDateInput, {
                    enable: fpAvailableDates,
                    dateFormat: 'Y-m-d',
                    altInput: fpLocale === 'ar',
                    altFormat: 'j F Y',
                    defaultDate: slotDateInput.value !== '' ? slotDateInput.value : (fpAvailableDates.length > 0 ? fpAvailableDates[0] : null),
                    locale: fpLocale,
                    disableMobile: true,
                    onReady: function (selDates, dateStr, instance) {
                        if (fpLocale === 'ar' && instance.altInput) {
                            instance.altInput.value = toArNums(instance.altInput.value);
                        }
                    },
                    onChange: function (selDates, dateStr, instance) {
                        if (fpLocale === 'ar' && instance.altInput) {
                            instance.altInput.value = toArNums(instance.altInput.value);
                        }
                        refreshVisibleSlots();
                        updateSlotSelectionState();
                    },
                    onDayCreate: function (dObj, dStr, fp, dayElem) {
                        var d = dayElem.dateObj;
                        var iso = d.getFullYear() + '-' +
                            String(d.getMonth() + 1).padStart(2, '0') + '-' +
                            String(d.getDate()).padStart(2, '0');
                        if (fpAvailableDates.indexOf(iso) !== -1) {
                            dayElem.classList.add('has-slots');
                        }
                        if (fpLocale === 'ar') {
                            dayElem.textContent = toArNums(dayElem.textContent);
                        }
                    }
                });
            } else {
                slotDateInput.addEventListener('change', refreshVisibleSlots);
            }

            refreshVisibleSlots();
            updateSlotSelectionState();
        })();

        /*
         * Disable submit button after first click to reduce duplicate form submissions.
         */
        document.querySelectorAll('.request-form').forEach(function (formElement) {
            formElement.addEventListener('submit', function () {
                var submitButton = formElement.querySelector('button[type="submit"]');
                if (!submitButton) {
                    return;
                }

                submitButton.disabled = true;
                submitButton.style.opacity = '0.72';
            });
        });
    </script>
</body>
</html>

