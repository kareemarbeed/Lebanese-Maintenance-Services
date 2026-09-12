<?php
declare(strict_types=1);

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

const DEFAULT_SERVICE_CATEGORIES = [
    ['name' => 'Plumbing',        'name_ar' => 'السباكة',         'description' => 'Leaks, fixtures, water heaters, and drain repairs.',              'description_ar' => 'إصلاح التسربات والتركيبات وسخانات المياه والمصارف.'],
    ['name' => 'Electrical',      'name_ar' => 'الكهرباء',        'description' => 'Wiring, outlets, lighting, and breaker troubleshooting.',          'description_ar' => 'الأسلاك الكهربائية والمنافذ والإضاءة وصيانة القواطع.'],
    ['name' => 'HVAC',            'name_ar' => 'التكييف والتدفئة','description' => 'Cooling, heating, and ventilation diagnostics.',                  'description_ar' => 'تشخيص وصيانة أنظمة التبريد والتدفئة والتهوية.'],
    ['name' => 'Carpentry',       'name_ar' => 'النجارة',         'description' => 'Woodwork, doors, cabinets, and structural repairs.',               'description_ar' => 'أعمال الخشب والأبواب والخزائن والإصلاحات الهيكلية.'],
    ['name' => 'Painting',        'name_ar' => 'الدهان',          'description' => 'Interior and exterior paint preparation and finish.',              'description_ar' => 'تحضير وتشطيب الدهان الداخلي والخارجي.'],
    ['name' => 'Cleaning',        'name_ar' => 'التنظيف',         'description' => 'Deep cleaning, move-in, and move-out services.',                  'description_ar' => 'التنظيف العميق وخدمات الانتقال والمغادرة.'],
    ['name' => 'Appliance Repair','name_ar' => 'إصلاح الأجهزة',  'description' => 'Fridge, washer, oven, and small appliance fixes.',                'description_ar' => 'إصلاح الثلاجات والغسالات والأفران والأجهزة الصغيرة.'],
    ['name' => 'Roofing',         'name_ar' => 'الأسقف',          'description' => 'Leak checks, patching, and preventative maintenance.',            'description_ar' => 'فحص التسربات والترقيع والصيانة الوقائية للأسقف.'],
    ['name' => 'Landscaping',     'name_ar' => 'تنسيق الحدائق',   'description' => 'Outdoor maintenance, trimming, and garden care.',                'description_ar' => 'صيانة الحدائق والتشذيب والعناية بالمساحات الخضراء.'],
    ['name' => 'Pest Control',    'name_ar' => 'مكافحة الحشرات',  'description' => 'Inspection and treatment for common pests.',                      'description_ar' => 'فحص ومعالجة الآفات الشائعة.'],
    ['name' => 'Other',           'name_ar' => 'أخرى',            'description' => 'General maintenance and custom requests.',                         'description_ar' => 'الصيانة العامة والطلبات المخصصة.'],
];

/*
 * Migrate servicecategory table to include Arabic columns if they don't exist yet.
 */
function migrateServiceCategoryArabicColumns(PDO $pdo): void
{
    try {
        $check = $pdo->query(
            "SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
             WHERE TABLE_SCHEMA = DATABASE()
               AND TABLE_NAME = 'servicecategory'
               AND COLUMN_NAME = 'name_ar'"
        );
        if ($check && (int) $check->fetchColumn() === 0) {
            $pdo->exec("ALTER TABLE servicecategory ADD COLUMN name_ar VARCHAR(200) NOT NULL DEFAULT ''");
        }

        $check2 = $pdo->query(
            "SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
             WHERE TABLE_SCHEMA = DATABASE()
               AND TABLE_NAME = 'servicecategory'
               AND COLUMN_NAME = 'description_ar'"
        );
        if ($check2 && (int) $check2->fetchColumn() === 0) {
            $pdo->exec("ALTER TABLE servicecategory ADD COLUMN description_ar TEXT NOT NULL DEFAULT ''");
        }
    } catch (PDOException $e) {
        // Non-fatal: site works with English fallback if migration fails
    }
}

/*
 * Load all service categories from the database (including Arabic columns).
 */
function loadServiceCategories(PDO $pdo): array
{
    $statement = $pdo->prepare(
        'SELECT category_id, name, description, name_ar, description_ar
         FROM servicecategory
         ORDER BY name ASC'
    );
    $statement->execute();

    $categories = [];
    while ($row = $statement->fetch()) {
        $categories[] = [
            'category_id'    => (int) $row['category_id'],
            'name'           => (string) $row['name'],
            'description'    => (string) ($row['description'] ?? ''),
            'name_ar'        => (string) ($row['name_ar'] ?? ''),
            'description_ar' => (string) ($row['description_ar'] ?? ''),
        ];
    }

    return $categories;
}

/*
 * Return the translated category name or description based on current language.
 * Falls back to English if no Arabic value is available.
 */
function tCategory(array $category, string $field = 'name'): string
{
    $lang = function_exists('getLang') ? getLang() : 'en';
    if ($lang === 'ar') {
        $arValue = (string) ($category[$field . '_ar'] ?? '');
        if ($arValue !== '') {
            return $arValue;
        }
    }
    return (string) ($category[$field] ?? '');
}

/*
 * Ensure the servicecategory table has data; seed defaults if empty.
 */
function backfillServiceCategoryArabic(PDO $pdo): void
{
    $updateStmt = $pdo->prepare(
        "UPDATE servicecategory SET name_ar = :name_ar, description_ar = :description_ar
         WHERE name = :name AND (name_ar = '' OR name_ar IS NULL)"
    );
    foreach (DEFAULT_SERVICE_CATEGORIES as $cat) {
        $updateStmt->execute([
            'name'           => $cat['name'],
            'name_ar'        => $cat['name_ar'],
            'description_ar' => $cat['description_ar'],
        ]);
    }
}

function ensureServiceCategories(PDO $pdo): array
{
    migrateServiceCategoryArabicColumns($pdo);

    $existing = loadServiceCategories($pdo);
    if (count($existing) > 0) {
        backfillServiceCategoryArabic($pdo);
        return loadServiceCategories($pdo);
    }

    $insertStatement = $pdo->prepare(
        'INSERT INTO servicecategory (name, description, name_ar, description_ar)
         VALUES (:name, :description, :name_ar, :description_ar)'
    );

    foreach (DEFAULT_SERVICE_CATEGORIES as $category) {
        $insertStatement->execute([
            'name'           => $category['name'],
            'description'    => $category['description'],
            'name_ar'        => $category['name_ar'],
            'description_ar' => $category['description_ar'],
        ]);
    }

    return loadServiceCategories($pdo);
}
