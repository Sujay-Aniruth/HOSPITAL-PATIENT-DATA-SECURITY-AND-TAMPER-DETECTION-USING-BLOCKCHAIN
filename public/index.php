<?php
/**
 * Main Web Router and Front Controller
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

require_once __DIR__ . '/../app/config/config.php';
require_once __DIR__ . '/../app/middleware/AuthMiddleware.php';
require_once __DIR__ . '/../app/middleware/CsrfMiddleware.php';

$page = trim((string)($_GET['page'] ?? 'dashboard'));

// Logout handling
if ($page === 'logout') {
    AuthMiddleware::logout();
    header('Location: index.php?page=login');
    exit;
}

// Authentication routing checks
$isLoggedIn = AuthMiddleware::check();

if (!$isLoggedIn && $page !== 'login') {
    header('Location: index.php?page=login');
    exit;
}

if ($isLoggedIn && $page === 'login') {
    header('Location: index.php?page=dashboard');
    exit;
}

// Page title map
$titles = [
    'login' => 'Sign In - Hospital Data Security',
    'dashboard' => 'Security & Integrity Operations Dashboard',
    'patients' => 'Patient Demographic Registry',
    'patient-create' => 'Register New Patient',
    'patient-view' => 'Patient Demographic Details & History',
    'patient-edit' => 'Authorized Demographic Amendment',
    'records' => 'Clinical Medical Records',
    'record-create' => 'Create Clinical Medical Record',
    'record-view' => 'Clinical Record Details & History',
    'record-amend' => 'Authorized Clinical Amendment',
    'verification' => 'Integrity Verification Center',
    'explorer' => 'Blockchain Ledger Explorer',
    'alerts' => 'Security Alerts & Audit Log',
    'demo' => 'Controlled Data Tampering Demonstration Lab',
];

$pageTitle = $titles[$page] ?? 'Hospital Patient Data Security & Tamper Detection';

// View mapping
$views = [
    'login' => __DIR__ . '/../app/views/auth/login.php',
    'dashboard' => __DIR__ . '/../app/views/dashboard/index.php',
    'patients' => __DIR__ . '/../app/views/patients/index.php',
    'patient-create' => __DIR__ . '/../app/views/patients/create.php',
    'patient-view' => __DIR__ . '/../app/views/patients/show.php',
    'patient-edit' => __DIR__ . '/../app/views/patients/edit.php',
    'records' => __DIR__ . '/../app/views/records/index.php',
    'record-create' => __DIR__ . '/../app/views/records/create.php',
    'record-view' => __DIR__ . '/../app/views/records/show.php',
    'record-amend' => __DIR__ . '/../app/views/records/amend.php',
    'verification' => __DIR__ . '/../app/views/verification/index.php',
    'explorer' => __DIR__ . '/../app/views/explorer/index.php',
    'alerts' => __DIR__ . '/../app/views/alerts/index.php',
    'demo' => __DIR__ . '/../app/views/demo/tamper.php',
];

if (!isset($views[$page]) || !file_exists($views[$page])) {
    http_response_code(404);
    $viewFile = null;
} else {
    $viewFile = $views[$page];
}

// Render layouts
require_once __DIR__ . '/../app/views/layouts/header.php';
require_once __DIR__ . '/../app/views/layouts/navbar.php';

if ($viewFile) {
    require $viewFile;
} else {
    echo '<div class="container py-5 text-center"><h3>404 - Page Not Found</h3><p class="text-muted">The requested page does not exist.</p><a href="index.php?page=dashboard" class="btn btn-primary">Return to Dashboard</a></div>';
}

require_once __DIR__ . '/../app/views/layouts/footer.php';
