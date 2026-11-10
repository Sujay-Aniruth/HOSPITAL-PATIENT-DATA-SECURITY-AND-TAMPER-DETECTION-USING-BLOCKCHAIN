<?php
/**
 * Patients List API Endpoint
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

header('Content-Type: application/json; charset=UTF-8');

require_once __DIR__ . '/../../../app/config/config.php';
require_once __DIR__ . '/../../../app/middleware/AuthMiddleware.php';
require_once __DIR__ . '/../../../app/models/Patient.php';

AuthMiddleware::requireAuth();

$search = trim((string)($_GET['search'] ?? ''));
$limit = min(100, max(1, (int)($_GET['limit'] ?? 50)));
$offset = max(0, (int)($_GET['offset'] ?? 0));

$patientModel = new Patient();
$patients = $patientModel->getAll($search, $limit, $offset);

echo json_encode([
    'status' => 'success',
    'count' => count($patients),
    'data' => $patients,
]);
