<?php
/**
 * Medical Records List API Endpoint
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

header('Content-Type: application/json; charset=UTF-8');

require_once __DIR__ . '/../../../app/config/config.php';
require_once __DIR__ . '/../../../app/middleware/AuthMiddleware.php';
require_once __DIR__ . '/../../../app/models/MedicalRecord.php';

AuthMiddleware::requireAuth();

$patientId = isset($_GET['patient_id']) ? (int)$_GET['patient_id'] : null;
$limit = min(100, max(1, (int)($_GET['limit'] ?? 50)));
$offset = max(0, (int)($_GET['offset'] ?? 0));

$recordModel = new MedicalRecord();
$records = $recordModel->getAll($limit, $offset, $patientId);

echo json_encode([
    'status' => 'success',
    'count' => count($records),
    'data' => $records,
]);
