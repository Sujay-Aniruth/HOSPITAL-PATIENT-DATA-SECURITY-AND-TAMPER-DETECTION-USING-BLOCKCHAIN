<?php
/**
 * Medical Record Details & Version History API Endpoint
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

header('Content-Type: application/json; charset=UTF-8');

require_once __DIR__ . '/../../../app/config/config.php';
require_once __DIR__ . '/../../../app/middleware/AuthMiddleware.php';
require_once __DIR__ . '/../../../app/models/MedicalRecord.php';

AuthMiddleware::requireAuth();

$id = (int)($_GET['id'] ?? 0);
if ($id <= 0) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'Valid medical record ID is required.']);
    exit;
}

$recordModel = new MedicalRecord();
$record = $recordModel->findById($id);

if (!$record) {
    http_response_code(404);
    echo json_encode(['status' => 'error', 'message' => 'Medical record not found.']);
    exit;
}

$versions = $recordModel->getVersions($id);

echo json_encode([
    'status' => 'success',
    'record' => $record,
    'versions' => $versions,
]);
