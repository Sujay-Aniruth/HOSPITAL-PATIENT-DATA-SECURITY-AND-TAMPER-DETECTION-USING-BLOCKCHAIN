<?php
/**
 * Medical Record Authorized Amendment API Endpoint
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

header('Content-Type: application/json; charset=UTF-8');

require_once __DIR__ . '/../../../app/config/config.php';
require_once __DIR__ . '/../../../app/middleware/AuthMiddleware.php';
require_once __DIR__ . '/../../../app/middleware/CsrfMiddleware.php';
require_once __DIR__ . '/../../../app/models/MedicalRecord.php';

$user = AuthMiddleware::requireRole(['admin', 'doctor']);
CsrfMiddleware::requireValid();

$input = json_decode(file_get_contents('php://input'), true);
if (!is_array($input)) {
    $input = $_POST;
}

$id = (int)($input['medical_record_id'] ?? $input['id'] ?? $_GET['id'] ?? 0);
if ($id <= 0) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'Valid medical record ID is required.']);
    exit;
}

try {
    $recordModel = new MedicalRecord();
    $result = $recordModel->amend($id, $input, (int)$user['id']);

    echo json_encode([
        'status' => 'success',
        'message' => "Medical record amended successfully. Created and anchored Version {$result['new_version']} on blockchain.",
        'data' => $result,
    ]);
} catch (InvalidArgumentException $e) {
    http_response_code(422);
    echo json_encode(['status' => 'error', 'message' => $e->getMessage()]);
} catch (Throwable $e) {
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Failed to amend record: ' . $e->getMessage()]);
}
