<?php
/**
 * Create Clinical Medical Record API Endpoint
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

header('Content-Type: application/json; charset=UTF-8');

require_once __DIR__ . '/../../../app/config/config.php';
require_once __DIR__ . '/../../../app/middleware/AuthMiddleware.php';
require_once __DIR__ . '/../../../app/middleware/CsrfMiddleware.php';
require_once __DIR__ . '/../../../app/models/MedicalRecord.php';
require_once __DIR__ . '/../../../app/models/Encounter.php';

// Clinical records can only be created by doctors and administrators
$user = AuthMiddleware::requireRole(['admin', 'doctor']);
CsrfMiddleware::requireValid();

$input = json_decode(file_get_contents('php://input'), true);
if (!is_array($input)) {
    $input = $_POST;
}

$patientId = (int)($input['patient_id'] ?? 0);
$encounterId = (int)($input['encounter_id'] ?? 0);

if ($patientId <= 0) {
    http_response_code(422);
    echo json_encode(['status' => 'error', 'message' => 'Valid patient ID is required.']);
    exit;
}

try {
    // If no encounter ID provided, create one automatically
    if ($encounterId <= 0) {
        $encounterModel = new Encounter();
        $visitAt = !empty($input['visit_at']) ? trim((string)$input['visit_at']) : date('Y-m-d H:i:s');
        $reason = !empty($input['reason']) ? trim((string)$input['reason']) : 'Clinical Consultation';
        $encounterId = $encounterModel->create($patientId, (int)$user['id'], $visitAt, $reason);
    }

    $recordModel = new MedicalRecord();
    $result = $recordModel->create($patientId, $encounterId, $input, (int)$user['id']);

    http_response_code(201);
    echo json_encode([
        'status' => 'success',
        'message' => 'Clinical record created and Version 1 anchored to blockchain.',
        'data' => $result,
    ]);
} catch (InvalidArgumentException $e) {
    http_response_code(422);
    echo json_encode(['status' => 'error', 'message' => $e->getMessage()]);
} catch (Throwable $e) {
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Failed to create medical record: ' . $e->getMessage()]);
}
