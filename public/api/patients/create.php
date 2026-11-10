<?php
/**
 * Patient Registration API Endpoint
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

header('Content-Type: application/json; charset=UTF-8');

require_once __DIR__ . '/../../../app/config/config.php';
require_once __DIR__ . '/../../../app/middleware/AuthMiddleware.php';
require_once __DIR__ . '/../../../app/middleware/CsrfMiddleware.php';
require_once __DIR__ . '/../../../app/models/Patient.php';

// Allowed roles: admin and staff
$user = AuthMiddleware::requireRole(['admin', 'staff']);
CsrfMiddleware::requireValid();

$input = json_decode(file_get_contents('php://input'), true);
if (!is_array($input)) {
    $input = $_POST;
}

try {
    $patientModel = new Patient();
    $result = $patientModel->create($input, (int)$user['id']);

    http_response_code(201);
    echo json_encode([
        'status' => 'success',
        'message' => "Patient {$result['patient_code']} registered and profile anchored to blockchain.",
        'data' => $result,
    ]);
} catch (InvalidArgumentException $e) {
    http_response_code(422);
    echo json_encode(['status' => 'error', 'message' => $e->getMessage()]);
} catch (Throwable $e) {
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Failed to register patient: ' . $e->getMessage()]);
}
