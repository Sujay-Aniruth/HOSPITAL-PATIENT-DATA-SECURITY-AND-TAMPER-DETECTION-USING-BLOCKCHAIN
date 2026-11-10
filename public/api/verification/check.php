<?php
/**
 * Single Record Integrity Verification API Endpoint
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

header('Content-Type: application/json; charset=UTF-8');

require_once __DIR__ . '/../../../app/config/config.php';
require_once __DIR__ . '/../../../app/middleware/AuthMiddleware.php';
require_once __DIR__ . '/../../../app/services/CanonicalHashingService.php';
require_once __DIR__ . '/../../../app/services/IntegrityVerificationService.php';

$user = AuthMiddleware::requireAuth();

$type = trim((string)($_GET['type'] ?? ''));
$id = (int)($_GET['id'] ?? 0);
$version = (int)($_GET['version'] ?? 1);

if (empty($type) || $id <= 0 || $version <= 0) {
    http_response_code(400);
    echo json_encode([
        'status' => 'error',
        'message' => 'Query parameters type, id, and version are required (e.g., ?type=MEDICAL_RECORD&id=1&version=1).'
    ]);
    exit;
}

$verifier = new IntegrityVerificationService();

if (strtoupper($type) === CanonicalHashingService::TYPE_PATIENT_PROFILE) {
    $result = $verifier->verifyPatientProfile($id, $version, (int)$user['id']);
} elseif (strtoupper($type) === CanonicalHashingService::TYPE_MEDICAL_RECORD) {
    $result = $verifier->verifyMedicalRecord($id, $version, (int)$user['id']);
} else {
    http_response_code(400);
    echo json_encode([
        'status' => 'error',
        'message' => "Invalid record type: {$type}. Supported types: PATIENT_PROFILE, MEDICAL_RECORD."
    ]);
    exit;
}

echo json_encode([
    'status' => 'success',
    'data' => $result,
]);
