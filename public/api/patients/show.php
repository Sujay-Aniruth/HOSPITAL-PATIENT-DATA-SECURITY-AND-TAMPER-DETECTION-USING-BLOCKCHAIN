<?php
/**
 * Patient Details and History API Endpoint
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

header('Content-Type: application/json; charset=UTF-8');

require_once __DIR__ . '/../../../app/config/config.php';
require_once __DIR__ . '/../../../app/middleware/AuthMiddleware.php';
require_once __DIR__ . '/../../../app/models/Patient.php';
require_once __DIR__ . '/../../../app/models/Encounter.php';
require_once __DIR__ . '/../../../app/models/MedicalRecord.php';

AuthMiddleware::requireAuth();

$id = (int)($_GET['id'] ?? 0);
if ($id <= 0) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'Valid patient ID is required.']);
    exit;
}

$patientModel = new Patient();
$patient = $patientModel->findById($id);

if (!$patient) {
    http_response_code(404);
    echo json_encode(['status' => 'error', 'message' => 'Patient not found.']);
    exit;
}

$versions = $patientModel->getVersions($id);
$encounterModel = new Encounter();
$encounters = $encounterModel->getByPatient($id);

echo json_encode([
    'status' => 'success',
    'patient' => $patient,
    'versions' => $versions,
    'encounters' => $encounters,
]);
