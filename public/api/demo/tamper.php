<?php
/**
 * Development-Only Tampering Demonstration API Endpoint
 * Hospital Patient Data Security and Tamper Detection
 * 
 * STRICT SECURITY RESTRICTIONS:
 * - Operates ONLY when APP_ENV === 'local'.
 * - Accessible ONLY to authenticated administrators.
 * - Enforces CSRF token validation.
 * - Modifies ONLY fictional test fixtures directly in MySQL without updating blockchain anchor.
 */

declare(strict_types=1);

header('Content-Type: application/json; charset=UTF-8');

require_once __DIR__ . '/../../../app/config/config.php';
require_once __DIR__ . '/../../../app/config/database.php';
require_once __DIR__ . '/../../../app/middleware/AuthMiddleware.php';
require_once __DIR__ . '/../../../app/middleware/CsrfMiddleware.php';
require_once __DIR__ . '/../../../app/services/AuditService.php';

// Check development environment
if (config('APP_ENV') !== 'local') {
    http_response_code(403);
    echo json_encode([
        'status' => 'error',
        'message' => 'Tamper simulation is strictly disabled outside local development environments.'
    ]);
    exit;
}

$user = AuthMiddleware::requireRole(['admin']);
CsrfMiddleware::requireValid();

$input = json_decode(file_get_contents('php://input'), true);
if (!is_array($input)) {
    $input = $_POST;
}

$recordType = strtoupper(trim((string)($input['record_type'] ?? '')));
$recordId = (int)($input['record_id'] ?? 0);
$version = (int)($input['version'] ?? 1);
$tamperField = trim((string)($input['field'] ?? ''));
$tamperValue = trim((string)($input['value'] ?? ''));

if (empty($recordType) || $recordId <= 0 || $version <= 0 || empty($tamperField)) {
    http_response_code(422);
    echo json_encode([
        'status' => 'error',
        'message' => 'Missing required parameters: record_type, record_id, version, field, and value.'
    ]);
    exit;
}

$db = Database::getConnection();

try {
    $originalValue = null;

    if ($recordType === 'MEDICAL_RECORD') {
        $allowedFields = ['diagnosis', 'symptoms', 'notes', 'prescription', 'treatment_plan'];
        if (!in_array($tamperField, $allowedFields, true)) {
            http_response_code(422);
            echo json_encode(['status' => 'error', 'message' => "Invalid clinical field for tamper test: {$tamperField}"]);
            exit;
        }

        // Get original value
        $stmt = $db->prepare("SELECT `{$tamperField}` as val FROM `medical_record_versions` WHERE `medical_record_id` = :id AND `version_number` = :ver");
        $stmt->execute([':id' => $recordId, ':ver' => $version]);
        $row = $stmt->fetch();
        if (!$row) {
            http_response_code(404);
            echo json_encode(['status' => 'error', 'message' => "Medical record #{$recordId} (v{$version}) not found."]);
            exit;
        }
        $originalValue = $row['val'];

        // Tamper directly in MySQL WITHOUT updating blockchain or sha256_hash column
        $update = $db->prepare("UPDATE `medical_record_versions` SET `{$tamperField}` = :val WHERE `medical_record_id` = :id AND `version_number` = :ver");
        $update->execute([':val' => $tamperValue, ':id' => $recordId, ':ver' => $version]);

    } elseif ($recordType === 'PATIENT_PROFILE') {
        $allowedFields = ['name', 'phone', 'address', 'emergency_contact', 'date_of_birth', 'gender'];
        if (!in_array($tamperField, $allowedFields, true)) {
            http_response_code(422);
            echo json_encode(['status' => 'error', 'message' => "Invalid patient demographic field for tamper test: {$tamperField}"]);
            exit;
        }

        $stmt = $db->prepare("SELECT `{$tamperField}` as val FROM `patient_profile_versions` WHERE `patient_id` = :id AND `version_number` = :ver");
        $stmt->execute([':id' => $recordId, ':ver' => $version]);
        $row = $stmt->fetch();
        if (!$row) {
            http_response_code(404);
            echo json_encode(['status' => 'error', 'message' => "Patient profile #{$recordId} (v{$version}) not found."]);
            exit;
        }
        $originalValue = $row['val'];

        // Tamper in MySQL
        $update = $db->prepare("UPDATE `patient_profile_versions` SET `{$tamperField}` = :val WHERE `patient_id` = :id AND `version_number` = :ver");
        $update->execute([':val' => $tamperValue, ':id' => $recordId, ':ver' => $version]);

    } else {
        http_response_code(422);
        echo json_encode(['status' => 'error', 'message' => "Invalid record type: {$recordType}"]);
        exit;
    }

    AuditService::log(
        'DEMO_TAMPER_SIMULATION',
        $recordType,
        $recordId,
        [
            'version' => $version,
            'field' => $tamperField,
            'original_value' => $originalValue,
            'tampered_value' => $tamperValue,
            'notice' => 'Deliberate laboratory database modification for integrity verification demonstration.'
        ],
        (int)$user['id']
    );

    echo json_encode([
        'status' => 'success',
        'message' => "DELIBERATE TAMPER APPLIED: Field '{$tamperField}' modified in MySQL for {$recordType} #{$recordId} (v{$version}). Blockchain anchor remains immutable. Now run verification to observe TAMPERED outcome.",
        'details' => [
            'record_type' => $recordType,
            'record_id' => $recordId,
            'version' => $version,
            'field' => $tamperField,
            'original_value' => $originalValue,
            'tampered_value' => $tamperValue,
        ],
    ]);
} catch (Throwable $e) {
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Tamper execution failed: ' . $e->getMessage()]);
}
