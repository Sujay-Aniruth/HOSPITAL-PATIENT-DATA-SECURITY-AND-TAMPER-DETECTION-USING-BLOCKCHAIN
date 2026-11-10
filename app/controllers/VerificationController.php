<?php
/**
 * Verification Controller
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

require_once __DIR__ . '/../services/IntegrityVerificationService.php';
require_once __DIR__ . '/../middleware/AuthMiddleware.php';

class VerificationController {
    private IntegrityVerificationService $verifier;

    public function __construct() {
        $this->verifier = new IntegrityVerificationService();
    }

    public function check(string $type, int $id, int $version, ?int $userId = null): array {
        AuthMiddleware::requireAuth();
        if ($type === CanonicalHashingService::TYPE_PATIENT_PROFILE) {
            return $this->verifier->verifyPatientProfile($id, $version, $userId);
        } elseif ($type === CanonicalHashingService::TYPE_MEDICAL_RECORD) {
            return $this->verifier->verifyMedicalRecord($id, $version, $userId);
        }
        throw new InvalidArgumentException("Unsupported record type: {$type}");
    }

    public function checkAll(?int $userId = null, int $limit = 100): array {
        AuthMiddleware::requireAuth();
        return $this->verifier->verifyAll($userId, $limit);
    }
}
