<?php
/**
 * Medical Record Controller
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

require_once __DIR__ . '/../models/MedicalRecord.php';
require_once __DIR__ . '/../middleware/AuthMiddleware.php';

class MedicalRecordController {
    private MedicalRecord $recordModel;

    public function __construct() {
        $this->recordModel = new MedicalRecord();
    }

    public function index(int $limit = 50, int $offset = 0, ?int $patientId = null): array {
        AuthMiddleware::requireAuth();
        return $this->recordModel->getAll($limit, $offset, $patientId);
    }

    public function show(int $id): ?array {
        AuthMiddleware::requireAuth();
        return $this->recordModel->findById($id);
    }

    public function create(int $patientId, int $encounterId, array $data, int $userId): array {
        AuthMiddleware::requireRole(['admin', 'doctor']);
        return $this->recordModel->create($patientId, $encounterId, $data, $userId);
    }

    public function amend(int $id, array $data, int $userId): array {
        AuthMiddleware::requireRole(['admin', 'doctor']);
        return $this->recordModel->amend($id, $data, $userId);
    }
}
