<?php
/**
 * Patient Controller
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

require_once __DIR__ . '/../models/Patient.php';
require_once __DIR__ . '/../middleware/AuthMiddleware.php';

class PatientController {
    private Patient $patientModel;

    public function __construct() {
        $this->patientModel = new Patient();
    }

    public function index(string $search = '', int $limit = 50, int $offset = 0): array {
        AuthMiddleware::requireAuth();
        return $this->patientModel->getAll($search, $limit, $offset);
    }

    public function show(int $id): ?array {
        AuthMiddleware::requireAuth();
        return $this->patientModel->findById($id);
    }

    public function create(array $data, int $userId): array {
        AuthMiddleware::requireRole(['admin', 'staff']);
        return $this->patientModel->create($data, $userId);
    }

    public function update(int $id, array $data, int $userId): array {
        AuthMiddleware::requireRole(['admin', 'staff']);
        return $this->patientModel->update($id, $data, $userId);
    }
}
