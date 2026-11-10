<?php
/**
 * Encounter Model
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../services/AuditService.php';

class Encounter {
    private PDO $db;

    public function __construct() {
        $this->db = Database::getConnection();
    }

    public function generateEncounterCode(): string {
        $year = date('Y');
        $stmt = $this->db->query("SELECT MAX(id) as max_id FROM `encounters`");
        $row = $stmt->fetch();
        $nextId = ((int)($row['max_id'] ?? 0)) + 1;
        return sprintf("ENC-%s-%03d", $year, $nextId);
    }

    public function create(int $patientId, int $doctorId, string $visitAt, string $reason): int {
        $code = $this->generateEncounterCode();
        $stmt = $this->db->prepare("
            INSERT INTO `encounters` (`encounter_code`, `patient_id`, `doctor_id`, `visit_at`, `reason`, `created_at`)
            VALUES (:code, :patient_id, :doctor_id, :visit_at, :reason, NOW())
        ");
        $stmt->execute([
            ':code' => $code,
            ':patient_id' => $patientId,
            ':doctor_id' => $doctorId,
            ':visit_at' => $visitAt,
            ':reason' => $reason,
        ]);
        $encounterId = (int)$this->db->lastInsertId();

        AuditService::log(
            'ENCOUNTER_CREATE',
            'ENCOUNTER',
            $encounterId,
            ['encounter_code' => $code, 'patient_id' => $patientId],
            $doctorId
        );

        return $encounterId;
    }

    public function findById(int $id): ?array {
        $stmt = $this->db->prepare("
            SELECT e.*, p.patient_code, p.name as patient_name, u.name as doctor_name
            FROM `encounters` e
            JOIN `patients` p ON e.patient_id = p.id
            JOIN `users` u ON e.doctor_id = u.id
            WHERE e.id = :id
        ");
        $stmt->execute([':id' => $id]);
        $row = $stmt->fetch();
        return $row ?: null;
    }

    public function getByPatient(int $patientId): array {
        $stmt = $this->db->prepare("
            SELECT e.*, u.name as doctor_name, mr.id as medical_record_id, mr.current_version
            FROM `encounters` e
            JOIN `users` u ON e.doctor_id = u.id
            LEFT JOIN `medical_records` mr ON e.id = mr.encounter_id
            WHERE e.patient_id = :patient_id
            ORDER BY e.visit_at DESC
        ");
        $stmt->execute([':patient_id' => $patientId]);
        return $stmt->fetchAll();
    }
}
