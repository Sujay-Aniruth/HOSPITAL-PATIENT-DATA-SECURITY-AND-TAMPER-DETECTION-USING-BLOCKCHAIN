<?php
/**
 * Medical Record Model
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../services/CanonicalHashingService.php';
require_once __DIR__ . '/../services/BlockchainService.php';
require_once __DIR__ . '/../services/AuditService.php';

class MedicalRecord {
    private PDO $db;
    private BlockchainService $blockchain;

    public function __construct(?BlockchainService $blockchain = null) {
        $this->db = Database::getConnection();
        $this->blockchain = $blockchain ?? new BlockchainService();
    }

    /**
     * Create new medical record and anchor clinical version 1 on blockchain.
     */
    public function create(int $patientId, int $encounterId, array $data, int $userId): array {
        $symptoms = trim($data['symptoms'] ?? '');
        $diagnosis = trim($data['diagnosis'] ?? '');
        $notes = trim($data['notes'] ?? '');
        $prescription = trim($data['prescription'] ?? '');
        $treatmentPlan = trim($data['treatment_plan'] ?? '');

        if (empty($diagnosis) || empty($symptoms)) {
            throw new InvalidArgumentException("Clinical symptoms and diagnosis are required fields.");
        }

        // Verify encounter exists and matches patient
        $encStmt = $this->db->prepare("SELECT * FROM `encounters` WHERE `id` = :id AND `patient_id` = :pid LIMIT 1");
        $encStmt->execute([':id' => $encounterId, ':pid' => $patientId]);
        $encounter = $encStmt->fetch();

        if (!$encounter) {
            throw new InvalidArgumentException("Encounter #{$encounterId} not found or does not belong to patient #{$patientId}.");
        }

        $this->db->beginTransaction();
        try {
            // 1. Insert header
            $stmt = $this->db->prepare("
                INSERT INTO `medical_records` (`encounter_id`, `patient_id`, `current_version`, `created_at`)
                VALUES (:eid, :pid, 1, NOW())
            ");
            $stmt->execute([':eid' => $encounterId, ':pid' => $patientId]);
            $recordId = (int)$this->db->lastInsertId();

            // 2. Canonicalize Version 1
            $clinicalPayload = [
                'medical_record_id' => $recordId,
                'patient_id' => $patientId,
                'encounter_id' => $encounterId,
                'doctor_id' => (int)$encounter['doctor_id'],
                'symptoms' => $symptoms,
                'diagnosis' => $diagnosis,
                'notes' => $notes,
                'prescription' => $prescription,
                'treatment_plan' => $treatmentPlan,
            ];
            $hashData = CanonicalHashingService::canonicalizeMedicalRecord($clinicalPayload, 1);

            // 3. Insert Version 1
            $verStmt = $this->db->prepare("
                INSERT INTO `medical_record_versions` (
                    `medical_record_id`, `version_number`, `symptoms`, `diagnosis`, `notes`, `prescription`, `treatment_plan`,
                    `canonical_json`, `sha256_hash`, `anchor_status`, `created_by`, `created_at`
                ) VALUES (
                    :rec_id, 1, :symptoms, :diagnosis, :notes, :prescription, :treatment,
                    :json, :hash, 'PENDING', :created_by, NOW()
                )
            ");
            $verStmt->execute([
                ':rec_id' => $recordId,
                ':symptoms' => $symptoms,
                ':diagnosis' => $diagnosis,
                ':notes' => $notes,
                ':prescription' => $prescription,
                ':treatment' => $treatmentPlan,
                ':json' => $hashData['canonical_json'],
                ':hash' => $hashData['sha256_hash'],
                ':created_by' => $userId,
            ]);
            $versionId = (int)$this->db->lastInsertId();

            $this->db->commit();
        } catch (Throwable $e) {
            $this->db->rollBack();
            throw $e;
        }

        // 4. Anchor on blockchain
        $txInfo = null;
        try {
            $txInfo = $this->blockchain->storeRecordHash(
                CanonicalHashingService::TYPE_MEDICAL_RECORD,
                $recordId,
                1,
                $hashData['sha256_hash']
            );

            $upd = $this->db->prepare("
                UPDATE `medical_record_versions`
                SET `anchor_status` = 'ANCHORED',
                    `transaction_hash` = :tx,
                    `block_number` = :blk,
                    `anchored_at` = NOW()
                WHERE `id` = :id
            ");
            $upd->execute([
                ':tx' => $txInfo['transactionHash'],
                ':blk' => $txInfo['blockNumber'],
                ':id' => $versionId,
            ]);
        } catch (Throwable $e) {
            error_log("Blockchain anchoring failed for medical record {$recordId}: " . $e->getMessage());
            $upd = $this->db->prepare("UPDATE `medical_record_versions` SET `anchor_status` = 'FAILED' WHERE `id` = :id");
            $upd->execute([':id' => $versionId]);
        }

        AuditService::log(
            'RECORD_CREATE',
            'MEDICAL_RECORD',
            $recordId,
            [
                'version' => 1,
                'patient_id' => $patientId,
                'sha256_hash' => $hashData['sha256_hash'],
                'tx_hash' => $txInfo['transactionHash'] ?? null,
            ],
            $userId
        );

        return [
            'medical_record_id' => $recordId,
            'version' => 1,
            'sha256_hash' => $hashData['sha256_hash'],
            'blockchain' => $txInfo,
        ];
    }

    /**
     * Authorized clinical amendment: creates version N+1, anchors new hash, preserves prior versions.
     */
    public function amend(int $medicalRecordId, array $data, int $userId): array {
        $record = $this->findById($medicalRecordId);
        if (!$record) {
            throw new RuntimeException("Medical record ID {$medicalRecordId} not found.");
        }

        $nextVersion = (int)$record['current_version'] + 1;

        $symptoms = trim($data['symptoms'] ?? $record['current_symptoms']);
        $diagnosis = trim($data['diagnosis'] ?? $record['current_diagnosis']);
        $notes = trim($data['notes'] ?? $record['current_notes']);
        $prescription = trim($data['prescription'] ?? $record['current_prescription']);
        $treatmentPlan = trim($data['treatment_plan'] ?? $record['current_treatment_plan']);

        $this->db->beginTransaction();
        try {
            // Update current_version pointer
            $updHeader = $this->db->prepare("
                UPDATE `medical_records`
                SET `current_version` = :ver, `updated_at` = NOW()
                WHERE `id` = :id
            ");
            $updHeader->execute([':ver' => $nextVersion, ':id' => $medicalRecordId]);

            // Canonicalize Version N+1
            $clinicalPayload = [
                'medical_record_id' => $medicalRecordId,
                'patient_id' => (int)$record['patient_id'],
                'encounter_id' => (int)$record['encounter_id'],
                'doctor_id' => (int)$record['doctor_id'],
                'symptoms' => $symptoms,
                'diagnosis' => $diagnosis,
                'notes' => $notes,
                'prescription' => $prescription,
                'treatment_plan' => $treatmentPlan,
            ];
            $hashData = CanonicalHashingService::canonicalizeMedicalRecord($clinicalPayload, $nextVersion);

            // Insert Version N+1
            $verStmt = $this->db->prepare("
                INSERT INTO `medical_record_versions` (
                    `medical_record_id`, `version_number`, `symptoms`, `diagnosis`, `notes`, `prescription`, `treatment_plan`,
                    `canonical_json`, `sha256_hash`, `anchor_status`, `created_by`, `created_at`
                ) VALUES (
                    :rec_id, :ver, :symptoms, :diagnosis, :notes, :prescription, :treatment,
                    :json, :hash, 'PENDING', :created_by, NOW()
                )
            ");
            $verStmt->execute([
                ':rec_id' => $medicalRecordId,
                ':ver' => $nextVersion,
                ':symptoms' => $symptoms,
                ':diagnosis' => $diagnosis,
                ':notes' => $notes,
                ':prescription' => $prescription,
                ':treatment' => $treatmentPlan,
                ':json' => $hashData['canonical_json'],
                ':hash' => $hashData['sha256_hash'],
                ':created_by' => $userId,
            ]);
            $versionId = (int)$this->db->lastInsertId();

            $this->db->commit();
        } catch (Throwable $e) {
            $this->db->rollBack();
            throw $e;
        }

        // Anchor version N+1 to blockchain
        $txInfo = null;
        try {
            $txInfo = $this->blockchain->storeRecordHash(
                CanonicalHashingService::TYPE_MEDICAL_RECORD,
                $medicalRecordId,
                $nextVersion,
                $hashData['sha256_hash']
            );

            $upd = $this->db->prepare("
                UPDATE `medical_record_versions`
                SET `anchor_status` = 'ANCHORED',
                    `transaction_hash` = :tx,
                    `block_number` = :blk,
                    `anchored_at` = NOW()
                WHERE `id` = :id
            ");
            $upd->execute([
                ':tx' => $txInfo['transactionHash'],
                ':blk' => $txInfo['blockNumber'],
                ':id' => $versionId,
            ]);
        } catch (Throwable $e) {
            error_log("Blockchain anchoring failed for record amendment {$medicalRecordId} v{$nextVersion}: " . $e->getMessage());
            $upd = $this->db->prepare("UPDATE `medical_record_versions` SET `anchor_status` = 'FAILED' WHERE `id` = :id");
            $upd->execute([':id' => $versionId]);
        }

        AuditService::log(
            'RECORD_AMEND',
            'MEDICAL_RECORD',
            $medicalRecordId,
            [
                'previous_version' => $record['current_version'],
                'new_version' => $nextVersion,
                'sha256_hash' => $hashData['sha256_hash'],
                'tx_hash' => $txInfo['transactionHash'] ?? null,
            ],
            $userId
        );

        return [
            'medical_record_id' => $medicalRecordId,
            'new_version' => $nextVersion,
            'sha256_hash' => $hashData['sha256_hash'],
            'blockchain' => $txInfo,
        ];
    }

    public function findById(int $id): ?array {
        $stmt = $this->db->prepare("
            SELECT mr.*, 
                   p.patient_code, p.name as patient_name, p.gender, p.date_of_birth,
                   e.encounter_code, e.visit_at, e.reason as encounter_reason, e.doctor_id,
                   doc.name as doctor_name,
                   mrv.symptoms as current_symptoms, mrv.diagnosis as current_diagnosis,
                   mrv.notes as current_notes, mrv.prescription as current_prescription,
                   mrv.treatment_plan as current_treatment_plan, mrv.sha256_hash as current_hash,
                   mrv.anchor_status as current_anchor_status, mrv.transaction_hash as current_tx_hash,
                   mrv.block_number as current_block_number
            FROM `medical_records` mr
            JOIN `patients` p ON mr.patient_id = p.id
            JOIN `encounters` e ON mr.encounter_id = e.id
            JOIN `users` doc ON e.doctor_id = doc.id
            LEFT JOIN `medical_record_versions` mrv ON mr.id = mrv.medical_record_id AND mr.current_version = mrv.version_number
            WHERE mr.id = :id
        ");
        $stmt->execute([':id' => $id]);
        $row = $stmt->fetch();
        return $row ?: null;
    }

    public function getVersions(int $medicalRecordId): array {
        $stmt = $this->db->prepare("
            SELECT mrv.*, u.name as created_by_name
            FROM `medical_record_versions` mrv
            LEFT JOIN `users` u ON mrv.created_by = u.id
            WHERE mrv.medical_record_id = :id
            ORDER BY mrv.version_number DESC
        ");
        $stmt->execute([':id' => $medicalRecordId]);
        return $stmt->fetchAll();
    }

    public function getVersion(int $medicalRecordId, int $versionNumber): ?array {
        $stmt = $this->db->prepare("
            SELECT mrv.*, u.name as created_by_name
            FROM `medical_record_versions` mrv
            LEFT JOIN `users` u ON mrv.created_by = u.id
            WHERE mrv.medical_record_id = :id AND mrv.version_number = :ver
            LIMIT 1
        ");
        $stmt->execute([':id' => $medicalRecordId, ':ver' => $versionNumber]);
        $row = $stmt->fetch();
        return $row ?: null;
    }

    public function getAll(int $limit = 50, int $offset = 0, ?int $patientId = null): array {
        $sql = "
            SELECT mr.*, 
                   p.patient_code, p.name as patient_name,
                   e.encounter_code, e.visit_at,
                   doc.name as doctor_name,
                   mrv.diagnosis as current_diagnosis,
                   mrv.sha256_hash, mrv.anchor_status, mrv.transaction_hash, mrv.block_number
            FROM `medical_records` mr
            JOIN `patients` p ON mr.patient_id = p.id
            JOIN `encounters` e ON mr.encounter_id = e.id
            JOIN `users` doc ON e.doctor_id = doc.id
            LEFT JOIN `medical_record_versions` mrv ON mr.id = mrv.medical_record_id AND mr.current_version = mrv.version_number
        ";
        $params = [];

        if ($patientId !== null) {
            $sql .= " WHERE mr.patient_id = :pid";
            $params[':pid'] = $patientId;
        }

        $sql .= " ORDER BY mr.id DESC LIMIT " . (int)$limit . " OFFSET " . (int)$offset;
        $stmt = $this->db->prepare($sql);
        $stmt->execute($params);
        return $stmt->fetchAll();
    }
}
