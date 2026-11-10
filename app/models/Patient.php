<?php
/**
 * Patient Model
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../services/CanonicalHashingService.php';
require_once __DIR__ . '/../services/BlockchainService.php';
require_once __DIR__ . '/../services/AuditService.php';

class Patient {
    private PDO $db;
    private BlockchainService $blockchain;

    public function __construct(?BlockchainService $blockchain = null) {
        $this->db = Database::getConnection();
        $this->blockchain = $blockchain ?? new BlockchainService();
    }

    /**
     * Generate next patient code: PAT-YYYY-XXX
     */
    public function generatePatientCode(): string {
        $year = date('Y');
        $stmt = $this->db->query("SELECT MAX(id) as max_id FROM `patients`");
        $row = $stmt->fetch();
        $nextId = ((int)($row['max_id'] ?? 0)) + 1;
        return sprintf("PAT-%s-%03d", $year, $nextId);
    }

    /**
     * Register a new patient and anchor profile version 1 on blockchain.
     */
    public function create(array $data, int $userId): array {
        $patientCode = trim($data['patient_code'] ?? '') ?: $this->generatePatientCode();
        $name = trim($data['name'] ?? '');
        $dob = trim($data['date_of_birth'] ?? '');
        $gender = trim($data['gender'] ?? 'Other');
        $phone = trim($data['phone'] ?? '');
        $address = trim($data['address'] ?? '');
        $emergencyContact = trim($data['emergency_contact'] ?? '');

        if (empty($name) || empty($dob) || empty($phone)) {
            throw new InvalidArgumentException("Patient name, date of birth, and phone number are required.");
        }

        $this->db->beginTransaction();
        try {
            // 1. Insert patient header
            $stmt = $this->db->prepare("
                INSERT INTO `patients` (
                    `patient_code`, `name`, `date_of_birth`, `gender`, `phone`, `address`, `emergency_contact`, `current_profile_version`, `created_by`, `created_at`
                ) VALUES (
                    :code, :name, :dob, :gender, :phone, :address, :emergency, 1, :created_by, NOW()
                )
            ");
            $stmt->execute([
                ':code' => $patientCode,
                ':name' => $name,
                ':dob' => $dob,
                ':gender' => $gender,
                ':phone' => $phone,
                ':address' => $address,
                ':emergency' => $emergencyContact,
                ':created_by' => $userId,
            ]);
            $patientId = (int)$this->db->lastInsertId();

            // 2. Canonicalize protected demographic fields for Version 1
            $profileData = [
                'id' => $patientId,
                'patient_code' => $patientCode,
                'name' => $name,
                'date_of_birth' => $dob,
                'gender' => $gender,
                'phone' => $phone,
                'address' => $address,
                'emergency_contact' => $emergencyContact,
            ];
            $hashData = CanonicalHashingService::canonicalizePatientProfile($profileData, 1);

            // 3. Insert patient_profile_versions (initial status PENDING)
            $verStmt = $this->db->prepare("
                INSERT INTO `patient_profile_versions` (
                    `patient_id`, `version_number`, `patient_code`, `name`, `date_of_birth`, `gender`, `phone`, `address`, `emergency_contact`, `canonical_json`, `sha256_hash`, `anchor_status`, `created_by`, `created_at`
                ) VALUES (
                    :patient_id, 1, :code, :name, :dob, :gender, :phone, :address, :emergency, :json, :hash, 'PENDING', :created_by, NOW()
                )
            ");
            $verStmt->execute([
                ':patient_id' => $patientId,
                ':code' => $patientCode,
                ':name' => $name,
                ':dob' => $dob,
                ':gender' => $gender,
                ':phone' => $phone,
                ':address' => $address,
                ':emergency' => $emergencyContact,
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

        // 4. Anchor to blockchain (outside SQL transaction to guarantee recovery & state separation)
        $txInfo = null;
        try {
            $txInfo = $this->blockchain->storeRecordHash(
                CanonicalHashingService::TYPE_PATIENT_PROFILE,
                $patientId,
                1,
                $hashData['sha256_hash']
            );

            // Update status to ANCHORED
            $updStmt = $this->db->prepare("
                UPDATE `patient_profile_versions`
                SET `anchor_status` = 'ANCHORED',
                    `transaction_hash` = :tx_hash,
                    `block_number` = :block_num,
                    `anchored_at` = NOW()
                WHERE `id` = :id
            ");
            $updStmt->execute([
                ':tx_hash' => $txInfo['transactionHash'],
                ':block_num' => $txInfo['blockNumber'],
                ':id' => $versionId,
            ]);
        } catch (Throwable $e) {
            error_log("Blockchain anchoring failed for patient {$patientId}: " . $e->getMessage());
            $updStmt = $this->db->prepare("UPDATE `patient_profile_versions` SET `anchor_status` = 'FAILED' WHERE `id` = :id");
            $updStmt->execute([':id' => $versionId]);
        }

        AuditService::log(
            'PATIENT_CREATE',
            'PATIENT',
            $patientId,
            [
                'patient_code' => $patientCode,
                'name' => $name,
                'version' => 1,
                'sha256_hash' => $hashData['sha256_hash'],
                'tx_hash' => $txInfo['transactionHash'] ?? null,
            ],
            $userId
        );

        return [
            'patient_id' => $patientId,
            'patient_code' => $patientCode,
            'version' => 1,
            'sha256_hash' => $hashData['sha256_hash'],
            'blockchain' => $txInfo,
        ];
    }

    /**
     * Authorized profile update: creates version N+1, anchors new hash, preserves prior versions.
     */
    public function update(int $patientId, array $data, int $userId): array {
        $patient = $this->findById($patientId);
        if (!$patient) {
            throw new RuntimeException("Patient ID {$patientId} not found.");
        }

        $nextVersion = (int)$patient['current_profile_version'] + 1;

        $name = trim($data['name'] ?? $patient['name']);
        $dob = trim($data['date_of_birth'] ?? $patient['date_of_birth']);
        $gender = trim($data['gender'] ?? $patient['gender']);
        $phone = trim($data['phone'] ?? $patient['phone']);
        $address = trim($data['address'] ?? $patient['address']);
        $emergencyContact = trim($data['emergency_contact'] ?? $patient['emergency_contact']);

        $this->db->beginTransaction();
        try {
            // Update patient header with current version pointer N+1
            $upd = $this->db->prepare("
                UPDATE `patients`
                SET `name` = :name, `date_of_birth` = :dob, `gender` = :gender, `phone` = :phone,
                    `address` = :address, `emergency_contact` = :emergency, `current_profile_version` = :version
                WHERE `id` = :id
            ");
            $upd->execute([
                ':name' => $name,
                ':dob' => $dob,
                ':gender' => $gender,
                ':phone' => $phone,
                ':address' => $address,
                ':emergency' => $emergencyContact,
                ':version' => $nextVersion,
                ':id' => $patientId,
            ]);

            // Canonicalize Version N+1
            $profileData = [
                'id' => $patientId,
                'patient_code' => $patient['patient_code'],
                'name' => $name,
                'date_of_birth' => $dob,
                'gender' => $gender,
                'phone' => $phone,
                'address' => $address,
                'emergency_contact' => $emergencyContact,
            ];
            $hashData = CanonicalHashingService::canonicalizePatientProfile($profileData, $nextVersion);

            // Insert new version row
            $verStmt = $this->db->prepare("
                INSERT INTO `patient_profile_versions` (
                    `patient_id`, `version_number`, `patient_code`, `name`, `date_of_birth`, `gender`, `phone`, `address`, `emergency_contact`, `canonical_json`, `sha256_hash`, `anchor_status`, `created_by`, `created_at`
                ) VALUES (
                    :patient_id, :ver, :code, :name, :dob, :gender, :phone, :address, :emergency, :json, :hash, 'PENDING', :created_by, NOW()
                )
            ");
            $verStmt->execute([
                ':patient_id' => $patientId,
                ':ver' => $nextVersion,
                ':code' => $patient['patient_code'],
                ':name' => $name,
                ':dob' => $dob,
                ':gender' => $gender,
                ':phone' => $phone,
                ':address' => $address,
                ':emergency' => $emergencyContact,
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
                CanonicalHashingService::TYPE_PATIENT_PROFILE,
                $patientId,
                $nextVersion,
                $hashData['sha256_hash']
            );

            $updStmt = $this->db->prepare("
                UPDATE `patient_profile_versions`
                SET `anchor_status` = 'ANCHORED',
                    `transaction_hash` = :tx_hash,
                    `block_number` = :block_num,
                    `anchored_at` = NOW()
                WHERE `id` = :id
            ");
            $updStmt->execute([
                ':tx_hash' => $txInfo['transactionHash'],
                ':block_num' => $txInfo['blockNumber'],
                ':id' => $versionId,
            ]);
        } catch (Throwable $e) {
            error_log("Blockchain anchoring failed for patient amendment {$patientId} v{$nextVersion}: " . $e->getMessage());
            $updStmt = $this->db->prepare("UPDATE `patient_profile_versions` SET `anchor_status` = 'FAILED' WHERE `id` = :id");
            $updStmt->execute([':id' => $versionId]);
        }

        AuditService::log(
            'PATIENT_AMEND',
            'PATIENT',
            $patientId,
            [
                'previous_version' => $patient['current_profile_version'],
                'new_version' => $nextVersion,
                'sha256_hash' => $hashData['sha256_hash'],
                'tx_hash' => $txInfo['transactionHash'] ?? null,
            ],
            $userId
        );

        return [
            'patient_id' => $patientId,
            'new_version' => $nextVersion,
            'sha256_hash' => $hashData['sha256_hash'],
            'blockchain' => $txInfo,
        ];
    }

    public function findById(int $id): ?array {
        $stmt = $this->db->prepare("
            SELECT p.*, u.name as created_by_name
            FROM `patients` p
            LEFT JOIN `users` u ON p.created_by = u.id
            WHERE p.id = :id
        ");
        $stmt->execute([':id' => $id]);
        $row = $stmt->fetch();
        return $row ?: null;
    }

    public function findByCode(string $code): ?array {
        $stmt = $this->db->prepare("SELECT * FROM `patients` WHERE `patient_code` = :code LIMIT 1");
        $stmt->execute([':code' => $code]);
        $row = $stmt->fetch();
        return $row ?: null;
    }

    public function getAll(string $search = '', int $limit = 50, int $offset = 0): array {
        $sql = "
            SELECT p.*, u.name as created_by_name,
                   (SELECT COUNT(*) FROM encounters e WHERE e.patient_id = p.id) as encounter_count
            FROM `patients` p
            LEFT JOIN `users` u ON p.created_by = u.id
        ";
        $params = [];

        if (!empty($search)) {
            $sql .= " WHERE p.patient_code LIKE :s1 OR p.name LIKE :s2 OR p.phone LIKE :s3";
            $term = "%{$search}%";
            $params[':s1'] = $term;
            $params[':s2'] = $term;
            $params[':s3'] = $term;
        }

        $sql .= " ORDER BY p.id DESC LIMIT " . (int)$limit . " OFFSET " . (int)$offset;
        $stmt = $this->db->prepare($sql);
        $stmt->execute($params);
        return $stmt->fetchAll();
    }

    public function getVersions(int $patientId): array {
        $stmt = $this->db->prepare("
            SELECT pv.*, u.name as created_by_name
            FROM `patient_profile_versions` pv
            LEFT JOIN `users` u ON pv.created_by = u.id
            WHERE pv.patient_id = :id
            ORDER BY pv.version_number DESC
        ");
        $stmt->execute([':id' => $patientId]);
        return $stmt->fetchAll();
    }
}
