<?php
/**
 * Integrity Verification Service
 * Hospital Patient Data Security and Tamper Detection
 * 
 * Verifies mathematical integrity between local MySQL patient/clinical records
 * and immutable cryptographic anchors stored on the Ethereum blockchain.
 */

declare(strict_types=1);

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/CanonicalHashingService.php';
require_once __DIR__ . '/BlockchainService.php';
require_once __DIR__ . '/AuditService.php';

class IntegrityVerificationService {
    public const RESULT_VALID = 'VALID';
    public const RESULT_TAMPERED = 'TAMPERED';
    public const RESULT_PENDING = 'PENDING';
    public const RESULT_MISSING_ANCHOR = 'MISSING_ANCHOR';
    public const RESULT_ERROR = 'ERROR';

    private PDO $db;
    private BlockchainService $blockchain;

    public function __construct(?BlockchainService $blockchain = null) {
        $this->db = Database::getConnection();
        $this->blockchain = $blockchain ?? new BlockchainService();
    }

    /**
     * Verify a specific patient profile version.
     */
    public function verifyPatientProfile(int $patientId, int $versionNumber, ?int $checkedBy = null): array {
        // Fetch version from database
        $stmt = $this->db->prepare("
            SELECT ppv.*, p.patient_code as cur_patient_code, p.current_profile_version
            FROM `patient_profile_versions` ppv
            JOIN `patients` p ON ppv.patient_id = p.id
            WHERE ppv.patient_id = :patient_id AND ppv.version_number = :version
        ");
        $stmt->execute([':patient_id' => $patientId, ':version' => $versionNumber]);
        $row = $stmt->fetch();

        if (!$row) {
            return [
                'result' => self::RESULT_ERROR,
                'message' => "Patient profile version {$versionNumber} not found in database for patient ID {$patientId}.",
                'calculated_hash' => null,
                'blockchain_hash' => null,
            ];
        }

        // Recalculate deterministic hash directly from stored database fields
        $hashResult = CanonicalHashingService::canonicalizePatientProfile($row, $versionNumber);
        $calculatedHash = $hashResult['sha256_hash'];

        // Query blockchain contract for anchored proof
        return $this->evaluateIntegrity(
            CanonicalHashingService::TYPE_PATIENT_PROFILE,
            $patientId,
            $versionNumber,
            $calculatedHash,
            $row['sha256_hash'], // hash stored in DB version row
            $row['anchor_status'],
            $row['transaction_hash'],
            $row['block_number'],
            $checkedBy
        );
    }

    /**
     * Verify a specific medical record clinical version.
     */
    public function verifyMedicalRecord(int $medicalRecordId, int $versionNumber, ?int $checkedBy = null): array {
        $stmt = $this->db->prepare("
            SELECT mrv.*, mr.patient_id, mr.encounter_id, mr.current_version, e.doctor_id
            FROM `medical_record_versions` mrv
            JOIN `medical_records` mr ON mrv.medical_record_id = mr.id
            JOIN `encounters` e ON mr.encounter_id = e.id
            WHERE mrv.medical_record_id = :record_id AND mrv.version_number = :version
        ");
        $stmt->execute([':record_id' => $medicalRecordId, ':version' => $versionNumber]);
        $row = $stmt->fetch();

        if (!$row) {
            return [
                'result' => self::RESULT_ERROR,
                'message' => "Medical record version {$versionNumber} not found in database for record ID {$medicalRecordId}.",
                'calculated_hash' => null,
                'blockchain_hash' => null,
            ];
        }

        // Recalculate deterministic hash directly from stored clinical fields
        $hashResult = CanonicalHashingService::canonicalizeMedicalRecord($row, $versionNumber);
        $calculatedHash = $hashResult['sha256_hash'];

        return $this->evaluateIntegrity(
            CanonicalHashingService::TYPE_MEDICAL_RECORD,
            $medicalRecordId,
            $versionNumber,
            $calculatedHash,
            $row['sha256_hash'],
            $row['anchor_status'],
            $row['transaction_hash'],
            $row['block_number'],
            $checkedBy
        );
    }

    /**
     * Core comparison logic between calculated database hash and on-chain anchor.
     */
    private function evaluateIntegrity(
        string $recordType,
        int $recordId,
        int $versionNumber,
        string $calculatedHash,
        string $storedDbHash,
        string $anchorStatus,
        ?string $dbTxHash,
        ?int $dbBlockNumber,
        ?int $checkedBy
    ): array {
        if ($checkedBy === null && isset($_SESSION['user']['id'])) {
            $checkedBy = (int)$_SESSION['user']['id'];
        }
        $checkedBy = $checkedBy ?: 1; // Default to admin if unauthenticated batch

        try {
            // Read anchor directly from smart contract on Ethereum
            $chainData = $this->blockchain->getRecordHash($recordType, $recordId, $versionNumber);
            $blockchainHash = $chainData['hash'] ?? null;
            $onChainExists = !empty($chainData['exists']);

            $result = self::RESULT_ERROR;
            $details = '';
            $txHash = $dbTxHash;
            $blockNumber = $dbBlockNumber;

            if (!$onChainExists) {
                if ($anchorStatus === 'PENDING') {
                    $result = self::RESULT_PENDING;
                    $details = 'Record version is pending blockchain confirmation.';
                } else {
                    $result = self::RESULT_MISSING_ANCHOR;
                    $details = 'Record exists in database, but no anchor exists on the blockchain.';
                }
            } else {
                // Blockchain anchor exists! Compare calculated SHA-256 with on-chain hash
                if (CanonicalHashingService::verifyHash($calculatedHash, $blockchainHash)) {
                    $result = self::RESULT_VALID;
                    $details = 'Cryptographic hash verified: database content matches immutable blockchain anchor.';
                } else {
                    $result = self::RESULT_TAMPERED;
                    $details = 'INTEGRITY VIOLATION: Database content has been modified. Calculated SHA-256 does not match blockchain anchor!';
                }
            }

            // Record verification result into integrity_checks table
            $checkStmt = $this->db->prepare("
                INSERT INTO `integrity_checks` (
                    `record_type`, `record_id`, `version_number`, `calculated_hash`, `blockchain_hash`, `result`, `details`, `checked_by`, `checked_at`
                ) VALUES (
                    :record_type, :record_id, :version, :calc_hash, :bc_hash, :result, :details, :checked_by, NOW()
                )
            ");
            $checkStmt->execute([
                ':record_type' => $recordType,
                ':record_id' => $recordId,
                ':version' => $versionNumber,
                ':calc_hash' => $calculatedHash,
                ':bc_hash' => $blockchainHash,
                ':result' => $result,
                ':details' => $details,
                ':checked_by' => $checkedBy,
            ]);
            $checkId = (int)$this->db->lastInsertId();

            // If TAMPERED, create or update security alert
            if ($result === self::RESULT_TAMPERED) {
                $this->triggerSecurityAlert(
                    $recordType,
                    $recordId,
                    $versionNumber,
                    $calculatedHash,
                    $blockchainHash ?? $storedDbHash,
                    "Unauthorized modification detected in {$recordType} #{$recordId} (v{$versionNumber}). Stored database content produces SHA-256 {$calculatedHash}, but blockchain anchored hash is {$blockchainHash}."
                );

                AuditService::log(
                    'TAMPER_DETECTED',
                    $recordType,
                    $recordId,
                    [
                        'version' => $versionNumber,
                        'calculated_hash' => $calculatedHash,
                        'blockchain_hash' => $blockchainHash,
                        'check_id' => $checkId,
                    ],
                    $checkedBy
                );
            } else {
                AuditService::log(
                    'VERIFICATION_CHECK',
                    $recordType,
                    $recordId,
                    [
                        'version' => $versionNumber,
                        'result' => $result,
                        'check_id' => $checkId,
                    ],
                    $checkedBy
                );
            }

            return [
                'check_id' => $checkId,
                'record_type' => $recordType,
                'record_id' => $recordId,
                'version' => $versionNumber,
                'calculated_hash' => $calculatedHash,
                'stored_db_hash' => $storedDbHash,
                'blockchain_hash' => $blockchainHash,
                'result' => $result,
                'details' => $details,
                'transaction_hash' => $txHash,
                'block_number' => $blockNumber,
                'blockchain_timestamp' => $chainData['timestamp'] ?? null,
                'anchored_by' => $chainData['anchoredBy'] ?? null,
                'checked_at' => date('Y-m-d H:i:s'),
            ];
        } catch (Throwable $e) {
            return [
                'result' => self::RESULT_ERROR,
                'record_type' => $recordType,
                'record_id' => $recordId,
                'version' => $versionNumber,
                'calculated_hash' => $calculatedHash,
                'blockchain_hash' => null,
                'details' => 'Verification failed due to blockchain or database error: ' . $e->getMessage(),
                'error' => $e->getMessage(),
            ];
        }
    }

    /**
     * Create an un-resolved security alert if not already active.
     */
    public function triggerSecurityAlert(
        string $recordType,
        int $recordId,
        int $versionNumber,
        string $detectedHash,
        string $expectedHash,
        string $message
    ): int {
        // Check if an unresolved alert already exists for this exact record version
        $existing = $this->db->prepare("
            SELECT id FROM `security_alerts`
            WHERE `record_type` = :type AND `record_id` = :id AND `version_number` = :version AND `resolved` = 0
            LIMIT 1
        ");
        $existing->execute([':type' => $recordType, ':id' => $recordId, ':version' => $versionNumber]);
        $row = $existing->fetch();

        if ($row) {
            return (int)$row['id'];
        }

        $stmt = $this->db->prepare("
            INSERT INTO `security_alerts` (
                `record_type`, `record_id`, `version_number`, `severity`, `message`, `detected_hash`, `expected_hash`, `resolved`, `detected_at`
            ) VALUES (
                :type, :id, :version, 'CRITICAL', :message, :detected_hash, :expected_hash, 0, NOW()
            )
        ");
        $stmt->execute([
            ':type' => $recordType,
            ':id' => $recordId,
            ':version' => $versionNumber,
            ':message' => $message,
            ':detected_hash' => $detectedHash,
            ':expected_hash' => $expectedHash,
        ]);

        return (int)$this->db->lastInsertId();
    }

    /**
     * Run bulk integrity verification across all patient profile versions and medical record versions.
     */
    public function verifyAll(?int $checkedBy = null, int $limit = 100): array {
        $results = [];

        // 1. Verify Patient Profile Versions
        $patStmt = $this->db->prepare("
            SELECT patient_id, version_number 
            FROM `patient_profile_versions`
            ORDER BY id DESC LIMIT :limit
        ");
        $patStmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $patStmt->execute();
        $patVersions = $patStmt->fetchAll();

        foreach ($patVersions as $pv) {
            $results[] = $this->verifyPatientProfile(
                (int)$pv['patient_id'],
                (int)$pv['version_number'],
                $checkedBy
            );
        }

        // 2. Verify Medical Record Versions
        $mrStmt = $this->db->prepare("
            SELECT medical_record_id, version_number 
            FROM `medical_record_versions`
            ORDER BY id DESC LIMIT :limit
        ");
        $mrStmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $mrStmt->execute();
        $mrVersions = $mrStmt->fetchAll();

        foreach ($mrVersions as $mv) {
            $results[] = $this->verifyMedicalRecord(
                (int)$mv['medical_record_id'],
                (int)$mv['version_number'],
                $checkedBy
            );
        }

        return $results;
    }
}
