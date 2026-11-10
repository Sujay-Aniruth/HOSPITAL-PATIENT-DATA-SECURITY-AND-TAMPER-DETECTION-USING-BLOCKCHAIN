<?php
/**
 * Integrity Verification & Tamper Detection Tests
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

require_once __DIR__ . '/../app/config/config.php';
require_once __DIR__ . '/../app/config/database.php';
require_once __DIR__ . '/../app/services/IntegrityVerificationService.php';
require_once __DIR__ . '/../app/models/SecurityAlert.php';

class IntegrityVerificationTest {
    private int $passed = 0;
    private int $failed = 0;

    private function assert(bool $condition, string $message): void {
        if ($condition) {
            $this->passed++;
            echo "  [PASS] {$message}\n";
        } else {
            $this->failed++;
            echo "  [FAIL] {$message}\n";
        }
    }

    public function run(): array {
        echo "\n=== Running Integrity Verification & Tamper Detection Suite ===\n";

        $db = Database::getConnection();
        $verifier = new IntegrityVerificationService();
        $alertModel = new SecurityAlert();

        // Test 1: Verify baseline patient profile #1
        $patCheck = $verifier->verifyPatientProfile(1, 1, 1);
        $this->assert($patCheck['result'] === 'VALID', "Patient #1 (v1) verifies as VALID against on-chain anchor");
        $this->assert(!empty($patCheck['calculated_hash']), "Calculated hash returned: " . substr($patCheck['calculated_hash'], 0, 16) . "...");

        // Test 2: Verify baseline medical record #1
        $medCheck = $verifier->verifyMedicalRecord(1, 1, 1);
        $this->assert($medCheck['result'] === 'VALID', "Medical Record #1 (v1) verifies as VALID against on-chain anchor");

        // Test 3: Perform direct MySQL tampering on Medical Record #2
        // Fetch original diagnosis
        $stmt = $db->prepare("SELECT diagnosis FROM `medical_record_versions` WHERE `medical_record_id` = 2 AND `version_number` = 1");
        $stmt->execute();
        $origDiagnosis = $stmt->fetchColumn();

        // Alter diagnosis in MySQL without updating on-chain anchor
        $db->prepare("UPDATE `medical_record_versions` SET `diagnosis` = 'MALICIOUS_ALTERATION_TEST' WHERE `medical_record_id` = 2 AND `version_number` = 1")->execute();

        // Test 4: Run verification on tampered record
        $tamperedCheck = $verifier->verifyMedicalRecord(2, 1, 1);
        $this->assert($tamperedCheck['result'] === 'TAMPERED', "Direct database modification was detected as TAMPERED");
        $this->assert($tamperedCheck['calculated_hash'] !== $tamperedCheck['blockchain_hash'], "Calculated hash does not match immutable on-chain anchor");

        // Test 5: Verify security alert was triggered
        $activeAlerts = $alertModel->getActive(10);
        $hasAlert = false;
        foreach ($activeAlerts as $a) {
            if ($a['record_type'] === 'MEDICAL_RECORD' && (int)$a['record_id'] === 2 && (int)$a['version_number'] === 1) {
                $hasAlert = true;
                break;
            }
        }
        $this->assert($hasAlert, "Security alert automatically registered in security_alerts table");

        // Test 6: Restore pristine diagnosis and re-verify returns VALID
        $db->prepare("UPDATE `medical_record_versions` SET `diagnosis` = :orig WHERE `medical_record_id` = 2 AND `version_number` = 1")
           ->execute([':orig' => $origDiagnosis]);

        $restoredCheck = $verifier->verifyMedicalRecord(2, 1, 1);
        $this->assert($restoredCheck['result'] === 'VALID', "Restoring original database content returns status to VALID");

        return ['passed' => $this->passed, 'failed' => $this->failed];
    }
}
