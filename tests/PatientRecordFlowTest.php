<?php
/**
 * End-to-End Patient and Clinical Record Lifecycle Tests
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

require_once __DIR__ . '/../app/config/config.php';
require_once __DIR__ . '/../app/models/Patient.php';
require_once __DIR__ . '/../app/models/Encounter.php';
require_once __DIR__ . '/../app/models/MedicalRecord.php';
require_once __DIR__ . '/../app/services/IntegrityVerificationService.php';

class PatientRecordFlowTest {
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
        echo "\n=== Running Patient & Clinical Record Lifecycle Suite ===\n";

        $patientModel = new Patient();
        $encounterModel = new Encounter();
        $recordModel = new MedicalRecord();
        $verifier = new IntegrityVerificationService();

        // 1. Create a new test patient
        $testCode = 'PAT-TEST-' . rand(100, 999);
        $patRes = $patientModel->create([
            'patient_code' => $testCode,
            'name' => 'Automated Test Patient',
            'date_of_birth' => '1995-10-10',
            'gender' => 'Other',
            'phone' => '+91-9999900000',
            'address' => '789 Testing Blvd, Lab City',
            'emergency_contact' => 'Emergency Proxy - 9999911111',
        ], 1);

        $patientId = $patRes['patient_id'];
        $this->assert($patientId > 0, "Patient {$testCode} created with ID #{$patientId}");
        $this->assert($patRes['version'] === 1, "Initial profile version set to 1");

        // Verify patient v1 on-chain
        $patCheck = $verifier->verifyPatientProfile($patientId, 1, 1);
        $this->assert($patCheck['result'] === 'VALID', "Patient #{$patientId} v1 verified as VALID on blockchain");

        // 2. Create Encounter
        $encId = $encounterModel->create($patientId, 2, date('Y-m-d H:i:s'), 'Initial Diagnostic Intake');
        $this->assert($encId > 0, "Encounter created with ID #{$encId}");

        // 3. Create Clinical Medical Record (Version 1)
        $recRes = $recordModel->create($patientId, $encId, [
            'symptoms' => 'Mild cephalalgia and asthenia',
            'diagnosis' => 'Tension-type Headache',
            'notes' => 'Neurological exam normal.',
            'prescription' => 'Paracetamol 500mg PRN',
            'treatment_plan' => 'Hydration and rest',
        ], 2);

        $recordId = $recRes['medical_record_id'];
        $this->assert($recordId > 0, "Medical Record created with ID #{$recordId}");
        $this->assert($recRes['version'] === 1, "Initial clinical version set to 1");

        // Verify record v1 on-chain
        $recCheckV1 = $verifier->verifyMedicalRecord($recordId, 1, 1);
        $this->assert($recCheckV1['result'] === 'VALID', "Record #{$recordId} (v1) verified as VALID on blockchain");

        // 4. Authorized Clinical Amendment (creates Version 2)
        $amendRes = $recordModel->amend($recordId, [
            'symptoms' => 'Mild cephalalgia with neck soreness',
            'diagnosis' => 'Cervicogenic Headache with Muscle Spasm',
            'notes' => 'Cervical paraspinal tenderness observed.',
            'prescription' => 'Paracetamol 500mg + Thiocolchicoside 4mg BD x 3 days',
            'treatment_plan' => 'Physical therapy review',
        ], 2);

        $this->assert($amendRes['new_version'] === 2, "Authorized amendment created Version 2");

        // 5. Verify that BOTH versions (v1 and v2) are simultaneously VALID on the blockchain!
        $verifyV1Again = $verifier->verifyMedicalRecord($recordId, 1, 1);
        $verifyV2 = $verifier->verifyMedicalRecord($recordId, 2, 1);

        $this->assert($verifyV1Again['result'] === 'VALID', "Historical Version 1 remains VALID and un-overwritten on chain");
        $this->assert($verifyV2['result'] === 'VALID', "Amended Version 2 is independently anchored and VALID on chain");
        $this->assert($verifyV1Again['blockchain_hash'] !== $verifyV2['blockchain_hash'], "v1 and v2 have distinct immutable cryptographic hash proofs");

        return ['passed' => $this->passed, 'failed' => $this->failed];
    }
}
