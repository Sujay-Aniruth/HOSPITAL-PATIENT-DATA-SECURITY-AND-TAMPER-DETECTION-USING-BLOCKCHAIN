<?php
/**
 * Blockchain Anchor Seeder Script
 * Hospital Patient Data Security and Tamper Detection
 * 
 * Computes canonical SHA-256 hashes for fictional demonstration patients and clinical
 * records and anchors them to the local blockchain contract.
 */

declare(strict_types=1);

require_once __DIR__ . '/../app/config/config.php';
require_once __DIR__ . '/../app/config/database.php';
require_once __DIR__ . '/../app/services/CanonicalHashingService.php';
require_once __DIR__ . '/../app/services/BlockchainService.php';
require_once __DIR__ . '/../app/services/IntegrityVerificationService.php';

echo "=========================================================\n";
echo " Seeding Canonical Hashes & Anchoring Initial Records\n";
echo "=========================================================\n";

$db = Database::getConnection();
$blockchain = new BlockchainService();
$status = $blockchain->getStatus();

if (!$status['connected'] || !$status['contractDeployed']) {
    echo "ERROR: Blockchain node or contract not available.\n";
    print_r($status);
    exit(1);
}

echo "Connected to blockchain at {$status['rpcUrl']}\n";
echo "Contract address: {$status['contractAddress']}\n\n";

// 1. Anchor Patient Profiles (v1)
$patients = $db->query("SELECT * FROM `patients` ORDER BY id ASC")->fetchAll();
foreach ($patients as $pat) {
    $patientId = (int)$pat['id'];
    echo "Processing Patient #{$patientId} ({$pat['patient_code']}: {$pat['name']})...\n";

    $hashData = CanonicalHashingService::canonicalizePatientProfile($pat, 1);
    $sha256 = $hashData['sha256_hash'];

    // Check if version 1 row exists
    $stmt = $db->prepare("SELECT * FROM `patient_profile_versions` WHERE `patient_id` = :id AND `version_number` = 1");
    $stmt->execute([':id' => $patientId]);
    $verRow = $stmt->fetch();

    if (!$verRow) {
        $ins = $db->prepare("
            INSERT INTO `patient_profile_versions` (
                `patient_id`, `version_number`, `patient_code`, `name`, `date_of_birth`, `gender`, `phone`, `address`, `emergency_contact`,
                `canonical_json`, `sha256_hash`, `anchor_status`, `created_by`, `created_at`
            ) VALUES (
                :id, 1, :code, :name, :dob, :gender, :phone, :address, :emergency,
                :json, :hash, 'PENDING', :created_by, NOW()
            )
        ");
        $ins->execute([
            ':id' => $patientId,
            ':code' => $pat['patient_code'],
            ':name' => $pat['name'],
            ':dob' => $pat['date_of_birth'],
            ':gender' => $pat['gender'],
            ':phone' => $pat['phone'],
            ':address' => $pat['address'],
            ':emergency' => $pat['emergency_contact'],
            ':json' => $hashData['canonical_json'],
            ':hash' => $sha256,
            ':created_by' => $pat['created_by'],
        ]);
    } else {
        $versionId = (int)$verRow['id'];
        $db->prepare("
            UPDATE `patient_profile_versions`
            SET `name` = :name, `date_of_birth` = :dob, `gender` = :gender,
                `phone` = :phone, `address` = :address, `emergency_contact` = :emergency,
                `canonical_json` = :json, `sha256_hash` = :hash
            WHERE `id` = :id
        ")->execute([
            ':name' => $pat['name'],
            ':dob' => $pat['date_of_birth'],
            ':gender' => $pat['gender'],
            ':phone' => $pat['phone'],
            ':address' => $pat['address'],
            ':emergency' => $pat['emergency_contact'],
            ':json' => $hashData['canonical_json'],
            ':hash' => $sha256,
            ':id' => $versionId,
        ]);
    }

    // Check if on-chain
    $existsOnChain = $blockchain->hashExists(CanonicalHashingService::TYPE_PATIENT_PROFILE, $patientId, 1);
    if (!$existsOnChain) {
        echo "  -> Anchoring on blockchain...\n";
        try {
            $tx = $blockchain->storeRecordHash(CanonicalHashingService::TYPE_PATIENT_PROFILE, $patientId, 1, $sha256);
            $db->prepare("
                UPDATE `patient_profile_versions`
                SET `anchor_status` = 'ANCHORED', `transaction_hash` = :tx, `block_number` = :blk, `anchored_at` = NOW()
                WHERE `id` = :id
            ")->execute([':tx' => $tx['transactionHash'], ':blk' => $tx['blockNumber'], ':id' => $versionId]);
            echo "  -> ANCHORED: Tx {$tx['transactionHash']}, Block {$tx['blockNumber']}\n";
        } catch (Throwable $e) {
            echo "  -> Error anchoring: " . $e->getMessage() . "\n";
        }
    } else {
        echo "  -> Already anchored on blockchain.\n";
    }
}

// 2. Anchor Sample Medical Records
$clinicalData = [
    1 => [
        'symptoms' => 'Fatigue, excessive thirst, blurred vision',
        'diagnosis' => 'Type 2 Diabetes Mellitus with Mild Hypertension',
        'notes' => 'Fasting blood sugar 168 mg/dL. BP 138/88 mmHg. Advised dietary control and 30 min daily walking.',
        'prescription' => 'Metformin 500mg BD after meals; Telmisartan 40mg OD morning.',
        'treatment_plan' => 'Review after 4 weeks with HbA1c test and daily fasting glucose log.',
    ],
    2 => [
        'symptoms' => 'Low grade fever, dry cough for 7 days, chest tightness',
        'diagnosis' => 'Acute Bronchitis (Non-specific)',
        'notes' => 'Bilateral rhonchi present on auscultation. SpO2 98% on room air.',
        'prescription' => 'Azithromycin 500mg OD x 5 days; Levocetirizine + Montelukast OD at bedtime.',
        'treatment_plan' => 'Steam inhalation twice daily. Review if fever persists beyond 3 days.',
    ],
    3 => [
        'symptoms' => 'Swelling and joint pain in right knee, difficulty bearing weight',
        'diagnosis' => 'Right Knee Medial Meniscus Grade 1 Strain',
        'notes' => 'No effusion. McMurray test mildly positive. X-ray rules out bony fracture.',
        'prescription' => 'Aceclofenac 100mg + Paracetamol 325mg BD x 5 days; Pantoprazole 40mg OD before breakfast.',
        'treatment_plan' => 'RICE protocol (Rest, Ice, Compression, Elevation). Physiotherapy consultation in 1 week.',
    ],
];

$records = $db->query("
    SELECT mr.*, e.doctor_id 
    FROM `medical_records` mr 
    JOIN `encounters` e ON mr.encounter_id = e.id 
    ORDER BY mr.id ASC
")->fetchAll();

foreach ($records as $rec) {
    $recId = (int)$rec['id'];
    echo "\nProcessing Medical Record #{$recId} (Patient #{$rec['patient_id']})...\n";

    $sample = $clinicalData[$recId] ?? [
        'symptoms' => 'General malaise',
        'diagnosis' => 'Observation',
        'notes' => 'Stable',
        'prescription' => 'None',
        'treatment_plan' => 'Observation',
    ];

    $payload = [
        'medical_record_id' => $recId,
        'patient_id' => (int)$rec['patient_id'],
        'encounter_id' => (int)$rec['encounter_id'],
        'doctor_id' => (int)$rec['doctor_id'],
        'symptoms' => $sample['symptoms'],
        'diagnosis' => $sample['diagnosis'],
        'notes' => $sample['notes'],
        'prescription' => $sample['prescription'],
        'treatment_plan' => $sample['treatment_plan'],
    ];

    $hashData = CanonicalHashingService::canonicalizeMedicalRecord($payload, 1);
    $sha256 = $hashData['sha256_hash'];

    $stmt = $db->prepare("SELECT * FROM `medical_record_versions` WHERE `medical_record_id` = :id AND `version_number` = 1");
    $stmt->execute([':id' => $recId]);
    $verRow = $stmt->fetch();

    if (!$verRow) {
        $ins = $db->prepare("
            INSERT INTO `medical_record_versions` (
                `medical_record_id`, `version_number`, `symptoms`, `diagnosis`, `notes`, `prescription`, `treatment_plan`,
                `canonical_json`, `sha256_hash`, `anchor_status`, `created_by`, `created_at`
            ) VALUES (
                :id, 1, :symptoms, :diagnosis, :notes, :prescription, :treatment,
                :json, :hash, 'PENDING', 2, NOW()
            )
        ");
        $ins->execute([
            ':id' => $recId,
            ':symptoms' => $sample['symptoms'],
            ':diagnosis' => $sample['diagnosis'],
            ':notes' => $sample['notes'],
            ':prescription' => $sample['prescription'],
            ':treatment' => $sample['treatment_plan'],
            ':json' => $hashData['canonical_json'],
            ':hash' => $sha256,
        ]);
    } else {
        $versionId = (int)$verRow['id'];
        $db->prepare("
            UPDATE `medical_record_versions`
            SET `symptoms` = :symptoms, `diagnosis` = :diagnosis, `notes` = :notes,
                `prescription` = :prescription, `treatment_plan` = :treatment,
                `canonical_json` = :json, `sha256_hash` = :hash
            WHERE `id` = :id
        ")->execute([
            ':symptoms' => $sample['symptoms'],
            ':diagnosis' => $sample['diagnosis'],
            ':notes' => $sample['notes'],
            ':prescription' => $sample['prescription'],
            ':treatment' => $sample['treatment_plan'],
            ':json' => $hashData['canonical_json'],
            ':hash' => $sha256,
            ':id' => $versionId,
        ]);
    }

    $existsOnChain = $blockchain->hashExists(CanonicalHashingService::TYPE_MEDICAL_RECORD, $recId, 1);
    if (!$existsOnChain) {
        echo "  -> Anchoring on blockchain...\n";
        try {
            $tx = $blockchain->storeRecordHash(CanonicalHashingService::TYPE_MEDICAL_RECORD, $recId, 1, $sha256);
            $db->prepare("
                UPDATE `medical_record_versions`
                SET `anchor_status` = 'ANCHORED', `transaction_hash` = :tx, `block_number` = :blk, `anchored_at` = NOW()
                WHERE `id` = :id
            ")->execute([':tx' => $tx['transactionHash'], ':blk' => $tx['blockNumber'], ':id' => $versionId]);
            echo "  -> ANCHORED: Tx {$tx['transactionHash']}, Block {$tx['blockNumber']}\n";
        } catch (Throwable $e) {
            echo "  -> Error anchoring: " . $e->getMessage() . "\n";
        }
    } else {
        echo "  -> Already anchored on blockchain.\n";
    }
}

// 3. Clear outstanding test alerts
$db->query("UPDATE `security_alerts` SET `resolved` = 1, `resolved_at` = NOW() WHERE `resolved` = 0");

// 4. Run verification check
echo "\n--- Running Baseline Integrity Verification ---\n";
$verifier = new IntegrityVerificationService($blockchain);
$results = $verifier->verifyAll(1);
foreach ($results as $r) {
    echo "{$r['record_type']} #{$r['record_id']} (v{$r['version']}): [{$r['result']}] - {$r['calculated_hash']}\n";
}

echo "\nSeeding & baseline verification completed successfully!\n";
