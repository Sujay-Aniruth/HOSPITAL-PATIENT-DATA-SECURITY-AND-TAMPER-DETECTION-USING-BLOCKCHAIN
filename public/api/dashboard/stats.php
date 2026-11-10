<?php
/**
 * Dashboard Metrics and Chart Data API Endpoint
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

header('Content-Type: application/json; charset=UTF-8');

require_once __DIR__ . '/../../../app/config/config.php';
require_once __DIR__ . '/../../../app/config/database.php';
require_once __DIR__ . '/../../../app/middleware/AuthMiddleware.php';
require_once __DIR__ . '/../../../app/models/IntegrityCheck.php';
require_once __DIR__ . '/../../../app/models/SecurityAlert.php';
require_once __DIR__ . '/../../../app/services/BlockchainService.php';

AuthMiddleware::requireAuth();

$db = Database::getConnection();

// 1. Core entity counts
$patCount = (int)$db->query("SELECT COUNT(*) FROM `patients`")->fetchColumn();
$recCount = (int)$db->query("SELECT COUNT(*) FROM `medical_records`")->fetchColumn();
$encCount = (int)$db->query("SELECT COUNT(*) FROM `encounters`")->fetchColumn();
$userCount = (int)$db->query("SELECT COUNT(*) FROM `users`")->fetchColumn();

// 2. Anchored versions
$anchoredPatVersions = (int)$db->query("SELECT COUNT(*) FROM `patient_profile_versions` WHERE `anchor_status` = 'ANCHORED'")->fetchColumn();
$anchoredMedVersions = (int)$db->query("SELECT COUNT(*) FROM `medical_record_versions` WHERE `anchor_status` = 'ANCHORED'")->fetchColumn();
$totalAnchoredVersions = $anchoredPatVersions + $anchoredMedVersions;

$pendingPatVersions = (int)$db->query("SELECT COUNT(*) FROM `patient_profile_versions` WHERE `anchor_status` = 'PENDING'")->fetchColumn();
$pendingMedVersions = (int)$db->query("SELECT COUNT(*) FROM `medical_record_versions` WHERE `anchor_status` = 'PENDING'")->fetchColumn();
$totalPendingVersions = $pendingPatVersions + $pendingMedVersions;

// 3. Verification stats
$checkModel = new IntegrityCheck();
$checkStats = $checkModel->getStats();

// 4. Security alerts
$alertModel = new SecurityAlert();
$activeAlertCount = $alertModel->countUnresolved();
$recentAlerts = $alertModel->getActive(10);

// 5. Blockchain status
$blockchain = new BlockchainService();
$blockchainStatus = $blockchain->getStatus();

// 6. Chart data: integrity check outcomes
$chartOutcomes = [
    'labels' => ['VALID', 'TAMPERED', 'PENDING', 'MISSING_ANCHOR', 'ERROR'],
    'data' => [
        $checkStats['valid_count'],
        $checkStats['tampered_count'],
        $checkStats['pending_count'],
        $checkStats['missing_anchor_count'],
        $checkStats['error_count'],
    ],
];

// 7. Recent integrity checks
$recentChecks = $checkModel->getRecent(10);

echo json_encode([
    'status' => 'success',
    'metrics' => [
        'total_patients' => $patCount,
        'total_medical_records' => $recCount,
        'total_encounters' => $encCount,
        'total_users' => $userCount,
        'anchored_versions' => $totalAnchoredVersions,
        'pending_versions' => $totalPendingVersions,
        'active_alerts' => $activeAlertCount,
        'total_checks' => $checkStats['total_checks'],
        'valid_checks' => $checkStats['valid_count'],
        'tampered_checks' => $checkStats['tampered_count'],
    ],
    'blockchain' => $blockchainStatus,
    'chart_outcomes' => $chartOutcomes,
    'recent_alerts' => $recentAlerts,
    'recent_checks' => $recentChecks,
]);
