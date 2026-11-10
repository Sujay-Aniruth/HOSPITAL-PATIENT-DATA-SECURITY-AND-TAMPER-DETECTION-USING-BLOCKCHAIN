<?php
/**
 * Dashboard Controller
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../models/IntegrityCheck.php';
require_once __DIR__ . '/../models/SecurityAlert.php';
require_once __DIR__ . '/../services/BlockchainService.php';
require_once __DIR__ . '/../middleware/AuthMiddleware.php';

class DashboardController {
    public function getStats(): array {
        AuthMiddleware::requireAuth();
        $db = Database::getConnection();

        $patCount = (int)$db->query("SELECT COUNT(*) FROM `patients`")->fetchColumn();
        $recCount = (int)$db->query("SELECT COUNT(*) FROM `medical_records`")->fetchColumn();
        $encCount = (int)$db->query("SELECT COUNT(*) FROM `encounters`")->fetchColumn();
        $userCount = (int)$db->query("SELECT COUNT(*) FROM `users`")->fetchColumn();

        $checkModel = new IntegrityCheck();
        $checkStats = $checkModel->getStats();

        $alertModel = new SecurityAlert();
        $activeAlerts = $alertModel->countUnresolved();

        $blockchain = new BlockchainService();
        $nodeStatus = $blockchain->getStatus();

        return [
            'metrics' => [
                'total_patients' => $patCount,
                'total_medical_records' => $recCount,
                'total_encounters' => $encCount,
                'total_users' => $userCount,
                'active_alerts' => $activeAlerts,
                'valid_checks' => $checkStats['valid_count'],
                'tampered_checks' => $checkStats['tampered_count'],
            ],
            'blockchain' => $nodeStatus,
        ];
    }
}
