<?php
/**
 * Health Check API Endpoint
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

header('Content-Type: application/json; charset=UTF-8');

require_once __DIR__ . '/../../app/config/config.php';
require_once __DIR__ . '/../../app/config/database.php';
require_once __DIR__ . '/../../app/services/BlockchainService.php';

try {
    // Check MySQL
    $db = Database::getConnection();
    $db->query("SELECT 1");
    $dbStatus = 'healthy';
} catch (Throwable $e) {
    $dbStatus = 'unhealthy: ' . $e->getMessage();
}

// Check Blockchain
$blockchain = new BlockchainService();
$chainStatus = $blockchain->getStatus();

$allHealthy = ($dbStatus === 'healthy' && !empty($chainStatus['connected']));

http_response_code($allHealthy ? 200 : 503);
echo json_encode([
    'status' => $allHealthy ? 'ok' : 'degraded',
    'timestamp' => date('c'),
    'app_name' => config('APP_NAME'),
    'environment' => config('APP_ENV', 'local'),
    'database' => $dbStatus,
    'blockchain' => $chainStatus,
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
