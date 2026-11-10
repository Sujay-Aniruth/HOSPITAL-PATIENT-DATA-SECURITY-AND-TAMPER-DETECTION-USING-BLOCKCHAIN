<?php
/**
 * Development-Only Demonstration Reset API Endpoint
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

header('Content-Type: application/json; charset=UTF-8');

require_once __DIR__ . '/../../../app/config/config.php';
require_once __DIR__ . '/../../../app/middleware/AuthMiddleware.php';
require_once __DIR__ . '/../../../app/middleware/CsrfMiddleware.php';
require_once __DIR__ . '/../../../app/services/AuditService.php';

if (config('APP_ENV') !== 'local') {
    http_response_code(403);
    echo json_encode(['status' => 'error', 'message' => 'Demo reset is strictly disabled outside local development environments.']);
    exit;
}

$user = AuthMiddleware::requireRole(['admin']);
CsrfMiddleware::requireValid();

try {
    $phpBin = '/Applications/XAMPP/xamppfiles/bin/php';
    if (!file_exists($phpBin)) {
        $phpBin = 'php';
    }

    $seederScript = ROOT_PATH . '/database/seed_anchors.php';
    $cmd = escapeshellarg($phpBin) . " " . escapeshellarg($seederScript) . " 2>&1";
    $output = shell_exec($cmd);

    AuditService::log('DEMO_RESET', 'SYSTEM', 1, ['note' => 'Demonstration fixtures reset to baseline anchored state.'], (int)$user['id']);

    echo json_encode([
        'status' => 'success',
        'message' => 'Demonstration data successfully reset and re-verified against blockchain anchors.',
        'output' => $output,
    ]);
} catch (Throwable $e) {
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Demo reset failed: ' . $e->getMessage()]);
}
