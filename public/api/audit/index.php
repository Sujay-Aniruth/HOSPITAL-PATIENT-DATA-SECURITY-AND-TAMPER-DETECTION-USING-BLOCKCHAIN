<?php
/**
 * Audit Logs List API Endpoint
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

header('Content-Type: application/json; charset=UTF-8');

require_once __DIR__ . '/../../../app/config/config.php';
require_once __DIR__ . '/../../../app/middleware/AuthMiddleware.php';
require_once __DIR__ . '/../../../app/services/AuditService.php';

AuthMiddleware::requireRole(['admin']);

$limit = min(200, max(1, (int)($_GET['limit'] ?? 50)));
$type = !empty($_GET['type']) ? trim((string)$_GET['type']) : null;

$logs = AuditService::getRecentLogs($limit, $type);

echo json_encode([
    'status' => 'success',
    'count' => count($logs),
    'data' => $logs,
]);
