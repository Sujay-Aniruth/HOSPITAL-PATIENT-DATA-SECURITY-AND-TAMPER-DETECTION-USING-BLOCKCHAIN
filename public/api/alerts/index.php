<?php
/**
 * Security Alerts List API Endpoint
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

header('Content-Type: application/json; charset=UTF-8');

require_once __DIR__ . '/../../../app/config/config.php';
require_once __DIR__ . '/../../../app/middleware/AuthMiddleware.php';
require_once __DIR__ . '/../../../app/models/SecurityAlert.php';

AuthMiddleware::requireAuth();

$activeOnly = isset($_GET['active']) && $_GET['active'] === '1';
$limit = min(200, max(1, (int)($_GET['limit'] ?? 50)));

$alertModel = new SecurityAlert();
$alerts = $activeOnly ? $alertModel->getActive($limit) : $alertModel->getAll($limit);

echo json_encode([
    'status' => 'success',
    'count' => count($alerts),
    'data' => $alerts,
]);
