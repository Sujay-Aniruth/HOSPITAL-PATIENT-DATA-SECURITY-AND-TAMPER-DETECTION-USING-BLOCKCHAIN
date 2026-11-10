<?php
/**
 * Security Alert Resolution API Endpoint
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

header('Content-Type: application/json; charset=UTF-8');

require_once __DIR__ . '/../../../app/config/config.php';
require_once __DIR__ . '/../../../app/middleware/AuthMiddleware.php';
require_once __DIR__ . '/../../../app/middleware/CsrfMiddleware.php';
require_once __DIR__ . '/../../../app/models/SecurityAlert.php';

$user = AuthMiddleware::requireRole(['admin']);
CsrfMiddleware::requireValid();

$input = json_decode(file_get_contents('php://input'), true);
if (!is_array($input)) {
    $input = $_POST;
}

$alertId = (int)($input['id'] ?? 0);
$note = trim((string)($input['note'] ?? ''));

if ($alertId <= 0) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'Valid alert ID is required.']);
    exit;
}

$alertModel = new SecurityAlert();
$success = $alertModel->resolve($alertId, (int)$user['id'], $note);

echo json_encode([
    'status' => $success ? 'success' : 'error',
    'message' => $success ? 'Security alert resolved successfully.' : 'Failed to resolve alert.',
]);
