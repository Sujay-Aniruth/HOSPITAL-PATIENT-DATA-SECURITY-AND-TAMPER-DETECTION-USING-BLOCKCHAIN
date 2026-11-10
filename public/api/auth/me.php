<?php
/**
 * Current Session User API Endpoint
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

header('Content-Type: application/json; charset=UTF-8');

require_once __DIR__ . '/../../../app/config/config.php';
require_once __DIR__ . '/../../../app/middleware/AuthMiddleware.php';
require_once __DIR__ . '/../../../app/middleware/CsrfMiddleware.php';

$user = AuthMiddleware::user();

if (!$user) {
    http_response_code(401);
    echo json_encode(['status' => 'unauthenticated', 'user' => null]);
    exit;
}

echo json_encode([
    'status' => 'authenticated',
    'user' => $user,
    'csrf_token' => CsrfMiddleware::getToken(),
]);
