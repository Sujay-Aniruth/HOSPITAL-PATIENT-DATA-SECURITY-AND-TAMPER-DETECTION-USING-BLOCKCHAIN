<?php
/**
 * Authentication Logout API Endpoint
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

header('Content-Type: application/json; charset=UTF-8');

require_once __DIR__ . '/../../../app/config/config.php';
require_once __DIR__ . '/../../../app/middleware/AuthMiddleware.php';

AuthMiddleware::logout();

echo json_encode([
    'status' => 'success',
    'message' => 'Logged out successfully.'
]);
