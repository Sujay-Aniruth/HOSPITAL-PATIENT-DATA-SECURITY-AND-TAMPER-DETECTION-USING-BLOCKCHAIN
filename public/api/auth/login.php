<?php
/**
 * Authentication Login API Endpoint
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

header('Content-Type: application/json; charset=UTF-8');

require_once __DIR__ . '/../../../app/config/config.php';
require_once __DIR__ . '/../../../app/middleware/AuthMiddleware.php';
require_once __DIR__ . '/../../../app/middleware/CsrfMiddleware.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['status' => 'error', 'message' => 'Method not allowed. Use POST.']);
    exit;
}

$input = json_decode(file_get_contents('php://input'), true);
if (!is_array($input)) {
    $input = $_POST;
}

$identifier = trim((string)($input['identifier'] ?? $input['email'] ?? $input['username'] ?? ''));
$password = (string)($input['password'] ?? '');

if (empty($identifier) || empty($password)) {
    http_response_code(422);
    echo json_encode(['status' => 'error', 'message' => 'Email/username and password are required.']);
    exit;
}

$result = AuthMiddleware::attempt($identifier, $password);

if (!$result['success']) {
    http_response_code(401);
    echo json_encode(['status' => 'error', 'message' => $result['message']]);
    exit;
}

http_response_code(200);
echo json_encode([
    'status' => 'success',
    'message' => 'Login successful.',
    'user' => $result['user'],
    'csrf_token' => CsrfMiddleware::getToken(),
]);
