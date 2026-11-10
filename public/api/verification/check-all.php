<?php
/**
 * Bulk Integrity Verification API Endpoint
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

header('Content-Type: application/json; charset=UTF-8');

require_once __DIR__ . '/../../../app/config/config.php';
require_once __DIR__ . '/../../../app/middleware/AuthMiddleware.php';
require_once __DIR__ . '/../../../app/middleware/CsrfMiddleware.php';
require_once __DIR__ . '/../../../app/services/IntegrityVerificationService.php';

$user = AuthMiddleware::requireAuth();
CsrfMiddleware::requireValid();

$limit = min(200, max(1, (int)($_POST['limit'] ?? $_GET['limit'] ?? 100)));

$verifier = new IntegrityVerificationService();
$results = $verifier->verifyAll((int)$user['id'], $limit);

$counts = [
    'total' => count($results),
    'valid' => 0,
    'tampered' => 0,
    'pending' => 0,
    'missing_anchor' => 0,
    'error' => 0,
];

foreach ($results as $r) {
    $res = strtolower($r['result'] ?? 'error');
    if (isset($counts[$res])) {
        $counts[$res]++;
    }
}

echo json_encode([
    'status' => 'success',
    'summary' => $counts,
    'results' => $results,
]);
