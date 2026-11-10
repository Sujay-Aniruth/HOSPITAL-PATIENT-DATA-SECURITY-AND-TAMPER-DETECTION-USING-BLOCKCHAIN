<?php
/**
 * Blockchain Live Status & Ledger Explorer API Endpoint
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

header('Content-Type: application/json; charset=UTF-8');

require_once __DIR__ . '/../../../app/config/config.php';
require_once __DIR__ . '/../../../app/middleware/AuthMiddleware.php';
require_once __DIR__ . '/../../../app/services/BlockchainService.php';

AuthMiddleware::requireAuth();

$blockchain = new BlockchainService();
$status = $blockchain->getStatus();
$records = $blockchain->getAllAnchoredRecords();

echo json_encode([
    'status' => 'success',
    'blockchain' => $status,
    'total_anchors' => count($records),
    'records' => $records,
]);
