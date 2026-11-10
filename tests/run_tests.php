<?php
/**
 * Master Automated Test Suite Runner
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

require_once __DIR__ . '/CanonicalHashingTest.php';
require_once __DIR__ . '/BlockchainIntegrationTest.php';
require_once __DIR__ . '/IntegrityVerificationTest.php';
require_once __DIR__ . '/PatientRecordFlowTest.php';

echo "======================================================================\n";
echo " Hospital Patient Data Security and Tamper Detection - Test Suite\n";
echo " Academic Project Verification and Test Report\n";
echo "======================================================================\n";

$startTime = microtime(true);
$totalPassed = 0;
$totalFailed = 0;

$suites = [
    'Canonical Hashing & Test Vectors' => new CanonicalHashingTest(),
    'Blockchain & Smart Contract' => new BlockchainIntegrationTest(),
    'Integrity Verification & Tamper Detection' => new IntegrityVerificationTest(),
    'End-to-End Patient Lifecycle & Amendments' => new PatientRecordFlowTest(),
];

foreach ($suites as $name => $suite) {
    try {
        $result = $suite->run();
        $totalPassed += $result['passed'];
        $totalFailed += $result['failed'];
    } catch (Throwable $e) {
        $totalFailed++;
        echo "  [FATAL ERROR in {$name}]: " . $e->getMessage() . "\n";
        echo "  Stack trace: " . $e->getTraceAsString() . "\n";
    }
}

$elapsed = round(microtime(true) - $startTime, 3);

echo "\n======================================================================\n";
echo " FINAL TEST REPORT\n";
echo " Total Assertions Passed: {$totalPassed}\n";
echo " Total Assertions Failed: {$totalFailed}\n";
echo " Execution Time: {$elapsed} seconds\n";
echo " Overall Status: " . ($totalFailed === 0 ? "ALL TESTS PASSED [SUCCESS]" : "TESTS FAILED [FAILURE]") . "\n";
echo "======================================================================\n";

exit($totalFailed === 0 ? 0 : 1);
