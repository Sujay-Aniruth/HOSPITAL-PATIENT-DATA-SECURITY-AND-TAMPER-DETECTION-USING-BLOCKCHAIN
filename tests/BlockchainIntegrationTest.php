<?php
/**
 * Blockchain Smart Contract Integration Tests
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

require_once __DIR__ . '/../app/config/config.php';
require_once __DIR__ . '/../app/services/BlockchainService.php';

class BlockchainIntegrationTest {
    private int $passed = 0;
    private int $failed = 0;

    private function assert(bool $condition, string $message): void {
        if ($condition) {
            $this->passed++;
            echo "  [PASS] {$message}\n";
        } else {
            $this->failed++;
            echo "  [FAIL] {$message}\n";
        }
    }

    public function run(): array {
        echo "\n=== Running Blockchain & Smart Contract Suite ===\n";

        $blockchain = new BlockchainService();
        $status = $blockchain->getStatus();

        // Test 1: Node connectivity
        $this->assert(!empty($status['connected']), "Local Ethereum node connection active at {$status['rpcUrl']}");
        $this->assert(!empty($status['contractDeployed']), "HospitalRecordIntegrity contract deployed at {$status['contractAddress']}");
        $this->assert($status['blockNumber'] > 0, "Current EVM block height is #{$status['blockNumber']}");

        // Test 2: Store unique test hash
        $uniqueId = rand(10000, 99999);
        $testHash = '0x' . hash('sha256', 'test_payload_' . $uniqueId);
        $tx = $blockchain->storeRecordHash('TEST_INTEGRATION', $uniqueId, 1, $testHash);
        $this->assert(!empty($tx['transactionHash']), "Transaction confirmed with hash {$tx['transactionHash']}");
        $this->assert($tx['blockNumber'] > 0, "Mined in block #{$tx['blockNumber']}");

        // Test 3: Query anchored hash from contract
        $record = $blockchain->getRecordHash('TEST_INTEGRATION', $uniqueId, 1);
        $this->assert(!empty($record['exists']), "hashExists confirms record is anchored on blockchain");
        $this->assert(strtolower($record['hash']) === strtolower($testHash), "On-chain hash exactly matches stored SHA-256");
        $this->assert($record['timestamp'] > 0, "Block timestamp recorded ({$record['timestamp']})");
        $this->assert(!empty($record['anchoredBy']), "Anchoring signer recorded ({$record['anchoredBy']})");

        // Test 4: Duplicate anchor prevention
        $duplicateRejected = false;
        try {
            $blockchain->storeRecordHash('TEST_INTEGRATION', $uniqueId, 1, $testHash);
        } catch (Throwable $e) {
            $duplicateRejected = true;
        }
        $this->assert($duplicateRejected, "Contract reverts on duplicate anchor attempt for same (recordType, id, version)");

        // Test 5: Rejection of zero hash
        $zeroHashRejected = false;
        try {
            $blockchain->storeRecordHash('TEST_INTEGRATION', $uniqueId, 2, '0x' . str_repeat('0', 64));
        } catch (Throwable $e) {
            $zeroHashRejected = true;
        }
        $this->assert($zeroHashRejected, "Contract reverts on zero bytes32 hash attempt");

        return ['passed' => $this->passed, 'failed' => $this->failed];
    }
}
