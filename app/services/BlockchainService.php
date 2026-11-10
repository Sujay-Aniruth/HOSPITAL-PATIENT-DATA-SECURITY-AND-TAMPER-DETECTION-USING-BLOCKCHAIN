<?php
/**
 * Blockchain Service
 * Hospital Patient Data Security and Tamper Detection
 * 
 * Provides EVM JSON-RPC communication and cryptographic anchor management.
 * Supports direct JSON-RPC interaction with unlocked local node accounts
 * as well as external signer bridge integration.
 */

declare(strict_types=1);

require_once __DIR__ . '/../config/config.php';

class BlockchainService {
    private string $rpcUrl;
    private string $contractAddress;
    private string $signerAccount;
    private string $mode;
    private bool $enabled;

    // Precomputed Solidity function selectors (from keccak-256)
    private const SELECTOR_STORE_RECORD_HASH = '85f8b8e3'; // storeRecordHash(string,uint256,uint256,bytes32)
    private const SELECTOR_GET_RECORD_HASH   = 'e2eb7d31'; // getRecordHash(string,uint256,uint256)
    private const SELECTOR_HASH_EXISTS       = '3936dc7a'; // hashExists(string,uint256,uint256)
    private const SELECTOR_TOTAL_RECORDS     = 'ee188b3f'; // totalAnchoredRecords()
    private const SELECTOR_GET_AT_INDEX      = 'c0a469fb'; // getRecordAtIndex(uint256)

    public function __construct() {
        $this->rpcUrl = config('RPC_URL', 'http://127.0.0.1:8545');
        $this->signerAccount = config('SIGNER_ACCOUNT', '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266');
        $this->mode = config('BLOCKCHAIN_MODE', 'direct');
        $this->enabled = filter_var(config('USE_BLOCKCHAIN', true), FILTER_VALIDATE_BOOLEAN);

        // Load contract address from .env or deployed-contract.json
        $contractAddr = config('CONTRACT_ADDRESS', '');
        if (empty($contractAddr)) {
            $jsonFile = ROOT_PATH . '/app/config/contract.json';
            if (file_exists($jsonFile)) {
                $info = json_decode(file_get_contents($jsonFile), true);
                $contractAddr = $info['address'] ?? '';
            }
        }
        $this->contractAddress = $contractAddr;
    }

    public function isEnabled(): bool {
        return $this->enabled;
    }

    public function getContractAddress(): string {
        return $this->contractAddress;
    }

    /**
     * Send raw JSON-RPC HTTP request to Ethereum node.
     */
    public function callRpc(string $method, array $params = []): array {
        $payload = json_encode([
            'jsonrpc' => '2.0',
            'id' => time() + rand(1, 10000),
            'method' => $method,
            'params' => $params,
        ]);

        $ch = curl_init($this->rpcUrl);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);

        $response = curl_exec($ch);
        $curlError = curl_error($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($curlError) {
            throw new RuntimeException("Blockchain RPC connection failed: {$curlError}. Ensure Hardhat node is running.");
        }
        if ($httpCode !== 200) {
            throw new RuntimeException("Blockchain RPC returned HTTP code {$httpCode}: {$response}");
        }

        $decoded = json_decode($response, true);
        if ($decoded === null) {
            throw new RuntimeException("Failed to decode blockchain RPC response: {$response}");
        }
        if (isset($decoded['error'])) {
            $msg = $decoded['error']['message'] ?? json_encode($decoded['error']);
            throw new RuntimeException("Blockchain RPC error: {$msg}");
        }

        return $decoded;
    }

    /**
     * Check connection status to blockchain and smart contract.
     */
    public function getStatus(): array {
        try {
            $res = $this->callRpc('eth_blockNumber');
            $blockNumber = hexdec($res['result']);

            $contractCode = '0x';
            $deployed = false;
            $totalAnchored = 0;

            if (!empty($this->contractAddress)) {
                $codeRes = $this->callRpc('eth_getCode', [$this->contractAddress, 'latest']);
                $contractCode = $codeRes['result'] ?? '0x';
                $deployed = ($contractCode !== '0x' && $contractCode !== '0x0');

                if ($deployed) {
                    try {
                        $totalAnchored = $this->getTotalAnchoredRecords();
                    } catch (Throwable) {
                        $totalAnchored = 0;
                    }
                }
            }

            return [
                'status' => 'connected',
                'connected' => true,
                'blockNumber' => $blockNumber,
                'contractAddress' => $this->contractAddress,
                'contractDeployed' => $deployed,
                'totalAnchored' => $totalAnchored,
                'rpcUrl' => $this->rpcUrl,
                'mode' => $this->mode,
            ];
        } catch (Throwable $e) {
            return [
                'status' => 'disconnected',
                'connected' => false,
                'error' => $e->getMessage(),
                'contractAddress' => $this->contractAddress,
                'contractDeployed' => false,
                'rpcUrl' => $this->rpcUrl,
                'mode' => $this->mode,
            ];
        }
    }

    /**
     * Store record hash on the blockchain.
     * Uses direct JSON-RPC or node bridge depending on configuration.
     */
    public function storeRecordHash(string $recordType, int $recordId, int $version, string $hash): array {
        if (!$this->enabled) {
            throw new RuntimeException("Blockchain anchoring is disabled in configuration.");
        }
        if (empty($this->contractAddress)) {
            throw new RuntimeException("Contract address not configured. Please deploy the smart contract first.");
        }

        // Clean and validate hash format
        $cleanHash = trim($hash);
        if (!str_starts_with($cleanHash, '0x')) {
            $cleanHash = '0x' . $cleanHash;
        }
        if (strlen($cleanHash) !== 66) {
            throw new InvalidArgumentException("Invalid hash format for bytes32: {$cleanHash}");
        }

        // Bridge mode execution if selected
        if ($this->mode === 'bridge') {
            return $this->storeViaBridge($recordType, $recordId, $version, $cleanHash);
        }

        // Direct JSON-RPC execution via unlocked local node account
        return $this->storeViaRpc($recordType, $recordId, $version, $cleanHash);
    }

    /**
     * Store via direct eth_sendTransaction RPC call.
     */
    private function storeViaRpc(string $recordType, int $recordId, int $version, string $hash): array {
        $calldata = $this->encodeStoreRecordHashCalldata($recordType, $recordId, $version, $hash);

        $txParams = [
            'from' => $this->signerAccount,
            'to' => $this->contractAddress,
            'data' => $calldata,
            'gas' => '0x' . dechex(300000),
        ];

        $sendRes = $this->callRpc('eth_sendTransaction', [$txParams]);
        $txHash = $sendRes['result'];

        // Wait for transaction receipt (local node mines immediately or within 1s)
        $receipt = $this->waitForReceipt($txHash, 5);

        $status = hexdec($receipt['status'] ?? '0x0');
        if ($status !== 1) {
            throw new RuntimeException("Blockchain transaction reverted. Tx: {$txHash}");
        }

        $blockNumber = hexdec($receipt['blockNumber'] ?? '0x0');
        $gasUsed = hexdec($receipt['gasUsed'] ?? '0x0');

        return [
            'status' => 'success',
            'transactionHash' => $txHash,
            'blockNumber' => $blockNumber,
            'gasUsed' => (string)$gasUsed,
            'recordType' => $recordType,
            'recordId' => $recordId,
            'version' => $version,
            'hash' => $hash,
        ];
    }

    /**
     * Store via node bridge CLI.
     */
    private function storeViaBridge(string $recordType, int $recordId, int $version, string $hash): array {
        $script = escapeshellarg(ROOT_PATH . '/blockchain/scripts/bridge.js');
        $cmd = "node {$script} store " . escapeshellarg($recordType) . " " .
               escapeshellarg((string)$recordId) . " " .
               escapeshellarg((string)$version) . " " .
               escapeshellarg($hash) . " 2>&1";

        $output = shell_exec($cmd);
        $result = json_decode($output ?? '', true);

        if (!$result || ($result['status'] ?? '') !== 'success') {
            $msg = $result['message'] ?? $output ?? 'Bridge execution failed';
            throw new RuntimeException("Blockchain bridge error: {$msg}");
        }

        return $result;
    }

    /**
     * Retrieve anchored hash and proof metadata from the blockchain.
     */
    public function getRecordHash(string $recordType, int $recordId, int $version): array {
        if (!$this->enabled || empty($this->contractAddress)) {
            return [
                'exists' => false,
                'hash' => null,
                'timestamp' => 0,
                'anchoredBy' => null,
            ];
        }

        $calldata = $this->encodeGetRecordHashCalldata($recordType, $recordId, $version);

        $callRes = $this->callRpc('eth_call', [
            [
                'to' => $this->contractAddress,
                'data' => $calldata,
            ],
            'latest'
        ]);

        $hex = $callRes['result'] ?? '';
        return $this->decodeGetRecordHashResult($hex);
    }

    /**
     * Check if a record version hash exists on-chain.
     */
    public function hashExists(string $recordType, int $recordId, int $version): bool {
        $res = $this->getRecordHash($recordType, $recordId, $version);
        return !empty($res['exists']);
    }

    /**
     * Query total anchored records in contract.
     */
    public function getTotalAnchoredRecords(): int {
        $callRes = $this->callRpc('eth_call', [
            [
                'to' => $this->contractAddress,
                'data' => '0x' . self::SELECTOR_TOTAL_RECORDS,
            ],
            'latest'
        ]);

        $hex = $callRes['result'] ?? '0x0';
        return hexdec($hex);
    }

    /**
     * Query all anchored records for the Blockchain Explorer UI.
     */
    public function getAllAnchoredRecords(): array {
        try {
            $script = ROOT_PATH . '/blockchain/scripts/bridge.js';
            if (file_exists($script)) {
                $cmd = "node " . escapeshellarg($script) . " list 2>&1";
                $output = shell_exec($cmd);
                $decoded = json_decode($output ?? '', true);
                if ($decoded && isset($decoded['records'])) {
                    return $decoded['records'];
                }
            }
        } catch (Throwable) {
            // fallback
        }
        return [];
    }

    /**
     * Poll for transaction receipt until confirmed or timeout.
     */
    private function waitForReceipt(string $txHash, int $maxAttempts = 5): array {
        for ($i = 0; $i < $maxAttempts; $i++) {
            $res = $this->callRpc('eth_getTransactionReceipt', [$txHash]);
            if (!empty($res['result'])) {
                return $res['result'];
            }
            usleep(250000); // 250ms
        }
        throw new RuntimeException("Transaction receipt timeout for {$txHash}");
    }

    // =========================================================================
    // Pure PHP ABI Encoding and Decoding Helpers
    // =========================================================================

    /**
     * Encode ABI data for storeRecordHash(string,uint256,uint256,bytes32)
     */
    private function encodeStoreRecordHashCalldata(string $recordType, int $recordId, int $version, string $hash): string {
        $selector = self::SELECTOR_STORE_RECORD_HASH;

        // Argument 1: string offset (128 bytes = 0x80)
        $offsetWord = str_pad(dechex(128), 64, '0', STR_PAD_LEFT);
        // Argument 2: uint256 recordId
        $recordIdWord = str_pad(dechex($recordId), 64, '0', STR_PAD_LEFT);
        // Argument 3: uint256 version
        $versionWord = str_pad(dechex($version), 64, '0', STR_PAD_LEFT);
        // Argument 4: bytes32 hash (strip 0x safely)
        $hashHex = (str_starts_with($hash, '0x') || str_starts_with($hash, '0X')) ? substr($hash, 2) : $hash;
        $hashWord = str_pad($hashHex, 64, '0', STR_PAD_RIGHT);

        // String data tail: length + string content right-padded to 32 bytes
        $strLen = strlen($recordType);
        $lenWord = str_pad(dechex($strLen), 64, '0', STR_PAD_LEFT);
        $strHex = bin2hex($recordType);
        $strPadded = str_pad($strHex, (int)ceil($strLen / 32) * 64, '0', STR_PAD_RIGHT);

        return '0x' . $selector . $offsetWord . $recordIdWord . $versionWord . $hashWord . $lenWord . $strPadded;
    }

    /**
     * Encode ABI data for getRecordHash(string,uint256,uint256)
     */
    private function encodeGetRecordHashCalldata(string $recordType, int $recordId, int $version): string {
        $selector = self::SELECTOR_GET_RECORD_HASH;

        // Argument 1: string offset (96 bytes = 0x60)
        $offsetWord = str_pad(dechex(96), 64, '0', STR_PAD_LEFT);
        // Argument 2: uint256 recordId
        $recordIdWord = str_pad(dechex($recordId), 64, '0', STR_PAD_LEFT);
        // Argument 3: uint256 version
        $versionWord = str_pad(dechex($version), 64, '0', STR_PAD_LEFT);

        // String data tail: length + padded content
        $strLen = strlen($recordType);
        $lenWord = str_pad(dechex($strLen), 64, '0', STR_PAD_LEFT);
        $strHex = bin2hex($recordType);
        $strPadded = str_pad($strHex, (int)ceil($strLen / 32) * 64, '0', STR_PAD_RIGHT);

        return '0x' . $selector . $offsetWord . $recordIdWord . $versionWord . $lenWord . $strPadded;
    }

    /**
     * Decode return data from getRecordHash()
     * Returns (bytes32 hash, uint256 timestamp, address anchoredBy, bool exists)
     */
    private function decodeGetRecordHashResult(string $hex): array {
        $raw = (str_starts_with($hex, '0x') || str_starts_with($hex, '0X')) ? substr($hex, 2) : $hex;
        if (strlen($raw) < 256) {
            return [
                'exists' => false,
                'hash' => null,
                'timestamp' => 0,
                'anchoredBy' => null,
            ];
        }

        $hashWord = substr($raw, 0, 64);
        $timestampWord = substr($raw, 64, 64);
        $addressWord = substr($raw, 128, 64);
        $existsWord = substr($raw, 192, 64);

        $exists = (hexdec($existsWord) !== 0);
        $hash = '0x' . strtolower($hashWord);
        $timestamp = hexdec($timestampWord);
        $anchoredBy = '0x' . substr($addressWord, 24, 40);

        return [
            'exists' => $exists,
            'hash' => $exists ? $hash : null,
            'timestamp' => $timestamp,
            'anchoredBy' => $exists ? $anchoredBy : null,
        ];
    }
}
