<?php
/**
 * Canonical Hashing Unit Tests & Test Vectors
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

require_once __DIR__ . '/../app/services/CanonicalHashingService.php';

class CanonicalHashingTest {
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
        echo "\n=== Running Canonical Hashing & Test Vector Suite ===\n";

        // Test 1: Deterministic key ordering
        $fields1 = ['phone' => '+1234', 'name' => 'John', 'address' => '123 Main'];
        $fields2 = ['address' => '123 Main', 'name' => 'John', 'phone' => '+1234'];
        $json1 = CanonicalHashingService::canonicalizeRecord('PATIENT_PROFILE', 1, 1, $fields1);
        $json2 = CanonicalHashingService::canonicalizeRecord('PATIENT_PROFILE', 1, 1, $fields2);
        $this->assert($json1 === $json2, "Different input key orders produce identical canonical JSON");

        // Test 2: Whitespace and CRLF line normalization
        $fieldsWithCrlf = ['diagnosis' => "Fever\r\nCough\r\n"];
        $fieldsWithLf = ['diagnosis' => "Fever\nCough"];
        $hashCrlf = CanonicalHashingService::generateHash(CanonicalHashingService::canonicalizeRecord('MEDICAL_RECORD', 1, 1, $fieldsWithCrlf));
        $hashLf = CanonicalHashingService::generateHash(CanonicalHashingService::canonicalizeRecord('MEDICAL_RECORD', 1, 1, $fieldsWithLf));
        $this->assert($hashCrlf === $hashLf, "CRLF line endings and trailing whitespace normalize to identical SHA-256");

        // Test 3: Null vs Empty handling consistency
        $fieldsNull = ['notes' => null];
        $jsonNull = CanonicalHashingService::canonicalizeRecord('MEDICAL_RECORD', 1, 1, $fieldsNull);
        $this->assert(str_contains($jsonNull, '"notes":null'), "Null values serialize strictly as JSON null");

        // Test 4: Known deterministic test vector
        $vectorPayload = [
            'address' => '456 Healthcare Way, Silicon Valley',
            'date_of_birth' => '1990-01-01',
            'emergency_contact' => 'Jane Doe - 555-0100',
            'gender' => 'Female',
            'name' => 'Alice Test',
            'patient_code' => 'PAT-VECTOR-001',
            'phone' => '+1-555-0199',
        ];
        $canonical = CanonicalHashingService::canonicalizeRecord('PATIENT_PROFILE', 100, 1, $vectorPayload);
        $hash = CanonicalHashingService::generateHash($canonical);
        $expectedHash = '0x' . hash('sha256', $canonical);
        $this->assert($hash === $expectedHash, "Generated SHA-256 matches independent PHP hash('sha256')");
        $this->assert(strlen($hash) === 66, "Hash is formatted as 66-character bytes32 (0x + 64 hex)");

        // Test 5: Verify hash comparison helper
        $this->assert(CanonicalHashingService::verifyHash($hash, strtoupper($hash)), "verifyHash is case-insensitive");
        $this->assert(!CanonicalHashingService::verifyHash($hash, '0x' . str_repeat('0', 64)), "verifyHash rejects mismatching hash");

        // Test 6: Tamper detection sensitivity: changing single character produces completely different avalanche hash
        $tamperedPayload = $vectorPayload;
        $tamperedPayload['name'] = 'Alice Teso'; // 1 character changed
        $tamperedJson = CanonicalHashingService::canonicalizeRecord('PATIENT_PROFILE', 100, 1, $tamperedPayload);
        $tamperedHash = CanonicalHashingService::generateHash($tamperedJson);
        $this->assert($tamperedHash !== $hash, "Single character edit produces completely distinct avalanche hash proof");

        return ['passed' => $this->passed, 'failed' => $this->failed];
    }
}
