<?php
/**
 * Canonical Hashing Service
 * Hospital Patient Data Security and Tamper Detection
 * 
 * Provides deterministic canonical JSON serialization and SHA-256 cryptographic
 * hashing for patient profiles and clinical medical record versions.
 */

declare(strict_types=1);

class CanonicalHashingService {
    public const SCHEMA_VERSION = '1.0';

    public const TYPE_PATIENT_PROFILE = 'PATIENT_PROFILE';
    public const TYPE_MEDICAL_RECORD = 'MEDICAL_RECORD';

    /**
     * Normalize string content: convert Windows/Mac line breaks to \n and trim trailing whitespace.
     */
    public static function normalizeString(?string $str): ?string {
        if ($str === null) {
            return null;
        }
        $str = str_replace(["\r\n", "\r"], "\n", $str);
        return trim($str);
    }

    /**
     * Recursively sort and normalize data fields.
     */
    public static function normalizeFields(array $fields): array {
        $normalized = [];
        foreach ($fields as $key => $value) {
            $k = (string)$key;
            if (is_array($value)) {
                $normalized[$k] = self::normalizeFields($value);
            } elseif (is_string($value)) {
                $normalized[$k] = self::normalizeString($value);
            } elseif (is_int($value) || is_float($value) || is_bool($value) || $value === null) {
                $normalized[$k] = $value;
            } else {
                $normalized[$k] = self::normalizeString((string)$value);
            }
        }
        ksort($normalized, SORT_STRING);
        return $normalized;
    }

    /**
     * Build canonical JSON representation of a protected record version.
     */
    public static function canonicalizeRecord(
        string $recordType,
        int $recordId,
        int $versionNumber,
        array $fields
    ): string {
        if ($recordId <= 0) {
            throw new InvalidArgumentException("Record ID must be greater than zero.");
        }
        if ($versionNumber <= 0) {
            throw new InvalidArgumentException("Version number must be greater than zero.");
        }

        $payload = [
            'fields' => self::normalizeFields($fields),
            'record_id' => $recordId,
            'record_type' => $recordType,
            'schema_version' => self::SCHEMA_VERSION,
            'version_number' => $versionNumber,
        ];

        ksort($payload, SORT_STRING);

        $json = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($json === false) {
            throw new RuntimeException("Failed to canonicalize record JSON: " . json_last_error_msg());
        }

        return $json;
    }

    /**
     * Generate deterministic SHA-256 hash formatted as Ethereum bytes32 (0x-prefixed 64 hex chars).
     */
    public static function generateHash(string $canonicalJson): string {
        $rawHash = hash('sha256', $canonicalJson);
        return '0x' . strtolower($rawHash);
    }

    /**
     * Verify equality between two bytes32 hashes (case-insensitive, normalized).
     */
    public static function verifyHash(?string $calculatedHash, ?string $blockchainHash): bool {
        if (empty($calculatedHash) || empty($blockchainHash)) {
            return false;
        }

        $calc = strtolower(trim($calculatedHash));
        $bc = strtolower(trim($blockchainHash));

        if (!str_starts_with($calc, '0x')) {
            $calc = '0x' . $calc;
        }
        if (!str_starts_with($bc, '0x')) {
            $bc = '0x' . $bc;
        }

        return hash_equals($calc, $bc);
    }

    /**
     * Helper: Canonicalize and hash a Patient Profile version.
     * Protected demographic fields: patient_code, name, date_of_birth, gender, phone, address, emergency_contact.
     */
    public static function canonicalizePatientProfile(array $patient, int $versionNumber): array {
        $fields = [
            'address' => (string)($patient['address'] ?? ''),
            'date_of_birth' => (string)($patient['date_of_birth'] ?? ''),
            'emergency_contact' => (string)($patient['emergency_contact'] ?? ''),
            'gender' => (string)($patient['gender'] ?? ''),
            'name' => (string)($patient['name'] ?? ''),
            'patient_code' => (string)($patient['patient_code'] ?? ''),
            'phone' => (string)($patient['phone'] ?? ''),
        ];

        $patientId = (int)($patient['id'] ?? 0);
        $canonicalJson = self::canonicalizeRecord(
            self::TYPE_PATIENT_PROFILE,
            $patientId,
            $versionNumber,
            $fields
        );
        $hash = self::generateHash($canonicalJson);

        return [
            'canonical_json' => $canonicalJson,
            'sha256_hash' => $hash,
            'fields' => $fields,
        ];
    }

    /**
     * Helper: Canonicalize and hash a Medical Record clinical version.
     * Protected clinical fields: patient_id, encounter_id, doctor_id, symptoms, diagnosis, notes, prescription, treatment_plan.
     */
    public static function canonicalizeMedicalRecord(array $record, int $versionNumber): array {
        $fields = [
            'diagnosis' => (string)($record['diagnosis'] ?? ''),
            'doctor_id' => (int)($record['doctor_id'] ?? 0),
            'encounter_id' => (int)($record['encounter_id'] ?? 0),
            'notes' => (string)($record['notes'] ?? ''),
            'patient_id' => (int)($record['patient_id'] ?? 0),
            'prescription' => (string)($record['prescription'] ?? ''),
            'symptoms' => (string)($record['symptoms'] ?? ''),
            'treatment_plan' => (string)($record['treatment_plan'] ?? ''),
        ];

        $recordId = (int)($record['medical_record_id'] ?? $record['id'] ?? 0);
        $canonicalJson = self::canonicalizeRecord(
            self::TYPE_MEDICAL_RECORD,
            $recordId,
            $versionNumber,
            $fields
        );
        $hash = self::generateHash($canonicalJson);

        return [
            'canonical_json' => $canonicalJson,
            'sha256_hash' => $hash,
            'fields' => $fields,
        ];
    }
}
