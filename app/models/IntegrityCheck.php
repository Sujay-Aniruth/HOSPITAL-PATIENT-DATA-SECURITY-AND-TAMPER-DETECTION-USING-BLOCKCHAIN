<?php
/**
 * Integrity Check Model
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

require_once __DIR__ . '/../config/database.php';

class IntegrityCheck {
    private PDO $db;

    public function __construct() {
        $this->db = Database::getConnection();
    }

    public function getRecent(int $limit = 50): array {
        $stmt = $this->db->prepare("
            SELECT ic.*, u.name as checked_by_name
            FROM `integrity_checks` ic
            LEFT JOIN `users` u ON ic.checked_by = u.id
            ORDER BY ic.id DESC
            LIMIT :limit
        ");
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->execute();
        return $stmt->fetchAll();
    }

    public function getStats(): array {
        $stmt = $this->db->query("
            SELECT 
                COUNT(*) as total_checks,
                SUM(CASE WHEN `result` = 'VALID' THEN 1 ELSE 0 END) as valid_count,
                SUM(CASE WHEN `result` = 'TAMPERED' THEN 1 ELSE 0 END) as tampered_count,
                SUM(CASE WHEN `result` = 'PENDING' THEN 1 ELSE 0 END) as pending_count,
                SUM(CASE WHEN `result` = 'MISSING_ANCHOR' THEN 1 ELSE 0 END) as missing_anchor_count,
                SUM(CASE WHEN `result` = 'ERROR' THEN 1 ELSE 0 END) as error_count
            FROM `integrity_checks`
        ");
        $row = $stmt->fetch();

        return [
            'total_checks' => (int)($row['total_checks'] ?? 0),
            'valid_count' => (int)($row['valid_count'] ?? 0),
            'tampered_count' => (int)($row['tampered_count'] ?? 0),
            'pending_count' => (int)($row['pending_count'] ?? 0),
            'missing_anchor_count' => (int)($row['missing_anchor_count'] ?? 0),
            'error_count' => (int)($row['error_count'] ?? 0),
        ];
    }
}
