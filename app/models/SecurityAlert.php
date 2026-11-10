<?php
/**
 * Security Alert Model
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../services/AuditService.php';

class SecurityAlert {
    private PDO $db;

    public function __construct() {
        $this->db = Database::getConnection();
    }

    public function getActive(int $limit = 50): array {
        $stmt = $this->db->prepare("
            SELECT sa.*, u.name as resolver_name
            FROM `security_alerts` sa
            LEFT JOIN `users` u ON sa.resolved_by = u.id
            WHERE sa.resolved = 0
            ORDER BY sa.id DESC
            LIMIT :limit
        ");
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->execute();
        return $stmt->fetchAll();
    }

    public function getAll(int $limit = 100): array {
        $stmt = $this->db->prepare("
            SELECT sa.*, u.name as resolver_name
            FROM `security_alerts` sa
            LEFT JOIN `users` u ON sa.resolved_by = u.id
            ORDER BY sa.id DESC
            LIMIT :limit
        ");
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->execute();
        return $stmt->fetchAll();
    }

    public function countUnresolved(): int {
        $stmt = $this->db->query("SELECT COUNT(*) as cnt FROM `security_alerts` WHERE `resolved` = 0");
        $row = $stmt->fetch();
        return (int)($row['cnt'] ?? 0);
    }

    public function resolve(int $alertId, int $resolvedBy, ?string $note = null): bool {
        $stmt = $this->db->prepare("
            UPDATE `security_alerts`
            SET `resolved` = 1, `resolved_by` = :by, `resolved_at` = NOW()
            WHERE `id` = :id
        ");
        $res = $stmt->execute([':by' => $resolvedBy, ':id' => $alertId]);

        AuditService::log('ALERT_RESOLVE', 'SECURITY_ALERT', $alertId, ['note' => $note], $resolvedBy);
        return $res;
    }
}
