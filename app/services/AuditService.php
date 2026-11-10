<?php
/**
 * Audit Logging Service
 * Hospital Patient Data Security and Tamper Detection
 * 
 * Records non-sensitive operational events and security lifecycle actions.
 */

declare(strict_types=1);

require_once __DIR__ . '/../config/database.php';

class AuditService {
    public static function log(
        string $action,
        string $targetType,
        ?int $targetId = null,
        ?array $metadata = null,
        ?int $actorId = null
    ): void {
        try {
            $db = Database::getConnection();

            if ($actorId === null && isset($_SESSION['user']['id'])) {
                $actorId = (int)$_SESSION['user']['id'];
            }

            $ipAddress = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
            $userAgent = substr($_SERVER['HTTP_USER_AGENT'] ?? 'CLI/Internal', 0, 255);

            $metaJson = $metadata !== null ? json_encode($metadata, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) : null;

            $stmt = $db->prepare("
                INSERT INTO `audit_logs` (`actor_id`, `action`, `target_type`, `target_id`, `ip_address`, `user_agent`, `metadata`, `timestamp`)
                VALUES (:actor_id, :action, :target_type, :target_id, :ip_address, :user_agent, :metadata, NOW())
            ");

            $stmt->execute([
                ':actor_id' => $actorId,
                ':action' => $action,
                ':target_type' => $targetType,
                ':target_id' => $targetId,
                ':ip_address' => $ipAddress,
                ':user_agent' => $userAgent,
                ':metadata' => $metaJson,
            ]);
        } catch (Throwable $e) {
            // Fail silently to avoid breaking primary transaction, but log to error_log
            error_log("AuditService logging failure: " . $e->getMessage());
        }
    }

    public static function getRecentLogs(int $limit = 50, ?string $targetType = null): array {
        $db = Database::getConnection();
        $sql = "
            SELECT a.*, u.name as actor_name, u.role as actor_role, u.username as actor_username
            FROM `audit_logs` a
            LEFT JOIN `users` u ON a.actor_id = u.id
        ";
        $params = [];

        if ($targetType !== null) {
            $sql .= " WHERE a.target_type = :target_type";
            $params[':target_type'] = $targetType;
        }

        $sql .= " ORDER BY a.id DESC LIMIT " . (int)$limit;
        $stmt = $db->prepare($sql);
        $stmt->execute($params);
        return $stmt->fetchAll();
    }
}
