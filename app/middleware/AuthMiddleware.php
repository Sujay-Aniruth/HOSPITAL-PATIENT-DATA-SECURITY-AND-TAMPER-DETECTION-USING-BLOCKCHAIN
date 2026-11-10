<?php
/**
 * Authentication and RBAC Middleware
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../services/AuditService.php';

class AuthMiddleware {
    public const ROLE_ADMIN = 'admin';
    public const ROLE_DOCTOR = 'doctor';
    public const ROLE_STAFF = 'staff';

    /**
     * Check if a session has an authenticated user.
     */
    public static function check(): bool {
        return !empty($_SESSION['user']['id']);
    }

    /**
     * Get currently authenticated user data.
     */
    public static function user(): ?array {
        return $_SESSION['user'] ?? null;
    }

    /**
     * Require authenticated session or redirect/abort.
     */
    public static function requireAuth(): array {
        if (!self::check()) {
            if (self::isApiRequest()) {
                http_response_code(401);
                echo json_encode([
                    'status' => 'error',
                    'message' => 'Unauthorized: Please log in to access this resource.'
                ]);
                exit;
            }
            $loginUrl = config('APP_URL') . '/public/index.php?page=login';
            header("Location: {$loginUrl}");
            exit;
        }
        return $_SESSION['user'];
    }

    /**
     * Require one of specified roles.
     */
    public static function requireRole(array|string $roles): array {
        $user = self::requireAuth();
        $allowed = is_array($roles) ? $roles : [$roles];

        if (!in_array($user['role'], $allowed, true)) {
            AuditService::log(
                'ACCESS_DENIED',
                'AUTH_GATE',
                null,
                ['required_roles' => $allowed, 'user_role' => $user['role']],
                (int)$user['id']
            );

            http_response_code(403);
            if (self::isApiRequest()) {
                echo json_encode([
                    'status' => 'error',
                    'message' => 'Forbidden: Your role (' . $user['role'] . ') does not have permission for this action.'
                ]);
                exit;
            }
            die("Access Forbidden: Insufficient permissions for role [{$user['role']}].");
        }

        return $user;
    }

    /**
     * Attempt login with brute-force throttling.
     */
    public static function attempt(string $identifier, string $password): array {
        $db = Database::getConnection();

        // Check user existence
        $stmt = $db->prepare("
            SELECT * FROM `users`
            WHERE (`email` = :id1 OR `username` = :id2)
            LIMIT 1
        ");
        $stmt->execute([':id1' => $identifier, ':id2' => $identifier]);
        $user = $stmt->fetch();

        if (!$user) {
            AuditService::log('LOGIN_FAILED', 'USER', null, ['identifier' => $identifier]);
            return ['success' => false, 'message' => 'Invalid email/username or password.'];
        }

        if (empty($user['active'])) {
            return ['success' => false, 'message' => 'Your account has been deactivated.'];
        }

        // Check brute-force lock
        if (!empty($user['locked_until']) && strtotime($user['locked_until']) > time()) {
            $remaining = ceil((strtotime($user['locked_until']) - time()) / 60);
            return [
                'success' => false,
                'message' => "Account is temporarily locked due to multiple failed login attempts. Try again in {$remaining} minutes."
            ];
        }

        // Verify bcrypt password
        if (!password_verify($password, $user['password_hash'])) {
            $failed = (int)$user['failed_logins'] + 1;
            $lockSql = "";
            $lockParams = [':failed' => $failed, ':id' => $user['id']];

            // Lock account for 5 minutes after 5 consecutive failures
            if ($failed >= 5) {
                $lockSql = ", `locked_until` = DATE_ADD(NOW(), INTERVAL 5 MINUTE)";
            }

            $update = $db->prepare("UPDATE `users` SET `failed_logins` = :failed {$lockSql} WHERE `id` = :id");
            $update->execute($lockParams);

            AuditService::log('LOGIN_FAILED', 'USER', (int)$user['id'], ['failed_attempts' => $failed]);
            return ['success' => false, 'message' => 'Invalid email/username or password.'];
        }

        // Successful login: reset failed counters and regenerate session
        $reset = $db->prepare("UPDATE `users` SET `failed_logins` = 0, `locked_until` = NULL WHERE `id` = :id");
        $reset->execute([':id' => $user['id']]);

        session_regenerate_id(true);

        $_SESSION['user'] = [
            'id' => (int)$user['id'],
            'name' => $user['name'],
            'email' => $user['email'],
            'username' => $user['username'],
            'role' => $user['role'],
        ];

        AuditService::log('LOGIN_SUCCESS', 'USER', (int)$user['id']);

        return ['success' => true, 'user' => $_SESSION['user']];
    }

    /**
     * Terminate user session.
     */
    public static function logout(): void {
        if (isset($_SESSION['user']['id'])) {
            AuditService::log('LOGOUT', 'USER', (int)$_SESSION['user']['id']);
        }
        $_SESSION = [];
        if (ini_get("session.use_cookies")) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000,
                $params["path"], $params["domain"],
                $params["secure"], $params["httponly"]
            );
        }
        session_destroy();
    }

    private static function isApiRequest(): bool {
        return str_contains($_SERVER['HTTP_ACCEPT'] ?? '', 'application/json') ||
               str_contains($_SERVER['REQUEST_URI'] ?? '', '/api/');
    }
}
