<?php
/**
 * CSRF Protection Middleware
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

require_once __DIR__ . '/../config/config.php';

class CsrfMiddleware {
    public static function getToken(): string {
        if (empty($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }
        return $_SESSION['csrf_token'];
    }

    public static function getField(): string {
        $token = htmlspecialchars(self::getToken(), ENT_QUOTES, 'UTF-8');
        return '<input type="hidden" name="csrf_token" value="' . $token . '">';
    }

    public static function verify(?string $token = null): bool {
        if ($token === null) {
            // Check POST parameter or HTTP header
            $token = $_POST['csrf_token'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? null;
        }

        if (empty($token) || empty($_SESSION['csrf_token'])) {
            return false;
        }

        return hash_equals($_SESSION['csrf_token'], $token);
    }

    public static function requireValid(): void {
        if (!self::verify()) {
            http_response_code(403);
            if (str_contains($_SERVER['HTTP_ACCEPT'] ?? '', 'application/json') || 
                str_starts_with($_SERVER['REQUEST_URI'] ?? '', '/api/')) {
                echo json_encode([
                    'status' => 'error',
                    'message' => 'CSRF token validation failed. Please refresh the page.'
                ]);
            } else {
                die('CSRF token validation failed. Please refresh the page and try again.');
            }
            exit;
        }
    }
}
