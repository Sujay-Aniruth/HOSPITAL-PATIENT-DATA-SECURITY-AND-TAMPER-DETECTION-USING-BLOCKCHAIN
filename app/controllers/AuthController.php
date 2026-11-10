<?php
/**
 * Auth Controller
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

require_once __DIR__ . '/../middleware/AuthMiddleware.php';
require_once __DIR__ . '/../middleware/CsrfMiddleware.php';

class AuthController {
    public function login(string $identifier, string $password): array {
        return AuthMiddleware::attempt($identifier, $password);
    }

    public function logout(): void {
        AuthMiddleware::logout();
    }

    public function me(): ?array {
        return AuthMiddleware::user();
    }
}
