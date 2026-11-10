<?php
/**
 * Demo Controller
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../middleware/AuthMiddleware.php';
require_once __DIR__ . '/../middleware/CsrfMiddleware.php';

class DemoController {
    public function verifyAccess(): void {
        if (config('APP_ENV') !== 'local') {
            throw new RuntimeException("Demo features are restricted to local development environments.");
        }
        AuthMiddleware::requireRole(['admin']);
        CsrfMiddleware::requireValid();
    }
}
