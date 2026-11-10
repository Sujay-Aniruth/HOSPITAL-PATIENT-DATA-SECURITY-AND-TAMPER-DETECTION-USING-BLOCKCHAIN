<?php
/**
 * Application Configuration and Environment Loader
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

if (!defined('ROOT_PATH')) {
    define('ROOT_PATH', dirname(__DIR__, 2));
}
if (!defined('APP_PATH')) {
    define('APP_PATH', dirname(__DIR__));
}

// Simple deterministic .env loader
function loadEnvironment(): array {
    static $env = null;
    if ($env !== null) {
        return $env;
    }

    $env = [];
    $envFile = ROOT_PATH . '/.env';

    if (file_exists($envFile)) {
        $lines = file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }
            if (str_contains($line, '=')) {
                [$key, $val] = explode('=', $line, 2);
                $key = trim($key);
                $val = trim($val);
                // Strip surrounding quotes
                if ((str_starts_with($val, '"') && str_ends_with($val, '"')) ||
                    (str_starts_with($val, "'") && str_ends_with($val, "'"))) {
                    $val = substr($val, 1, -1);
                }
                $env[$key] = $val;
                if (!isset($_ENV[$key])) {
                    $_ENV[$key] = $val;
                }
            }
        }
    }
    return $env;
}

function config(string $key, mixed $default = null): mixed {
    $env = loadEnvironment();
    return $env[$key] ?? $_ENV[$key] ?? $default;
}

// Start PHP Session with secure parameters
if (session_status() === PHP_SESSION_NONE) {
    ini_set('session.cookie_httponly', '1');
    ini_set('session.use_only_cookies', '1');
    ini_set('session.cookie_samesite', 'Lax');
    session_start();
}
