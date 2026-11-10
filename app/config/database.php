<?php
/**
 * Database Connection Service
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

require_once __DIR__ . '/config.php';

class Database {
    private static ?PDO $instance = null;

    public static function getConnection(): PDO {
        if (self::$instance === null) {
            $host = config('DB_HOST', '127.0.0.1');
            $port = config('DB_PORT', '3306');
            $dbname = config('DB_NAME', 'hospital_blockchain_security');
            $username = config('DB_USER', 'root');
            $password = config('DB_PASSWORD', '');

            $dsn = "mysql:host={$host};port={$port};dbname={$dbname};charset=utf8mb4";

            $options = [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
                PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci"
            ];

            try {
                self::$instance = new PDO($dsn, $username, $password, $options);
            } catch (PDOException $e) {
                error_log("Database connection failure: " . $e->getMessage());
                throw new RuntimeException("Database connection failed. Please ensure MySQL is running in XAMPP.");
            }
        }

        return self::$instance;
    }
}
