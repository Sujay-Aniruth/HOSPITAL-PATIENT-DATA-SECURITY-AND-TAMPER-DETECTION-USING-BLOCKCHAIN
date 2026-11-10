-- Hospital Patient Data Security and Tamper Detection Using Blockchain
-- Database Schema Definition
-- Database: hospital_blockchain_security

CREATE DATABASE IF NOT EXISTS `hospital_blockchain_security` 
CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE `hospital_blockchain_security`;

SET FOREIGN_KEY_CHECKS = 0;

-- Drop existing tables to allow clean re-import
DROP TABLE IF EXISTS `audit_logs`;
DROP TABLE IF EXISTS `security_alerts`;
DROP TABLE IF EXISTS `integrity_checks`;
DROP TABLE IF EXISTS `medical_record_versions`;
DROP TABLE IF EXISTS `medical_records`;
DROP TABLE IF EXISTS `encounters`;
DROP TABLE IF EXISTS `patient_profile_versions`;
DROP TABLE IF EXISTS `patients`;
DROP TABLE IF EXISTS `users`;

SET FOREIGN_KEY_CHECKS = 1;

-- 1. Users Table (Role-based accounts)
CREATE TABLE `users` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `name` VARCHAR(100) NOT NULL,
  `username` VARCHAR(50) NOT NULL UNIQUE,
  `email` VARCHAR(100) NOT NULL UNIQUE,
  `password_hash` VARCHAR(255) NOT NULL,
  `role` ENUM('admin', 'doctor', 'staff') NOT NULL,
  `active` TINYINT(1) NOT NULL DEFAULT 1,
  `failed_logins` INT NOT NULL DEFAULT 0,
  `locked_until` DATETIME NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX `idx_users_role` (`role`),
  INDEX `idx_users_username` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 2. Patients Table
CREATE TABLE `patients` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `patient_code` VARCHAR(30) NOT NULL UNIQUE,
  `name` VARCHAR(100) NOT NULL,
  `date_of_birth` DATE NOT NULL,
  `gender` ENUM('Male', 'Female', 'Other') NOT NULL,
  `phone` VARCHAR(30) NOT NULL,
  `address` TEXT NOT NULL,
  `emergency_contact` VARCHAR(150) NOT NULL,
  `current_profile_version` INT NOT NULL DEFAULT 1,
  `created_by` INT NOT NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX `idx_patients_code` (`patient_code`),
  INDEX `idx_patients_name` (`name`),
  CONSTRAINT `fk_patients_created_by` FOREIGN KEY (`created_by`) REFERENCES `users` (`id`) ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 3. Patient Profile Versions (Immutable history of demographic updates)
CREATE TABLE `patient_profile_versions` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `patient_id` INT NOT NULL,
  `version_number` INT NOT NULL,
  `patient_code` VARCHAR(30) NOT NULL,
  `name` VARCHAR(100) NOT NULL,
  `date_of_birth` DATE NOT NULL,
  `gender` VARCHAR(20) NOT NULL,
  `phone` VARCHAR(30) NOT NULL,
  `address` TEXT NOT NULL,
  `emergency_contact` VARCHAR(150) NOT NULL,
  `canonical_json` TEXT NOT NULL,
  `sha256_hash` VARCHAR(66) NOT NULL,
  `anchor_status` ENUM('PENDING', 'ANCHORED', 'FAILED') NOT NULL DEFAULT 'PENDING',
  `transaction_hash` VARCHAR(66) NULL,
  `block_number` BIGINT NULL,
  `anchored_at` DATETIME NULL,
  `created_by` INT NOT NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY `uq_patient_profile_version` (`patient_id`, `version_number`),
  INDEX `idx_pat_ver_hash` (`sha256_hash`),
  INDEX `idx_pat_ver_status` (`anchor_status`),
  CONSTRAINT `fk_ppv_patient` FOREIGN KEY (`patient_id`) REFERENCES `patients` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_ppv_creator` FOREIGN KEY (`created_by`) REFERENCES `users` (`id`) ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 4. Clinical Encounters / Visits
CREATE TABLE `encounters` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `encounter_code` VARCHAR(30) NOT NULL UNIQUE,
  `patient_id` INT NOT NULL,
  `doctor_id` INT NOT NULL,
  `visit_at` DATETIME NOT NULL,
  `reason` VARCHAR(255) NOT NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX `idx_encounters_patient` (`patient_id`),
  INDEX `idx_encounters_doctor` (`doctor_id`),
  CONSTRAINT `fk_encounters_patient` FOREIGN KEY (`patient_id`) REFERENCES `patients` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_encounters_doctor` FOREIGN KEY (`doctor_id`) REFERENCES `users` (`id`) ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 5. Medical Records Header
CREATE TABLE `medical_records` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `encounter_id` INT NOT NULL,
  `patient_id` INT NOT NULL,
  `current_version` INT NOT NULL DEFAULT 1,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX `idx_med_records_patient` (`patient_id`),
  INDEX `idx_med_records_encounter` (`encounter_id`),
  CONSTRAINT `fk_mr_encounter` FOREIGN KEY (`encounter_id`) REFERENCES `encounters` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_mr_patient` FOREIGN KEY (`patient_id`) REFERENCES `patients` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 6. Medical Record Versions (Immutable clinical record history)
CREATE TABLE `medical_record_versions` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `medical_record_id` INT NOT NULL,
  `version_number` INT NOT NULL,
  `symptoms` TEXT NOT NULL,
  `diagnosis` TEXT NOT NULL,
  `notes` TEXT NOT NULL,
  `prescription` TEXT NOT NULL,
  `treatment_plan` TEXT NOT NULL,
  `canonical_json` TEXT NOT NULL,
  `sha256_hash` VARCHAR(66) NOT NULL,
  `anchor_status` ENUM('PENDING', 'ANCHORED', 'FAILED') NOT NULL DEFAULT 'PENDING',
  `transaction_hash` VARCHAR(66) NULL,
  `block_number` BIGINT NULL,
  `anchored_at` DATETIME NULL,
  `created_by` INT NOT NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY `uq_med_record_version` (`medical_record_id`, `version_number`),
  INDEX `idx_mrv_hash` (`sha256_hash`),
  INDEX `idx_mrv_status` (`anchor_status`),
  CONSTRAINT `fk_mrv_record` FOREIGN KEY (`medical_record_id`) REFERENCES `medical_records` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_mrv_creator` FOREIGN KEY (`created_by`) REFERENCES `users` (`id`) ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 7. Integrity Verification Log
CREATE TABLE `integrity_checks` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `record_type` ENUM('PATIENT_PROFILE', 'MEDICAL_RECORD') NOT NULL,
  `record_id` INT NOT NULL,
  `version_number` INT NOT NULL,
  `calculated_hash` VARCHAR(66) NOT NULL,
  `blockchain_hash` VARCHAR(66) NULL,
  `result` ENUM('VALID', 'TAMPERED', 'PENDING', 'MISSING_ANCHOR', 'ERROR') NOT NULL,
  `details` TEXT NULL,
  `checked_by` INT NOT NULL,
  `checked_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX `idx_ic_type_id_ver` (`record_type`, `record_id`, `version_number`),
  INDEX `idx_ic_result` (`result`),
  CONSTRAINT `fk_ic_user` FOREIGN KEY (`checked_by`) REFERENCES `users` (`id`) ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 8. Security Alerts
CREATE TABLE `security_alerts` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `record_type` ENUM('PATIENT_PROFILE', 'MEDICAL_RECORD') NOT NULL,
  `record_id` INT NOT NULL,
  `version_number` INT NOT NULL,
  `severity` ENUM('INFO', 'WARNING', 'CRITICAL') NOT NULL DEFAULT 'CRITICAL',
  `message` TEXT NOT NULL,
  `detected_hash` VARCHAR(66) NOT NULL,
  `expected_hash` VARCHAR(66) NOT NULL,
  `resolved` TINYINT(1) NOT NULL DEFAULT 0,
  `resolved_by` INT NULL,
  `detected_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `resolved_at` DATETIME NULL,
  INDEX `idx_sa_resolved` (`resolved`),
  INDEX `idx_sa_severity` (`severity`),
  CONSTRAINT `fk_sa_resolver` FOREIGN KEY (`resolved_by`) REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 9. Audit Logs
CREATE TABLE `audit_logs` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `actor_id` INT NULL,
  `action` VARCHAR(50) NOT NULL,
  `target_type` VARCHAR(50) NOT NULL,
  `target_id` INT NULL,
  `ip_address` VARCHAR(45) NULL,
  `user_agent` VARCHAR(255) NULL,
  `metadata` LONGTEXT NULL,
  `timestamp` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX `idx_audit_actor` (`actor_id`),
  INDEX `idx_audit_action` (`action`),
  INDEX `idx_audit_target` (`target_type`, `target_id`),
  CONSTRAINT `fk_audit_actor` FOREIGN KEY (`actor_id`) REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
