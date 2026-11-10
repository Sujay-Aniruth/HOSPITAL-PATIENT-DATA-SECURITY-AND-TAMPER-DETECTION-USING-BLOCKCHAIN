-- Hospital Patient Data Security and Tamper Detection Using Blockchain
-- Fictional Demonstration Seed Data
-- Database: hospital_blockchain_security

USE `hospital_blockchain_security`;

SET FOREIGN_KEY_CHECKS = 0;

-- Clean existing data for deterministic re-seeding
TRUNCATE TABLE `audit_logs`;
TRUNCATE TABLE `security_alerts`;
TRUNCATE TABLE `integrity_checks`;
TRUNCATE TABLE `medical_record_versions`;
TRUNCATE TABLE `medical_records`;
TRUNCATE TABLE `encounters`;
TRUNCATE TABLE `patient_profile_versions`;
TRUNCATE TABLE `patients`;
TRUNCATE TABLE `users`;

SET FOREIGN_KEY_CHECKS = 1;

-- 1. Demo Users (Passwords are documented for local demonstration only)
-- admin@hospital.local   / Admin@12345
-- dr.sharma@hospital.local / Doctor@12345
-- staff.priya@hospital.local / Staff@12345
INSERT INTO `users` (`id`, `name`, `username`, `email`, `password_hash`, `role`, `active`, `created_at`) VALUES
(1, 'Dr. Alok Verma (Chief Admin)', 'admin', 'admin@hospital.local', '$2y$10$AQglaFGFHRfcxRarUct6eOFvqdyW2KfRH0ZoXCchLLEVB.78sL9qS', 'admin', 1, '2026-11-01 09:00:00'),
(2, 'Dr. Sunita Sharma (Lead Physician)', 'dr.sharma', 'dr.sharma@hospital.local', '$2y$10$C/sKBKrQ7eADhnvaDXH7juEgGfrfwFI42xpMOcVT3t.iHc28I1TC.', 'doctor', 1, '2026-11-01 09:15:00'),
(3, 'Priya Nair (Senior Registrar)', 'staff.priya', 'staff.priya@hospital.local', '$2y$10$IZSCgImXyQcTA6uShYVWJu07wnsUL5N/IZp93XM8CBxfgq3xL5Esi', 'staff', 1, '2026-11-01 09:30:00');

-- 2. Fictional Patient Records
INSERT INTO `patients` (`id`, `patient_code`, `name`, `date_of_birth`, `gender`, `phone`, `address`, `emergency_contact`, `current_profile_version`, `created_by`, `created_at`) VALUES
(1, 'PAT-2026-001', 'Rajesh Kumar', '1982-05-14', 'Male', '+91-9876543210', 'Flat 402, Green Meadows, MG Road, Bengaluru 560001', 'Sunita Kumar (Spouse) - +91-9876543211', 1, 3, '2026-11-02 10:00:00'),
(2, 'PAT-2026-002', 'Anita Roy', '1990-11-20', 'Female', '+91-9812345678', 'Plot 18, Lakeview Residency, Whitefield, Bengaluru 560066', 'Rohan Roy (Brother) - +91-9812345679', 1, 3, '2026-11-03 11:30:00'),
(3, 'PAT-2026-003', 'Vikram Singh', '1975-08-03', 'Male', '+91-9701234567', 'House 55, Defense Colony, Indiranagar, Bengaluru 560038', 'Meera Singh (Spouse) - +91-9701234568', 1, 3, '2026-11-04 14:15:00');

-- 3. Fictional Patient Encounters
INSERT INTO `encounters` (`id`, `encounter_code`, `patient_id`, `doctor_id`, `visit_at`, `reason`, `created_at`) VALUES
(1, 'ENC-2026-001', 1, 2, '2026-11-05 10:30:00', 'Routine checkup and high blood sugar complaints', '2026-11-05 10:30:00'),
(2, 'ENC-2026-002', 2, 2, '2026-11-06 11:00:00', 'Persistent dry cough and mild fever', '2026-11-06 11:00:00'),
(3, 'ENC-2026-003', 3, 2, '2026-11-07 15:00:00', 'Knee pain and joint stiffness following tennis match', '2026-11-07 15:00:00');

-- 4. Fictional Medical Records
INSERT INTO `medical_records` (`id`, `encounter_id`, `patient_id`, `current_version`, `created_at`) VALUES
(1, 1, 1, 1, '2026-11-05 10:45:00'),
(2, 2, 2, 1, '2026-11-06 11:20:00'),
(3, 3, 3, 1, '2026-11-07 15:30:00');

-- 5. Audit log entries for seeding
INSERT INTO `audit_logs` (`actor_id`, `action`, `target_type`, `target_id`, `ip_address`, `metadata`, `timestamp`) VALUES
(1, 'SYSTEM_INIT', 'SYSTEM', 1, '127.0.0.1', '{"event":"System database seeded with baseline demonstration data"}', '2026-11-01 09:00:00'),
(3, 'PATIENT_REGISTER', 'PATIENT', 1, '127.0.0.1', '{"patient_code":"PAT-2026-001","name":"Rajesh Kumar"}', '2026-11-02 10:00:00'),
(3, 'PATIENT_REGISTER', 'PATIENT', 2, '127.0.0.1', '{"patient_code":"PAT-2026-002","name":"Anita Roy"}', '2026-11-03 11:30:00'),
(3, 'PATIENT_REGISTER', 'PATIENT', 3, '127.0.0.1', '{"patient_code":"PAT-2026-003","name":"Vikram Singh"}', '2026-11-04 14:15:00'),
(2, 'ENCOUNTER_CREATE', 'ENCOUNTER', 1, '127.0.0.1', '{"encounter_code":"ENC-2026-001","patient_id":1}', '2026-11-05 10:30:00');
