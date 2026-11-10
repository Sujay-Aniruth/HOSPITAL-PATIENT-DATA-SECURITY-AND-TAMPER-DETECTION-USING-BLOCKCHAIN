<?php
/**
 * Register New Patient View
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

require_once __DIR__ . '/../../middleware/AuthMiddleware.php';
require_once __DIR__ . '/../../middleware/CsrfMiddleware.php';
require_once __DIR__ . '/../../models/Patient.php';

$user = AuthMiddleware::requireRole(['admin', 'staff']);
$patientModel = new Patient();
$suggestedCode = $patientModel->generatePatientCode();

$error = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    CsrfMiddleware::requireValid();
    try {
        $result = $patientModel->create($_POST, (int)$user['id']);
        header("Location: index.php?page=patient-view&id={$result['patient_id']}&created=1");
        exit;
    } catch (Throwable $e) {
        $error = $e->getMessage();
    }
}
?>

<div class="container-fluid px-4 py-4">
  <div class="row justify-content-center">
    <div class="col-lg-8">
      <div class="d-flex align-items-center justify-content-between mb-4">
        <div>
          <h3 class="fw-bold mb-1">Register New Patient</h3>
          <p class="text-muted small mb-0">Patient demographic data will be recorded in MySQL and anchored on the blockchain.</p>
        </div>
        <a href="index.php?page=patients" class="btn btn-outline-secondary btn-sm">
          <i class="bi bi-arrow-left"></i> Back to Directory
        </a>
      </div>

      <?php if (!empty($error)): ?>
        <div class="alert alert-danger py-2 small d-flex align-items-center gap-2 mb-3">
          <i class="bi bi-exclamation-triangle-fill"></i>
          <span><?= htmlspecialchars($error) ?></span>
        </div>
      <?php endif; ?>

      <div class="card card-hospital">
        <div class="card-header-hospital">
          <span><i class="bi bi-person-lines-fill text-primary me-2"></i> Demographic Profile Information</span>
          <span class="badge bg-primary-subtle text-primary">Initial Version: v1</span>
        </div>
        <div class="card-body p-4">
          <form method="POST" action="index.php?page=patient-create">
            <?= CsrfMiddleware::getField() ?>

            <div class="row g-3 mb-3">
              <div class="col-md-6">
                <label for="patient_code" class="form-label small fw-bold">Patient Code <span class="text-danger">*</span></label>
                <input type="text" class="form-control font-mono" id="patient_code" name="patient_code" required value="<?= htmlspecialchars($_POST['patient_code'] ?? $suggestedCode) ?>">
                <div class="form-text small">Unique institutional patient code.</div>
              </div>
              <div class="col-md-6">
                <label for="name" class="form-label small fw-bold">Full Legal Name <span class="text-danger">*</span></label>
                <input type="text" class="form-control" id="name" name="name" required placeholder="e.g. Ramesh Patel" value="<?= htmlspecialchars($_POST['name'] ?? '') ?>">
              </div>
            </div>

            <div class="row g-3 mb-3">
              <div class="col-md-4">
                <label for="date_of_birth" class="form-label small fw-bold">Date of Birth <span class="text-danger">*</span></label>
                <input type="date" class="form-control" id="date_of_birth" name="date_of_birth" required value="<?= htmlspecialchars($_POST['date_of_birth'] ?? '1988-06-15') ?>">
              </div>
              <div class="col-md-4">
                <label for="gender" class="form-label small fw-bold">Gender <span class="text-danger">*</span></label>
                <select class="form-select" id="gender" name="gender" required>
                  <option value="Male" <?= (($_POST['gender'] ?? '') === 'Male') ? 'selected' : '' ?>>Male</option>
                  <option value="Female" <?= (($_POST['gender'] ?? '') === 'Female') ? 'selected' : '' ?>>Female</option>
                  <option value="Other" <?= (($_POST['gender'] ?? '') === 'Other') ? 'selected' : '' ?>>Other</option>
                </select>
              </div>
              <div class="col-md-4">
                <label for="phone" class="form-label small fw-bold">Phone Number <span class="text-danger">*</span></label>
                <input type="tel" class="form-control" id="phone" name="phone" required placeholder="+91-9876543210" value="<?= htmlspecialchars($_POST['phone'] ?? '') ?>">
              </div>
            </div>

            <div class="mb-3">
              <label for="address" class="form-label small fw-bold">Residential Address <span class="text-danger">*</span></label>
              <textarea class="form-control" id="address" name="address" rows="2" required placeholder="Street address, City, Pincode"><?= htmlspecialchars($_POST['address'] ?? '') ?></textarea>
            </div>

            <div class="mb-4">
              <label for="emergency_contact" class="form-label small fw-bold">Emergency Contact Details <span class="text-danger">*</span></label>
              <input type="text" class="form-control" id="emergency_contact" name="emergency_contact" required placeholder="Name (Relationship) - Phone number" value="<?= htmlspecialchars($_POST['emergency_contact'] ?? '') ?>">
            </div>

            <!-- Security Commitment Callout -->
            <div class="alert alert-info py-2 small d-flex align-items-center gap-2 mb-4">
              <i class="bi bi-shield-check fs-5"></i>
              <div>
                <strong>Blockchain Security Guarantee:</strong> Upon submission, demographic fields will be canonicalized into standard JSON schema v1.0, hashed with SHA-256, and permanently anchored onto the Ethereum blockchain.
              </div>
            </div>

            <div class="d-flex justify-content-end gap-2">
              <a href="index.php?page=patients" class="btn btn-outline-secondary">Cancel</a>
              <button type="submit" class="btn btn-primary fw-bold">
                <i class="bi bi-check-circle me-1"></i> Register & Anchor Profile
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  </div>
</div>
