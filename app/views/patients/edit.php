<?php
/**
 * Patient Authorized Amendment View
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

require_once __DIR__ . '/../../middleware/AuthMiddleware.php';
require_once __DIR__ . '/../../middleware/CsrfMiddleware.php';
require_once __DIR__ . '/../../models/Patient.php';

$user = AuthMiddleware::requireRole(['admin', 'staff']);
$id = (int)($_GET['id'] ?? 0);

$patientModel = new Patient();
$patient = $patientModel->findById($id);

if (!$patient) {
    die("Patient #{$id} not found.");
}

$nextVersion = (int)$patient['current_profile_version'] + 1;
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    CsrfMiddleware::requireValid();
    try {
        $result = $patientModel->update($id, $_POST, (int)$user['id']);
        header("Location: index.php?page=patient-view&id={$id}&amended=1");
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
          <h3 class="fw-bold mb-1">Authorized Demographic Amendment</h3>
          <p class="text-muted small mb-0">Create Version <?= $nextVersion ?> for <?= htmlspecialchars($patient['name']) ?> (<?= htmlspecialchars($patient['patient_code']) ?>)</p>
        </div>
        <a href="index.php?page=patient-view&id=<?= $id ?>" class="btn btn-outline-secondary btn-sm">
          <i class="bi bi-arrow-left"></i> Cancel
        </a>
      </div>

      <!-- Educational Notice Box -->
      <div class="alert alert-warning py-3 small mb-4">
        <div class="d-flex gap-2">
          <i class="bi bi-info-circle-fill fs-5 text-warning"></i>
          <div>
            <strong>Append-Only Integrity Principle:</strong>
            Submitting this form does <em>not</em> overwrite the prior version. A new immutable version <strong>v<?= $nextVersion ?></strong> will be created in the database and anchored on the blockchain. Prior versions (v1 through v<?= (int)$patient['current_profile_version'] ?>) remain intact and verifiable.
          </div>
        </div>
      </div>

      <?php if (!empty($error)): ?>
        <div class="alert alert-danger py-2 small d-flex align-items-center gap-2 mb-3">
          <i class="bi bi-exclamation-triangle-fill"></i>
          <span><?= htmlspecialchars($error) ?></span>
        </div>
      <?php endif; ?>

      <div class="card card-hospital">
        <div class="card-header-hospital">
          <span><i class="bi bi-pencil-square text-primary me-2"></i> Update Demographic Details</span>
          <span class="badge bg-primary">Creating Version: v<?= $nextVersion ?></span>
        </div>
        <div class="card-body p-4">
          <form method="POST" action="index.php?page=patient-edit&id=<?= $id ?>">
            <?= CsrfMiddleware::getField() ?>

            <div class="row g-3 mb-3">
              <div class="col-md-6">
                <label class="form-label small fw-bold">Patient Code (Immutable)</label>
                <input type="text" class="form-control font-mono bg-light" value="<?= htmlspecialchars($patient['patient_code']) ?>" readonly>
              </div>
              <div class="col-md-6">
                <label for="name" class="form-label small fw-bold">Full Legal Name <span class="text-danger">*</span></label>
                <input type="text" class="form-control" id="name" name="name" required value="<?= htmlspecialchars($_POST['name'] ?? $patient['name']) ?>">
              </div>
            </div>

            <div class="row g-3 mb-3">
              <div class="col-md-4">
                <label for="date_of_birth" class="form-label small fw-bold">Date of Birth <span class="text-danger">*</span></label>
                <input type="date" class="form-control" id="date_of_birth" name="date_of_birth" required value="<?= htmlspecialchars($_POST['date_of_birth'] ?? $patient['date_of_birth']) ?>">
              </div>
              <div class="col-md-4">
                <label for="gender" class="form-label small fw-bold">Gender <span class="text-danger">*</span></label>
                <select class="form-select" id="gender" name="gender" required>
                  <option value="Male" <?= (($patient['gender'] ?? '') === 'Male') ? 'selected' : '' ?>>Male</option>
                  <option value="Female" <?= (($patient['gender'] ?? '') === 'Female') ? 'selected' : '' ?>>Female</option>
                  <option value="Other" <?= (($patient['gender'] ?? '') === 'Other') ? 'selected' : '' ?>>Other</option>
                </select>
              </div>
              <div class="col-md-4">
                <label for="phone" class="form-label small fw-bold">Phone Number <span class="text-danger">*</span></label>
                <input type="tel" class="form-control" id="phone" name="phone" required value="<?= htmlspecialchars($_POST['phone'] ?? $patient['phone']) ?>">
              </div>
            </div>

            <div class="mb-3">
              <label for="address" class="form-label small fw-bold">Residential Address <span class="text-danger">*</span></label>
              <textarea class="form-control" id="address" name="address" rows="2" required><?= htmlspecialchars($_POST['address'] ?? $patient['address']) ?></textarea>
            </div>

            <div class="mb-4">
              <label for="emergency_contact" class="form-label small fw-bold">Emergency Contact Details <span class="text-danger">*</span></label>
              <input type="text" class="form-control" id="emergency_contact" name="emergency_contact" required value="<?= htmlspecialchars($_POST['emergency_contact'] ?? $patient['emergency_contact']) ?>">
            </div>

            <div class="d-flex justify-content-end gap-2">
              <a href="index.php?page=patient-view&id=<?= $id ?>" class="btn btn-outline-secondary">Cancel</a>
              <button type="submit" class="btn btn-primary fw-bold">
                <i class="bi bi-shield-lock me-1"></i> Authorize & Anchor Version <?= $nextVersion ?>
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  </div>
</div>
