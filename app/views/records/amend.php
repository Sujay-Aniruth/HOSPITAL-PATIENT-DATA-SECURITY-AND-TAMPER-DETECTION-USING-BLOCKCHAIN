<?php
/**
 * Medical Record Authorized Amendment View
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

require_once __DIR__ . '/../../middleware/AuthMiddleware.php';
require_once __DIR__ . '/../../middleware/CsrfMiddleware.php';
require_once __DIR__ . '/../../models/MedicalRecord.php';

$user = AuthMiddleware::requireRole(['admin', 'doctor']);
$id = (int)($_GET['id'] ?? 0);

$recordModel = new MedicalRecord();
$record = $recordModel->findById($id);

if (!$record) {
    die("Medical Record #{$id} not found.");
}

$nextVersion = (int)$record['current_version'] + 1;
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    CsrfMiddleware::requireValid();
    try {
        $result = $recordModel->amend($id, $_POST, (int)$user['id']);
        header("Location: index.php?page=record-view&id={$id}&amended=1");
        exit;
    } catch (Throwable $e) {
        $error = $e->getMessage();
    }
}
?>

<div class="container-fluid px-4 py-4">
  <div class="row justify-content-center">
    <div class="col-lg-9">
      <div class="d-flex align-items-center justify-content-between mb-4">
        <div>
          <h3 class="fw-bold mb-1">Authorized Clinical Amendment</h3>
          <p class="text-muted small mb-0">Record #<?= $id ?> &bull; Patient: <?= htmlspecialchars($record['patient_name']) ?> (<?= htmlspecialchars($record['patient_code']) ?>)</p>
        </div>
        <a href="index.php?page=record-view&id=<?= $id ?>" class="btn btn-outline-secondary btn-sm">
          <i class="bi bi-arrow-left"></i> Cancel
        </a>
      </div>

      <!-- Integrity Notice Box -->
      <div class="alert alert-warning py-3 small mb-4">
        <div class="d-flex gap-2">
          <i class="bi bi-shield-lock-fill fs-5 text-warning"></i>
          <div>
            <strong>Authorized Versioning Workflow:</strong>
            Submitting this clinical revision creates <strong>Version <?= $nextVersion ?></strong> and securely anchors its SHA-256 hash onto the Ethereum blockchain. Previous clinical versions (v1 to v<?= (int)$record['current_version'] ?>) are retained permanently in the audit history.
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
          <span><i class="bi bi-pencil-square text-primary me-2"></i> Amend Clinical Findings & Orders</span>
          <span class="badge bg-primary">Creating Version: v<?= $nextVersion ?></span>
        </div>
        <div class="card-body p-4">
          <form method="POST" action="index.php?page=record-amend&id=<?= $id ?>">
            <?= CsrfMiddleware::getField() ?>

            <div class="mb-3">
              <label for="diagnosis" class="form-label small fw-bold">Updated Clinical Diagnosis <span class="text-danger">*</span></label>
              <input type="text" class="form-control" id="diagnosis" name="diagnosis" required value="<?= htmlspecialchars($_POST['diagnosis'] ?? $record['current_diagnosis'] ?? '') ?>">
            </div>

            <div class="mb-3">
              <label for="symptoms" class="form-label small fw-bold">Presenting Symptoms <span class="text-danger">*</span></label>
              <textarea class="form-control" id="symptoms" name="symptoms" rows="2" required><?= htmlspecialchars($_POST['symptoms'] ?? $record['current_symptoms'] ?? '') ?></textarea>
            </div>

            <div class="mb-3">
              <label for="notes" class="form-label small fw-bold">Clinical Notes & Addendum</label>
              <textarea class="form-control" id="notes" name="notes" rows="3"><?= htmlspecialchars($_POST['notes'] ?? $record['current_notes'] ?? '') ?></textarea>
            </div>

            <div class="mb-3">
              <label for="prescription" class="form-label small fw-bold">Updated Prescriptions <span class="text-danger">*</span></label>
              <textarea class="form-control" id="prescription" name="prescription" rows="2" required><?= htmlspecialchars($_POST['prescription'] ?? $record['current_prescription'] ?? '') ?></textarea>
            </div>

            <div class="mb-4">
              <label for="treatment_plan" class="form-label small fw-bold">Updated Treatment Plan</label>
              <textarea class="form-control" id="treatment_plan" name="treatment_plan" rows="2"><?= htmlspecialchars($_POST['treatment_plan'] ?? $record['current_treatment_plan'] ?? '') ?></textarea>
            </div>

            <div class="d-flex justify-content-end gap-2">
              <a href="index.php?page=record-view&id=<?= $id ?>" class="btn btn-outline-secondary">Cancel</a>
              <button type="submit" class="btn btn-primary fw-bold">
                <i class="bi bi-check-circle-fill me-1"></i> Authorize & Anchor Version <?= $nextVersion ?>
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  </div>
</div>
