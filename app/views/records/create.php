<?php
/**
 * Create Clinical Medical Record View
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

require_once __DIR__ . '/../../middleware/AuthMiddleware.php';
require_once __DIR__ . '/../../middleware/CsrfMiddleware.php';
require_once __DIR__ . '/../../models/Patient.php';
require_once __DIR__ . '/../../models/MedicalRecord.php';
require_once __DIR__ . '/../../models/Encounter.php';

$user = AuthMiddleware::requireRole(['admin', 'doctor']);
$patientModel = new Patient();
$patients = $patientModel->getAll('', 100);

$preselectedPatientId = (int)($_GET['patient_id'] ?? 0);
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    CsrfMiddleware::requireValid();
    $patientId = (int)($_POST['patient_id'] ?? 0);
    $encounterId = (int)($_POST['encounter_id'] ?? 0);

    try {
        if ($encounterId <= 0) {
            $encounterModel = new Encounter();
            $visitAt = !empty($_POST['visit_at']) ? trim((string)$_POST['visit_at']) : date('Y-m-d H:i:s');
            $reason = !empty($_POST['reason']) ? trim((string)$_POST['reason']) : 'Clinical Consultation';
            $encounterId = $encounterModel->create($patientId, (int)$user['id'], $visitAt, $reason);
        }

        $recordModel = new MedicalRecord();
        $result = $recordModel->create($patientId, $encounterId, $_POST, (int)$user['id']);
        header("Location: index.php?page=record-view&id={$result['medical_record_id']}&created=1");
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
          <h3 class="fw-bold mb-1">Create Clinical Medical Record</h3>
          <p class="text-muted small mb-0">Record clinical examination findings, diagnoses, and anchor cryptographic integrity proof.</p>
        </div>
        <a href="index.php?page=records" class="btn btn-outline-secondary btn-sm">
          <i class="bi bi-arrow-left"></i> Cancel
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
          <span><i class="bi bi-clipboard2-pulse text-primary me-2"></i> Clinical Consultation Form</span>
          <span class="badge bg-primary">Creating Version: v1</span>
        </div>
        <div class="card-body p-4">
          <form method="POST" action="index.php?page=record-create">
            <?= CsrfMiddleware::getField() ?>

            <!-- Patient and Visit Selection -->
            <div class="row g-3 mb-4">
              <div class="col-md-6">
                <label for="patient_id" class="form-label small fw-bold">Select Patient <span class="text-danger">*</span></label>
                <select class="form-select" id="patient_id" name="patient_id" required>
                  <option value="">-- Choose Patient --</option>
                  <?php foreach ($patients as $p): ?>
                    <option value="<?= (int)$p['id'] ?>" <?= ($preselectedPatientId === (int)$p['id']) ? 'selected' : '' ?>>
                      <?= htmlspecialchars($p['patient_code']) ?> &bull; <?= htmlspecialchars($p['name']) ?> (<?= htmlspecialchars($p['gender']) ?>, <?= htmlspecialchars($p['phone']) ?>)
                    </option>
                  <?php endforeach; ?>
                </select>
              </div>
              <div class="col-md-3">
                <label for="visit_at" class="form-label small fw-bold">Visit Date/Time <span class="text-danger">*</span></label>
                <input type="datetime-local" class="form-control" id="visit_at" name="visit_at" required value="<?= date('Y-m-d\TH:i') ?>">
              </div>
              <div class="col-md-3">
                <label for="reason" class="form-label small fw-bold">Consultation Reason <span class="text-danger">*</span></label>
                <input type="text" class="form-control" id="reason" name="reason" required placeholder="e.g. Chest pain follow-up" value="<?= htmlspecialchars($_POST['reason'] ?? 'Routine Clinical Checkup') ?>">
              </div>
            </div>

            <hr class="my-3 text-muted">

            <!-- Clinical Information -->
            <div class="mb-3">
              <label for="symptoms" class="form-label small fw-bold">Presenting Symptoms <span class="text-danger">*</span></label>
              <textarea class="form-control" id="symptoms" name="symptoms" rows="2" required placeholder="Describe patient complaints, onset, duration, and severity"><?= htmlspecialchars($_POST['symptoms'] ?? '') ?></textarea>
            </div>

            <div class="mb-3">
              <label for="diagnosis" class="form-label small fw-bold">Clinical Diagnosis <span class="text-danger">*</span></label>
              <input type="text" class="form-control" id="diagnosis" name="diagnosis" required placeholder="e.g. Essential Primary Hypertension (Stage 1)" value="<?= htmlspecialchars($_POST['diagnosis'] ?? '') ?>">
            </div>

            <div class="mb-3">
              <label for="notes" class="form-label small fw-bold">Clinical Notes & Objective Findings</label>
              <textarea class="form-control" id="notes" name="notes" rows="3" placeholder="Blood pressure, heart rate, physical examination notes, lab observations"><?= htmlspecialchars($_POST['notes'] ?? '') ?></textarea>
            </div>

            <div class="mb-3">
              <label for="prescription" class="form-label small fw-bold">Prescriptions & Pharmacotherapy <span class="text-danger">*</span></label>
              <textarea class="form-control" id="prescription" name="prescription" rows="2" required placeholder="Medication, dosage, frequency, and instructions"><?= htmlspecialchars($_POST['prescription'] ?? '') ?></textarea>
            </div>

            <div class="mb-4">
              <label for="treatment_plan" class="form-label small fw-bold">Treatment Plan & Follow-up</label>
              <textarea class="form-control" id="treatment_plan" name="treatment_plan" rows="2" placeholder="Lifestyle modifications, dietary guidance, review schedule"><?= htmlspecialchars($_POST['treatment_plan'] ?? '') ?></textarea>
            </div>

            <!-- Blockchain Notice -->
            <div class="alert alert-info py-2 small d-flex align-items-center gap-2 mb-4">
              <i class="bi bi-shield-lock-fill fs-5"></i>
              <div>
                <strong>Cryptographic Anchor Commitment:</strong> These clinical fields will be canonicalized according to schema v1.0 and hashed using SHA-256. The hash will be permanently written to the smart contract at block height.
              </div>
            </div>

            <div class="d-flex justify-content-end gap-2">
              <a href="index.php?page=records" class="btn btn-outline-secondary">Cancel</a>
              <button type="submit" class="btn btn-primary fw-bold">
                <i class="bi bi-shield-check me-1"></i> Save Clinical Record & Anchor
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  </div>
</div>
