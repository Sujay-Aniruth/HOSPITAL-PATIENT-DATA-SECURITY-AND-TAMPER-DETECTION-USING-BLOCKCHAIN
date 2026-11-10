<?php
/**
 * Medical Records Directory View
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

require_once __DIR__ . '/../../middleware/AuthMiddleware.php';
require_once __DIR__ . '/../../models/MedicalRecord.php';

$user = AuthMiddleware::requireAuth();
$recordModel = new MedicalRecord();

$patientId = isset($_GET['patient_id']) ? (int)$_GET['patient_id'] : null;
$records = $recordModel->getAll(50, 0, $patientId);
?>

<div class="container-fluid px-4 py-4">
  <div class="d-flex flex-column flex-md-row justify-content-between align-items-md-center mb-4 gap-2">
    <div>
      <h3 class="fw-bold mb-1">Clinical Medical Records</h3>
      <p class="text-muted small mb-0">Protected patient clinical diagnoses, prescriptions, and cryptographic version ledger</p>
    </div>
    <?php if (in_array($user['role'], ['admin', 'doctor'], true)): ?>
      <a href="index.php?page=record-create" class="btn btn-primary btn-sm d-flex align-items-center gap-1">
        <i class="bi bi-plus-circle"></i> Create Clinical Record
      </a>
    <?php endif; ?>
  </div>

  <div class="card card-hospital">
    <div class="card-body p-0">
      <div class="table-responsive">
        <table class="table table-hover align-middle mb-0">
          <thead class="table-light">
            <tr>
              <th>Record #</th>
              <th>Patient</th>
              <th>Encounter</th>
              <th>Treating Physician</th>
              <th>Current Diagnosis</th>
              <th>Version</th>
              <th>Anchor Status</th>
              <th class="text-end">Actions</th>
            </tr>
          </thead>
          <tbody>
            <?php if (empty($records)): ?>
              <tr>
                <td colspan="8" class="text-center py-5 text-muted">
                  <i class="bi bi-folder-x fs-1 d-block mb-2"></i>
                  No medical records found.
                </td>
              </tr>
            <?php else: ?>
              <?php foreach ($records as $rec): ?>
                <tr>
                  <td>
                    <span class="badge bg-light text-dark border font-mono">
                      REC-#<?= (int)$rec['id'] ?>
                    </span>
                  </td>
                  <td>
                    <a href="index.php?page=patient-view&id=<?= (int)$rec['patient_id'] ?>" class="text-decoration-none fw-bold">
                      <?= htmlspecialchars($rec['patient_name']) ?>
                    </a>
                    <div class="small text-muted font-mono"><?= htmlspecialchars($rec['patient_code']) ?></div>
                  </td>
                  <td>
                    <span class="badge bg-secondary-subtle text-secondary font-mono">
                      <?= htmlspecialchars($rec['encounter_code']) ?>
                    </span>
                    <div class="small text-muted"><?= htmlspecialchars(date('M d, Y', strtotime($rec['visit_at']))) ?></div>
                  </td>
                  <td class="small"><?= htmlspecialchars($rec['doctor_name']) ?></td>
                  <td class="small" style="max-width: 250px;">
                    <div class="text-truncate fw-semibold" title="<?= htmlspecialchars($rec['current_diagnosis'] ?? '') ?>">
                      <?= htmlspecialchars($rec['current_diagnosis'] ?? 'No Diagnosis') ?>
                    </div>
                  </td>
                  <td>
                    <span class="badge bg-primary-subtle text-primary border">
                      v<?= (int)$rec['current_version'] ?>
                    </span>
                  </td>
                  <td>
                    <span class="status-badge status-<?= strtolower($rec['anchor_status'] ?? 'pending') ?>">
                      <?= htmlspecialchars($rec['anchor_status'] ?? 'PENDING') ?>
                    </span>
                  </td>
                  <td class="text-end">
                    <div class="btn-group btn-group-sm">
                      <a href="index.php?page=record-view&id=<?= (int)$rec['id'] ?>" class="btn btn-outline-secondary" title="View Details & Audit History">
                        <i class="bi bi-eye"></i>
                      </a>
                      <button type="button" class="btn btn-outline-primary" title="Cryptographically Verify Current Clinical Version"
                              onclick="runSingleVerification('MEDICAL_RECORD', <?= (int)$rec['id'] ?>, <?= (int)$rec['current_version'] ?>, this)">
                        <i class="bi bi-shield-check"></i>
                      </button>
                      <?php if (in_array($user['role'], ['admin', 'doctor'], true)): ?>
                        <a href="index.php?page=record-amend&id=<?= (int)$rec['id'] ?>" class="btn btn-outline-secondary" title="Authorized Clinical Amendment">
                          <i class="bi bi-pencil"></i>
                        </a>
                      <?php endif; ?>
                    </div>
                  </td>
                </tr>
              <?php endforeach; ?>
            <?php endif; ?>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</div>
