<?php
/**
 * Patient Details and Audit History View
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

require_once __DIR__ . '/../../middleware/AuthMiddleware.php';
require_once __DIR__ . '/../../models/Patient.php';
require_once __DIR__ . '/../../models/Encounter.php';
require_once __DIR__ . '/../../models/MedicalRecord.php';

$user = AuthMiddleware::requireAuth();
$id = (int)($_GET['id'] ?? 0);

$patientModel = new Patient();
$patient = $patientModel->findById($id);

if (!$patient) {
    die("Patient #{$id} not found.");
}

$versions = $patientModel->getVersions($id);
$encounterModel = new Encounter();
$encounters = $encounterModel->getByPatient($id);

$isCreated = isset($_GET['created']);
?>

<div class="container-fluid px-4 py-4">
  <?php if ($isCreated): ?>
    <div class="alert alert-success alert-dismissible fade show d-flex align-items-center gap-2 mb-4" role="alert">
      <i class="bi bi-check-circle-fill fs-5"></i>
      <div>
        <strong>Patient successfully registered!</strong> Initial demographic version (v1) has been canonicalized and anchored on the Ethereum blockchain.
      </div>
      <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    </div>
  <?php endif; ?>

  <!-- Header -->
  <div class="d-flex flex-column flex-md-row justify-content-between align-items-md-center mb-4 gap-2">
    <div>
      <div class="d-flex align-items-center gap-2">
        <h3 class="fw-bold mb-0"><?= htmlspecialchars($patient['name']) ?></h3>
        <span class="badge bg-light text-primary border font-mono fs-6"><?= htmlspecialchars($patient['patient_code']) ?></span>
        <span class="badge bg-info-subtle text-info border">Version <?= (int)$patient['current_profile_version'] ?></span>
      </div>
      <p class="text-muted small mb-0 mt-1">Patient Profile & Blockchain Anchored Version Ledger</p>
    </div>
    <div class="d-flex gap-2">
      <button type="button" class="btn btn-outline-primary btn-sm d-flex align-items-center gap-1"
              onclick="runSingleVerification('PATIENT_PROFILE', <?= (int)$patient['id'] ?>, <?= (int)$patient['current_profile_version'] ?>, this)">
        <i class="bi bi-shield-check"></i> Verify Integrity
      </button>
      <?php if (in_array($user['role'], ['admin', 'staff'], true)): ?>
        <a href="index.php?page=patient-edit&id=<?= (int)$patient['id'] ?>" class="btn btn-outline-secondary btn-sm d-flex align-items-center gap-1">
          <i class="bi bi-pencil"></i> Amend Profile
        </a>
      <?php endif; ?>
      <?php if (in_array($user['role'], ['admin', 'doctor'], true)): ?>
        <a href="index.php?page=record-create&patient_id=<?= (int)$patient['id'] ?>" class="btn btn-primary btn-sm d-flex align-items-center gap-1">
          <i class="bi bi-plus-circle"></i> New Clinical Visit
        </a>
      <?php endif; ?>
    </div>
  </div>

  <div class="row g-4">
    <!-- Left Column: Current Demographics -->
    <div class="col-lg-4">
      <div class="card card-hospital mb-4">
        <div class="card-header-hospital">
          <span><i class="bi bi-person-badge text-primary me-2"></i> Current Demographic Data</span>
          <span class="badge bg-secondary-subtle text-secondary"><?= htmlspecialchars($patient['gender']) ?></span>
        </div>
        <div class="card-body p-0">
          <table class="table table-sm mb-0">
            <tbody>
              <tr>
                <th class="ps-3 text-muted" style="width: 40%;">DOB</th>
                <td><?= htmlspecialchars($patient['date_of_birth']) ?></td>
              </tr>
              <tr>
                <th class="ps-3 text-muted">Phone</th>
                <td class="font-mono"><?= htmlspecialchars($patient['phone']) ?></td>
              </tr>
              <tr>
                <th class="ps-3 text-muted">Address</th>
                <td><?= nl2br(htmlspecialchars($patient['address'])) ?></td>
              </tr>
              <tr>
                <th class="ps-3 text-muted">Emergency</th>
                <td><?= htmlspecialchars($patient['emergency_contact']) ?></td>
              </tr>
              <tr>
                <th class="ps-3 text-muted">Registered By</th>
                <td><?= htmlspecialchars($patient['created_by_name'] ?? 'System') ?></td>
              </tr>
              <tr>
                <th class="ps-3 text-muted">Registered At</th>
                <td class="small text-muted"><?= htmlspecialchars($patient['created_at']) ?></td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Clinical Encounters Card -->
      <div class="card card-hospital">
        <div class="card-header-hospital">
          <span><i class="bi bi-calendar2-heart text-info me-2"></i> Clinical Encounters</span>
          <span class="badge bg-light text-dark"><?= count($encounters) ?> Total</span>
        </div>
        <div class="card-body p-0">
          <?php if (empty($encounters)): ?>
            <div class="p-3 text-center text-muted small">No clinical visits recorded yet.</div>
          <?php else: ?>
            <div class="list-group list-group-flush small">
              <?php foreach ($encounters as $enc): ?>
                <div class="list-group-item p-3">
                  <div class="d-flex justify-content-between align-items-center mb-1">
                    <span class="font-mono fw-bold text-primary"><?= htmlspecialchars($enc['encounter_code']) ?></span>
                    <span class="text-muted"><?= htmlspecialchars(date('M d, Y', strtotime($enc['visit_at']))) ?></span>
                  </div>
                  <div class="mb-1 text-dark"><?= htmlspecialchars($enc['reason']) ?></div>
                  <div class="text-muted mb-2">Doctor: <?= htmlspecialchars($enc['doctor_name']) ?></div>
                  <?php if (!empty($enc['medical_record_id'])): ?>
                    <a href="index.php?page=record-view&id=<?= (int)$enc['medical_record_id'] ?>" class="btn btn-outline-primary btn-sm py-0">
                      <i class="bi bi-file-earmark-medical"></i> View Clinical Record (v<?= (int)$enc['current_version'] ?>)
                    </a>
                  <?php endif; ?>
                </div>
              <?php endforeach; ?>
            </div>
          <?php endif; ?>
        </div>
      </div>
    </div>

    <!-- Right Column: Demographic Profile Version Ledger -->
    <div class="col-lg-8">
      <div class="card card-hospital">
        <div class="card-header-hospital">
          <span><i class="bi bi-journal-code text-secondary me-2"></i> Demographic Profile Version Ledger (Append-Only)</span>
          <span class="badge bg-light text-dark"><?= count($versions) ?> Historical Versions</span>
        </div>
        <div class="card-body p-0">
          <div class="table-responsive">
            <table class="table table-hover align-middle mb-0">
              <thead class="table-light small">
                <tr>
                  <th>Version</th>
                  <th>Protected SHA-256 Hash</th>
                  <th>Blockchain Status</th>
                  <th>Anchored At</th>
                  <th class="text-end">Verify</th>
                </tr>
              </thead>
              <tbody>
                <?php foreach ($versions as $ver): ?>
                  <tr class="<?= ((int)$ver['version_number'] === (int)$patient['current_profile_version']) ? 'table-light' : '' ?>">
                    <td>
                      <span class="badge <?= ((int)$ver['version_number'] === (int)$patient['current_profile_version']) ? 'bg-primary' : 'bg-secondary' ?>">
                        v<?= (int)$ver['version_number'] ?>
                      </span>
                      <?php if ((int)$ver['version_number'] === (int)$patient['current_profile_version']): ?>
                        <span class="badge bg-light text-primary border ms-1">Current</span>
                      <?php endif; ?>
                    </td>
                    <td>
                      <span class="hash-badge" title="<?= htmlspecialchars($ver['sha256_hash']) ?>">
                        <?= htmlspecialchars(substr($ver['sha256_hash'], 0, 16)) ?>...<?= htmlspecialchars(substr($ver['sha256_hash'], -8)) ?>
                      </span>
                    </td>
                    <td>
                      <span class="status-badge status-<?= strtolower($ver['anchor_status']) ?>">
                        <?= htmlspecialchars($ver['anchor_status']) ?>
                      </span>
                      <?php if (!empty($ver['transaction_hash'])): ?>
                        <div class="small font-mono text-muted text-truncate" style="max-width: 140px;" title="<?= htmlspecialchars($ver['transaction_hash']) ?>">
                          Tx: <?= htmlspecialchars(substr($ver['transaction_hash'], 0, 10)) ?>...
                        </div>
                      <?php endif; ?>
                    </td>
                    <td class="small text-muted text-nowrap">
                      <?= htmlspecialchars(date('M d, Y H:i', strtotime($ver['created_at']))) ?>
                    </td>
                    <td class="text-end">
                      <button type="button" class="btn btn-outline-primary btn-sm py-1"
                              onclick="runSingleVerification('PATIENT_PROFILE', <?= (int)$patient['id'] ?>, <?= (int)$ver['version_number'] ?>, this)">
                        <i class="bi bi-shield-check"></i> Verify
                      </button>
                    </td>
                  </tr>
                <?php endforeach; ?>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>
