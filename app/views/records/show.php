<?php
/**
 * Medical Record Details & Version History View
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

require_once __DIR__ . '/../../middleware/AuthMiddleware.php';
require_once __DIR__ . '/../../models/MedicalRecord.php';

$user = AuthMiddleware::requireAuth();
$id = (int)($_GET['id'] ?? 0);

$recordModel = new MedicalRecord();
$record = $recordModel->findById($id);

if (!$record) {
    die("Medical Record #{$id} not found.");
}

$versions = $recordModel->getVersions($id);
$isCreated = isset($_GET['created']);
$isAmended = isset($_GET['amended']);
?>

<div class="container-fluid px-4 py-4">
  <?php if ($isCreated): ?>
    <div class="alert alert-success alert-dismissible fade show d-flex align-items-center gap-2 mb-4">
      <i class="bi bi-check-circle-fill fs-5"></i>
      <div>
        <strong>Clinical record created!</strong> Version 1 SHA-256 hash has been anchored onto the Ethereum blockchain.
      </div>
      <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    </div>
  <?php elseif ($isAmended): ?>
    <div class="alert alert-info alert-dismissible fade show d-flex align-items-center gap-2 mb-4">
      <i class="bi bi-shield-check fs-5"></i>
      <div>
        <strong>Authorized amendment recorded!</strong> New Version <?= (int)$record['current_version'] ?> anchored on the blockchain. Prior versions remain immutable.
      </div>
      <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    </div>
  <?php endif; ?>

  <!-- Top Header -->
  <div class="d-flex flex-column flex-md-row justify-content-between align-items-md-center mb-4 gap-2">
    <div>
      <div class="d-flex align-items-center gap-2">
        <h3 class="fw-bold mb-0">Medical Record #<?= (int)$record['id'] ?></h3>
        <span class="badge bg-primary-subtle text-primary border">Version <?= (int)$record['current_version'] ?></span>
        <span class="status-badge status-<?= strtolower($record['current_anchor_status'] ?? 'pending') ?>">
          <?= htmlspecialchars($record['current_anchor_status'] ?? 'PENDING') ?>
        </span>
      </div>
      <p class="text-muted small mb-0 mt-1">
        Patient: <a href="index.php?page=patient-view&id=<?= (int)$record['patient_id'] ?>" class="fw-semibold text-decoration-none"><?= htmlspecialchars($record['patient_name']) ?></a> (<?= htmlspecialchars($record['patient_code']) ?>) &bull; Doctor: <?= htmlspecialchars($record['doctor_name']) ?>
      </p>
    </div>

    <div class="d-flex gap-2">
      <button type="button" class="btn btn-outline-primary btn-sm d-flex align-items-center gap-1"
              onclick="runSingleVerification('MEDICAL_RECORD', <?= (int)$record['id'] ?>, <?= (int)$record['current_version'] ?>, this)">
        <i class="bi bi-shield-check"></i> Verify Integrity
      </button>
      <?php if (in_array($user['role'], ['admin', 'doctor'], true)): ?>
        <a href="index.php?page=record-amend&id=<?= (int)$record['id'] ?>" class="btn btn-primary btn-sm d-flex align-items-center gap-1">
          <i class="bi bi-pencil-square"></i> Authorized Amendment
        </a>
      <?php endif; ?>
    </div>
  </div>

  <div class="row g-4">
    <!-- Left Column: Current Clinical Snapshot -->
    <div class="col-lg-6">
      <div class="card card-hospital mb-4">
        <div class="card-header-hospital">
          <span><i class="bi bi-file-earmark-medical text-primary me-2"></i> Active Clinical Content (Version <?= (int)$record['current_version'] ?>)</span>
          <span class="badge bg-light text-dark font-mono"><?= htmlspecialchars($record['encounter_code']) ?></span>
        </div>
        <div class="card-body">
          <div class="mb-3">
            <label class="small text-muted fw-bold text-uppercase d-block mb-1">Clinical Diagnosis</label>
            <div class="p-2 bg-light rounded border fw-bold text-primary">
              <?= htmlspecialchars($record['current_diagnosis'] ?? '') ?>
            </div>
          </div>

          <div class="mb-3">
            <label class="small text-muted fw-bold text-uppercase d-block mb-1">Presenting Symptoms</label>
            <div class="p-2 bg-light rounded border">
              <?= nl2br(htmlspecialchars($record['current_symptoms'] ?? '')) ?>
            </div>
          </div>

          <div class="mb-3">
            <label class="small text-muted fw-bold text-uppercase d-block mb-1">Clinical Notes & Objective Findings</label>
            <div class="p-2 bg-light rounded border">
              <?= nl2br(htmlspecialchars($record['current_notes'] ?? 'None recorded.')) ?>
            </div>
          </div>

          <div class="mb-3">
            <label class="small text-muted fw-bold text-uppercase d-block mb-1">Prescriptions & Pharmacotherapy</label>
            <div class="p-2 bg-light rounded border font-mono small">
              <?= nl2br(htmlspecialchars($record['current_prescription'] ?? '')) ?>
            </div>
          </div>

          <div>
            <label class="small text-muted fw-bold text-uppercase d-block mb-1">Treatment Plan & Follow-up</label>
            <div class="p-2 bg-light rounded border">
              <?= nl2br(htmlspecialchars($record['current_treatment_plan'] ?? '')) ?>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Right Column: Blockchain Anchor Proof & Version Ledger -->
    <div class="col-lg-6">
      <!-- Active Hash Proof Card -->
      <div class="card card-hospital mb-4">
        <div class="card-header-hospital">
          <span><i class="bi bi-shield-lock-fill text-success me-2"></i> Current Cryptographic Anchor</span>
          <span class="badge bg-success-subtle text-success">Ethereum Protected</span>
        </div>
        <div class="card-body p-0">
          <table class="table table-sm mb-0">
            <tbody>
              <tr>
                <th class="ps-3 text-muted" style="width: 35%;">SHA-256 Hash</th>
                <td>
                  <span class="hash-badge" title="<?= htmlspecialchars($record['current_hash'] ?? '') ?>">
                    <?= htmlspecialchars($record['current_hash'] ?? 'N/A') ?>
                  </span>
                </td>
              </tr>
              <tr>
                <th class="ps-3 text-muted">Anchor Status</th>
                <td>
                  <span class="status-badge status-<?= strtolower($record['current_anchor_status'] ?? 'pending') ?>">
                    <?= htmlspecialchars($record['current_anchor_status'] ?? 'PENDING') ?>
                  </span>
                </td>
              </tr>
              <tr>
                <th class="ps-3 text-muted">Transaction ID</th>
                <td>
                  <code class="text-primary text-break"><?= htmlspecialchars($record['current_tx_hash'] ?? 'Pending Block Confirmation') ?></code>
                </td>
              </tr>
              <tr>
                <th class="ps-3 text-muted">Block Height</th>
                <td>
                  <?= $record['current_block_number'] ? "<span class='badge bg-secondary'>Block #{$record['current_block_number']}</span>" : "<span class='text-muted'>Pending</span>" ?>
                </td>
              </tr>
              <tr>
                <th class="ps-3 text-muted">Consultation Date</th>
                <td class="small text-muted"><?= htmlspecialchars($record['visit_at']) ?></td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Version Ledger -->
      <div class="card card-hospital">
        <div class="card-header-hospital">
          <span><i class="bi bi-clock-history text-secondary me-2"></i> Clinical Version Ledger</span>
          <span class="badge bg-light text-dark"><?= count($versions) ?> Historical Versions</span>
        </div>
        <div class="card-body p-0">
          <div class="table-responsive">
            <table class="table table-hover align-middle mb-0">
              <thead class="table-light small">
                <tr>
                  <th>Version</th>
                  <th>Diagnosis Snapshot</th>
                  <th>Hash</th>
                  <th>Status</th>
                  <th class="text-end">Verify</th>
                </tr>
              </thead>
              <tbody>
                <?php foreach ($versions as $ver): ?>
                  <tr class="<?= ((int)$ver['version_number'] === (int)$record['current_version']) ? 'table-light' : '' ?>">
                    <td>
                      <span class="badge <?= ((int)$ver['version_number'] === (int)$record['current_version']) ? 'bg-primary' : 'bg-secondary' ?>">
                        v<?= (int)$ver['version_number'] ?>
                      </span>
                    </td>
                    <td class="small" style="max-width: 140px;">
                      <div class="text-truncate" title="<?= htmlspecialchars($ver['diagnosis']) ?>">
                        <?= htmlspecialchars($ver['diagnosis']) ?>
                      </div>
                    </td>
                    <td>
                      <span class="hash-badge" title="<?= htmlspecialchars($ver['sha256_hash']) ?>">
                        <?= htmlspecialchars(substr($ver['sha256_hash'], 0, 10)) ?>...
                      </span>
                    </td>
                    <td>
                      <span class="status-badge status-<?= strtolower($ver['anchor_status']) ?>">
                        <?= htmlspecialchars($ver['anchor_status']) ?>
                      </span>
                    </td>
                    <td class="text-end">
                      <button type="button" class="btn btn-outline-primary btn-sm py-0"
                              onclick="runSingleVerification('MEDICAL_RECORD', <?= (int)$record['id'] ?>, <?= (int)$ver['version_number'] ?>, this)">
                        <i class="bi bi-shield-check"></i>
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
