<?php
/**
 * Integrity Verification Center View
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

require_once __DIR__ . '/../../middleware/AuthMiddleware.php';
require_once __DIR__ . '/../../middleware/CsrfMiddleware.php';
require_once __DIR__ . '/../../models/IntegrityCheck.php';
require_once __DIR__ . '/../../services/BlockchainService.php';

$user = AuthMiddleware::requireAuth();
$checkModel = new IntegrityCheck();
$recentChecks = $checkModel->getRecent(50);
$stats = $checkModel->getStats();

$blockchain = new BlockchainService();
$nodeStatus = $blockchain->getStatus();
?>

<div class="container-fluid px-4 py-4">
  <div class="d-flex flex-column flex-md-row justify-content-between align-items-md-center mb-4 gap-2">
    <div>
      <h3 class="fw-bold mb-1">Cryptographic Integrity Verification Center</h3>
      <p class="text-muted small mb-0">Mathematically audit stored MySQL records against immutable Ethereum blockchain anchors</p>
    </div>
    <div class="d-flex gap-2">
      <button type="button" class="btn btn-primary btn-sm d-flex align-items-center gap-1" onclick="runBulkVerification('<?= CsrfMiddleware::getToken() ?>', this)">
        <i class="bi bi-shield-check"></i> Run Bulk System Audit
      </button>
    </div>
  </div>

  <!-- Top Metrics Row -->
  <div class="row g-3 mb-4">
    <div class="col-sm-6 col-md-3">
      <div class="kpi-card">
        <div class="kpi-icon blue"><i class="bi bi-clipboard2-check"></i></div>
        <div>
          <div class="kpi-value"><?= $stats['total_checks'] ?></div>
          <div class="kpi-label">Total Verifications</div>
        </div>
      </div>
    </div>
    <div class="col-sm-6 col-md-3">
      <div class="kpi-card">
        <div class="kpi-icon green"><i class="bi bi-shield-check"></i></div>
        <div>
          <div class="kpi-value text-success"><?= $stats['valid_count'] ?></div>
          <div class="kpi-label">Confirmed Valid</div>
        </div>
      </div>
    </div>
    <div class="col-sm-6 col-md-3">
      <div class="kpi-card">
        <div class="kpi-icon red"><i class="bi bi-shield-slash-fill"></i></div>
        <div>
          <div class="kpi-value text-danger"><?= $stats['tampered_count'] ?></div>
          <div class="kpi-label">Tamper Detections</div>
        </div>
      </div>
    </div>
    <div class="col-sm-6 col-md-3">
      <div class="kpi-card">
        <div class="kpi-icon amber"><i class="bi bi-hourglass-split"></i></div>
        <div>
          <div class="kpi-value text-warning"><?= $stats['pending_count'] + $stats['missing_anchor_count'] ?></div>
          <div class="kpi-label">Pending / Missing</div>
        </div>
      </div>
    </div>
  </div>

  <!-- Interactive Verification Tool Card -->
  <div class="card card-hospital mb-4">
    <div class="card-header-hospital">
      <span><i class="bi bi-search text-primary me-2"></i> Targeted Cryptographic Audit</span>
      <span class="badge bg-light text-dark">On-Demand Verification</span>
    </div>
    <div class="card-body p-4">
      <form id="singleVerifyForm" class="row g-3 align-items-end" onsubmit="event.preventDefault(); triggerManualVerify();">
        <div class="col-md-4">
          <label for="target_type" class="form-label small fw-bold">Record Category</label>
          <select class="form-select" id="target_type" required>
            <option value="MEDICAL_RECORD" selected>Clinical Medical Record</option>
            <option value="PATIENT_PROFILE">Patient Demographic Profile</option>
          </select>
        </div>
        <div class="col-md-3">
          <label for="target_id" class="form-label small fw-bold">Internal Record ID</label>
          <input type="number" class="form-control" id="target_id" required min="1" value="1" placeholder="e.g. 1">
        </div>
        <div class="col-md-2">
          <label for="target_version" class="form-label small fw-bold">Version Number</label>
          <input type="number" class="form-control" id="target_version" required min="1" value="1" placeholder="e.g. 1">
        </div>
        <div class="col-md-3">
          <button type="submit" id="btnManualVerify" class="btn btn-primary w-100 fw-bold">
            <i class="bi bi-shield-check me-1"></i> Verify Against Blockchain
          </button>
        </div>
      </form>
    </div>
  </div>

  <!-- Verification History Table -->
  <div class="card card-hospital">
    <div class="card-header-hospital">
      <span><i class="bi bi-journal-check text-secondary me-2"></i> Cryptographic Audit Log Ledger</span>
      <span class="badge bg-light text-dark"><?= count($recentChecks) ?> Logged Events</span>
    </div>
    <div class="card-body p-0">
      <div class="table-responsive">
        <table class="table table-hover align-middle mb-0">
          <thead class="table-light small">
            <tr>
              <th>Target Record</th>
              <th>Calculated SHA-256 (MySQL)</th>
              <th>Anchored SHA-256 (Blockchain)</th>
              <th>Integrity Outcome</th>
              <th>Audited By</th>
              <th>Timestamp</th>
              <th class="text-end">Re-Verify</th>
            </tr>
          </thead>
          <tbody>
            <?php if (empty($recentChecks)): ?>
              <tr>
                <td colspan="7" class="text-center py-5 text-muted">
                  <i class="bi bi-shield-exclamation fs-1 d-block mb-2"></i>
                  No cryptographic verification checks recorded yet.
                </td>
              </tr>
            <?php else: ?>
              <?php foreach ($recentChecks as $check): ?>
                <?php $isMatch = ($check['result'] === 'VALID'); ?>
                <tr class="<?= $check['result'] === 'TAMPERED' ? 'table-danger' : '' ?>">
                  <td>
                    <span class="badge bg-light text-dark border font-mono"><?= htmlspecialchars($check['record_type']) ?></span>
                    <strong>#<?= (int)$check['record_id'] ?></strong>
                    <div class="small text-muted">Version <?= (int)$check['version_number'] ?></div>
                  </td>
                  <td>
                    <span class="hash-badge <?= $isMatch ? 'match' : ($check['result'] === 'TAMPERED' ? 'mismatch' : '') ?>" title="<?= htmlspecialchars($check['calculated_hash']) ?>">
                      <?= htmlspecialchars(substr($check['calculated_hash'], 0, 14)) ?>...<?= htmlspecialchars(substr($check['calculated_hash'], -6)) ?>
                    </span>
                  </td>
                  <td>
                    <?php if (!empty($check['blockchain_hash'])): ?>
                      <span class="hash-badge <?= $isMatch ? 'match' : 'mismatch' ?>" title="<?= htmlspecialchars($check['blockchain_hash']) ?>">
                        <?= htmlspecialchars(substr($check['blockchain_hash'], 0, 14)) ?>...<?= htmlspecialchars(substr($check['blockchain_hash'], -6)) ?>
                      </span>
                    <?php else: ?>
                      <span class="text-muted small">No On-Chain Anchor</span>
                    <?php endif; ?>
                  </td>
                  <td>
                    <span class="status-badge status-<?= strtolower($check['result']) ?>">
                      <?= htmlspecialchars($check['result']) ?>
                    </span>
                  </td>
                  <td class="small"><?= htmlspecialchars($check['checked_by_name'] ?? 'System') ?></td>
                  <td class="small text-muted text-nowrap"><?= htmlspecialchars(date('M d, Y H:i:s', strtotime($check['checked_at']))) ?></td>
                  <td class="text-end">
                    <button type="button" class="btn btn-outline-primary btn-sm py-0"
                            onclick="runSingleVerification('<?= htmlspecialchars($check['record_type']) ?>', <?= (int)$check['record_id'] ?>, <?= (int)$check['version_number'] ?>, this)">
                      <i class="bi bi-arrow-repeat"></i> Verify
                    </button>
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

<script>
function triggerManualVerify() {
  const type = document.getElementById('target_type').value;
  const id = document.getElementById('target_id').value;
  const version = document.getElementById('target_version').value;
  const btn = document.getElementById('btnManualVerify');
  runSingleVerification(type, id, version, btn);
}
</script>
