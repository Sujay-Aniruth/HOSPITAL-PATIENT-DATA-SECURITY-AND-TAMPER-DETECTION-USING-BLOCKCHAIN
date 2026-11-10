<?php
/**
 * Dashboard View
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';
require_once __DIR__ . '/../../middleware/AuthMiddleware.php';
require_once __DIR__ . '/../../middleware/CsrfMiddleware.php';
require_once __DIR__ . '/../../models/IntegrityCheck.php';
require_once __DIR__ . '/../../models/SecurityAlert.php';
require_once __DIR__ . '/../../services/BlockchainService.php';

$user = AuthMiddleware::requireAuth();
$db = Database::getConnection();

// Entity counts
$patCount = (int)$db->query("SELECT COUNT(*) FROM `patients`")->fetchColumn();
$recCount = (int)$db->query("SELECT COUNT(*) FROM `medical_records`")->fetchColumn();
$anchoredPat = (int)$db->query("SELECT COUNT(*) FROM `patient_profile_versions` WHERE `anchor_status` = 'ANCHORED'")->fetchColumn();
$anchoredMed = (int)$db->query("SELECT COUNT(*) FROM `medical_record_versions` WHERE `anchor_status` = 'ANCHORED'")->fetchColumn();
$totalAnchored = $anchoredPat + $anchoredMed;

$checkModel = new IntegrityCheck();
$checkStats = $checkModel->getStats();
$recentChecks = $checkModel->getRecent(8);

$alertModel = new SecurityAlert();
$activeAlerts = $alertModel->getActive(5);
$unresolvedCount = $alertModel->countUnresolved();

$blockchain = new BlockchainService();
$nodeStatus = $blockchain->getStatus();
?>

<div class="container-fluid px-4 py-4">
  <!-- Page Header -->
  <div class="d-flex flex-column flex-md-row justify-content-between align-items-md-center mb-4 gap-2">
    <div>
      <h3 class="fw-bold mb-1">Security & Integrity Operations Dashboard</h3>
      <p class="text-muted small mb-0">Real-time status of local MySQL patient store and Ethereum blockchain anchors</p>
    </div>
    <div class="d-flex gap-2">
      <button type="button" class="btn btn-outline-primary btn-sm d-flex align-items-center gap-1" onclick="runBulkVerification('<?= CsrfMiddleware::getToken() ?>', this)">
        <i class="bi bi-shield-check"></i> Run System Audit
      </button>
      <?php if ($user['role'] === 'admin'): ?>
        <a href="index.php?page=demo" class="btn btn-danger btn-sm d-flex align-items-center gap-1">
          <i class="bi bi-bug"></i> Tampering Lab
        </a>
      <?php endif; ?>
    </div>
  </div>

  <!-- KPI Metrics Cards Row -->
  <div class="row g-3 mb-4">
    <div class="col-sm-6 col-xl-3">
      <div class="kpi-card">
        <div class="kpi-icon blue"><i class="bi bi-people-fill"></i></div>
        <div>
          <div class="kpi-value"><?= $patCount ?></div>
          <div class="kpi-label">Registered Patients</div>
        </div>
      </div>
    </div>
    <div class="col-sm-6 col-xl-3">
      <div class="kpi-card">
        <div class="kpi-icon purple"><i class="bi bi-file-earmark-medical-fill"></i></div>
        <div>
          <div class="kpi-value"><?= $recCount ?></div>
          <div class="kpi-label">Clinical Records</div>
        </div>
      </div>
    </div>
    <div class="col-sm-6 col-xl-3">
      <div class="kpi-card">
        <div class="kpi-icon green"><i class="bi bi-link-45deg"></i></div>
        <div>
          <div class="kpi-value"><?= $totalAnchored ?></div>
          <div class="kpi-label">Anchored Versions</div>
        </div>
      </div>
    </div>
    <div class="col-sm-6 col-xl-3">
      <div class="kpi-card">
        <div class="kpi-icon <?= $unresolvedCount > 0 ? 'red' : 'green' ?>">
          <i class="bi <?= $unresolvedCount > 0 ? 'bi-exclamation-triangle-fill' : 'bi-shield-check' ?>"></i>
        </div>
        <div>
          <div class="kpi-value text-<?= $unresolvedCount > 0 ? 'danger' : 'success' ?>"><?= $unresolvedCount ?></div>
          <div class="kpi-label">Tamper Alerts</div>
        </div>
      </div>
    </div>
  </div>

  <!-- Main Content Row -->
  <div class="row g-4">
    <!-- Left Column: Verification Breakdown & Blockchain Status -->
    <div class="col-lg-5">
      <!-- Integrity Breakdown Chart -->
      <div class="card card-hospital mb-4">
        <div class="card-header-hospital">
          <span><i class="bi bi-pie-chart-fill text-primary me-2"></i> Integrity Verification Outcomes</span>
          <span class="badge bg-light text-dark"><?= $checkStats['total_checks'] ?> Total Audits</span>
        </div>
        <div class="card-body">
          <div style="height: 220px; position: relative;">
            <canvas id="integrityChart"></canvas>
          </div>
          <div class="row text-center mt-3 g-2">
            <div class="col-4">
              <span class="badge status-valid d-block py-2">VALID: <?= $checkStats['valid_count'] ?></span>
            </div>
            <div class="col-4">
              <span class="badge status-tampered d-block py-2">TAMPERED: <?= $checkStats['tampered_count'] ?></span>
            </div>
            <div class="col-4">
              <span class="badge status-pending d-block py-2">PENDING: <?= $checkStats['pending_count'] ?></span>
            </div>
          </div>
        </div>
      </div>

      <!-- Blockchain Node Details -->
      <div class="card card-hospital">
        <div class="card-header-hospital">
          <span><i class="bi bi-boxes text-info me-2"></i> Local EVM Blockchain Anchor</span>
          <span class="status-badge <?= !empty($nodeStatus['connected']) ? 'status-valid' : 'status-tampered' ?>">
            <?= !empty($nodeStatus['connected']) ? 'Connected' : 'Offline' ?>
          </span>
        </div>
        <div class="card-body p-0">
          <table class="table table-sm mb-0 align-middle">
            <tbody>
              <tr>
                <th class="ps-3 text-muted">RPC Endpoint</th>
                <td class="font-mono"><?= htmlspecialchars((string)($nodeStatus['rpcUrl'] ?? '')) ?></td>
              </tr>
              <tr>
                <th class="ps-3 text-muted">Chain ID</th>
                <td><span class="badge bg-secondary">31337 (Hardhat)</span></td>
              </tr>
              <tr>
                <th class="ps-3 text-muted">Contract Address</th>
                <td class="font-mono text-truncate" style="max-width: 200px;">
                  <a href="index.php?page=explorer" class="text-decoration-none">
                    <?= htmlspecialchars((string)($nodeStatus['contractAddress'] ?? 'Not Deployed')) ?>
                  </a>
                </td>
              </tr>
              <tr>
                <th class="ps-3 text-muted">Current Block Height</th>
                <td><strong>#<?= htmlspecialchars((string)($nodeStatus['blockNumber'] ?? 0)) ?></strong></td>
              </tr>
              <tr>
                <th class="ps-3 text-muted">Contract Total Anchors</th>
                <td><span class="badge bg-primary"><?= htmlspecialchars((string)($nodeStatus['totalAnchored'] ?? 0)) ?></span></td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Right Column: Active Alerts & Recent Verifications -->
    <div class="col-lg-7">
      <!-- Active Security Alerts -->
      <?php if (!empty($activeAlerts)): ?>
        <div class="card card-hospital border-danger mb-4">
          <div class="card-header-hospital bg-danger text-white">
            <span class="fw-bold"><i class="bi bi-shield-slash-fill me-2"></i> Active Tamper & Integrity Violations</span>
            <span class="badge bg-white text-danger"><?= count($activeAlerts) ?> Unresolved</span>
          </div>
          <div class="card-body p-0">
            <div class="table-responsive">
              <table class="table table-hover mb-0 align-middle">
                <thead class="table-light small">
                  <tr>
                    <th>Record Target</th>
                    <th>Message</th>
                    <th>Detected At</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  <?php foreach ($activeAlerts as $alert): ?>
                    <tr class="table-danger">
                      <td>
                        <strong><?= htmlspecialchars($alert['record_type']) ?></strong> #<?= (int)$alert['record_id'] ?>
                        <div class="small text-muted">Version <?= (int)$alert['version_number'] ?></div>
                      </td>
                      <td class="small text-break">
                        <?= htmlspecialchars($alert['message']) ?>
                      </td>
                      <td class="small text-muted text-nowrap">
                        <?= htmlspecialchars($alert['detected_at']) ?>
                      </td>
                      <td>
                        <?php if ($user['role'] === 'admin'): ?>
                          <button type="button" class="btn btn-outline-danger btn-sm text-nowrap" onclick="resolveSecurityAlert(<?= (int)$alert['id'] ?>, '<?= CsrfMiddleware::getToken() ?>')">
                            <i class="bi bi-check2"></i> Resolve
                          </button>
                        <?php endif; ?>
                      </td>
                    </tr>
                  <?php endforeach; ?>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      <?php endif; ?>

      <!-- Recent Integrity Checks Log -->
      <div class="card card-hospital">
        <div class="card-header-hospital">
          <span><i class="bi bi-activity text-secondary me-2"></i> Recent Cryptographic Verifications</span>
          <a href="index.php?page=verification" class="btn btn-sm btn-link text-decoration-none">View All</a>
        </div>
        <div class="card-body p-0">
          <div class="table-responsive">
            <table class="table table-hover mb-0 align-middle">
              <thead class="table-light small">
                <tr>
                  <th>Target</th>
                  <th>Calculated SHA-256</th>
                  <th>Result</th>
                  <th>Audited At</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                <?php if (empty($recentChecks)): ?>
                  <tr>
                    <td colspan="5" class="text-center py-4 text-muted">No integrity checks logged yet.</td>
                  </tr>
                <?php else: ?>
                  <?php foreach ($recentChecks as $check): ?>
                    <tr>
                      <td>
                        <span class="badge bg-light text-dark border"><?= htmlspecialchars($check['record_type']) ?></span>
                        <strong>#<?= (int)$check['record_id'] ?></strong>
                        <small class="text-muted">v<?= (int)$check['version_number'] ?></small>
                      </td>
                      <td>
                        <span class="hash-badge" title="<?= htmlspecialchars($check['calculated_hash']) ?>">
                          <?= htmlspecialchars(substr($check['calculated_hash'], 0, 14)) ?>...
                        </span>
                      </td>
                      <td>
                        <span class="status-badge status-<?= strtolower($check['result']) ?>">
                          <?= htmlspecialchars($check['result']) ?>
                        </span>
                      </td>
                      <td class="small text-muted text-nowrap">
                        <?= htmlspecialchars(date('M d, H:i', strtotime($check['checked_at']))) ?>
                      </td>
                      <td>
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
  </div>
</div>

<script>
document.addEventListener("DOMContentLoaded", function() {
  const ctx = document.getElementById('integrityChart');
  if (ctx) {
    new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: ['Valid', 'Tampered', 'Pending', 'Missing Anchor'],
        datasets: [{
          data: [
            <?= (int)$checkStats['valid_count'] ?>,
            <?= (int)$checkStats['tampered_count'] ?>,
            <?= (int)$checkStats['pending_count'] ?>,
            <?= (int)$checkStats['missing_anchor_count'] ?>
          ],
          backgroundColor: ['#10b981', '#ef4444', '#f59e0b', '#94a3b8'],
          borderWidth: 2,
          borderColor: '#ffffff'
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'bottom',
            labels: { boxWidth: 12, font: { size: 11 } }
          }
        }
      }
    });
  }
});
</script>
