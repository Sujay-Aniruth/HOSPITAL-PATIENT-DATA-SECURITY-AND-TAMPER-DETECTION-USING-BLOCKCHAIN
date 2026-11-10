<?php
/**
 * Security Alerts and Audit Log View
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

require_once __DIR__ . '/../../middleware/AuthMiddleware.php';
require_once __DIR__ . '/../../middleware/CsrfMiddleware.php';
require_once __DIR__ . '/../../models/SecurityAlert.php';
require_once __DIR__ . '/../../services/AuditService.php';

$user = AuthMiddleware::requireAuth();
$alertModel = new SecurityAlert();
$allAlerts = $alertModel->getAll(100);

$auditLogs = AuditService::getRecentLogs(50);
?>

<div class="container-fluid px-4 py-4">
  <div class="d-flex flex-column flex-md-row justify-content-between align-items-md-center mb-4 gap-2">
    <div>
      <h3 class="fw-bold mb-1">Security Alerts & Audit Log Ledger</h3>
      <p class="text-muted small mb-0">Record of detected cryptographic tamper violations and security lifecycle actions</p>
    </div>
  </div>

  <!-- Security Alerts Table -->
  <div class="card card-hospital mb-4">
    <div class="card-header-hospital">
      <span><i class="bi bi-shield-slash-fill text-danger me-2"></i> Detected Tamper Violations</span>
      <span class="badge bg-danger"><?= count(array_filter($allAlerts, fn($a) => empty($a['resolved']))) ?> Active Violations</span>
    </div>
    <div class="card-body p-0">
      <div class="table-responsive">
        <table class="table table-hover align-middle mb-0">
          <thead class="table-light small">
            <tr>
              <th>Target Record</th>
              <th>Severity</th>
              <th>Incident Details</th>
              <th>Hashes (Detected vs Expected)</th>
              <th>Detection Time</th>
              <th>Status</th>
              <th class="text-end">Resolution</th>
            </tr>
          </thead>
          <tbody>
            <?php if (empty($allAlerts)): ?>
              <tr>
                <td colspan="7" class="text-center py-5 text-muted">
                  <i class="bi bi-shield-check fs-1 text-success d-block mb-2"></i>
                  Zero security alerts. All stored records match blockchain anchors.
                </td>
              </tr>
            <?php else: ?>
              <?php foreach ($allAlerts as $alert): ?>
                <?php $isResolved = !empty($alert['resolved']); ?>
                <tr class="<?= !$isResolved ? 'table-danger' : '' ?>">
                  <td>
                    <strong><?= htmlspecialchars($alert['record_type']) ?></strong> #<?= (int)$alert['record_id'] ?>
                    <div class="small text-muted">Version <?= (int)$alert['version_number'] ?></div>
                  </td>
                  <td>
                    <span class="badge <?= $alert['severity'] === 'CRITICAL' ? 'bg-danger' : 'bg-warning text-dark' ?>">
                      <?= htmlspecialchars($alert['severity']) ?>
                    </span>
                  </td>
                  <td class="small" style="max-width: 250px;">
                    <div class="text-break"><?= htmlspecialchars($alert['message']) ?></div>
                  </td>
                  <td class="font-mono small">
                    <div class="text-danger" title="Detected Hash in DB">
                      <i class="bi bi-database me-1"></i><?= htmlspecialchars(substr($alert['detected_hash'], 0, 10)) ?>...
                    </div>
                    <div class="text-success" title="Immutable Blockchain Hash">
                      <i class="bi bi-link-45deg me-1"></i><?= htmlspecialchars(substr($alert['expected_hash'], 0, 10)) ?>...
                    </div>
                  </td>
                  <td class="small text-muted text-nowrap">
                    <?= htmlspecialchars(date('M d, Y H:i', strtotime($alert['detected_at']))) ?>
                  </td>
                  <td>
                    <?php if ($isResolved): ?>
                      <span class="badge bg-success-subtle text-success border">Resolved</span>
                      <div class="small text-muted">By <?= htmlspecialchars($alert['resolver_name'] ?? 'Admin') ?></div>
                    <?php else: ?>
                      <span class="status-badge status-tampered">Active</span>
                    <?php endif; ?>
                  </td>
                  <td class="text-end">
                    <?php if (!$isResolved && $user['role'] === 'admin'): ?>
                      <button type="button" class="btn btn-outline-danger btn-sm text-nowrap"
                              onclick="resolveSecurityAlert(<?= (int)$alert['id'] ?>, '<?= CsrfMiddleware::getToken() ?>')">
                        <i class="bi bi-check2-circle"></i> Resolve
                      </button>
                    <?php else: ?>
                      <button type="button" class="btn btn-outline-primary btn-sm py-0"
                              onclick="runSingleVerification('<?= htmlspecialchars($alert['record_type']) ?>', <?= (int)$alert['record_id'] ?>, <?= (int)$alert['version_number'] ?>, this)">
                        <i class="bi bi-arrow-repeat"></i> Verify
                      </button>
                    <?php endif; ?>
                  </td>
                </tr>
              <?php endforeach; ?>
            <?php endif; ?>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- Audit Log Ledger Table -->
  <div class="card card-hospital">
    <div class="card-header-hospital">
      <span><i class="bi bi-list-check text-secondary me-2"></i> System Audit Trail</span>
      <span class="badge bg-light text-dark"><?= count($auditLogs) ?> Log Entries</span>
    </div>
    <div class="card-body p-0">
      <div class="table-responsive">
        <table class="table table-hover align-middle mb-0 small">
          <thead class="table-light">
            <tr>
              <th>Timestamp</th>
              <th>Actor</th>
              <th>Action</th>
              <th>Target</th>
              <th>IP Address</th>
              <th>Metadata</th>
            </tr>
          </thead>
          <tbody>
            <?php foreach ($auditLogs as $log): ?>
              <tr>
                <td class="text-muted text-nowrap"><?= htmlspecialchars($log['timestamp']) ?></td>
                <td>
                  <strong><?= htmlspecialchars($log['actor_name'] ?? 'System/Anonymous') ?></strong>
                  <?php if (!empty($log['actor_role'])): ?>
                    <span class="role-badge role-<?= htmlspecialchars($log['actor_role']) ?> ms-1">
                      <?= htmlspecialchars($log['actor_role']) ?>
                    </span>
                  <?php endif; ?>
                </td>
                <td>
                  <span class="badge bg-light text-dark border font-mono">
                    <?= htmlspecialchars($log['action']) ?>
                  </span>
                </td>
                <td>
                  <?= htmlspecialchars($log['target_type']) ?>
                  <?= !empty($log['target_id']) ? '#' . (int)$log['target_id'] : '' ?>
                </td>
                <td class="font-mono text-muted"><?= htmlspecialchars($log['ip_address'] ?? '') ?></td>
                <td class="font-mono text-muted text-truncate" style="max-width: 250px;" title="<?= htmlspecialchars((string)($log['metadata'] ?? '')) ?>">
                  <?= htmlspecialchars((string)($log['metadata'] ?? '')) ?>
                </td>
              </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</div>
