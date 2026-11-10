<?php
/**
 * Layout Navbar
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

require_once __DIR__ . '/../../models/SecurityAlert.php';

$alertModel = new SecurityAlert();
$unresolvedAlerts = $alertModel->countUnresolved();
$currentPage = $_GET['page'] ?? 'dashboard';
?>

<!-- Top Brand Header Bar -->
<header class="navbar navbar-expand-lg navbar-dark navbar-hospital">
  <div class="container-fluid">
    <a class="navbar-brand text-white" href="index.php?page=dashboard">
      <div class="brand-icon">
        <i class="bi bi-shield-shaded"></i>
      </div>
      <div>
        <div style="line-height: 1.1;">Hospital Data Security</div>
        <small class="text-white-50" style="font-size: 0.72rem; font-weight: normal;">Blockchain Tamper Detection System</small>
      </div>
    </a>

    <!-- Right Side Status & User Controls -->
    <div class="d-flex align-items-center gap-3">
      <!-- Live Blockchain Node Pill -->
      <?php if (!empty($nodeStatus['connected'])): ?>
        <span class="node-status-pill connected" title="Local Hardhat Node Active (Chain ID <?= htmlspecialchars((string)($nodeStatus['chainId'] ?? 31337)) ?>)">
          <span class="pulse-dot"></span> Hardhat Node: Block #<?= htmlspecialchars((string)($nodeStatus['blockNumber'] ?? 0)) ?>
        </span>
      <?php else: ?>
        <span class="node-status-pill disconnected" title="Local Hardhat Node not detected at 127.0.0.1:8545">
          <span class="pulse-dot"></span> Blockchain Disconnected
        </span>
      <?php endif; ?>

      <!-- Active Security Alert Bell -->
      <?php if ($currentUser): ?>
        <a href="index.php?page=alerts" class="btn btn-outline-light btn-sm position-relative" title="Security Alerts">
          <i class="bi bi-bell"></i>
          <?php if ($unresolvedAlerts > 0): ?>
            <span class="position-absolute top-0 start-100 translate-middle badge rounded-pill bg-danger">
              <?= $unresolvedAlerts ?>
            </span>
          <?php endif; ?>
        </a>

        <!-- User Role Profile Pill -->
        <div class="dropdown">
          <button class="btn btn-dark btn-sm dropdown-toggle d-flex align-items-center gap-2 border-secondary" type="button" data-bs-toggle="dropdown">
            <i class="bi bi-person-circle"></i>
            <span><?= htmlspecialchars($currentUser['name']) ?></span>
            <span class="role-badge role-<?= htmlspecialchars($currentUser['role']) ?>">
              <?= htmlspecialchars($currentUser['role']) ?>
            </span>
          </button>
          <ul class="dropdown-menu dropdown-menu-end shadow">
            <li class="dropdown-header">
              Signed in as <strong><?= htmlspecialchars($currentUser['username']) ?></strong>
            </li>
            <li><hr class="dropdown-divider"></li>
            <li>
              <a class="dropdown-item text-danger" href="index.php?page=logout">
                <i class="bi bi-box-arrow-right me-2"></i> Sign Out
              </a>
            </li>
          </ul>
        </div>
      <?php else: ?>
        <a href="index.php?page=login" class="btn btn-primary btn-sm">
          <i class="bi bi-box-arrow-in-right"></i> Sign In
        </a>
      <?php endif; ?>
    </div>
  </div>
</header>

<!-- Module Navigation Bar -->
<?php if ($currentUser): ?>
<nav class="nav-subbar">
  <div class="d-flex align-items-center gap-1 overflow-auto">
    <a href="index.php?page=dashboard" class="nav-link-custom <?= $currentPage === 'dashboard' ? 'active' : '' ?>">
      <i class="bi bi-speedometer2 me-1"></i> Dashboard
    </a>
    <a href="index.php?page=patients" class="nav-link-custom <?= str_starts_with($currentPage, 'patient') ? 'active' : '' ?>">
      <i class="bi bi-people me-1"></i> Patients
    </a>
    <a href="index.php?page=records" class="nav-link-custom <?= str_starts_with($currentPage, 'record') ? 'active' : '' ?>">
      <i class="bi bi-file-earmark-medical me-1"></i> Medical Records
    </a>
    <a href="index.php?page=verification" class="nav-link-custom <?= $currentPage === 'verification' ? 'active' : '' ?>">
      <i class="bi bi-shield-check me-1"></i> Integrity Verification
    </a>
    <a href="index.php?page=explorer" class="nav-link-custom <?= $currentPage === 'explorer' ? 'active' : '' ?>">
      <i class="bi bi-boxes me-1"></i> Blockchain Explorer
    </a>
    <a href="index.php?page=alerts" class="nav-link-custom <?= $currentPage === 'alerts' ? 'active' : '' ?>">
      <i class="bi bi-exclamation-triangle me-1"></i> Security Alerts
      <?php if ($unresolvedAlerts > 0): ?>
        <span class="badge bg-danger ms-1"><?= $unresolvedAlerts ?></span>
      <?php endif; ?>
    </a>

    <?php if ($currentUser['role'] === 'admin'): ?>
      <a href="index.php?page=demo" class="nav-link-custom text-danger fw-bold <?= $currentPage === 'demo' ? 'active bg-danger-subtle' : '' ?>">
        <i class="bi bi-bug me-1"></i> Tampering Lab
      </a>
    <?php endif; ?>
  </div>

  <div class="d-none d-md-block text-muted small">
    <i class="bi bi-cpu"></i> EVM: <code class="text-secondary"><?= htmlspecialchars(substr($nodeStatus['contractAddress'] ?? 'Unset', 0, 10)) ?>...</code>
  </div>
</nav>
<?php endif; ?>
