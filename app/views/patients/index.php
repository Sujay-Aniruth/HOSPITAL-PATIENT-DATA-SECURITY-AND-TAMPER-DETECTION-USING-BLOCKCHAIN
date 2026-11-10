<?php
/**
 * Patient Directory View
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

require_once __DIR__ . '/../../middleware/AuthMiddleware.php';
require_once __DIR__ . '/../../models/Patient.php';

$user = AuthMiddleware::requireAuth();
$patientModel = new Patient();

$search = trim((string)($_GET['search'] ?? ''));
$patients = $patientModel->getAll($search);
?>

<div class="container-fluid px-4 py-4">
  <div class="d-flex flex-column flex-md-row justify-content-between align-items-md-center mb-4 gap-2">
    <div>
      <h3 class="fw-bold mb-1">Patient Demographic Registry</h3>
      <p class="text-muted small mb-0">Demographic profiles with append-only versioning and cryptographic blockchain anchors</p>
    </div>
    <?php if (in_array($user['role'], ['admin', 'staff'], true)): ?>
      <a href="index.php?page=patient-create" class="btn btn-primary btn-sm d-flex align-items-center gap-1">
        <i class="bi bi-person-plus-fill"></i> Register New Patient
      </a>
    <?php endif; ?>
  </div>

  <!-- Search Filter Card -->
  <div class="card card-hospital mb-4">
    <div class="card-body p-3">
      <form method="GET" action="index.php" class="row g-2 align-items-center">
        <input type="hidden" name="page" value="patients">
        <div class="col-md-5">
          <div class="input-group">
            <span class="input-group-text bg-white"><i class="bi bi-search text-muted"></i></span>
            <input type="text" name="search" class="form-control" placeholder="Search by name, patient code, or phone..." value="<?= htmlspecialchars($search) ?>">
          </div>
        </div>
        <div class="col-auto">
          <button type="submit" class="btn btn-outline-secondary">Filter</button>
          <?php if (!empty($search)): ?>
            <a href="index.php?page=patients" class="btn btn-link text-muted">Clear</a>
          <?php endif; ?>
        </div>
      </form>
    </div>
  </div>

  <!-- Patients Table -->
  <div class="card card-hospital">
    <div class="card-body p-0">
      <div class="table-responsive">
        <table class="table table-hover align-middle mb-0">
          <thead class="table-light">
            <tr>
              <th>Patient Code</th>
              <th>Full Name</th>
              <th>DOB & Gender</th>
              <th>Phone</th>
              <th>Current Version</th>
              <th>Registered</th>
              <th class="text-end">Actions</th>
            </tr>
          </thead>
          <tbody>
            <?php if (empty($patients)): ?>
              <tr>
                <td colspan="7" class="text-center py-5 text-muted">
                  <i class="bi bi-person-x fs-1 d-block mb-2"></i>
                  No patient records match the query.
                </td>
              </tr>
            <?php else: ?>
              <?php foreach ($patients as $pat): ?>
                <tr>
                  <td>
                    <span class="badge bg-light text-primary border font-mono">
                      <?= htmlspecialchars($pat['patient_code']) ?>
                    </span>
                  </td>
                  <td>
                    <strong><?= htmlspecialchars($pat['name']) ?></strong>
                  </td>
                  <td>
                    <div class="small"><?= htmlspecialchars($pat['date_of_birth']) ?></div>
                    <span class="badge bg-secondary-subtle text-secondary small"><?= htmlspecialchars($pat['gender']) ?></span>
                  </td>
                  <td class="font-mono small"><?= htmlspecialchars($pat['phone']) ?></td>
                  <td>
                    <span class="badge bg-info-subtle text-info border">
                      v<?= (int)$pat['current_profile_version'] ?>
                    </span>
                  </td>
                  <td class="small text-muted"><?= htmlspecialchars(date('M d, Y', strtotime($pat['created_at']))) ?></td>
                  <td class="text-end">
                    <div class="btn-group btn-group-sm">
                      <a href="index.php?page=patient-view&id=<?= (int)$pat['id'] ?>" class="btn btn-outline-secondary" title="View Profile & Encounters">
                        <i class="bi bi-eye"></i>
                      </a>
                      <button type="button" class="btn btn-outline-primary" title="Cryptographically Verify Current Version"
                              onclick="runSingleVerification('PATIENT_PROFILE', <?= (int)$pat['id'] ?>, <?= (int)$pat['current_profile_version'] ?>, this)">
                        <i class="bi bi-shield-check"></i>
                      </button>
                      <?php if (in_array($user['role'], ['admin', 'staff'], true)): ?>
                        <a href="index.php?page=patient-edit&id=<?= (int)$pat['id'] ?>" class="btn btn-outline-secondary" title="Authorized Amendment">
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
