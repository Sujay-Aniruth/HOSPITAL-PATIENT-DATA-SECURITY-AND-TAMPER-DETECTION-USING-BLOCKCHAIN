<?php
/**
 * Login View
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

require_once __DIR__ . '/../../middleware/CsrfMiddleware.php';
require_once __DIR__ . '/../../middleware/AuthMiddleware.php';

$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    CsrfMiddleware::requireValid();
    $identifier = trim((string)($_POST['identifier'] ?? ''));
    $password = (string)($_POST['password'] ?? '');

    $result = AuthMiddleware::attempt($identifier, $password);
    if ($result['success']) {
        header('Location: index.php?page=dashboard');
        exit;
    } else {
        $error = $result['message'];
    }
}
?>

<div class="container py-5 my-auto">
  <div class="row justify-content-center">
    <div class="col-md-5 col-lg-4">
      <div class="card card-hospital shadow-sm">
        <div class="card-body p-4">
          <div class="text-center mb-4">
            <div class="brand-icon mx-auto mb-3" style="width: 50px; height: 50px; font-size: 1.5rem;">
              <i class="bi bi-shield-shaded"></i>
            </div>
            <h4 class="fw-bold">Sign In</h4>
            <p class="text-muted small">Hospital Patient Data Security & Tamper Detection</p>
          </div>

          <?php if (!empty($error)): ?>
            <div class="alert alert-danger py-2 small d-flex align-items-center gap-2">
              <i class="bi bi-exclamation-triangle-fill"></i>
              <span><?= htmlspecialchars($error) ?></span>
            </div>
          <?php endif; ?>

          <form method="POST" action="index.php?page=login">
            <?= CsrfMiddleware::getField() ?>

            <div class="mb-3">
              <label for="identifier" class="form-label small fw-bold">Email or Username</label>
              <div class="input-group">
                <span class="input-group-text"><i class="bi bi-person"></i></span>
                <input type="text" class="form-control" id="identifier" name="identifier" required placeholder="admin@hospital.local">
              </div>
            </div>

            <div class="mb-4">
              <label for="password" class="form-label small fw-bold">Password</label>
              <div class="input-group">
                <span class="input-group-text"><i class="bi bi-key"></i></span>
                <input type="password" class="form-control" id="password" name="password" required placeholder="••••••••">
              </div>
            </div>

            <button type="submit" class="btn btn-primary w-100 fw-bold py-2">
              <i class="bi bi-box-arrow-in-right me-1"></i> Authenticate
            </button>
          </form>

          <!-- Quick Fill Demo Accounts -->
          <div class="mt-4 pt-3 border-top">
            <label class="small text-muted fw-bold d-block mb-2 text-center">Quick Demo Credentials:</label>
            <div class="d-grid gap-2">
              <button type="button" class="btn btn-sm btn-outline-secondary text-start" onclick="fillCreds('admin@hospital.local', 'Admin@12345')">
                <span class="badge bg-purple text-dark me-1">Admin</span> Dr. Alok Verma (Full System)
              </button>
              <button type="button" class="btn btn-sm btn-outline-secondary text-start" onclick="fillCreds('dr.sharma@hospital.local', 'Doctor@12345')">
                <span class="badge bg-info text-dark me-1">Doctor</span> Dr. Sunita Sharma (Clinical)
              </button>
              <button type="button" class="btn btn-sm btn-outline-secondary text-start" onclick="fillCreds('staff.priya@hospital.local', 'Staff@12345')">
                <span class="badge bg-success text-white me-1">Staff</span> Priya Nair (Registrar)
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>

<script>
function fillCreds(id, pass) {
  document.getElementById('identifier').value = id;
  document.getElementById('password').value = pass;
}
</script>
