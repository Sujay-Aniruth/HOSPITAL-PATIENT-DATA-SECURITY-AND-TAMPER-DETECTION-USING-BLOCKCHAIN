<?php
/**
 * Controlled Academic Tampering Demonstration Lab
 * Hospital Patient Data Security and Tamper Detection
 * 
 * STRICT ACCESS CONTROL:
 * - Admin role only
 * - APP_ENV === 'local' only
 * - Explicit CSRF protection
 */

declare(strict_types=1);

require_once __DIR__ . '/../../middleware/AuthMiddleware.php';
require_once __DIR__ . '/../../middleware/CsrfMiddleware.php';
require_once __DIR__ . '/../../config/database.php';

$user = AuthMiddleware::requireRole(['admin']);

if (config('APP_ENV') !== 'local') {
    die("The Tampering Demonstration Lab is strictly disabled in non-local environments.");
}

$db = Database::getConnection();

// Fetch sample medical records for testing
$records = $db->query("
    SELECT mr.id, mr.current_version, p.name as patient_name, p.patient_code,
           mrv.diagnosis, mrv.prescription, mrv.symptoms, mrv.sha256_hash
    FROM `medical_records` mr
    JOIN `patients` p ON mr.patient_id = p.id
    LEFT JOIN `medical_record_versions` mrv ON mr.id = mrv.medical_record_id AND mr.current_version = mrv.version_number
    ORDER BY mr.id ASC
")->fetchAll();

// Fetch sample patients
$patients = $db->query("
    SELECT p.id, p.current_profile_version, p.name, p.patient_code, p.phone, p.address
    FROM `patients` p
    ORDER BY p.id ASC
")->fetchAll();
?>

<div class="container-fluid px-4 py-4">
  <!-- Lab Banner -->
  <div class="tamper-lab-banner">
    <div class="d-flex flex-column flex-md-row justify-content-between align-items-md-center gap-3">
      <div>
        <div class="d-flex align-items-center gap-2">
          <span class="badge bg-danger text-uppercase px-2 py-1">Academic Security Lab</span>
          <h4 class="fw-bold text-danger mb-0">Controlled Data Tampering & Detection Simulator</h4>
        </div>
        <p class="text-danger-emphasis small mb-0 mt-1">
          Simulate an internal adversary or malicious DBA directly editing MySQL database rows behind the back of the hospital application.
        </p>
      </div>
      <div>
        <button type="button" class="btn btn-outline-danger btn-sm fw-bold" onclick="resetDemoFixtures('<?= CsrfMiddleware::getToken() ?>', this)">
          <i class="bi bi-arrow-counterclockwise"></i> Reset Fictional Fixtures
        </button>
      </div>
    </div>
  </div>

  <!-- Step-by-Step Walkthrough Guide -->
  <div class="card card-hospital mb-4">
    <div class="card-header-hospital">
      <span><i class="bi bi-mortarboard-fill text-primary me-2"></i> MTech Demonstration Methodology</span>
      <span class="badge bg-info-subtle text-info">Step-by-Step Academic Defense Guide</span>
    </div>
    <div class="card-body">
      <div class="row g-3">
        <div class="col-md-3">
          <div class="p-3 border rounded h-100 bg-light">
            <div class="fw-bold text-primary mb-1"><span class="badge bg-primary me-1">1</span> Baseline VALID</div>
            <div class="small text-muted">Verify any record below. The database computed SHA-256 matches the on-chain anchor bit-for-bit.</div>
          </div>
        </div>
        <div class="col-md-3">
          <div class="p-3 border rounded h-100 bg-light">
            <div class="fw-bold text-danger mb-1"><span class="badge bg-danger me-1">2</span> Inject Tamper</div>
            <div class="small text-muted">Modify one protected field (e.g. Diagnosis) directly in MySQL without blockchain interaction.</div>
          </div>
        </div>
        <div class="col-md-3">
          <div class="p-3 border rounded h-100 bg-light">
            <div class="fw-bold text-danger mb-1"><span class="badge bg-danger me-1">3</span> Verify TAMPERED</div>
            <div class="small text-muted">Re-run verification. The SHA-256 hash changes, exposing the mismatch. A security alert is generated!</div>
          </div>
        </div>
        <div class="col-md-3">
          <div class="p-3 border rounded h-100 bg-light">
            <div class="fw-bold text-success mb-1"><span class="badge bg-success me-1">4</span> Authorized Amend</div>
            <div class="small text-muted">Perform a legitimate revision. Version N+1 is created with a clean on-chain anchor.</div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <div class="row g-4">
    <!-- Test Bed 1: Clinical Medical Record Tampering -->
    <div class="col-lg-6">
      <div class="card card-hospital">
        <div class="card-header-hospital">
          <span><i class="bi bi-file-earmark-medical-fill text-danger me-2"></i> Clinical Record Tampering Test Bed</span>
          <span class="badge bg-danger-subtle text-danger">Target: MySQL Record Version</span>
        </div>
        <div class="card-body p-4">
          <form id="tamperClinicalForm" onsubmit="event.preventDefault(); submitTamper('tamperClinicalForm');">
            <input type="hidden" name="csrf_token" value="<?= CsrfMiddleware::getToken() ?>">
            <input type="hidden" name="record_type" value="MEDICAL_RECORD">

            <div class="mb-3">
              <label class="form-label small fw-bold">Select Clinical Record Target</label>
              <select class="form-select" name="record_id" id="clinical_record_id" onchange="updateClinicalPresets(this.value)">
                <?php foreach ($records as $r): ?>
                  <option value="<?= (int)$r['id'] ?>" 
                          data-diagnosis="<?= htmlspecialchars($r['diagnosis'] ?? '') ?>"
                          data-prescription="<?= htmlspecialchars($r['prescription'] ?? '') ?>"
                          data-version="<?= (int)$r['current_version'] ?>">
                    Record #<?= (int)$r['id'] ?> (<?= htmlspecialchars($r['patient_name']) ?>) - Current v<?= (int)$r['current_version'] ?>
                  </option>
                <?php endforeach; ?>
              </select>
            </div>

            <div class="row g-2 mb-3">
              <div class="col-6">
                <label class="form-label small fw-bold">Version to Tamper</label>
                <input type="number" class="form-control" name="version" id="clinical_version" value="1" min="1">
              </div>
              <div class="col-6">
                <label class="form-label small fw-bold">Target SQL Column</label>
                <select class="form-select" name="field" id="clinical_field">
                  <option value="diagnosis" selected>diagnosis (Diagnosis Text)</option>
                  <option value="prescription">prescription (Medication)</option>
                  <option value="symptoms">symptoms (Clinical Symptoms)</option>
                </select>
              </div>
            </div>

            <div class="mb-3">
              <label class="form-label small fw-bold">Altered / Malicious Value to Inject</label>
              <textarea class="form-control font-mono small text-danger" name="value" id="clinical_value" rows="2" required placeholder="Type fraudulent value here">Acute Appendicitis with Impending Perforation (Tampered via SQL)</textarea>
            </div>

            <div class="d-flex gap-2 justify-content-between">
              <button type="button" class="btn btn-outline-primary btn-sm" onclick="verifyCurrentTarget('MEDICAL_RECORD', 'clinical_record_id', 'clinical_version', this)">
                <i class="bi bi-shield-check"></i> 1. Verify Baseline
              </button>
              <button type="submit" class="btn btn-danger btn-sm fw-bold">
                <i class="bi bi-lightning-charge-fill"></i> 2. Inject Tamper into MySQL
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>

    <!-- Test Bed 2: Patient Demographics Tampering -->
    <div class="col-lg-6">
      <div class="card card-hospital">
        <div class="card-header-hospital">
          <span><i class="bi bi-person-x-fill text-danger me-2"></i> Patient Demographics Tampering Test Bed</span>
          <span class="badge bg-danger-subtle text-danger">Target: Demographic Version</span>
        </div>
        <div class="card-body p-4">
          <form id="tamperPatientForm" onsubmit="event.preventDefault(); submitTamper('tamperPatientForm');">
            <input type="hidden" name="csrf_token" value="<?= CsrfMiddleware::getToken() ?>">
            <input type="hidden" name="record_type" value="PATIENT_PROFILE">

            <div class="mb-3">
              <label class="form-label small fw-bold">Select Patient Target</label>
              <select class="form-select" name="record_id" id="patient_target_id">
                <?php foreach ($patients as $p): ?>
                  <option value="<?= (int)$p['id'] ?>" data-version="<?= (int)$p['current_profile_version'] ?>">
                    Patient #<?= (int)$p['id'] ?> (<?= htmlspecialchars($p['patient_code']) ?>: <?= htmlspecialchars($p['name']) ?>)
                  </option>
                <?php endforeach; ?>
              </select>
            </div>

            <div class="row g-2 mb-3">
              <div class="col-6">
                <label class="form-label small fw-bold">Version to Tamper</label>
                <input type="number" class="form-control" name="version" id="patient_version" value="1" min="1">
              </div>
              <div class="col-6">
                <label class="form-label small fw-bold">Target SQL Column</label>
                <select class="form-select" name="field">
                  <option value="name" selected>name (Legal Name)</option>
                  <option value="phone">phone (Contact Number)</option>
                  <option value="address">address (Home Address)</option>
                </select>
              </div>
            </div>

            <div class="mb-3">
              <label class="form-label small fw-bold">Altered / Malicious Value to Inject</label>
              <input type="text" class="form-control font-mono small text-danger" name="value" required value="Fraudulent Identity Tamper (SQL Injected)">
            </div>

            <div class="d-flex gap-2 justify-content-between">
              <button type="button" class="btn btn-outline-primary btn-sm" onclick="verifyCurrentTarget('PATIENT_PROFILE', 'patient_target_id', 'patient_version', this)">
                <i class="bi bi-shield-check"></i> 1. Verify Baseline
              </button>
              <button type="submit" class="btn btn-danger btn-sm fw-bold">
                <i class="bi bi-lightning-charge-fill"></i> 2. Inject Tamper into MySQL
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  </div>

  <!-- Real-time Demonstration Results Container -->
  <div id="tamperResultArea" class="mt-4" style="display: none;"></div>
</div>

<script>
async function submitTamper(formId) {
  const form = document.getElementById(formId);
  const formData = new FormData(form);

  const btn = form.querySelector('button[type="submit"]');
  const origHtml = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Injecting...';

  try {
    const res = await fetch("api/demo/tamper.php", {
      method: "POST",
      body: formData,
      headers: { Accept: "application/json" },
    });
    const data = await res.json();

    if (data.status === "success") {
      const area = document.getElementById("tamperResultArea");
      area.style.display = "block";
      area.innerHTML = `
        <div class="card card-hospital border-danger shadow">
          <div class="card-header-hospital bg-danger text-white">
            <span class="fw-bold"><i class="bi bi-exclamation-octagon-fill me-2"></i> Database Modification Injected!</span>
            <span class="badge bg-white text-danger font-mono">SQL Row Altered</span>
          </div>
          <div class="card-body p-4">
            <p class="mb-3 text-dark">${data.message}</p>
            <div class="alert alert-light border small font-mono mb-3">
              <div><strong>Record:</strong> ${data.details.record_type} #${data.details.record_id} (Version ${data.details.version})</div>
              <div><strong>Field Altered:</strong> ${data.details.field}</div>
              <div class="text-muted"><strong>Original Value:</strong> ${data.details.original_value}</div>
              <div class="text-danger"><strong>Tampered Value:</strong> ${data.details.tampered_value}</div>
            </div>
            <div class="d-flex gap-2">
              <button type="button" class="btn btn-danger fw-bold" onclick="runSingleVerification('${data.details.record_type}', ${data.details.record_id}, ${data.details.version}, this)">
                <i class="bi bi-shield-slash-fill me-1"></i> Verify Now & Observe TAMPERED Alert
              </button>
              <a href="index.php?page=alerts" class="btn btn-outline-danger">
                <i class="bi bi-bell-fill"></i> View Security Alerts
              </a>
            </div>
          </div>
        </div>
      `;
      area.scrollIntoView({ behavior: 'smooth' });
    } else {
      alert("Error injecting tamper: " + (data.message || "Unknown error"));
    }
  } catch (err) {
    alert("Network error: " + err.message);
  } finally {
    btn.disabled = false;
    btn.innerHTML = origHtml;
  }
}

function verifyCurrentTarget(type, idField, verField, btn) {
  const id = document.getElementById(idField).value;
  const ver = document.getElementById(verField).value;
  runSingleVerification(type, id, ver, btn);
}

async function resetDemoFixtures(csrfToken, btn) {
  if (!confirm("Reset all fictional patient and medical record demonstration fixtures back to their baseline anchored state?")) {
    return;
  }

  const origHtml = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Resetting...';

  try {
    const res = await fetch("api/demo/reset.php", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
      },
      body: `csrf_token=${encodeURIComponent(csrfToken)}`,
    });
    const data = await res.json();
    if (data.status === "success") {
      alert("Demonstration fixtures successfully restored to baseline anchored state!");
      window.location.reload();
    } else {
      alert("Reset failed: " + data.message);
    }
  } catch (err) {
    alert("Error: " + err.message);
  } finally {
    btn.disabled = false;
    btn.innerHTML = origHtml;
  }
}
</script>
