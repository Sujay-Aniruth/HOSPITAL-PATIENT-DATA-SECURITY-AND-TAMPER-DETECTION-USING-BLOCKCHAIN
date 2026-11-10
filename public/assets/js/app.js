/**
 * Hospital Patient Data Security and Tamper Detection
 * Frontend Client JavaScript
 */

document.addEventListener("DOMContentLoaded", function () {
  // Initialize tooltips
  if (window.bootstrap) {
    const tooltipTriggerList = [].slice.call(
      document.querySelectorAll('[data-bs-toggle="tooltip"]')
    );
    tooltipTriggerList.map(function (el) {
      return new bootstrap.Tooltip(el);
    });
  }

  // Setup copy to clipboard
  document.querySelectorAll(".copy-btn").forEach((btn) => {
    btn.addEventListener("click", function () {
      const target = this.getAttribute("data-copy");
      if (target) {
        navigator.clipboard.writeText(target).then(() => {
          const original = this.innerHTML;
          this.innerHTML = '<i class="bi bi-check2"></i> Copied!';
          setTimeout(() => {
            this.innerHTML = original;
          }, 1800);
        });
      }
    });
  });
});

// Quick Single Record Verification
async function runSingleVerification(type, id, version, btnEl) {
  let originalHtml = "";
  if (btnEl) {
    originalHtml = btnEl.innerHTML;
    btnEl.disabled = true;
    btnEl.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Verifying...';
  }

  try {
    const url = `api/verification/check.php?type=${encodeURIComponent(type)}&id=${encodeURIComponent(id)}&version=${encodeURIComponent(version)}`;
    const response = await fetch(url, {
      headers: { Accept: "application/json" },
    });
    const data = await response.json();

    if (data.status === "success" && data.data) {
      showVerificationModal(data.data);
    } else {
      alert("Verification error: " + (data.message || "Unknown error"));
    }
  } catch (err) {
    alert("Network or server failure during verification: " + err.message);
  } finally {
    if (btnEl) {
      btnEl.disabled = false;
      btnEl.innerHTML = originalHtml;
    }
  }
}

// Display Verification Result Modal
function showVerificationModal(res) {
  let modalEl = document.getElementById("verificationResultModal");
  if (!modalEl) {
    modalEl = document.createElement("div");
    modalEl.id = "verificationResultModal";
    modalEl.className = "modal fade";
    modalEl.setAttribute("tabindex", "-1");
    document.body.appendChild(modalEl);
  }

  const isMatch = res.result === "VALID";
  const badgeClass =
    res.result === "VALID"
      ? "status-valid"
      : res.result === "TAMPERED"
      ? "status-tampered"
      : res.result === "PENDING"
      ? "status-pending"
      : "status-missing";

  const icon =
    res.result === "VALID"
      ? '<i class="bi bi-shield-check text-success fs-1"></i>'
      : res.result === "TAMPERED"
      ? '<i class="bi bi-shield-slash-fill text-danger fs-1"></i>'
      : '<i class="bi bi-hourglass-split text-warning fs-1"></i>';

  modalEl.innerHTML = `
    <div class="modal-dialog modal-lg modal-dialog-centered">
      <div class="modal-content">
        <div class="modal-header border-bottom ${isMatch ? "bg-light" : "bg-danger text-white"}">
          <h5 class="modal-title d-flex align-items-center gap-2">
            <i class="bi bi-shield-lock"></i> Record Cryptographic Audit Result
          </h5>
          <button type="button" class="btn-close ${isMatch ? "" : "btn-close-white"}" data-bs-dismiss="modal"></button>
        </div>
        <div class="modal-body p-4">
          <div class="text-center mb-4">
            ${icon}
            <h4 class="mt-2 fw-bold">${res.result === "VALID" ? "Integrity Confirmed" : res.result === "TAMPERED" ? "Tamper Alert Detected!" : res.result}</h4>
            <span class="status-badge ${badgeClass} fs-6">${res.result}</span>
            <p class="text-muted mt-2">${res.details || ""}</p>
          </div>

          <div class="table-responsive">
            <table class="table table-bordered align-middle">
              <tbody>
                <tr>
                  <th style="width: 25%;" class="bg-light">Target Record</th>
                  <td><strong>${res.record_type}</strong> #<strong>${res.record_id}</strong> (Version ${res.version})</td>
                </tr>
                <tr>
                  <th class="bg-light">Database Computed Hash</th>
                  <td>
                    <span class="hash-badge ${isMatch ? "match" : "mismatch"}">${res.calculated_hash || "N/A"}</span>
                  </td>
                </tr>
                <tr>
                  <th class="bg-light">Blockchain Anchored Hash</th>
                  <td>
                    <span class="hash-badge ${isMatch ? "match" : "mismatch"}">${res.blockchain_hash || "NO ON-CHAIN ANCHOR"}</span>
                  </td>
                </tr>
                <tr>
                  <th class="bg-light">Comparison Outcome</th>
                  <td>
                    ${
                      isMatch
                        ? '<span class="text-success fw-bold"><i class="bi bi-check-circle-fill"></i> Bitwise Match (Deterministic SHA-256 Identical)</span>'
                        : '<span class="text-danger fw-bold"><i class="bi bi-exclamation-triangle-fill"></i> Cryptographic Hash Mismatch! Database row has been modified out-of-band.</span>'
                    }
                  </td>
                </tr>
                ${
                  res.transaction_hash
                    ? `
                <tr>
                  <th class="bg-light">Anchor Transaction</th>
                  <td>
                    <code class="text-primary">${res.transaction_hash}</code>
                    ${res.block_number ? `<span class="badge bg-secondary ms-2">Block #${res.block_number}</span>` : ""}
                  </td>
                </tr>`
                    : ""
                }
                <tr>
                  <th class="bg-light">Verification Timestamp</th>
                  <td class="text-muted">${res.checked_at || new Date().toLocaleString()}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
        <div class="modal-footer">
          <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
          ${
            !isMatch && res.result === "TAMPERED"
              ? '<a href="index.php?page=alerts" class="btn btn-danger"><i class="bi bi-bell-fill"></i> View Security Alerts</a>'
              : ""
          }
        </div>
      </div>
    </div>
  `;

  const bsModal = new bootstrap.Modal(modalEl);
  bsModal.show();
}

// Bulk Integrity Verification Runner
async function runBulkVerification(csrfToken, btnEl) {
  if (!confirm("Run complete cryptographic audit across all patient and medical records?")) {
    return;
  }

  let origHtml = "";
  if (btnEl) {
    origHtml = btnEl.innerHTML;
    btnEl.disabled = true;
    btnEl.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Auditing Blockchain...';
  }

  try {
    const res = await fetch("api/verification/check-all.php", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
      },
      body: `csrf_token=${encodeURIComponent(csrfToken)}`,
    });
    const data = await res.json();

    if (data.status === "success") {
      alert(`Audit Complete!\nTotal Checked: ${data.summary.total}\nValid: ${data.summary.valid}\nTampered: ${data.summary.tampered}\nPending: ${data.summary.pending}`);
      window.location.reload();
    } else {
      alert("Verification audit failed: " + (data.message || "Unknown error"));
    }
  } catch (err) {
    alert("Network error: " + err.message);
  } finally {
    if (btnEl) {
      btnEl.disabled = false;
      btnEl.innerHTML = origHtml;
    }
  }
}

// Resolve Security Alert
async function resolveSecurityAlert(alertId, csrfToken) {
  if (!confirm("Mark this security alert as resolved?")) {
    return;
  }

  try {
    const res = await fetch("api/alerts/resolve.php", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
      },
      body: `id=${encodeURIComponent(alertId)}&csrf_token=${encodeURIComponent(csrfToken)}`,
    });
    const data = await res.json();
    if (data.status === "success") {
      window.location.reload();
    } else {
      alert("Error resolving alert: " + data.message);
    }
  } catch (err) {
    alert("Error: " + err.message);
  }
}
