<?php
/**
 * Blockchain Ledger Explorer View
 * Hospital Patient Data Security and Tamper Detection
 */

declare(strict_types=1);

require_once __DIR__ . '/../../middleware/AuthMiddleware.php';
require_once __DIR__ . '/../../services/BlockchainService.php';

$user = AuthMiddleware::requireAuth();
$blockchain = new BlockchainService();
$nodeStatus = $blockchain->getStatus();
$anchoredList = $blockchain->getAllAnchoredRecords();
?>

<div class="container-fluid px-4 py-4">
  <div class="d-flex flex-column flex-md-row justify-content-between align-items-md-center mb-4 gap-2">
    <div>
      <h3 class="fw-bold mb-1">Blockchain Ledger Explorer</h3>
      <p class="text-muted small mb-0">Direct transparent query into the HospitalRecordIntegrity Solidity smart contract</p>
    </div>
    <div>
      <span class="status-badge <?= !empty($nodeStatus['connected']) ? 'status-valid' : 'status-tampered' ?> fs-6">
        <i class="bi bi-broadcast"></i> <?= !empty($nodeStatus['connected']) ? 'Hardhat Node Live' : 'Chain Offline' ?>
      </span>
    </div>
  </div>

  <!-- Smart Contract Details Card -->
  <div class="card card-hospital mb-4">
    <div class="card-header-hospital">
      <span><i class="bi bi-cpu-fill text-primary me-2"></i> Smart Contract Runtime Specifications</span>
      <span class="badge bg-light text-dark font-mono">EVM Solidity 0.8.20</span>
    </div>
    <div class="card-body">
      <div class="row g-3">
        <div class="col-md-6 col-lg-3">
          <label class="small text-muted fw-bold d-block">Contract Address</label>
          <div class="font-mono small text-break text-primary fw-bold">
            <?= htmlspecialchars((string)($nodeStatus['contractAddress'] ?? 'Unset')) ?>
          </div>
        </div>
        <div class="col-md-6 col-lg-3">
          <label class="small text-muted fw-bold d-block">Local Network / Chain</label>
          <div class="small">
            <span class="badge bg-secondary font-mono">Hardhat (Chain ID: 31337)</span>
          </div>
        </div>
        <div class="col-md-6 col-lg-3">
          <label class="small text-muted fw-bold d-block">Current Block Height</label>
          <div class="fw-bold text-dark fs-5">
            #<?= htmlspecialchars((string)($nodeStatus['blockNumber'] ?? 0)) ?>
          </div>
        </div>
        <div class="col-md-6 col-lg-3">
          <label class="small text-muted fw-bold d-block">Total Anchors on Chain</label>
          <div class="fw-bold text-success fs-5">
            <?= count($anchoredList) ?> Anchors
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- On-Chain Anchors Table -->
  <div class="card card-hospital">
    <div class="card-header-hospital">
      <span><i class="bi bi-link-45deg text-success me-2"></i> Immutable On-Chain Hash Records</span>
      <span class="badge bg-light text-dark"><?= count($anchoredList) ?> Total Records Anchored</span>
    </div>
    <div class="card-body p-0">
      <div class="table-responsive">
        <table class="table table-hover align-middle mb-0">
          <thead class="table-light small">
            <tr>
              <th>#</th>
              <th>Record Identifier</th>
              <th>Deterministic SHA-256 Hash Proof</th>
              <th>Anchored Timestamp</th>
              <th>Signer Account</th>
              <th>Record Key (Keccak-256)</th>
            </tr>
          </thead>
          <tbody>
            <?php if (empty($anchoredList)): ?>
              <tr>
                <td colspan="6" class="text-center py-5 text-muted">
                  <i class="bi bi-box-seam fs-1 d-block mb-2"></i>
                  No record hashes anchored on the smart contract yet.
                </td>
              </tr>
            <?php else: ?>
              <?php foreach ($anchoredList as $idx => $item): ?>
                <tr>
                  <td><span class="badge bg-light text-dark border"><?= $idx + 1 ?></span></td>
                  <td>
                    <span class="badge bg-primary-subtle text-primary border font-mono">
                      <?= htmlspecialchars($item['recordType']) ?>
                    </span>
                    <strong>#<?= (int)$item['recordId'] ?></strong>
                    <span class="badge bg-secondary small">v<?= (int)$item['version'] ?></span>
                  </td>
                  <td>
                    <div class="d-flex align-items-center gap-1">
                      <span class="hash-badge match font-mono" title="<?= htmlspecialchars($item['hash']) ?>">
                        <?= htmlspecialchars(substr($item['hash'], 0, 18)) ?>...<?= htmlspecialchars(substr($item['hash'], -8)) ?>
                      </span>
                      <button type="button" class="btn btn-outline-secondary btn-sm py-0 copy-btn" data-copy="<?= htmlspecialchars($item['hash']) ?>" title="Copy full hash">
                        <i class="bi bi-clipboard"></i>
                      </button>
                    </div>
                  </td>
                  <td class="small text-muted text-nowrap">
                    <?= !empty($item['timestamp']) ? htmlspecialchars(date('M d, Y H:i:s', $item['timestamp'])) : 'N/A' ?>
                  </td>
                  <td>
                    <span class="font-mono small text-muted" title="<?= htmlspecialchars($item['anchoredBy']) ?>">
                      <?= htmlspecialchars(substr($item['anchoredBy'], 0, 10)) ?>...
                    </span>
                  </td>
                  <td>
                    <span class="font-mono small text-secondary" title="<?= htmlspecialchars($item['key'] ?? '') ?>">
                      <?= htmlspecialchars(substr($item['key'] ?? '', 0, 12)) ?>...
                    </span>
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
