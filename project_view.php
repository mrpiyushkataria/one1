<?php
require_once __DIR__ . '/header.php';
$conn = db();

$project_id = max(1,(int)($_GET['project_id'] ?? 0));
if ($project_id < 1) die("Missing project_id");

$p = $conn->query("
  SELECT p.*, c.name company, c.domains
  FROM oneinseclabs_projects p
  JOIN oneinseclabs_companies c ON c.id=p.company_id
  WHERE p.id=$project_id
")->fetch_assoc();

$assets = $conn->query("SELECT asset_type, COUNT(*) c FROM oneinseclabs_assets WHERE project_id=$project_id GROUP BY asset_type");
$scans  = $conn->query("SELECT * FROM oneinseclabs_scans WHERE project_id=$project_id ORDER BY id DESC LIMIT 20");

$ports  = $conn->query("
  SELECT a.asset_value ip, p.protocol, p.port, p.state, p.service_name, p.product, p.version
  FROM oneinseclabs_ports p
  JOIN oneinseclabs_assets a ON a.id=p.ip_asset_id
  WHERE p.project_id=$project_id
  ORDER BY a.asset_value, p.port
  LIMIT 200
");
?>
<style>
  .wrap{max-width:1200px;margin:20px auto;padding:16px}
  .card{background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.08);border-radius:14px;padding:14px;margin-bottom:12px}
  table{width:100%;border-collapse:collapse}
  th,td{padding:10px;border-bottom:1px solid rgba(255,255,255,.08);text-align:left}
  .muted{color:#9ca3af}
  a{color:#93c5fd}
</style>
<div class="wrap">
  <div class="card">
    <h2 style="margin:0 0 6px 0;"><?= htmlspecialchars($p['title'] ?? '') ?></h2>
    <div class="muted">Company: <?= htmlspecialchars($p['company'] ?? '') ?></div>
    <div class="muted">Scope domains: <?= nl2br(htmlspecialchars($p['domains'] ?? '')) ?></div>
    <div style="margin-top:10px;display:flex;gap:10px;flex-wrap:wrap">
      <a href="/recon_upload.php" class="muted">Upload new scan</a>
      <a href="/visualization.php" class="muted">Open 3D Graph</a>
    </div>
  </div>

  <div class="card">
    <h3 style="margin:0 0 10px 0;">Stats</h3>
    <table>
      <thead><tr><th>Asset Type</th><th>Count</th></tr></thead>
      <tbody>
        <?php while($r=$assets->fetch_assoc()): ?>
          <tr><td><?= htmlspecialchars($r['asset_type']) ?></td><td><?= (int)$r['c'] ?></td></tr>
        <?php endwhile; ?>
      </tbody>
    </table>
  </div>

  <div class="card">
    <h3 style="margin:0 0 10px 0;">Recent Scans</h3>
    <table>
      <thead><tr><th>Type</th><th>Tool</th><th>File</th><th>Created</th><th>Summary</th></tr></thead>
      <tbody>
        <?php while($s=$scans->fetch_assoc()): ?>
          <tr>
            <td><?= htmlspecialchars($s['scan_type']) ?></td>
            <td><?= htmlspecialchars($s['tool_name']) ?></td>
            <td class="muted"><?= htmlspecialchars($s['original_filename']) ?></td>
            <td class="muted"><?= htmlspecialchars($s['created_at']) ?></td>
            <td class="muted"><?= htmlspecialchars($s['parsed_summary'] ?? '') ?></td>
          </tr>
        <?php endwhile; ?>
      </tbody>
    </table>
  </div>

  <div class="card">
    <h3 style="margin:0 0 10px 0;">Ports (Top 200)</h3>
    <table>
      <thead><tr><th>IP</th><th>Proto</th><th>Port</th><th>State</th><th>Service</th><th>Product</th></tr></thead>
      <tbody>
        <?php while($r=$ports->fetch_assoc()): ?>
          <tr>
            <td><?= htmlspecialchars($r['ip']) ?></td>
            <td><?= htmlspecialchars($r['protocol']) ?></td>
            <td><?= (int)$r['port'] ?></td>
            <td><?= htmlspecialchars($r['state']) ?></td>
            <td><?= htmlspecialchars($r['service_name'] ?? '') ?></td>
            <td class="muted"><?= htmlspecialchars(trim(($r['product'] ?? '').' '.($r['version'] ?? ''))) ?></td>
          </tr>
        <?php endwhile; ?>
      </tbody>
    </table>
  </div>
</div>
<?php require_once __DIR__ . '/footer.php'; ?>
