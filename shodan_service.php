<?php
/**
 * public_html/one.inseclabs.com/shodan_service.php
 * Single service detail + vulns list + create finding.
 */
declare(strict_types=1);
require_once __DIR__ . '/includes/header.php';

$conn = db();
$uid  = (int)current_user_id();
if ($uid <= 0) { header("Location: index.php"); exit; }

$project_id = (int)($_GET['project_id'] ?? 0);
$id = (int)($_GET['id'] ?? 0);
if ($project_id <= 0 || $id <= 0) redirect('dashboard.php');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  csrf_check();
  $title = trim((string)($_POST['title'] ?? ''));
  $severity = (string)($_POST['severity'] ?? 'info');
  $status = (string)($_POST['status'] ?? 'open');
  $cve = trim((string)($_POST['cve'] ?? ''));
  $notes = trim((string)($_POST['notes'] ?? ''));

  if ($title !== '') {
    $st = $conn->prepare("
      INSERT INTO oneinseclabs_shodan_findings
        (project_id, service_id, title, severity, status, cve, notes, created_by)
      VALUES (?,?,?,?,?,?,?,?)
    ");
    $st->bind_param("iisssssi", $project_id, $id, $title, $severity, $status, $cve, $notes, $uid);
    $st->execute();
  }
  redirect("shodan_service.php?id=".$id."&project_id=".$project_id);
}

$st = $conn->prepare("SELECT * FROM oneinseclabs_shodan_services WHERE id=? AND project_id=? LIMIT 1");
$st->bind_param("ii", $id, $project_id);
$st->execute();
$s = $st->get_result()->fetch_assoc();
if (!$s) redirect("shodan_explorer.php?project_id=".$project_id);

$vulns = [];
$st = $conn->prepare("SELECT vuln_id, verified, created_at FROM oneinseclabs_shodan_service_vulns WHERE project_id=? AND service_id=? ORDER BY vuln_id ASC");
$st->bind_param("ii", $project_id, $id);
$st->execute();
$rs = $st->get_result();
while ($r = $rs->fetch_assoc()) $vulns[] = $r;

$findings = [];
$st = $conn->prepare("SELECT * FROM oneinseclabs_shodan_findings WHERE project_id=? AND service_id=? ORDER BY created_at DESC LIMIT 50");
$st->bind_param("ii", $project_id, $id);
$st->execute();
$rs = $st->get_result();
while ($r = $rs->fetch_assoc()) $findings[] = $r;

?>
<div class="top">
  <div class="title">
    <h2><code><?= e($s['ip']) ?>:<?= (int)$s['port'] ?></code> • <?= e($s['product'] ?? '') ?> <?= e($s['version'] ?? '') ?></h2>
    <div class="muted"><?= e($s['org'] ?? '') ?> • <?= e($s['country'] ?? '') ?> <?= e($s['city'] ?? '') ?> • <?= e($s['transport'] ?? '') ?></div>
  </div>
  <div class="row">
    <a class="btn" href="shodan_explorer.php?project_id=<?= (int)$project_id ?>">← Explorer</a>
  </div>
</div>

<div class="grid">
  <div class="card col-6">
    <h3>Parsed</h3>
    <div class="muted">Hostnames</div>
    <div><code><?= e($s['hostnames'] ?? '') ?></code></div>
    <div style="height:10px"></div>
    <div class="muted">Domains</div>
    <div><code><?= e($s['domains'] ?? '') ?></code></div>
    <div style="height:10px"></div>
    <div class="muted">Banner (preview)</div>
    <pre style="white-space:pre-wrap;max-height:260px;overflow:auto"><?= e(mb_strimwidth((string)($s['banner'] ?? ''), 0, 2000, "…")) ?></pre>
  </div>

  <div class="card col-6">
    <h3>Vulnerabilities</h3>
    <table class="table">
      <thead><tr><th>CVE</th><th>Verified</th><th>Seen</th></tr></thead>
      <tbody>
        <?php foreach ($vulns as $v): ?>
          <tr>
            <td><code><?= e($v['vuln_id']) ?></code></td>
            <td class="muted"><?= ((int)$v['verified']===1) ? 'yes' : 'no' ?></td>
            <td class="muted"><?= e($v['created_at']) ?></td>
          </tr>
        <?php endforeach; ?>
        <?php if (!$vulns): ?><tr><td colspan="3" class="muted">No vulns recorded.</td></tr><?php endif; ?>
      </tbody>
    </table>
  </div>

  <div class="card col-12">
    <h3>Create Finding</h3>
    <form method="post">
      <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
      <div class="grid" style="grid-template-columns:2fr 1fr 1fr 1fr;gap:10px">
        <div>
          <label class="muted">Title</label>
          <input name="title" placeholder="e.g., Exposed admin panel / vulnerable service" required>
        </div>
        <div>
          <label class="muted">Severity</label>
          <select name="severity">
            <option>info</option><option>low</option><option selected>medium</option><option>high</option><option>critical</option>
          </select>
        </div>
        <div>
          <label class="muted">Status</label>
          <select name="status">
            <option selected>open</option><option>triage</option><option>valid</option><option>fixed</option><option>duplicate</option><option>na</option>
          </select>
        </div>
        <div>
          <label class="muted">CVE (optional)</label>
          <input name="cve" placeholder="CVE-YYYY-NNNN">
        </div>
      </div>
      <label class="muted" style="margin-top:10px">Notes</label>
      <textarea name="notes" style="min-height:80px"></textarea>
      <button class="btn primary" style="margin-top:10px">Save Finding</button>
    </form>
  </div>

  <div class="card col-12">
    <h3>Findings</h3>
    <table class="table">
      <thead><tr><th>Time</th><th>Title</th><th>Severity</th><th>Status</th><th>CVE</th></tr></thead>
      <tbody>
        <?php foreach ($findings as $f): ?>
          <tr>
            <td class="muted"><?= e($f['created_at'] ?? '') ?></td>
            <td><?= e($f['title'] ?? '') ?><div class="muted" style="font-size:12px"><?= e(mb_strimwidth((string)($f['notes'] ?? ''),0,140,'…')) ?></div></td>
            <td><code><?= e($f['severity'] ?? '') ?></code></td>
            <td><code><?= e($f['status'] ?? '') ?></code></td>
            <td class="muted"><?= e($f['cve'] ?? '') ?></td>
          </tr>
        <?php endforeach; ?>
        <?php if (!$findings): ?><tr><td colspan="5" class="muted">No findings yet.</td></tr><?php endif; ?>
      </tbody>
    </table>
  </div>

  <div class="card col-12">
    <h3>Raw JSON</h3>
    <pre style="white-space:pre-wrap;max-height:520px;overflow:auto"><?= e($s['raw_json'] ?? '') ?></pre>
  </div>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
