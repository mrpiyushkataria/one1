<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/header.php';
$conn = db();

$project_id = (int)($_GET['project_id'] ?? 0);
if ($project_id <= 0) redirect('dashboard.php');

function table_exists(mysqli $conn, string $table): bool {
  $t = $conn->real_escape_string($table);
  $rs = $conn->query("SHOW TABLES LIKE '{$t}'");
  return $rs && $rs->num_rows > 0;
}

if (!table_exists($conn, 'oneinseclabs_findings')) {
  echo "<div class='card'><h3>Findings</h3><div class='muted'>Table <code>oneinseclabs_findings</code> not found. Run the SQL migration first.</div>
        <div style='margin-top:10px'><a class='btn' href='project.php?id=".(int)$project_id."'>Back</a></div></div>";
  require __DIR__ . '/includes/footer.php';
  exit;
}

$q        = trim((string)($_GET['q'] ?? ''));
$tool     = trim((string)($_GET['tool'] ?? ''));
$severity = trim((string)($_GET['severity'] ?? ''));
$page     = max(1, (int)($_GET['page'] ?? 1));
$per_page = 100;
$offset   = ($page - 1) * $per_page;

$where = " WHERE project_id=? ";
$types = "i";
$args  = [$project_id];

if ($tool !== '') {
  $where .= " AND tool=? ";
  $types .= "s";
  $args[] = $tool;
}
if ($severity !== '') {
  $where .= " AND severity=? ";
  $types .= "s";
  $args[] = $severity;
}
if ($q !== '') {
  $where .= " AND (target LIKE CONCAT('%',?,'%') OR title LIKE CONCAT('%',?,'%') OR template_id LIKE CONCAT('%',?,'%')) ";
  $types .= "sss";
  $args[] = $q; $args[] = $q; $args[] = $q;
}

$st = $conn->prepare("SELECT COUNT(*) FROM oneinseclabs_findings {$where}");
$st->bind_param($types, ...$args);
$st->execute();
$total = (int)($st->get_result()->fetch_row()[0] ?? 0);

$sql = "SELECT id, run_id, tool, severity, template_id, target, title, created_at
        FROM oneinseclabs_findings {$where}
        ORDER BY id DESC
        LIMIT {$per_page} OFFSET {$offset}";
$st = $conn->prepare($sql);
$st->bind_param($types, ...$args);
$st->execute();
$rs = $st->get_result();

$tools = [];
$sr = $conn->prepare("SELECT DISTINCT tool FROM oneinseclabs_findings WHERE project_id=? ORDER BY tool ASC");
$sr->bind_param("i", $project_id);
$sr->execute();
$srr = $sr->get_result();
while ($r = $srr->fetch_assoc()) $tools[] = (string)$r['tool'];

$sevs = [];
$sr = $conn->prepare("SELECT DISTINCT severity FROM oneinseclabs_findings WHERE project_id=? ORDER BY FIELD(severity,'critical','high','medium','low','info'), severity ASC");
$sr->bind_param("i", $project_id);
$sr->execute();
$srr = $sr->get_result();
while ($r = $srr->fetch_assoc()) $sevs[] = (string)$r['severity'];

$pages = max(1, (int)ceil($total / $per_page));
$baseQS = $_GET; unset($baseQS['page']);
function qs(array $base, array $add): string { return http_build_query(array_merge($base, $add)); }
?>
<div class="card">
  <div style="display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;align-items:center">
    <div>
      <h2 style="margin:0 0 6px 0;">Findings</h2>
      <div class="muted">Project #<?= (int)$project_id ?> • Total: <?= (int)$total ?></div>
    </div>
    <div style="display:flex;gap:8px;flex-wrap:wrap">
      <a class="btn" href="project.php?id=<?= (int)$project_id ?>">Back</a>
      <a class="btn" href="mindmap.php?project_id=<?= (int)$project_id ?>">3D Graph</a>
    </div>
  </div>
</div>

<div class="card" style="margin-top:12px">
  <form method="get" style="display:flex;gap:10px;flex-wrap:wrap;align-items:end">
    <input type="hidden" name="project_id" value="<?= (int)$project_id ?>">
    <div>
      <label class="muted">Search</label>
      <input name="q" value="<?= e($q) ?>" placeholder="target / title / template..." style="min-width:260px">
    </div>
    <div>
      <label class="muted">Tool</label>
      <select name="tool">
        <option value="">All</option>
        <?php foreach($tools as $t): ?>
          <option value="<?= e($t) ?>" <?= $t===$tool?'selected':'' ?>><?= e($t) ?></option>
        <?php endforeach; ?>
      </select>
    </div>
    <div>
      <label class="muted">Severity</label>
      <select name="severity">
        <option value="">All</option>
        <?php foreach($sevs as $s): ?>
          <option value="<?= e($s) ?>" <?= $s===$severity?'selected':'' ?>><?= e($s) ?></option>
        <?php endforeach; ?>
      </select>
    </div>
    <button class="btn primary" type="submit">Apply</button>
    <a class="btn" href="assets_findings.php?project_id=<?= (int)$project_id ?>">Reset</a>
  </form>
</div>

<div class="card" style="margin-top:12px">
  <table class="table">
    <thead>
      <tr>
        <th>ID</th>
        <th>Severity</th>
        <th>Tool</th>
        <th>Template</th>
        <th>Target</th>
        <th>Title</th>
        <th>Run</th>
        <th>Time</th>
      </tr>
    </thead>
    <tbody>
      <?php while($r = $rs->fetch_assoc()): ?>
        <tr>
          <td class="muted"><?= (int)$r['id'] ?></td>
          <td><span class="badge"><?= e((string)($r['severity'] ?? '')) ?></span></td>
          <td class="muted"><?= e((string)($r['tool'] ?? '')) ?></td>
          <td class="muted" style="max-width:240px;word-break:break-all"><?= e((string)($r['template_id'] ?? '')) ?></td>
          <td style="max-width:520px;word-break:break-all"><?= e((string)($r['target'] ?? '')) ?></td>
          <td style="max-width:420px;word-break:break-word"><?= e((string)($r['title'] ?? '')) ?></td>
          <td class="muted"><?= (int)($r['run_id'] ?? 0) ?></td>
          <td class="muted"><?= e((string)($r['created_at'] ?? '')) ?></td>
        </tr>
      <?php endwhile; ?>
      <?php if ($total === 0): ?>
        <tr><td colspan="8" class="muted">No findings found.</td></tr>
      <?php endif; ?>
    </tbody>
  </table>

  <div style="display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;margin-top:12px">
    <div class="muted">Page <?= (int)$page ?> / <?= (int)$pages ?></div>
    <div style="display:flex;gap:8px;flex-wrap:wrap">
      <?php if ($page > 1): ?>
        <a class="btn" href="?<?= e(qs($baseQS, ['page'=>$page-1])) ?>">← Prev</a>
      <?php endif; ?>
      <?php if ($page < $pages): ?>
        <a class="btn" href="?<?= e(qs($baseQS, ['page'=>$page+1])) ?>">Next →</a>
      <?php endif; ?>
    </div>
  </div>
</div>

<?php require __DIR__ . '/includes/footer.php'; ?>
