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

if (!table_exists($conn, 'oneinseclabs_params')) {
  echo "<div class='card'><h3>Params</h3><div class='muted'>Table <code>oneinseclabs_params</code> not found. Run the SQL migration first.</div>
        <div style='margin-top:10px'><a class='btn' href='project.php?id=".(int)$project_id."'>Back</a></div></div>";
  require __DIR__ . '/includes/footer.php';
  exit;
}

$q      = trim((string)($_GET['q'] ?? ''));
$source = trim((string)($_GET['source'] ?? ''));
$host   = trim((string)($_GET['host'] ?? ''));
$page   = max(1, (int)($_GET['page'] ?? 1));
$per_page = 150;
$offset = ($page - 1) * $per_page;

$where = " WHERE project_id=? ";
$types = "i";
$args  = [$project_id];

if ($source !== '') { $where .= " AND source=? "; $types.="s"; $args[]=$source; }
if ($host !== '')   { $where .= " AND host=? ";   $types.="s"; $args[]=$host; }

if ($q !== '') {
  $where .= " AND (param_name LIKE CONCAT('%',?,'%') OR url LIKE CONCAT('%',?,'%') OR host LIKE CONCAT('%',?,'%')) ";
  $types .= "sss";
  $args[] = $q; $args[] = $q; $args[] = $q;
}

$st = $conn->prepare("SELECT COUNT(*) FROM oneinseclabs_params {$where}");
$st->bind_param($types, ...$args);
$st->execute();
$total = (int)($st->get_result()->fetch_row()[0] ?? 0);

$sql = "SELECT id, run_id, host, url, param_name, source, created_at
        FROM oneinseclabs_params {$where}
        ORDER BY id DESC
        LIMIT {$per_page} OFFSET {$offset}";
$st = $conn->prepare($sql);
$st->bind_param($types, ...$args);
$st->execute();
$rs = $st->get_result();

$sources = [];
$sr = $conn->prepare("SELECT DISTINCT source FROM oneinseclabs_params WHERE project_id=? ORDER BY source ASC");
$sr->bind_param("i", $project_id);
$sr->execute();
$srr = $sr->get_result();
while ($r = $srr->fetch_assoc()) $sources[] = (string)$r['source'];

$hosts = [];
$sr = $conn->prepare("SELECT DISTINCT host FROM oneinseclabs_params WHERE project_id=? AND host IS NOT NULL AND host<>'' ORDER BY host ASC LIMIT 300");
$sr->bind_param("i", $project_id);
$sr->execute();
$srr = $sr->get_result();
while ($r = $srr->fetch_assoc()) $hosts[] = (string)$r['host'];

$pages = max(1, (int)ceil($total / $per_page));
$baseQS = $_GET; unset($baseQS['page']);
function qs(array $base, array $add): string { return http_build_query(array_merge($base, $add)); }
?>
<div class="card">
  <div style="display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;align-items:center">
    <div>
      <h2 style="margin:0 0 6px 0;">Parameters</h2>
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
      <input name="q" value="<?= e($q) ?>" placeholder="param / url / host..." style="min-width:260px">
    </div>
    <div>
      <label class="muted">Source</label>
      <select name="source">
        <option value="">All</option>
        <?php foreach($sources as $s): ?>
          <option value="<?= e($s) ?>" <?= $s===$source?'selected':'' ?>><?= e($s) ?></option>
        <?php endforeach; ?>
      </select>
    </div>
    <div>
      <label class="muted">Host</label>
      <select name="host">
        <option value="">All</option>
        <?php foreach($hosts as $h): ?>
          <option value="<?= e($h) ?>" <?= $h===$host?'selected':'' ?>><?= e($h) ?></option>
        <?php endforeach; ?>
      </select>
    </div>
    <button class="btn primary" type="submit">Apply</button>
    <a class="btn" href="assets_params.php?project_id=<?= (int)$project_id ?>">Reset</a>
  </form>
</div>

<div class="card" style="margin-top:12px">
  <table class="table">
    <thead>
      <tr>
        <th>ID</th>
        <th>Param</th>
        <th>Host</th>
        <th>URL</th>
        <th>Source</th>
        <th>Run</th>
        <th>Time</th>
      </tr>
    </thead>
    <tbody>
      <?php while($r = $rs->fetch_assoc()): ?>
        <tr>
          <td class="muted"><?= (int)$r['id'] ?></td>
          <td><code><?= e((string)$r['param_name']) ?></code></td>
          <td class="muted"><?= e((string)($r['host'] ?? '')) ?></td>
          <td style="max-width:640px;word-break:break-all">
            <?php if (!empty($r['url'])): ?>
              <a href="<?= e((string)$r['url']) ?>" target="_blank" rel="noopener"><?= e((string)$r['url']) ?></a>
            <?php else: ?>
              <span class="muted">—</span>
            <?php endif; ?>
          </td>
          <td class="muted"><?= e((string)$r['source']) ?></td>
          <td class="muted"><?= (int)($r['run_id'] ?? 0) ?></td>
          <td class="muted"><?= e((string)($r['created_at'] ?? '')) ?></td>
        </tr>
      <?php endwhile; ?>
      <?php if ($total === 0): ?>
        <tr><td colspan="7" class="muted">No params found.</td></tr>
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
