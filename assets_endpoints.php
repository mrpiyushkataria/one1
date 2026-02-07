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

if (!table_exists($conn, 'oneinseclabs_endpoints')) {
  echo "<div class='card'><h3>Endpoints</h3><div class='muted'>Table <code>oneinseclabs_endpoints</code> not found. Run the SQL migration first.</div>
        <div style='margin-top:10px'><a class='btn' href='project.php?id=".(int)$project_id."'>Back</a></div></div>";
  require __DIR__ . '/includes/footer.php';
  exit;
}

$q        = trim((string)($_GET['q'] ?? ''));
$source   = trim((string)($_GET['source'] ?? ''));
$status   = trim((string)($_GET['status'] ?? '')); // "200", "4xx", "5xx", "live"
$page     = max(1, (int)($_GET['page'] ?? 1));
$per_page = 100;
$offset   = ($page - 1) * $per_page;

$where = " WHERE project_id=? ";
$types = "i";
$args  = [$project_id];

if ($source !== '') {
  $where .= " AND source=? ";
  $types .= "s";
  $args[] = $source;
}

if ($status !== '') {
  if ($status === 'live') $where .= " AND status_code BETWEEN 200 AND 399 ";
  elseif ($status === '2xx') $where .= " AND status_code BETWEEN 200 AND 299 ";
  elseif ($status === '3xx') $where .= " AND status_code BETWEEN 300 AND 399 ";
  elseif ($status === '4xx') $where .= " AND status_code BETWEEN 400 AND 499 ";
  elseif ($status === '5xx') $where .= " AND status_code BETWEEN 500 AND 599 ";
  elseif (ctype_digit($status)) {
    $where .= " AND status_code = " . (int)$status . " ";
  }
}

if ($q !== '') {
  $where .= " AND (url LIKE CONCAT('%',?,'%') OR content_type LIKE CONCAT('%',?,'%')) ";
  $types .= "ss";
  $args[] = $q;
  $args[] = $q;
}

// total
$st = $conn->prepare("SELECT COUNT(*) FROM oneinseclabs_endpoints {$where}");
$st->bind_param($types, ...$args);
$st->execute();
$total = (int)($st->get_result()->fetch_row()[0] ?? 0);

// list
$sql = "SELECT id, url, source, status_code, word_count, line_count, size_bytes, content_type, created_at
        FROM oneinseclabs_endpoints {$where}
        ORDER BY id DESC
        LIMIT {$per_page} OFFSET {$offset}";
$st = $conn->prepare($sql);
$st->bind_param($types, ...$args);
$st->execute();
$rs = $st->get_result();

$sources = [];
$sr = $conn->prepare("SELECT DISTINCT source FROM oneinseclabs_endpoints WHERE project_id=? ORDER BY source ASC");
$sr->bind_param("i", $project_id);
$sr->execute();
$srr = $sr->get_result();
while ($r = $srr->fetch_assoc()) $sources[] = (string)$r['source'];

$pages = max(1, (int)ceil($total / $per_page));
$baseQS = $_GET; unset($baseQS['page']);
function qs(array $base, array $add): string {
  return http_build_query(array_merge($base, $add));
}
?>
<div class="card">
  <div style="display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;align-items:center">
    <div>
      <h2 style="margin:0 0 6px 0;">Endpoints</h2>
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
      <input name="q" value="<?= e($q) ?>" placeholder="url / content-type..." style="min-width:260px">
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
      <label class="muted">Status</label>
      <select name="status">
        <option value="" <?= $status===''?'selected':'' ?>>All</option>
        <option value="live" <?= $status==='live'?'selected':'' ?>>Live (200-399)</option>
        <option value="2xx" <?= $status==='2xx'?'selected':'' ?>>2xx</option>
        <option value="3xx" <?= $status==='3xx'?'selected':'' ?>>3xx</option>
        <option value="4xx" <?= $status==='4xx'?'selected':'' ?>>4xx</option>
        <option value="5xx" <?= $status==='5xx'?'selected':'' ?>>5xx</option>
        <option value="200" <?= $status==='200'?'selected':'' ?>>200</option>
        <option value="301" <?= $status==='301'?'selected':'' ?>>301</option>
        <option value="302" <?= $status==='302'?'selected':'' ?>>302</option>
        <option value="401" <?= $status==='401'?'selected':'' ?>>401</option>
        <option value="403" <?= $status==='403'?'selected':'' ?>>403</option>
        <option value="404" <?= $status==='404'?'selected':'' ?>>404</option>
        <option value="500" <?= $status==='500'?'selected':'' ?>>500</option>
      </select>
    </div>
    <button class="btn primary" type="submit">Apply</button>
    <a class="btn" href="assets_endpoints.php?project_id=<?= (int)$project_id ?>">Reset</a>
  </form>
</div>

<div class="card" style="margin-top:12px">
  <table class="table">
    <thead>
      <tr>
        <th>ID</th>
        <th>URL</th>
        <th>Source</th>
        <th>Status</th>
        <th>Words</th>
        <th>Lines</th>
        <th>Size</th>
        <th>Content-Type</th>
        <th>Seen</th>
      </tr>
    </thead>
    <tbody>
      <?php while($r = $rs->fetch_assoc()): ?>
        <tr>
          <td class="muted"><?= (int)$r['id'] ?></td>
          <td style="max-width:640px;word-break:break-all">
            <a href="<?= e($r['url']) ?>" target="_blank" rel="noopener"><?= e($r['url']) ?></a>
          </td>
          <td class="muted"><?= e($r['source'] ?? '') ?></td>
          <td><span class="badge"><?= e((string)($r['status_code'] ?? '')) ?></span></td>
          <td class="muted"><?= e((string)($r['word_count'] ?? '')) ?></td>
          <td class="muted"><?= e((string)($r['line_count'] ?? '')) ?></td>
          <td class="muted"><?= e((string)($r['size_bytes'] ?? '')) ?></td>
          <td class="muted"><?= e((string)($r['content_type'] ?? '')) ?></td>
          <td class="muted"><?= e((string)($r['created_at'] ?? '')) ?></td>
        </tr>
      <?php endwhile; ?>
      <?php if ($total === 0): ?>
        <tr><td colspan="9" class="muted">No endpoints found.</td></tr>
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
