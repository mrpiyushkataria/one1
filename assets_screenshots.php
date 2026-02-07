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

if (!table_exists($conn, 'oneinseclabs_screenshots')) {
  echo "<div class='card'><h3>Screenshots</h3><div class='muted'>Table <code>oneinseclabs_screenshots</code> not found. Run the SQL migration first.</div>
        <div style='margin-top:10px'><a class='btn' href='project.php?id=".(int)$project_id."'>Back</a></div></div>";
  require __DIR__ . '/includes/footer.php';
  exit;
}

$q        = trim((string)($_GET['q'] ?? ''));      // url/title search
$status   = trim((string)($_GET['status'] ?? '')); // "live", "2xx", "4xx", etc
$page     = max(1, (int)($_GET['page'] ?? 1));
$per_page = 60;
$offset   = ($page - 1) * $per_page;

$where = " WHERE project_id=? ";
$types = "i";
$args  = [$project_id];

if ($status !== '') {
  if ($status === 'live') $where .= " AND status_code BETWEEN 200 AND 399 ";
  elseif ($status === '2xx') $where .= " AND status_code BETWEEN 200 AND 299 ";
  elseif ($status === '3xx') $where .= " AND status_code BETWEEN 300 AND 399 ";
  elseif ($status === '4xx') $where .= " AND status_code BETWEEN 400 AND 499 ";
  elseif ($status === '5xx') $where .= " AND status_code BETWEEN 500 AND 599 ";
  elseif (ctype_digit($status)) $where .= " AND status_code=".(int)$status." ";
}

if ($q !== '') {
  $where .= " AND (url LIKE CONCAT('%',?,'%') OR title LIKE CONCAT('%',?,'%') OR image_path LIKE CONCAT('%',?,'%')) ";
  $types .= "sss";
  $args[] = $q; $args[] = $q; $args[] = $q;
}

$st = $conn->prepare("SELECT COUNT(*) FROM oneinseclabs_screenshots {$where}");
$st->bind_param($types, ...$args);
$st->execute();
$total = (int)($st->get_result()->fetch_row()[0] ?? 0);

$sql = "SELECT id, run_id, url, image_path, title, status_code, created_at
        FROM oneinseclabs_screenshots {$where}
        ORDER BY id DESC
        LIMIT {$per_page} OFFSET {$offset}";
$st = $conn->prepare($sql);
$st->bind_param($types, ...$args);
$st->execute();
$rs = $st->get_result();

$pages = max(1, (int)ceil($total / $per_page));
$baseQS = $_GET; unset($baseQS['page']);
function qs(array $base, array $add): string { return http_build_query(array_merge($base, $add)); }

// Helper: safe image URL (stored as relative path)
function safe_image_url(string $p): string {
  $p = str_replace('\\','/',$p);
  $p = ltrim($p, '/');
  // allow only within uploads/
  if (!str_starts_with($p, 'uploads/')) return '';
  if (strpos($p, '../') !== false) return '';
  return $p;
}
?>
<div class="card">
  <div style="display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;align-items:center">
    <div>
      <h2 style="margin:0 0 6px 0;">Screenshots</h2>
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
      <input name="q" value="<?= e($q) ?>" placeholder="url / title / file..." style="min-width:260px">
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
      </select>
    </div>
    <button class="btn primary" type="submit">Apply</button>
    <a class="btn" href="assets_screenshots.php?project_id=<?= (int)$project_id ?>">Reset</a>
  </form>
</div>

<div class="card" style="margin-top:12px">
  <div class="grid" style="grid-template-columns:repeat(3,1fr);gap:12px">
    <?php while($r = $rs->fetch_assoc()): ?>
      <?php
        $img = safe_image_url((string)$r['image_path']);
      ?>
      <div class="card" style="margin:0">
        <div style="display:flex;justify-content:space-between;gap:8px;align-items:center">
          <span class="badge"><?= e((string)($r['status_code'] ?? '')) ?></span>
          <span class="muted" style="font-size:12px"><?= e((string)($r['created_at'] ?? '')) ?></span>
        </div>

        <div style="margin-top:8px;max-height:54px;overflow:hidden">
          <div style="word-break:break-all">
            <a href="<?= e((string)$r['url']) ?>" target="_blank" rel="noopener"><?= e((string)$r['url']) ?></a>
          </div>
          <?php if (!empty($r['title'])): ?>
            <div class="muted" style="font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">
              <?= e((string)$r['title']) ?>
            </div>
          <?php endif; ?>
        </div>

        <div style="margin-top:10px">
          <?php if ($img !== ''): ?>
            <a href="<?= e($img) ?>" target="_blank" rel="noopener">
              <img src="<?= e($img) ?>" alt="screenshot" style="width:100%;border-radius:10px;display:block">
            </a>
          <?php else: ?>
            <div class="muted">Image path not allowed: <?= e((string)$r['image_path']) ?></div>
          <?php endif; ?>
        </div>

        <div class="muted" style="margin-top:8px;font-size:12px;word-break:break-all">
          File: <?= e((string)$r['image_path']) ?> • Run #<?= (int)($r['run_id'] ?? 0) ?>
        </div>
      </div>
    <?php endwhile; ?>

    <?php if ($total === 0): ?>
      <div class="muted">No screenshots found.</div>
    <?php endif; ?>
  </div>

  <div style="display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;margin-top:14px">
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
