<?php
/**
 * public_html/one.inseclabs.com/shodan_explorer.php
 * Explore Shodan services with filters + pagination.
 */
declare(strict_types=1);
require_once __DIR__ . '/includes/header.php';

$conn = db();
$uid  = (int)current_user_id();
if ($uid <= 0) { header("Location: index.php"); exit; }

$project_id = (int)($_GET['project_id'] ?? 0);
if ($project_id <= 0) redirect('dashboard.php');

$page = max(1, (int)($_GET['page'] ?? 1));
$limit = 100;
$offset = ($page-1)*$limit;

$q = trim((string)($_GET['q'] ?? ''));
$org = trim((string)($_GET['org'] ?? ''));
$product = trim((string)($_GET['product'] ?? ''));
$vuln = trim((string)($_GET['vuln'] ?? ''));
$port = (int)($_GET['port'] ?? 0);

$where = " WHERE s.project_id=? ";
$types = "i";
$params = [$project_id];

if ($q !== '') {
  $where .= " AND (s.ip LIKE CONCAT('%',?,'%') OR s.hostnames LIKE CONCAT('%',?,'%') OR s.banner LIKE CONCAT('%',?,'%'))";
  $types .= "sss";
  $params[]=$q; $params[]=$q; $params[]=$q;
}
if ($org !== '') { $where .= " AND s.org LIKE CONCAT('%',?,'%')"; $types.="s"; $params[]=$org; }
if ($product !== '') { $where .= " AND s.product LIKE CONCAT('%',?,'%')"; $types.="s"; $params[]=$product; }
if ($port > 0) { $where .= " AND s.port=?"; $types.="i"; $params[]=$port; }
if ($vuln !== '') { $where .= " AND s.vulns LIKE CONCAT('%',?,'%')"; $types.="s"; $params[]=$vuln; }

$st = $conn->prepare("SELECT COUNT(*) FROM oneinseclabs_shodan_services s $where");
$st->bind_param($types, ...$params);
$st->execute();
$total = (int)($st->get_result()->fetch_row()[0] ?? 0);

$sql = "SELECT s.id, s.ip, s.port, s.transport, s.product, s.version, s.org, s.country, s.city, s.vulns, s.updated_at
        FROM oneinseclabs_shodan_services s
        $where
        ORDER BY s.updated_at DESC
        LIMIT $limit OFFSET $offset";

$st = $conn->prepare($sql);
$st->bind_param($types, ...$params);
$st->execute();
$rs = $st->get_result();
$rows = [];
while ($r = $rs->fetch_assoc()) $rows[] = $r;

$qs = $_GET;
unset($qs['page']);
$base = http_build_query($qs);
$exportUrl = "api/shodan_export.php?".$base;
?>
<div class="top">
  <div class="title">
    <h2>Shodan Explorer</h2>
    <div class="muted">Project #<?= (int)$project_id ?> • Total: <?= (int)$total ?></div>
  </div>
  <div class="row">
    <a class="btn" href="shodan.php?project_id=<?= (int)$project_id ?>">← Shodan</a>
    <a class="btn" href="<?= e($exportUrl) ?>">Export CSV</a>
  </div>
</div>

<div class="card">
  <form method="get" class="grid" style="grid-template-columns:2fr 1fr 1fr 1fr 1fr auto;gap:10px;align-items:end">
    <input type="hidden" name="project_id" value="<?= (int)$project_id ?>">
    <div>
      <label class="muted">Text</label>
      <input name="q" value="<?= e($q) ?>" placeholder="ip / hostnames / banner">
    </div>
    <div>
      <label class="muted">Org</label>
      <input name="org" value="<?= e($org) ?>">
    </div>
    <div>
      <label class="muted">Product</label>
      <input name="product" value="<?= e($product) ?>">
    </div>
    <div>
      <label class="muted">Port</label>
      <input name="port" value="<?= e((string)$port) ?>">
    </div>
    <div>
      <label class="muted">Vuln</label>
      <input name="vuln" value="<?= e($vuln) ?>" placeholder="CVE-">
    </div>
    <div>
      <button class="btn primary" type="submit">Filter</button>
    </div>
  </form>
</div>

<div class="card">
  <table class="table">
    <thead><tr><th>IP:Port</th><th>Product</th><th>Org</th><th>Country</th><th>Vulns</th><th>Updated</th></tr></thead>
    <tbody>
      <?php foreach ($rows as $r): ?>
        <tr>
          <td><a href="shodan_service.php?id=<?= (int)$r['id'] ?>&project_id=<?= (int)$project_id ?>"><code><?= e($r['ip']) ?>:<?= (int)$r['port'] ?></code></a></td>
          <td><?= e(trim(($r['product'] ?? '').' '.($r['version'] ?? ''))) ?><div class="muted" style="font-size:12px"><?= e($r['transport'] ?? '') ?></div></td>
          <td class="muted"><?= e($r['org'] ?? '') ?></td>
          <td class="muted"><?= e(trim(($r['country'] ?? '').' '.$r['city'])) ?></td>
          <td class="muted" style="font-size:12px"><?= e($r['vulns'] ?? '') ?></td>
          <td class="muted"><?= e($r['updated_at'] ?? '') ?></td>
        </tr>
      <?php endforeach; ?>
      <?php if (!$rows): ?><tr><td colspan="6" class="muted">No results.</td></tr><?php endif; ?>
    </tbody>
  </table>

  <?php
    $pages = (int)ceil($total / $limit);
    $pages = max(1, $pages);
    $prev = max(1, $page-1);
    $next = min($pages, $page+1);
  ?>
  <div style="display:flex;gap:10px;justify-content:flex-end;margin-top:10px;align-items:center">
    <span class="muted">Page <?= (int)$page ?> / <?= (int)$pages ?></span>
    <a class="btn" href="?<?= e($base) ?>&page=<?= (int)$prev ?>">Prev</a>
    <a class="btn" href="?<?= e($base) ?>&page=<?= (int)$next ?>">Next</a>
  </div>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
