<?php
/**
 * public_html/one.inseclabs.com/assets.php
 * Professional table views for assets with filters.
 */
declare(strict_types=1);
ini_set('display_errors','0');
error_reporting(E_ALL);

require_once __DIR__ . '/includes/header.php';
$conn = db();

$project_id = (int)($_GET['project_id'] ?? 0);
if ($project_id <= 0) redirect('dashboard.php');

$root = trim((string)($_GET['root'] ?? ''));
$root = preg_replace('#^https?://#','',$root);
$root = trim($root,'/');

$category = strtolower(trim((string)($_GET['category'] ?? 'all')));
if (!in_array($category, ['all','recon','dns','web','network'], true)) $category='all';

$types = trim((string)($_GET['types'] ?? 'subdomains,hosts,ports,urls'));
$typesArr = array_filter(array_map('trim', explode(',', $types)));

$q = trim((string)($_GET['q'] ?? ''));

function e2($s){ return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }

$like = "%".$q."%";

$stats = [
  'subdomains' => 0,
  'hosts' => 0,
  'ports' => 0,
  'urls' => 0,
];

if ($category === 'all' || $category === 'recon') {
  $sql = "SELECT COUNT(*) c FROM oneinseclabs_subdomains WHERE project_id=? ";
  $params = [$project_id]; $typesBind="i";
  if ($root !== '') { $sql .= " AND root_domain=? "; $params[]=$root; $typesBind.="s"; }
  if ($q !== '') { $sql .= " AND subdomain LIKE ? "; $params[]=$like; $typesBind.="s"; }
  $st = $conn->prepare($sql); $st->bind_param($typesBind, ...$params); $st->execute();
  $stats['subdomains'] = (int)($st->get_result()->fetch_assoc()['c'] ?? 0);
}

if ($category === 'all' || $category === 'dns' || $category === 'network') {
  $sql = "SELECT COUNT(*) c FROM oneinseclabs_hosts WHERE project_id=? ";
  $params = [$project_id]; $typesBind="i";
  if ($q !== '') { $sql .= " AND (ip_address LIKE ? OR hostname LIKE ?) "; $params[]=$like; $params[]=$like; $typesBind.="ss"; }
  $st = $conn->prepare($sql); $st->bind_param($typesBind, ...$params); $st->execute();
  $stats['hosts'] = (int)($st->get_result()->fetch_assoc()['c'] ?? 0);
}

if ($category === 'all' || $category === 'network') {
  $sql = "SELECT COUNT(*) c
          FROM oneinseclabs_ports p
          JOIN oneinseclabs_hosts h ON h.id=p.host_id
          WHERE p.project_id=? ";
  $params = [$project_id]; $typesBind="i";
  if ($q !== '') { $sql .= " AND (h.ip_address LIKE ? OR h.hostname LIKE ? OR p.service LIKE ?) "; $params[]=$like; $params[]=$like; $params[]=$like; $typesBind.="sss"; }
  $st = $conn->prepare($sql); $st->bind_param($typesBind, ...$params); $st->execute();
  $stats['ports'] = (int)($st->get_result()->fetch_assoc()['c'] ?? 0);
}

if ($category === 'all' || $category === 'web') {
  $sql = "SELECT COUNT(*) c FROM oneinseclabs_urls WHERE project_id=? ";
  $params = [$project_id]; $typesBind="i";
  if ($root !== '') { $sql .= " AND url LIKE ? "; $params[]="%".$root."%"; $typesBind.="s"; }
  if ($q !== '') { $sql .= " AND url LIKE ? "; $params[]=$like; $typesBind.="s"; }
  $st = $conn->prepare($sql); $st->bind_param($typesBind, ...$params); $st->execute();
  $stats['urls'] = (int)($st->get_result()->fetch_assoc()['c'] ?? 0);
}

?>
<style>
  .asset-kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}
  .asset-kpis .card{margin:0;padding:14px}
  .table thead th{position:sticky;top:0;background:rgba(5,10,20,.85);backdrop-filter:blur(6px)}
  .table tbody tr:hover{background:rgba(255,255,255,.03)}
  .table tbody tr:nth-child(even){background:rgba(255,255,255,.015)}
  @media (max-width:1000px){.asset-kpis{grid-template-columns:repeat(2,1fr)}}
  @media (max-width:700px){.asset-kpis{grid-template-columns:1fr}}
</style>
<div class="top">
  <div class="title">
    <h2>Assets</h2>
    <div class="muted">Project #<?= (int)$project_id ?></div>
  </div>
  <div class="row">
    <a class="btn" href="project.php?id=<?= (int)$project_id ?>">← Back</a>
    <a class="btn primary" href="mindmap.php?project_id=<?= (int)$project_id ?>">3D Graph</a>
  </div>
</div>

<div class="card">
  <form method="get" style="display:flex;gap:10px;flex-wrap:wrap;align-items:end">
    <input type="hidden" name="project_id" value="<?= (int)$project_id ?>">

    <div>
      <label class="muted">Category</label>
      <select name="category">
        <option value="all" <?= $category==='all'?'selected':'' ?>>All</option>
        <option value="recon" <?= $category==='recon'?'selected':'' ?>>Recon</option>
        <option value="dns" <?= $category==='dns'?'selected':'' ?>>DNS</option>
        <option value="web" <?= $category==='web'?'selected':'' ?>>Web</option>
        <option value="network" <?= $category==='network'?'selected':'' ?>>Network</option>
      </select>
    </div>

    <div>
      <label class="muted">Types</label>
      <select name="types">
        <option value="subdomains,hosts,ports,urls" <?= $types==='subdomains,hosts,ports,urls'?'selected':'' ?>>Assets</option>
        <option value="subdomains" <?= $types==='subdomains'?'selected':'' ?>>Subdomains</option>
        <option value="hosts" <?= $types==='hosts'?'selected':'' ?>>Hosts</option>
        <option value="ports" <?= $types==='ports'?'selected':'' ?>>Ports</option>
        <option value="urls" <?= $types==='urls'?'selected':'' ?>>URLs</option>
      </select>
    </div>

    <div>
      <label class="muted">Root (optional)</label>
      <input name="root" value="<?= e2($root) ?>" placeholder="example.com">
    </div>

    <div style="min-width:260px;flex:1">
      <label class="muted">Search</label>
      <input name="q" value="<?= e2($q) ?>" placeholder="contains...">
    </div>

    <button class="btn primary" type="submit">Apply</button>
  </form>
</div>

<?php
?>
<div class="asset-kpis" style="margin-bottom:14px">
  <div class="card">
    <div class="muted">Subdomains</div>
    <div style="font-size:22px;font-weight:700"><?= (int)$stats['subdomains'] ?></div>
  </div>
  <div class="card">
    <div class="muted">Hosts</div>
    <div style="font-size:22px;font-weight:700"><?= (int)$stats['hosts'] ?></div>
  </div>
  <div class="card">
    <div class="muted">Ports</div>
    <div style="font-size:22px;font-weight:700"><?= (int)$stats['ports'] ?></div>
  </div>
  <div class="card">
    <div class="muted">URLs</div>
    <div style="font-size:22px;font-weight:700"><?= (int)$stats['urls'] ?></div>
  </div>
</div>

<?php
// SUBDOMAINS
if (in_array('subdomains', $typesArr, true) && ($category==='all' || $category==='recon')) {
  $sql = "SELECT root_domain, subdomain, last_seen FROM oneinseclabs_subdomains WHERE project_id=? ";
  $params = [$project_id]; $typesBind="i";
  if ($root !== '') { $sql .= " AND root_domain=? "; $params[]=$root; $typesBind.="s"; }
  if ($q !== '') { $sql .= " AND subdomain LIKE ? "; $params[]=$like; $typesBind.="s"; }
  $sql .= " ORDER BY last_seen DESC LIMIT 3000";
  $st = $conn->prepare($sql); $st->bind_param($typesBind, ...$params); $st->execute();
  $rs = $st->get_result();
  echo "<div class='card'><h3>Subdomains</h3><table class='table'><thead><tr><th>Root</th><th>Subdomain</th><th>Last Seen</th></tr></thead><tbody>";
  $any=false;
  while($r=$rs->fetch_assoc()){ $any=true;
    echo "<tr><td><code>".e2($r['root_domain'])."</code></td><td><code>".e2($r['subdomain'])."</code></td><td class='muted'>".e2($r['last_seen'])."</td></tr>";
  }
  if(!$any) echo "<tr><td colspan='3' class='muted'>No results</td></tr>";
  echo "</tbody></table></div>";
}

// HOSTS
if (in_array('hosts', $typesArr, true) && ($category==='all' || $category==='dns' || $category==='network')) {
  $sql = "SELECT ip_address, hostname FROM oneinseclabs_hosts WHERE project_id=? ";
  $params = [$project_id]; $typesBind="i";
  if ($q !== '') { $sql .= " AND (ip_address LIKE ? OR hostname LIKE ?) "; $params[]=$like; $params[]=$like; $typesBind.="ss"; }
  $sql .= " ORDER BY id DESC LIMIT 3000";
  $st = $conn->prepare($sql); $st->bind_param($typesBind, ...$params); $st->execute();
  $rs = $st->get_result();
  echo "<div class='card'><h3>Hosts</h3><table class='table'><thead><tr><th>IP</th><th>Hostname</th></tr></thead><tbody>";
  $any=false;
  while($r=$rs->fetch_assoc()){ $any=true;
    echo "<tr><td><code>".e2($r['ip_address'])."</code></td><td><code>".e2($r['hostname'] ?? '')."</code></td></tr>";
  }
  if(!$any) echo "<tr><td colspan='2' class='muted'>No results</td></tr>";
  echo "</tbody></table></div>";
}

// PORTS
if (in_array('ports', $typesArr, true) && ($category==='all' || $category==='network')) {
  $sql = "SELECT h.ip_address, h.hostname, p.port, p.protocol, p.state, p.service, p.product, p.version
          FROM oneinseclabs_ports p
          JOIN oneinseclabs_hosts h ON h.id=p.host_id
          WHERE p.project_id=? ";
  $params = [$project_id]; $typesBind="i";
  if ($q !== '') { $sql .= " AND (h.ip_address LIKE ? OR h.hostname LIKE ? OR p.service LIKE ?) "; $params[]=$like; $params[]=$like; $params[]=$like; $typesBind.="sss"; }
  $sql .= " ORDER BY p.id DESC LIMIT 5000";
  $st = $conn->prepare($sql); $st->bind_param($typesBind, ...$params); $st->execute();
  $rs = $st->get_result();
  echo "<div class='card'><h3>Ports</h3><table class='table'><thead><tr><th>IP</th><th>Host</th><th>Port</th><th>Proto</th><th>State</th><th>Service</th><th>Version</th></tr></thead><tbody>";
  $any=false;
  while($r=$rs->fetch_assoc()){ $any=true;
    $ver = trim(($r['product']??'')." ".($r['version']??''));
    echo "<tr><td><code>".e2($r['ip_address'])."</code></td><td class='muted'>".e2($r['hostname']??'')."</td><td><code>".(int)$r['port']."</code></td><td>".e2($r['protocol'])."</td><td>".e2($r['state'])."</td><td>".e2($r['service'])."</td><td class='muted'>".e2($ver)."</td></tr>";
  }
  if(!$any) echo "<tr><td colspan='7' class='muted'>No results</td></tr>";
  echo "</tbody></table></div>";
}

// URLS
if (in_array('urls', $typesArr, true) && ($category==='all' || $category==='web')) {
  $sql = "SELECT url, source, status_code, title FROM oneinseclabs_urls WHERE project_id=? ";
  $params = [$project_id]; $typesBind="i";
  if ($root !== '') { $sql .= " AND url LIKE ? "; $params[]="%".$root."%"; $typesBind.="s"; }
  if ($q !== '') { $sql .= " AND url LIKE ? "; $params[]=$like; $typesBind.="s"; }
  $sql .= " ORDER BY id DESC LIMIT 5000";
  $st = $conn->prepare($sql); $st->bind_param($typesBind, ...$params); $st->execute();
  $rs = $st->get_result();
  echo "<div class='card'><h3>URLs</h3><table class='table'><thead><tr><th>URL</th><th>Source</th><th>Status</th><th>Title</th></tr></thead><tbody>";
  $any=false;
  while($r=$rs->fetch_assoc()){ $any=true;
    echo "<tr><td><code>".e2($r['url'])."</code></td><td class='muted'>".e2($r['source'])."</td><td class='muted'>".e2($r['status_code']??'')."</td><td class='muted'>".e2($r['title']??'')."</td></tr>";
  }
  if(!$any) echo "<tr><td colspan='4' class='muted'>No results</td></tr>";
  echo "</tbody></table></div>";
}

require_once __DIR__ . '/includes/footer.php';
