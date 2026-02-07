<?php
require_once __DIR__ . '/includes/header.php';
$conn = db();
$uid = current_user_id();

$project_id = (int)($_GET['project_id'] ?? 0);
if ($project_id <= 0) { echo "<div class='card'>Missing project_id</div>"; require __DIR__ . '/includes/footer.php'; exit; }

$st = $conn->prepare("SELECT p.*, c.name company_name FROM oneinseclabs_projects p JOIN oneinseclabs_companies c ON c.id=p.company_id WHERE p.id=?");
$st->bind_param("i",$project_id);
$st->execute();
$project = $st->get_result()->fetch_assoc();
if(!$project){ echo "<div class='card'>Project not found</div>"; require __DIR__ . '/includes/footer.php'; exit; }

$roots = $conn->query("SELECT root_domain FROM oneinseclabs_project_domains WHERE project_id=$project_id ORDER BY created_at DESC");
$root_list = [];
while($r=$roots->fetch_assoc()) $root_list[] = $r['root_domain'];

$selected_root = trim($_GET['root'] ?? ($root_list[0] ?? ''));
$selected_root = preg_replace('#^https?://#','',$selected_root);
$selected_root = trim($selected_root,'/');

function slugify($s){
  $s = strtolower(trim($s));
  $s = preg_replace('/[^a-z0-9]+/','_',$s);
  return trim($s,'_');
}
$slug = slugify(($project['company_name'] ?? 'company')."_".($project['title'] ?? 'project')."_".$selected_root);

$stats = [
  'subdomains' => (int)($conn->query("SELECT COUNT(*) c FROM oneinseclabs_subdomains WHERE project_id=$project_id")->fetch_assoc()['c'] ?? 0),
  'dns'        => (int)($conn->query("SELECT COUNT(*) c FROM oneinseclabs_dns_records WHERE project_id=$project_id")->fetch_assoc()['c'] ?? 0),
  'hosts'      => (int)($conn->query("SELECT COUNT(*) c FROM oneinseclabs_hosts WHERE project_id=$project_id")->fetch_assoc()['c'] ?? 0),
  'ports'      => (int)($conn->query("SELECT COUNT(*) c FROM oneinseclabs_ports WHERE project_id=$project_id")->fetch_assoc()['c'] ?? 0),
  'urls'       => (int)($conn->query("SELECT COUNT(*) c FROM oneinseclabs_urls WHERE project_id=$project_id")->fetch_assoc()['c'] ?? 0),
];

audit_log($uid,'view','Opened workflow',null,null,$project_id);
?>
<div class="card">
  <div style="display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;align-items:center">
    <div>
      <h2 style="margin:0 0 6px 0;">Workflow & Commands</h2>
      <div class="muted"><?= e($project['company_name']) ?> → <?= e($project['title']) ?></div>
      <div class="kv" style="margin-top:10px">
        <span class="badge">Subdomains <?= $stats['subdomains'] ?></span>
        <span class="badge">DNS <?= $stats['dns'] ?></span>
        <span class="badge">Hosts <?= $stats['hosts'] ?></span>
        <span class="badge">Ports <?= $stats['ports'] ?></span>
        <span class="badge">URLs <?= $stats['urls'] ?></span>
      </div>
    </div>

    <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
      <a class="btn" href="project.php?id=<?= (int)$project_id ?>">Back</a>
      <a class="btn orange" href="mindmap.php?project_id=<?= (int)$project_id ?>">Open 3D Graph</a>
    </div>
  </div>
</div>

<div class="card" style="margin-top:12px">
  <form method="get" style="display:flex;gap:10px;flex-wrap:wrap;align-items:center">
    <input type="hidden" name="project_id" value="<?= (int)$project_id ?>">
    <label class="muted">Root domain</label>
    <select name="root" onchange="this.form.submit()">
      <?php foreach($root_list as $rd): ?>
        <option value="<?= e($rd) ?>" <?= $rd===$selected_root?'selected':'' ?>><?= e($rd) ?></option>
      <?php endforeach; ?>
    </select>
    <span class="muted">Export:</span>
    <a class="btn" href="export.php?project_id=<?= (int)$project_id ?>&type=subdomains">subdomains.txt</a>
    <a class="btn" href="export.php?project_id=<?= (int)$project_id ?>&type=ips">ips.txt</a>
    <a class="btn" href="export.php?project_id=<?= (int)$project_id ?>&type=urls">urls.txt</a>
  </form>
</div>

<?php
// command templates (safe + practical)
$outDir = "outputs/{$slug}";
$subFile = "{$outDir}/subdomains.txt";
$dnsFile = "{$outDir}/dnsx.txt";
$aliveFile = "{$outDir}/alive.txt";
$ipsFile = "{$outDir}/ips.txt";
$nmapXml = "{$outDir}/nmap.xml";
$wayFile = "{$outDir}/wayback.txt";

$cmds = [
  [
    'title'=>"1) Subdomains (subfinder)",
    'desc'=>"Run first. Upload output as: Subdomains",
    'cmd'=>"mkdir -p {$outDir} && subfinder -d {$selected_root} --all --recursive -silent -o {$subFile}"
  ],
  [
    'title'=>"2) DNS Resolve (dnsx)",
    'desc'=>"Best for linking subdomain → IP. Upload as: DNSX",
    'cmd'=>"cat {$subFile} | dnsx -silent -a -resp -o {$dnsFile}"
  ],
  [
    'title'=>"3) HTTP Alive (httpx)",
    'desc'=>"Optional. Upload as: HTTPx",
    'cmd'=>"cat {$subFile} | httpx -silent -status-code -title -o {$aliveFile}"
  ],
  [
    'title'=>"4) Make IP list for Nmap",
    'desc'=>"Use dnsx output to make unique IP list",
    'cmd'=>"cat {$dnsFile} | grep -Eo \"\\b([0-9]{1,3}\\.){3}[0-9]{1,3}\\b\" | sort -u > {$ipsFile}"
  ],
  [
    'title'=>"5) Nmap scan (XML output)",
    'desc'=>"Upload XML as: Nmap (multi XML supported)",
    'cmd'=>"nmap -sV -Pn -T4 -iL {$ipsFile} -oX {$nmapXml}"
  ],
  [
    'title'=>"6) Wayback URLs",
    'desc'=>"Upload as: Wayback",
    'cmd'=>"cat {$subFile} | waybackurls | sort -u > {$wayFile}"
  ]
];
?>

<div class="grid" style="margin-top:12px">
  <?php foreach($cmds as $i=>$c): ?>
    <div class="card col-6">
      <div style="display:flex;justify-content:space-between;gap:10px;align-items:flex-start">
        <div>
          <h3 style="margin:0 0 6px 0;"><?= e($c['title']) ?></h3>
          <div class="muted"><?= e($c['desc']) ?></div>
        </div>
        <button class="btn primary" type="button" onclick="copyCmd('cmd<?= $i ?>')">Copy</button>
      </div>
      <pre id="cmd<?= $i ?>" style="margin-top:10px;white-space:pre-wrap;background:rgba(0,0,0,.25);padding:12px;border-radius:12px;border:1px solid rgba(255,255,255,.08)"><?= e($c['cmd']) ?></pre>
    </div>
  <?php endforeach; ?>
</div>

<script>
function copyCmd(id){
  const el = document.getElementById(id);
  const txt = el.innerText;
  navigator.clipboard.writeText(txt).then(()=>{
    el.style.outline = "2px solid rgba(34,197,94,.8)";
    setTimeout(()=>el.style.outline="none", 600);
  });
}
</script>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
