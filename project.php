<?php
/**
 * public_html/one.inseclabs.com/project.php
 * Project detail page + roots + uploads + recent runs + command helper + delete project data.
 */

declare(strict_types=1);
ini_set('display_errors', '0');
error_reporting(E_ALL);

require_once __DIR__ . '/includes/header.php'; // db(), current_user_id(), csrf_check(), redirect(), e(), csrf_token()

$conn = db();
$uid  = current_user_id();

$project_id = (int)($_GET['id'] ?? ($_GET['project_id'] ?? ($_GET['pid'] ?? 0)));
if ($project_id <= 0) {
  redirect('dashboard.php');
}

// -------------------------
// Handle POST actions
// -------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  csrf_check();

  // Add single root
  if (isset($_POST['add_root'])) {
    $root = trim((string)($_POST['root_domain'] ?? ''));
    $notes = trim((string)($_POST['root_notes'] ?? ''));

    $root = strtolower($root);
    $root = preg_replace('#^https?://#', '', $root);
    $root = preg_replace('#/.*$#', '', $root);
    $root = preg_replace('/^\*\./', '', $root);
    $root = rtrim($root, '.');

    if ($root !== '') {
      $st = $conn->prepare("INSERT IGNORE INTO oneinseclabs_project_domains (project_id, root_domain, notes) VALUES (?,?,?)");
      $st->bind_param("iss", $project_id, $root, $notes);
      $st->execute();
      audit_log($uid, 'project_add_root', "project_id=$project_id root=$root");
    }
    redirect("project.php?id=".$project_id);
  }

  // Bulk import roots
  if (isset($_POST['import_roots'])) {
    if (!isset($_FILES['roots_file']) || (int)($_FILES['roots_file']['error'] ?? 1) !== UPLOAD_ERR_OK) {
      redirect("project.php?id=".$project_id);
    }
    $raw = file_get_contents($_FILES['roots_file']['tmp_name']);
    $lines = preg_split("/\r\n|\n|\r/", (string)$raw);
    $added = 0;

    foreach ($lines as $line) {
      $d = strtolower(trim((string)$line));
      $d = preg_replace('#^https?://#', '', $d);
      $d = preg_replace('#/.*$#', '', $d);
      $d = preg_replace('/^\*\./', '', $d);
      $d = rtrim($d, '.');
      if ($d === '') continue;

      $st = $conn->prepare("INSERT IGNORE INTO oneinseclabs_project_domains (project_id, root_domain, notes) VALUES (?,?,?)");
      $note = 'bulk-import';
      $st->bind_param("iss", $project_id, $d, $note);
      $st->execute();
      if ($conn->affected_rows > 0) $added++;
    }

    audit_log($uid, 'project_import_roots', "project_id=$project_id added=$added");
    redirect("project.php?id=".$project_id);
  }

  // Delete root
  if (isset($_POST['delete_root'])) {
    $rid = (int)($_POST['root_id'] ?? 0);
    if ($rid > 0) {
      $st = $conn->prepare("DELETE FROM oneinseclabs_project_domains WHERE id=? AND project_id=?");
      $st->bind_param("ii", $rid, $project_id);
      $st->execute();
      audit_log($uid, 'project_delete_root', "project_id=$project_id root_id=$rid");
    }
    redirect("project.php?id=".$project_id);
  }
}

// -------------------------
// Helpers
// -------------------------
function table_exists(mysqli $conn, string $table): bool {
  $t = $conn->real_escape_string($table);
  $rs = $conn->query("SHOW TABLES LIKE '{$t}'");
  return $rs && $rs->num_rows > 0;
}
function count_for(mysqli $conn, string $sql, string $types, ...$params): int {
  $st = $conn->prepare($sql);
  if ($types !== '') $st->bind_param($types, ...$params);
  $st->execute();
  $row = $st->get_result()->fetch_row();
  return (int)($row[0] ?? 0);
}

// -------------------------
// Load project + company
// -------------------------
$st = $conn->prepare("
  SELECT p.*, c.name AS company_name
  FROM oneinseclabs_projects p
  LEFT JOIN oneinseclabs_companies c ON c.id = p.company_id
  WHERE p.id = ?
  LIMIT 1
");
$st->bind_param("i", $project_id);
$st->execute();
$project = $st->get_result()->fetch_assoc();

if (!$project) {
  redirect('dashboard.php');
}

// Roots
$roots = [];
$st = $conn->prepare("SELECT id, root_domain, notes, created_at FROM oneinseclabs_project_domains WHERE project_id=? ORDER BY root_domain ASC");
$st->bind_param("i", $project_id);
$st->execute();
$rs = $st->get_result();
while ($r = $rs->fetch_assoc()) $roots[] = $r;

// Counts
$cnt_sub  = table_exists($conn,'oneinseclabs_subdomains')   ? count_for($conn, "SELECT COUNT(*) FROM oneinseclabs_subdomains WHERE project_id=?", "i", $project_id) : 0;
$cnt_dns  = table_exists($conn,'oneinseclabs_dns_records')  ? count_for($conn, "SELECT COUNT(*) FROM oneinseclabs_dns_records WHERE project_id=?", "i", $project_id) : 0;
$cnt_hosts= table_exists($conn,'oneinseclabs_hosts')        ? count_for($conn, "SELECT COUNT(*) FROM oneinseclabs_hosts WHERE project_id=?", "i", $project_id) : 0;
$cnt_ports= table_exists($conn,'oneinseclabs_ports')        ? count_for($conn, "SELECT COUNT(*) FROM oneinseclabs_ports WHERE project_id=?", "i", $project_id) : 0;
$cnt_urls = table_exists($conn,'oneinseclabs_urls')         ? count_for($conn, "SELECT COUNT(*) FROM oneinseclabs_urls WHERE project_id=?", "i", $project_id) : 0;
$cnt_runs = table_exists($conn,'oneinseclabs_recon_runs')    ? count_for($conn, "SELECT COUNT(*) FROM oneinseclabs_recon_runs WHERE project_id=?", "i", $project_id) : 0;

// Recent runs
$runs = [];
if (table_exists($conn,'oneinseclabs_recon_runs')) {
  $st = $conn->prepare("
    SELECT r.*,
      (SELECT COUNT(*) FROM oneinseclabs_recon_files f WHERE f.run_id = r.id) AS files_count
    FROM oneinseclabs_recon_runs r
    WHERE r.project_id=?
    ORDER BY r.created_at DESC
    LIMIT 20
  ");
  $st->bind_param("i", $project_id);
  $st->execute();
  $rs = $st->get_result();
  while ($r = $rs->fetch_assoc()) $runs[] = $r;
}

$tools = [
  'auto'      => ['name'=>'Auto Detect', 'cat'=>'recon'],
  'bundle'    => ['name'=>'SecLabs ZIP Bundle (.zip)', 'cat'=>'bundle'],
  'subfinder' => ['name'=>'Subfinder Output (.txt)', 'cat'=>'recon'],
  'amass'     => ['name'=>'Amass Output (.txt)', 'cat'=>'recon'],
  'naabu'     => ['name'=>'Naabu Open Ports (host:port)', 'cat'=>'ports'],
  'katana'    => ['name'=>'Katana URLs (.txt)', 'cat'=>'urls'],
  'gau'       => ['name'=>'gau URLs (.txt)', 'cat'=>'urls'],
  'waybackurls'=> ['name'=>'waybackurls URLs (.txt)', 'cat'=>'urls'],
  'nuclei'    => ['name'=>'Nuclei Findings (.txt/.jsonl)', 'cat'=>'vulns'],
  'subdomains'=> ['name'=>'Subdomains List (.txt)', 'cat'=>'recon'],
  'dnsx'      => ['name'=>'DNSX Resolved', 'cat'=>'dns'],
  'httpx'     => ['name'=>'HTTPX Output', 'cat'=>'web'],
  'wayback'   => ['name'=>'Wayback URLs', 'cat'=>'web'],
  'nmap'      => ['name'=>'Nmap Output (-oN / -oG / XML)', 'cat'=>'network'],
];

$return_to = "project.php?id=".$project_id;
?>

<div class="top">
  <div class="title">
    <h2><?= e($project['title']) ?></h2>
    <div class="muted">
      Company: <strong><?= e($project['company_name'] ?? '—') ?></strong> •
      Status: <?= e($project['status']) ?> •
      Profile: <?= e($project['scan_profile']) ?>
    </div>
  </div>
<div class="row">
  <a class="btn" href="company.php?id=<?= (int)$project['company_id'] ?>">← Company</a>
  <a class="btn" href="dashboard.php">Dashboard</a>
  <a class="btn" href="assets.php?project_id=<?= (int)$project_id ?>&types=subdomains,hosts,ports,urls">Assets</a>
  <a class="btn primary" href="mindmap.php?project_id=<?= (int)$project_id ?>">3D Graph</a>
  <a class="btn" href="assets_endpoints.php?project_id=<?= (int)$project_id ?>">Endpoints</a>
<a class="btn" href="assets_findings.php?project_id=<?= (int)$project_id ?>">Findings</a>
<a class="btn" href="assets_params.php?project_id=<?= (int)$project_id ?>">Params</a>
<a class="btn" href="assets_screenshots.php?project_id=<?= (int)$project_id ?>">Screenshots</a>

  <a class="btn" href="dorks.php?project_id=<?= (int)$project_id ?>&mode=all">Dorks</a>
  <a class="btn" href="shodan.php?project_id=<?= (int)$project_id ?>">Shodan</a>

</div>

</div>

<div class="grid">

  <div class="card col-6">
    <h3>Root Domains</h3>

    <div class="grid" style="grid-template-columns:1fr 1fr;gap:12px">
      <form method="post">
        <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
        <label class="muted">Add single root domain</label>
        <input name="root_domain" placeholder="example.com" required>
        <input name="root_notes" placeholder="notes (optional)">
        <button class="btn primary" name="add_root" value="1">Add Root</button>
      </form>

      <form method="post" enctype="multipart/form-data">
        <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
        <label class="muted">Bulk import (.txt)</label>
        <input type="file" name="roots_file" accept=".txt" required>
        <button class="btn primary" name="import_roots" value="1">Import Roots</button>
      </form>
    </div>

    <hr>

    <table class="table">
      <thead><tr><th>Root</th><th>Notes</th><th>Created</th><th></th></tr></thead>
      <tbody>
        <?php foreach ($roots as $r): ?>
          <tr>
            <td><code><?= e($r['root_domain']) ?></code></td>
            <td class="muted"><?= e($r['notes'] ?? '') ?></td>
            <td class="muted"><?= e($r['created_at']) ?></td>
            <td>
              <form method="post" onsubmit="return confirm('Delete this root?')">
                <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
                <input type="hidden" name="root_id" value="<?= (int)$r['id'] ?>">
                <button class="btn danger" name="delete_root" value="1">Delete</button>
              </form>
            </td>
          </tr>
        <?php endforeach; ?>
        <?php if (!$roots): ?>
          <tr><td colspan="4" class="muted">No roots yet.</td></tr>
        <?php endif; ?>
      </tbody>
    </table>

    <hr>

    <div class="card">
      <h3>Commands (Copy & Run)</h3>
      <div class="muted" style="margin-bottom:8px">
        Select a tool + profile. Output files are compatible with your built-in parsers.
      </div>

      <div class="grid" style="grid-template-columns:1fr 1fr;gap:12px">
        <div>
          <label class="muted">Profile</label>
          <select id="cmd_profile" onchange="renderCmd()">
            <option value="safe">Safe</option>
            <option value="normal" selected>Normal</option>
            <option value="agress">Aggressive</option>
          </select>
        </div>
        <div>
          <label class="muted">Output folder</label>
          <input id="cmd_outdir" value="out" oninput="renderCmd()">
        </div>
      </div>

      <div style="height:10px"></div>

      <div class="grid" style="grid-template-columns:1fr 1fr;gap:12px">
        <div>
          <label class="muted">Tool</label>
          <select id="cmd_tool" onchange="renderCmd()">
            <option value="subfinder">Subfinder (subdomains)</option>
            <option value="dnsx">DNSX (resolve A/AAAA)</option>
            <option value="httpx">HTTPX (live endpoints)</option>
            <option value="wayback">Wayback URLs</option>
            <option value="nmap">Nmap (ports/services)</option>
          </select>
        </div>
        <div>
          <label class="muted">Input roots file</label>
          <input id="cmd_input" value="d.txt" oninput="renderCmd()">
          <div class="muted" style="font-size:12px;margin-top:6px">
            Put root domains list in <code>d.txt</code> (one per line).
          </div>
        </div>
      </div>

      <div style="height:10px"></div>
      <label class="muted">Command</label>
      <textarea id="cmd_box" style="min-height:170px;font-family:ui-monospace, SFMono-Regular, Menlo, monospace;"></textarea>

      <div style="display:flex;gap:10px;margin-top:10px;flex-wrap:wrap">
        <button type="button" class="btn primary" onclick="copyCmd()">Copy</button>
        <span class="muted" id="copy_state" style="align-self:center;font-size:12px"></span>
      </div>

      <div class="muted" style="margin-top:10px;font-size:12px">
        ✅ Nmap output can contain multiple hosts/subdomains in one file (your parser supports it).
      </div>
    </div>

  </div>

  <div class="card col-6">
    <h3>Upload Tool Output</h3>
    <form method="post" action="upload.php" enctype="multipart/form-data">
      <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
      <input type="hidden" name="project_id" value="<?= (int)$project_id ?>">
      <input type="hidden" name="return_to" value="<?= e($return_to) ?>">

      <label class="muted">Tool (parser preset)</label>
      <select name="tool_key" id="tool_key">
        <?php foreach ($tools as $k=>$t): ?>
          <option value="<?= e($k) ?>"><?= e($t['name']) ?> (<?= e($t['cat']) ?>)</option>
        <?php endforeach; ?>
      </select>

      <label class="muted">Root context (optional)</label>
      <select name="root_domain">
        <option value="">Auto / From project roots</option>
        <?php foreach ($roots as $r): ?>
          <option value="<?= e($r['root_domain']) ?>"><?= e($r['root_domain']) ?></option>
        <?php endforeach; ?>
      </select>

      <label class="muted">Category</label>
      <input name="category" value="recon">

      <label class="muted">Tool name</label>
      <input name="tool_name" value="Upload">

      <label class="muted">Upload files (multi)</label>
      <input type="file" name="file[]" multiple>

      <label class="muted">Or paste</label>
      <textarea name="paste_text" placeholder="optional"></textarea>

      <label class="muted">Split runs</label>
      <select name="split_runs">
        <option value="0">Single run</option>
        <option value="1">One run per file</option>
      </select>

      <label class="muted">Notes</label>
      <input name="notes" placeholder="optional">

      <button class="btn primary" type="submit">Upload & Parse</button>
    </form>

    <hr>

    <div class="grid" style="grid-template-columns:repeat(3,1fr);gap:10px">
      <div class="card"><div class="muted">Runs</div><div style="font-size:20px;font-weight:800"><?= (int)$cnt_runs ?></div></div>
      <div class="card"><div class="muted">Subdomains</div><div style="font-size:20px;font-weight:800"><?= (int)$cnt_sub ?></div></div>
      <div class="card"><div class="muted">URLs</div><div style="font-size:20px;font-weight:800"><?= (int)$cnt_urls ?></div></div>
    </div>

    <hr>

<div class="card" style="border:1px solid rgba(255,91,91,.35)">
  <h3 style="color:#ffb3b3">Danger Zone</h3>
  <div class="muted">Choose what to delete for this project.</div>

  <form method="post" action="project_delete.php" style="display:flex;gap:10px;flex-wrap:wrap">
    <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
    <input type="hidden" name="project_id" value="<?= (int)$project_id ?>">

    <button class="btn danger" type="submit"
      name="delete_project_data" value="1"
      onclick="return confirm('Delete ALL recon data for this project? (Project will remain)');">
      Delete Project Data
    </button>

    <button class="btn danger" type="submit"
      name="delete_project_full" value="1"
      onclick="return confirm('DELETE PROJECT COMPLETELY? This will remove the project and all related data.');">
      Delete Project (FULL)
    </button>
  </form>
</div>

  </div>

  <div class="card col-12">
    <h3>Recent Runs</h3>
    <table class="table">
      <thead><tr><th>Time</th><th>Tool</th><th>Root</th><th>Files</th></tr></thead>
      <tbody>
        <?php foreach ($runs as $r): ?>
          <tr>
            <td class="muted"><?= e($r['created_at'] ?? '') ?></td>
            <td><strong><?= e($r['tool_key'] ?? '') ?></strong> — <?= e($r['tool_name'] ?? '') ?><div class="muted"><?= e($r['notes'] ?? '') ?></div></td>
            <td class="muted"><?= e($r['root_domain'] ?? '') ?></td>
            <td class="muted"><?= (int)($r['files_count'] ?? 0) ?></td>
          </tr>
        <?php endforeach; ?>
        <?php if (!$runs): ?>
          <tr><td colspan="4" class="muted">No runs yet.</td></tr>
        <?php endif; ?>
      </tbody>
    </table>
  </div>

</div>

<script>
function renderCmd(){
  const tool = document.getElementById('cmd_tool').value;
  const input = (document.getElementById('cmd_input').value || 'd.txt').trim();
  const profile = (document.getElementById('cmd_profile')?.value || 'normal');
  const outdir = (document.getElementById('cmd_outdir')?.value || 'out').trim();

  const P = {
    safe:    { httpxRate: 40,  subAll: false, nmapTiming: "T2", nmapTop: "",   dnsThreads: 50 },
    normal:  { httpxRate: 80,  subAll: true,  nmapTiming: "T3", nmapTop: "",   dnsThreads: 80 },
    agress:  { httpxRate: 150, subAll: true,  nmapTiming: "T4", nmapTop: "--top-ports 3000", dnsThreads: 150 }
  }[profile] || { httpxRate: 80, subAll: true, nmapTiming: "T3", nmapTop: "", dnsThreads: 80 };

  let cmd = `mkdir -p ${outdir}\n`;

  if(tool === 'subfinder'){
    cmd +=
`# 1) Subdomain discovery (output: ${outdir}/subd.txt)
subfinder -dL ${input} ${P.subAll ? "--all --recursive" : ""} -silent -o ${outdir}/subd.txt

# Upload on website:
# Tool = Subdomains List (.txt)
# File = ${outdir}/subd.txt`;
  }

  if(tool === 'dnsx'){
    cmd +=
`# 2) DNS resolve (output: ${outdir}/dnsx.txt)
dnsx -l ${outdir}/subd.txt -a -aaaa -resp -silent -t ${P.dnsThreads} -o ${outdir}/dnsx.txt

# Extract resolved hosts for Nmap input
cat ${outdir}/dnsx.txt | awk '{print $1}' | tr -d '[]' | sort -u > ${outdir}/resolved_subd.txt

# Upload on website:
# Tool = DNSX Resolved
# File = ${outdir}/dnsx.txt`;
  }

  if(tool === 'httpx'){
    cmd +=
`# 3) HTTP probing (output: ${outdir}/httpx.txt)
httpx -l ${outdir}/subd.txt -status-code -title -follow-redirects -silent -rate-limit ${P.httpxRate} -o ${outdir}/httpx.txt

# Upload on website:
# Tool = HTTPX Output
# File = ${outdir}/httpx.txt`;
  }

  if(tool === 'wayback'){
    cmd +=
`# 4) Wayback URLs (output: ${outdir}/wayback.txt)
cat ${outdir}/subd.txt | waybackurls | sort -u > ${outdir}/wayback.txt

# Upload on website:
# Tool = Wayback URLs
# File = ${outdir}/wayback.txt`;
  }

  if(tool === 'nmap'){
    cmd +=
`# 5) Nmap scan (input: ${outdir}/resolved_subd.txt) (output: ${outdir}/nmap_subdomains.txt)
# NOTE: File can contain multiple hosts/subdomains; parser supports it.
nmap -sV -sC -Pn -${P.nmapTiming} ${P.nmapTop} -iL ${outdir}/resolved_subd.txt -oN ${outdir}/nmap_subdomains.txt

# Upload on website:
# Tool = Nmap Output
# File = ${outdir}/nmap_subdomains.txt`;
  }

  document.getElementById('cmd_box').value = cmd;
  document.getElementById('copy_state').textContent = '';
}

function copyCmd(){
  const t = document.getElementById('cmd_box');
  t.select(); t.setSelectionRange(0, 999999);
  document.execCommand('copy');
  document.getElementById('copy_state').textContent = 'Copied ✅';
}

renderCmd();
</script>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
