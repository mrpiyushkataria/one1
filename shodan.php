<?php
/**
 * public_html/one.inseclabs.com/shodan.php
 * Full Shodan module UI (Key + Templates + Saved Queries + Runs + Latest Services)
 *
 * ✅ Works with BOTH API styles:
 *  1) Your current api/shodan_run.php (returns totals immediately)
 *  2) New “start + continue” style (api/shodan_run.php returns run_id + next, then api/shodan_continue.php continues)
 *
 * Depends on:
 *  - includes/header.php  (db(), current_user_id(), csrf_check(), csrf_token(), redirect(), e())
 *  - includes/shodan_lib.php (shodan_get_api_key(), shodan_set_api_key())
 *
 * ✅ Added:
 *  - Delete Shodan results per run (api/shodan_delete.php)
 *    - Delete only Shodan tables
 *    - OR delete Shodan + hosts/ports created via source_run_id
 */

declare(strict_types=1);

ini_set('display_errors','0');
ini_set('log_errors','1');
ini_set('error_log', __DIR__.'/tmp_shodan_error.log');
error_reporting(E_ALL);

require_once __DIR__ . '/includes/header.php';
require_once __DIR__ . '/includes/shodan_lib.php';

$conn = db();
$uid  = (int)current_user_id();
if ($uid <= 0) { header("Location: index.php"); exit; }

$project_id = (int)($_GET['project_id'] ?? ($_GET['id'] ?? 0));
if ($project_id <= 0) redirect('dashboard.php');

function table_exists(mysqli $conn, string $table): bool {
  $t = $conn->real_escape_string($table);
  $rs = $conn->query("SHOW TABLES LIKE '{$t}'");
  return $rs && $rs->num_rows > 0;
}

$has_templates_table   = table_exists($conn, 'oneinseclabs_shodan_templates');
$has_saved_queries_tbl = table_exists($conn, 'oneinseclabs_shodan_saved_queries');
$has_services_table    = table_exists($conn, 'oneinseclabs_shodan_services');
$has_runs_table        = table_exists($conn, 'oneinseclabs_shodan_runs');

$api_key = shodan_get_api_key($conn, $uid);
$has_key = ($api_key !== '');

// -------------------- Load project + company --------------------
$st = $conn->prepare("
  SELECT p.*, c.name AS company_name
  FROM oneinseclabs_projects p
  LEFT JOIN oneinseclabs_companies c ON c.id=p.company_id
  WHERE p.id=? LIMIT 1
");
$st->bind_param("i", $project_id);
$st->execute();
$project = $st->get_result()->fetch_assoc();
if (!$project) redirect('dashboard.php');

// Roots
$roots = [];
$st = $conn->prepare("SELECT root_domain FROM oneinseclabs_project_domains WHERE project_id=? ORDER BY root_domain ASC");
$st->bind_param("i", $project_id);
$st->execute();
$rs = $st->get_result();
while ($r = $rs->fetch_assoc()) $roots[] = (string)$r['root_domain'];

// Subdomains (optional)
$subs = [];
if (table_exists($conn,'oneinseclabs_subdomains')) {
  $st = $conn->prepare("SELECT subdomain FROM oneinseclabs_subdomains WHERE project_id=? ORDER BY subdomain ASC LIMIT 5000");
  $st->bind_param("i", $project_id);
  $st->execute();
  $rs = $st->get_result();
  while ($r = $rs->fetch_assoc()) $subs[] = (string)$r['subdomain'];
}

// Hosts (IPs) (optional)
$ips = [];
if (table_exists($conn,'oneinseclabs_hosts')) {
  // Your schema has both ip and ip_address in different places historically.
  // Prefer ip if present; if not present in your table it will just return empty set.
  $st = $conn->prepare("SELECT DISTINCT ip FROM oneinseclabs_hosts WHERE project_id=? AND ip<>'' ORDER BY ip ASC LIMIT 2000");
  $st->bind_param("i", $project_id);
  $st->execute();
  $rs = $st->get_result();
  while ($r = $rs->fetch_assoc()) $ips[] = (string)$r['ip'];
}

// Default root selection: prefer domain not IP
$company_kw = trim((string)($project['company_name'] ?? ''));
$default_root = '';
foreach ($roots as $rr) {
  $rr = trim($rr);
  if ($rr === '') continue;
  if (filter_var($rr, FILTER_VALIDATE_IP)) continue;
  $default_root = $rr;
  break;
}
if ($default_root === '' && $roots) $default_root = (string)$roots[0];

// -------------------- Templates --------------------
$default_templates = [
  // NOTE: improved templates (less noisy) - still filtered at save-time in api/shodan_continue.php
  ['name'=>'Smart (hostname + ssl)', 'tpl'=>'(hostname:"{{root}}" OR hostname:"*.{{root}}" OR ssl:"{{root}}" OR http.host:"{{root}}" OR http.host:"*.{{root}}")'],
  ['name'=>'Web (80/443)', 'tpl'=>'(hostname:"{{root}}" OR hostname:"*.{{root}}") port:80,443'],
  ['name'=>'SSL only', 'tpl'=>'ssl:"{{root}}" OR ssl.cert.subject.cn:"{{root}}" OR ssl.cert.subject.cn:"*.{{root}}"'],
  ['name'=>'Subdomains', 'tpl'=>'hostname:"*.{{root}}" OR http.host:"*.{{root}}" OR ssl:"{{root}}"'],
  ['name'=>'Org + hostname', 'tpl'=>'org:"{{org}}" (hostname:"{{root}}" OR hostname:"*.{{root}}")'],
  ['name'=>'HTTP title contains org', 'tpl'=>'http.title:"{{org}}"'],
  ['name'=>'Vulns broad (CVE)', 'tpl'=>'(hostname:"{{root}}" OR hostname:"*.{{root}}") vuln:CVE-*'],
  ['name'=>'Tech: nginx', 'tpl'=>'(hostname:"{{root}}" OR hostname:"*.{{root}}") product:nginx'],
  ['name'=>'Tech: apache', 'tpl'=>'(hostname:"{{root}}" OR hostname:"*.{{root}}") product:Apache'],
  ['name'=>'Tech: IIS', 'tpl'=>'(hostname:"{{root}}" OR hostname:"*.{{root}}") product:"Microsoft IIS"'],
  ['name'=>'VPN/Remote Access', 'tpl'=>'(hostname:"{{root}}" OR hostname:"*.{{root}}") (product:OpenVPN OR product:"Pulse Secure" OR product:"Fortinet" OR product:"GlobalProtect")'],
  ['name'=>'RDP exposure', 'tpl'=>'(hostname:"{{root}}" OR hostname:"*.{{root}}") port:3389'],
  ['name'=>'SSH exposure', 'tpl'=>'(hostname:"{{root}}" OR hostname:"*.{{root}}") port:22'],
  ['name'=>'K8s / Docker hints', 'tpl'=>'(hostname:"{{root}}" OR hostname:"*.{{root}}") ("kubernetes" OR "docker" OR product:"Kubernetes")'],
  ['name'=>'Cloudflare keyword', 'tpl'=>'(hostname:"{{root}}" OR hostname:"*.{{root}}") "cloudflare"'],
];

// Custom templates
$custom_templates = [];
if ($has_templates_table) {
  $st = $conn->prepare("SELECT id, name, query_template FROM oneinseclabs_shodan_templates WHERE user_id=? ORDER BY name ASC");
  $st->bind_param("i", $uid);
  $st->execute();
  $rs = $st->get_result();
  while ($r = $rs->fetch_assoc()) $custom_templates[] = $r;
}

// Saved queries (per project)
$saved_queries = [];
if ($has_saved_queries_tbl) {
  $st = $conn->prepare("SELECT id, name, query_text, notes, updated_at FROM oneinseclabs_shodan_saved_queries WHERE user_id=? AND project_id=? ORDER BY updated_at DESC LIMIT 50");
  $st->bind_param("ii", $uid, $project_id);
  $st->execute();
  $rs = $st->get_result();
  while ($r = $rs->fetch_assoc()) $saved_queries[] = $r;
}

// -------------------- Handle POST: key / templates / saved queries --------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  csrf_check();

  // Save key
  if (isset($_POST['save_shodan_key'])) {
    $key = trim((string)($_POST['shodan_api_key'] ?? ''));
    if ($key !== '') shodan_set_api_key($conn, $uid, $key);
    redirect("shodan.php?project_id=".$project_id);
  }

  // Save template
  if (isset($_POST['save_template']) && $has_templates_table) {
    $name = trim((string)($_POST['tpl_name'] ?? ''));
    $tpl  = trim((string)($_POST['tpl_text'] ?? ''));
    if ($name !== '' && $tpl !== '') {
      $st = $conn->prepare("
        INSERT INTO oneinseclabs_shodan_templates (user_id, name, query_template)
        VALUES (?,?,?)
        ON DUPLICATE KEY UPDATE query_template=VALUES(query_template), updated_at=NOW()
      ");
      $st->bind_param("iss", $uid, $name, $tpl);
      $st->execute();
    }
    redirect("shodan.php?project_id=".$project_id);
  }

  // Delete template
  if (isset($_POST['delete_template']) && $has_templates_table) {
    $tid = (int)($_POST['tpl_id'] ?? 0);
    if ($tid > 0) {
      $st = $conn->prepare("DELETE FROM oneinseclabs_shodan_templates WHERE id=? AND user_id=?");
      $st->bind_param("ii", $tid, $uid);
      $st->execute();
    }
    redirect("shodan.php?project_id=".$project_id);
  }

  // Save saved query
  if (isset($_POST['save_saved_query']) && $has_saved_queries_tbl) {
    $name = trim((string)($_POST['sq_name'] ?? ''));
    $qt   = trim((string)($_POST['sq_text'] ?? ''));
    $notes= trim((string)($_POST['sq_notes'] ?? ''));
    if ($name !== '' && $qt !== '') {
      $st = $conn->prepare("
        INSERT INTO oneinseclabs_shodan_saved_queries (user_id, project_id, name, query_text, notes)
        VALUES (?,?,?,?,?)
        ON DUPLICATE KEY UPDATE query_text=VALUES(query_text), notes=VALUES(notes), updated_at=NOW()
      ");
      $st->bind_param("iisss", $uid, $project_id, $name, $qt, $notes);
      $st->execute();
    }
    redirect("shodan.php?project_id=".$project_id);
  }

  // Delete saved query
  if (isset($_POST['delete_saved_query']) && $has_saved_queries_tbl) {
    $sid = (int)($_POST['sq_id'] ?? 0);
    if ($sid > 0) {
      $st = $conn->prepare("DELETE FROM oneinseclabs_shodan_saved_queries WHERE id=? AND user_id=? AND project_id=?");
      $st->bind_param("iii", $sid, $uid, $project_id);
      $st->execute();
    }
    redirect("shodan.php?project_id=".$project_id);
  }
}

// -------------------- Recent runs + latest services --------------------
$runs = [];
if ($has_runs_table) {
  $st = $conn->prepare("SELECT * FROM oneinseclabs_shodan_runs WHERE project_id=? ORDER BY created_at DESC LIMIT 25");
  $st->bind_param("i", $project_id);
  $st->execute();
  $rs = $st->get_result();
  while ($r = $rs->fetch_assoc()) $runs[] = $r;
}

$services = [];
if ($has_services_table) {
  $st = $conn->prepare("
    SELECT s.*
    FROM oneinseclabs_shodan_services s
    WHERE s.project_id=?
    ORDER BY s.created_at DESC
    LIMIT 200
  ");
  $st->bind_param("i", $project_id);
  $st->execute();
  $rs = $st->get_result();
  while ($r = $rs->fetch_assoc()) $services[] = $r;
}

// CSRF token for JS calls
$csrf_js = (string)csrf_token();
?>
<div class="top">
  <div class="title">
    <h2><?= e($project['title']) ?> • Shodan</h2>
    <div class="muted">Project #<?= (int)$project_id ?> • roots: <?= count($roots) ?> • subs: <?= count($subs) ?> • ips: <?= count($ips) ?></div>
  </div>
  <div class="row">
    <a class="btn" href="project.php?id=<?= (int)$project_id ?>">← Back</a>
    <a class="btn" href="assets.php?project_id=<?= (int)$project_id ?>&types=hosts,ports">Assets</a>
    <a class="btn" href="shodan_graph.php?project_id=<?= (int)$project_id ?>">Shodan 3D Graph</a>
      <button class="btn danger" type="button" onclick="deleteProjectShodan(false)">
    Delete Project Shodan
  </button>
  <button class="btn danger" type="button" onclick="deleteProjectShodan(true)">
    Delete Project Shodan + assets
  </button>

    <?php if (file_exists(__DIR__ . '/shodan_explorer.php')): ?>
      <a class="btn" href="shodan_explorer.php?project_id=<?= (int)$project_id ?>">Explorer</a>
    <?php endif; ?>
  </div>
</div>

<div class="grid">
  <div class="card col-6">
    <h3>Shodan API Key</h3>
    <div class="muted">Stored encrypted per-user in DB.</div>

    <form method="post" style="margin-top:10px">
      <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
      <input type="password" name="shodan_api_key" placeholder="<?= $has_key ? 'Key saved (enter to replace)' : 'Paste your Shodan API key' ?>" autocomplete="off">
      <button class="btn primary" name="save_shodan_key" value="1" style="margin-top:10px">Save Key</button>
    </form>

    <?php if (!$has_key): ?>
      <div class="card" style="margin-top:12px;border:1px solid rgba(255,91,91,.35)">
        <b style="color:#ffb3b3">Key not set.</b>
        <div class="muted">Set your Shodan API key above to run scans.</div>
      </div>
    <?php else: ?>
      <div class="card" style="margin-top:12px;background:#0f1630">
        <div class="muted">✅ Key is saved.</div>
      </div>
    <?php endif; ?>

    <?php if ($has_saved_queries_tbl): ?>
      <hr>
      <h3>Saved Queries</h3>
      <div class="muted">Save reusable queries per project.</div>

      <form method="post" style="margin-top:10px">
        <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
        <label class="muted">Name</label>
        <input name="sq_name" placeholder="e.g., Smart Web + SSL" required>
        <label class="muted">Query text</label>
        <textarea name="sq_text" style="min-height:70px" placeholder='(hostname:"{{root}}" OR hostname:"*.{{root}}" OR ssl:"{{root}}")' required></textarea>
        <label class="muted">Notes (optional)</label>
        <input name="sq_notes" placeholder="optional">
        <button class="btn primary" name="save_saved_query" value="1" style="margin-top:10px">Save Query</button>
      </form>

      <?php if ($saved_queries): ?>
        <div style="height:10px"></div>
        <div class="muted" style="font-size:12px">Click a saved query below to load it into the Run box.</div>
        <div style="margin-top:8px;display:flex;flex-direction:column;gap:8px;max-height:240px;overflow:auto">
          <?php foreach ($saved_queries as $sq): ?>
            <div class="card" style="padding:10px">
              <div style="display:flex;justify-content:space-between;gap:10px;align-items:center">
                <div>
                  <b><?= e($sq['name']) ?></b>
                  <div class="muted" style="font-size:12px"><?= e($sq['notes'] ?? '') ?> • <?= e($sq['updated_at'] ?? '') ?></div>
                </div>
                <div style="display:flex;gap:8px">
                  <button type="button" class="btn" onclick="loadSavedQuery(<?= (int)$sq['id'] ?>)">Load</button>
                  <form method="post" onsubmit="return confirm('Delete saved query?')">
                    <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
                    <input type="hidden" name="sq_id" value="<?= (int)$sq['id'] ?>">
                    <button class="btn danger" name="delete_saved_query" value="1">Delete</button>
                  </form>
                </div>
              </div>
              <div style="height:6px"></div>
              <pre style="white-space:pre-wrap;margin:0;font-size:12px"><?= e(mb_strimwidth((string)$sq['query_text'], 0, 800, "…")) ?></pre>
              <textarea id="sq_<?= (int)$sq['id'] ?>" style="display:none"><?= e($sq['query_text']) ?></textarea>
            </div>
          <?php endforeach; ?>
        </div>
      <?php endif; ?>
    <?php endif; ?>
  </div>

  <div class="card col-6">
    <h3>Templates (Default + Custom)</h3>
    <div class="muted">Templates support variables: <code>{{root}}</code> and <code>{{org}}</code></div>

    <label class="muted" style="margin-top:10px">Root</label>
    <select id="rootPick">
      <?php foreach ($roots as $r): ?>
        <option value="<?= e($r) ?>" <?= $r===$default_root ? 'selected':'' ?>><?= e($r) ?></option>
      <?php endforeach; ?>
      <?php if (!$roots): ?>
        <option value="">(no roots yet)</option>
      <?php endif; ?>
    </select>

    <div class="grid" style="grid-template-columns:1fr 1fr;gap:10px;margin-top:12px">
      <div>
        <label class="muted">Default Templates</label>
        <select id="defaultTpl" onchange="applyDefaultTpl()">
          <option value="">-- choose --</option>
          <?php foreach ($default_templates as $t): ?>
            <option value="<?= e($t['tpl']) ?>"><?= e($t['name']) ?></option>
          <?php endforeach; ?>
        </select>
      </div>

      <div>
        <label class="muted">Custom Templates</label>
        <select id="customTpl" onchange="applyCustomTpl()">
          <option value="">-- choose --</option>
          <?php foreach ($custom_templates as $t): ?>
            <option value="<?= (int)$t['id'] ?>" data-tpl="<?= e($t['query_template']) ?>"><?= e($t['name']) ?></option>
          <?php endforeach; ?>
        </select>
      </div>
    </div>

    <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:12px">
      <button class="btn" type="button" onclick="buildSmart()">Build Smart Query</button>
      <button class="btn" type="button" onclick="buildBatchDefault()">Build Batch (best 8)</button>
      <button class="btn" type="button" onclick="fillFromSaved()">Use Saved Query → Run</button>
    </div>

    <?php if ($has_templates_table): ?>
      <hr>
      <h4>Save as Custom Template</h4>
      <form method="post">
        <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
        <label class="muted">Template name</label>
        <input name="tpl_name" placeholder="e.g., My smart web + ssl" required>
        <label class="muted">Template text</label>
        <textarea name="tpl_text" placeholder='Example: (hostname:"{{root}}" OR hostname:"*.{{root}}" OR ssl:"{{root}}")' style="min-height:80px" required></textarea>
        <button class="btn primary" name="save_template" value="1" style="margin-top:10px">Save Template</button>
      </form>

      <?php if ($custom_templates): ?>
        <div style="height:10px"></div>
        <form method="post" onsubmit="return confirm('Delete this template?')">
          <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
          <label class="muted">Delete custom template</label>
          <select name="tpl_id" required>
            <?php foreach ($custom_templates as $t): ?>
              <option value="<?= (int)$t['id'] ?>"><?= e($t['name']) ?></option>
            <?php endforeach; ?>
          </select>
          <button class="btn danger" name="delete_template" value="1" style="margin-top:10px">Delete</button>
        </form>
      <?php endif; ?>
    <?php else: ?>
      <hr>
      <div class="muted">Custom templates table not found. (Optional feature)</div>
    <?php endif; ?>
  </div>

  <div class="card col-12">
    <h3>Run Shodan Recon</h3>

    <div class="grid" style="grid-template-columns:1fr 1fr 1fr;gap:12px">
      <div>
        <label class="muted">Mode</label>
        <select id="mode">
          <option value="search" selected>Search (query)</option>
          <option value="host">Host Lookup (IPs)</option>
        </select>
      </div>
      <div>
        <label class="muted">Max results (per query)</label>
        <input id="max_results" value="200">
      </div>
      <div>
        <label class="muted">Root context (required for strict save)</label>
        <input id="root_domain" value="<?= e($default_root) ?>">
      </div>
    </div>

    <label class="muted" style="margin-top:10px">Single Query (Search mode)</label>
    <textarea id="query" style="min-height:80px;font-family:ui-monospace, SFMono-Regular, Menlo, monospace;"></textarea>

    <div style="height:10px"></div>
    <label class="muted">Batch Queries (one per line)</label>
    <textarea id="queries_text" placeholder="Paste multiple queries here (one per line)..." style="min-height:110px;font-family:ui-monospace, SFMono-Regular, Menlo, monospace;"></textarea>
    <div class="muted" style="font-size:12px;margin-top:6px">Tip: Click “Build Batch (best 8)” above to auto-fill.</div>

    <div id="ipBoxWrap" style="display:none;margin-top:10px">
      <label class="muted">IP List (one per line) — auto-filled from Project Hosts</label>
      <textarea id="ip_list" style="min-height:120px;font-family:ui-monospace, SFMono-Regular, Menlo, monospace;"><?= e(implode("\n", array_slice($ips,0,50))) ?></textarea>
      <div class="muted" style="font-size:12px;margin-top:6px">Safety: 50 IPs per click (your API may enforce this).</div>
    </div>

    <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:12px">
      <button class="btn primary" type="button" onclick="runSingle()">Run Single</button>
      <button class="btn primary" type="button" onclick="runBatch()">Run Batch</button>
      <button class="btn" type="button" onclick="resumeLastRunning()">Resume last running</button>
      <span class="muted" id="runState"></span>
    </div>

    <div class="muted" style="font-size:12px;margin-top:8px">
      If your server times out, use “Resume last running”. (If you installed the continue API.)
    </div>
  </div>

  <div class="card col-6">
    <h3>Recent Runs</h3>
    <div class="muted" style="font-size:12px;margin-bottom:8px">
      Delete buttons remove Shodan data for that run. “Delete + assets” also removes hosts/ports inserted by the run’s source_run_id.
    </div>
    <table class="table">
      <thead>
        <tr>
          <th>Time</th>
          <th>Mode</th>
          <th>Status</th>
          <th>Saved</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        <?php foreach ($runs as $r): ?>
          <tr>
            <td class="muted"><?= e($r['created_at'] ?? '') ?></td>
            <td>
              <code><?= e($r['mode'] ?? '') ?></code>
              <div class="muted" style="font-size:12px"><?= e(mb_strimwidth((string)($r['query'] ?? ''),0,90,'…')) ?></div>
            </td>
            <td>
              <?= e($r['status'] ?? '') ?>
              <?php if (($r['status'] ?? '')==='error'): ?>
                <div class="muted" style="color:#ffb3b3"><?= e(mb_strimwidth((string)($r['error_text'] ?? ''),0,120,'…')) ?></div>
              <?php endif; ?>
              <?php if (($r['status'] ?? '')==='running' && isset($r['id'])): ?>
                <div style="margin-top:6px">
                  <button class="btn" type="button" onclick="resumeRun(<?= (int)$r['id'] ?>)">Resume</button>
                </div>
              <?php endif; ?>
            </td>
            <td class="muted"><?= (int)($r['total_saved'] ?? 0) ?>/<?= (int)($r['total_found'] ?? 0) ?></td>
            <td>
              <?php if (isset($r['id'])): ?>
                <div style="display:flex;gap:8px;flex-wrap:wrap">
                  <button class="btn danger" type="button" onclick="deleteShodanRun(<?= (int)$r['id'] ?>, false)">
                    Delete
                  </button>
                  <button class="btn danger" type="button" style="opacity:.9" onclick="deleteShodanRun(<?= (int)$r['id'] ?>, true)">
                    Delete + assets
                  </button>
                </div>
              <?php endif; ?>
            </td>
          </tr>
        <?php endforeach; ?>
        <?php if (!$runs): ?><tr><td colspan="5" class="muted">No runs yet.</td></tr><?php endif; ?>
      </tbody>
    </table>
  </div>

  <div class="card col-6">
    <h3>Latest Shodan Services</h3>
    <div class="muted">Shows last 200 saved. Full dataset is in DB.</div>
    <table class="table" style="margin-top:10px">
      <thead><tr><th>IP:Port</th><th>Product</th><th>Org</th><th>Vulns</th></tr></thead>
      <tbody>
        <?php foreach ($services as $s): ?>
          <tr>
            <td>
              <code><?= e($s['ip'] ?? '') ?>:<?= (int)($s['port'] ?? 0) ?></code>
              <div class="muted" style="font-size:12px"><?= e($s['country'] ?? '') ?></div>
            </td>
            <td>
              <?= e(trim((string)($s['product'] ?? '') . ' ' . (string)($s['version'] ?? ''))) ?>
              <div class="muted" style="font-size:12px"><?= e($s['transport'] ?? '') ?></div>
            </td>
            <td class="muted"><?= e($s['org'] ?? '') ?></td>
            <td class="muted" style="font-size:12px"><?= e($s['vulns'] ?? '') ?></td>
          </tr>
        <?php endforeach; ?>
        <?php if (!$services): ?><tr><td colspan="4" class="muted">No services saved yet.</td></tr><?php endif; ?>
      </tbody>
    </table>
  </div>
</div>

<script>
function root(){ return (document.getElementById('rootPick')?.value || '').trim(); }
function org(){ return <?= json_encode($company_kw ?: ''); ?> || ''; }

function applyVars(tpl){
  const r = root();
  const o = org();
  return (tpl || '')
    .replaceAll('{{root}}', r)
    .replaceAll('{{org}}', o);
}

function applyDefaultTpl(){
  const sel = document.getElementById('defaultTpl');
  const tpl = sel.value || '';
  if (!tpl) return;
  document.getElementById('query').value = applyVars(tpl);
}

function applyCustomTpl(){
  const sel = document.getElementById('customTpl');
  const opt = sel.options[sel.selectedIndex];
  const tpl = opt?.getAttribute('data-tpl') || '';
  if (!tpl) return;
  document.getElementById('query').value = applyVars(tpl);
}

function buildSmart(){
  const r = root();
  const o = org();
  const q = `(hostname:"${r}" OR hostname:"*.${r}" OR ssl:"${r}" OR http.host:"${r}" OR http.host:"*.${r}")` + (o ? ` OR org:"${o}"` : '');
  document.getElementById('query').value = q;
}

function buildBatchDefault(){
  const r = root();
  const o = org();
  const list = [
    `(hostname:"${r}" OR hostname:"*.${r}" OR ssl:"${r}" OR http.host:"${r}" OR http.host:"*.${r}")`,
    `ssl:"${r}" OR ssl.cert.subject.cn:"${r}" OR ssl.cert.subject.cn:"*.${r}"`,
    `(hostname:"${r}" OR hostname:"*.${r}") port:80,443`,
    `(hostname:"${r}" OR hostname:"*.${r}") vuln:CVE-*`,
    `(hostname:"${r}" OR hostname:"*.${r}") product:nginx`,
    `(hostname:"${r}" OR hostname:"*.${r}") product:Apache`,
    `(hostname:"${r}" OR hostname:"*.${r}") product:"Microsoft IIS"`,
    o ? `org:"${o}" (hostname:"${r}" OR hostname:"*.${r}")` : ''
  ].filter(Boolean);
  document.getElementById('queries_text').value = list.join("\n");
}

function loadSavedQuery(id){
  const el = document.getElementById('sq_'+id);
  const txt = el ? el.value : '';
  if (!txt) return;
  document.getElementById('query').value = applyVars(txt);
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

function fillFromSaved(){
  alert('Tip: Click “Load” on a saved query to fill the Run box, then click Run.');
}

document.getElementById('mode').addEventListener('change', () => {
  const m = document.getElementById('mode').value;
  document.getElementById('ipBoxWrap').style.display = (m === 'host') ? 'block' : 'none';
});

async function postJSON(url, fd){
  const r = await fetch(url, { method:'POST', body: fd });
  const txt = await r.text();
  let j;
  try { j = JSON.parse(txt); } catch(e){ throw new Error('API returned non-JSON: ' + txt.slice(0,200)); }
  if (!j.ok) throw new Error(j.error || 'failed');
  return j;
}

/** ✅ Delete Shodan run + results */
async function deleteShodanRun(runId, deleteAssets){
  const msg = deleteAssets
    ? "Delete this Shodan run AND also delete hosts/ports created by it? (Cannot undo)"
    : "Delete this Shodan run results? (Cannot undo)";
  if (!confirm(msg)) return;

  const fd = new FormData();
  fd.append('csrf', <?= json_encode($csrf_js) ?>);
  fd.append('shodan_run_id', String(runId));
  fd.append('delete_assets', deleteAssets ? '1' : '0');

  try{
    const j = await postJSON('api/shodan_delete.php', fd);
    alert("Deleted ✅\n" + JSON.stringify(j.deleted || {}, null, 2));
    location.reload();
  } catch(e){
    alert("Delete failed: " + e.message);
  }
}



async function deleteProjectShodan(deleteAssets){
  const msg = deleteAssets
    ? "Delete ALL Shodan runs/results for this project AND delete hosts/ports created by Shodan? (Cannot undo)"
    : "Delete ALL Shodan runs/results for this project? (Cannot undo)";
  if (!confirm(msg)) return;

  const fd = new FormData();
  fd.append('csrf', <?= json_encode(csrf_token()) ?>);
  fd.append('project_id', String(<?= (int)$project_id ?>));
  fd.append('delete_assets', deleteAssets ? '1' : '0');

  try{
    const j = await postJSON('api/shodan_delete_project.php', fd);
    alert("Deleted ✅\n" + JSON.stringify(j.deleted || {}, null, 2));
    location.reload();
  } catch(e){
    alert("Delete failed: " + e.message);
  }
}





/**
 * Compatibility runner:
 * - If api/shodan_run.php returns {run_id, next} => start+continue mode (new)
 * - Else if it returns {total_saved,total_found} => immediate mode (old)
 */
async function runSingle(){
  const state = document.getElementById('runState');
  state.textContent = 'Running…';

  const mode = document.getElementById('mode').value;
  const query = document.getElementById('query').value.trim();
  const maxResults = document.getElementById('max_results').value.trim();
  const rootDomain = document.getElementById('root_domain').value.trim();
  const ipList = document.getElementById('ip_list') ? document.getElementById('ip_list').value : '';

  if (mode === 'search' && !query) { alert('Query is required.'); state.textContent=''; return; }
  if (!rootDomain) { alert('Root context is required.'); state.textContent=''; return; }
  if (mode === 'host' && !ipList.trim()) { alert('IP list is required.'); state.textContent=''; return; }

  const fd = new FormData();
  fd.append('csrf', <?= json_encode($csrf_js) ?>);
  fd.append('project_id', <?= (int)$project_id ?>);
  fd.append('mode', mode);
  fd.append('query', query);
  fd.append('max_results', maxResults);
  fd.append('root_domain', rootDomain);
  fd.append('ip_list', ipList);

  try {
    const j = await postJSON('api/shodan_run.php', fd);

    // NEW style: start run only
    if (j.run_id) {
      if (mode === 'host' && !await existsEndpoint('api/shodan_continue.php')) {
        alert('Host mode needs your old runner or a host-continue endpoint. Use Search mode, or keep old api/shodan_run.php for host.');
        location.reload();
        return;
      }
      state.textContent = `Running… (run #${j.run_id})`;
      await continueLoop(j.run_id, state);
      return;
    }

    // OLD style: run completed immediately
    if (typeof j.total_saved !== 'undefined') {
      alert(`Done ✅\nSaved: ${j.total_saved}\nTotal found: ${j.total_found}`);
      location.reload();
      return;
    }

    alert('Done ✅');
    location.reload();
  } catch(e) {
    alert('Error: ' + e.message);
    state.textContent = 'Error';
  }
}

async function runBatch(){
  const state = document.getElementById('runState');
  state.textContent = 'Running batch…';

  const mode = document.getElementById('mode').value;
  if (mode !== 'search') { alert('Batch is only for Search mode.'); state.textContent=''; return; }

  const queriesText = document.getElementById('queries_text').value.trim();
  const maxResults = document.getElementById('max_results').value.trim();
  const rootDomain = document.getElementById('root_domain').value.trim();

  if (!queriesText) { alert('Paste queries (one per line) in Batch box.'); state.textContent=''; return; }
  if (!rootDomain) { alert('Root context is required.'); state.textContent=''; return; }

  const fd = new FormData();
  fd.append('csrf', <?= json_encode($csrf_js) ?>);
  fd.append('project_id', <?= (int)$project_id ?>);
  fd.append('mode', 'search');
  fd.append('batch', '1');
  fd.append('queries_text', queriesText);
  fd.append('max_results', maxResults);
  fd.append('root_domain', rootDomain);

  try {
    const j = await postJSON('api/shodan_run.php', fd);

    if (j.items && Array.isArray(j.items)) {
      const lines = j.items.map(x => `• saved ${x.total_saved} | run #${x.run_id} | ${x.query}`);
      alert("Batch Done ✅\n\n" + lines.join("\n"));
      location.reload();
      return;
    }

    if (j.run_id) {
      alert('Batch-start detected but continue mode for batch is not installed. Use single runs or implement batch continue.');
      location.reload();
      return;
    }

    alert('Batch finished ✅');
    location.reload();
  } catch(e) {
    alert('Error: ' + e.message);
    state.textContent = 'Error';
  }
}

async function existsEndpoint(path){
  try {
    const r = await fetch(path, { method:'HEAD' });
    return r.ok;
  } catch(e){
    try {
      const r = await fetch(path, { method:'GET' });
      return r.ok;
    } catch(e2){
      return false;
    }
  }
}

async function continueOnce(runId){
  const fd = new FormData();
  fd.append('csrf', <?= json_encode($csrf_js) ?>);
  fd.append('run_id', String(runId));
  fd.append('step_pages', '2');
  return postJSON('api/shodan_continue.php', fd);
}

async function continueLoop(runId, stateEl){
  if (!await existsEndpoint('api/shodan_continue.php')) {
    alert('Continue endpoint not found (api/shodan_continue.php). If you are using the old runner, you can ignore this.');
    location.reload();
    return;
  }

  for (let i=0; i<60; i++){
    const step = await continueOnce(runId);

    if (step.status === 'done'){
      alert(`Done ✅\nSaved +${step.saved}\nVulns +${step.vulns || 0}\nTotal found: ${step.total_found || ''}`);
      location.reload();
      return;
    }

    if (step.status === 'error'){
      alert('Run error / rate limit. Check Recent Runs.');
      location.reload();
      return;
    }

    const p = step.next_page ? `page ${step.next_page}` : '';
    stateEl.textContent = `Running… saved +${step.saved || 0} ${p}`;
    await new Promise(r => setTimeout(r, 450));
  }

  alert('Still running. Click Resume on the run row.');
  location.reload();
}

function resumeRun(runId){
  const state = document.getElementById('runState');
  state.textContent = `Resuming run #${runId}…`;
  continueLoop(runId, state).catch(e => {
    alert('Resume error: ' + e.message);
    state.textContent = 'Error';
  });
}

function resumeLastRunning(){
  const rows = <?= json_encode(array_values(array_filter($runs, fn($r) => (($r['status'] ?? '')==='running') && isset($r['id'])))); ?>;
  if (!rows.length){ alert('No running run found.'); return; }
  resumeRun(rows[0].id);
}
</script>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
