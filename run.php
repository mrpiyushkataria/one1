<?php
require_once __DIR__ . '/header.php';
require_once __DIR__ . '/includes/parse.php';
csrf_check();
$conn = db();

$project_id = (int)($_GET['project_id'] ?? 0);
$tool_id = (int)($_GET['tool_id'] ?? 0);
if ($project_id<=0 || $tool_id<=0) die("Missing project_id/tool_id.");

$tool = $conn->query("SELECT * FROM oneinseclabs_tools WHERE id={$tool_id}")->fetch_assoc();
if (!$tool) die("Tool not found.");

$cmds = $conn->query("SELECT * FROM oneinseclabs_tool_commands WHERE tool_id={$tool_id} ORDER BY step_number ASC");

$msg = '';
$parsed_summary = null;

// Create a run row if not exists for this session view
if (empty($_SESSION['current_run_id']) || (int)($_SESSION['current_run_tool_id'] ?? 0) !== $tool_id) {
  $stmt = $conn->prepare("INSERT INTO oneinseclabs_recon_runs (project_id, tool_id, status, created_by, started_at) VALUES (?,?, 'running', ?, NOW())");
  $uid = (int)$_SESSION['user_id'];
  $stmt->bind_param("iii", $project_id, $tool_id, $uid);
  $stmt->execute();
  $_SESSION['current_run_id'] = (int)$stmt->insert_id;
  $_SESSION['current_run_tool_id'] = $tool_id;
}

$run_id = (int)$_SESSION['current_run_id'];

if ($_SERVER['REQUEST_METHOD']==='POST' && isset($_POST['upload_output'])) {
  if (!isset($_FILES['file']) || $_FILES['file']['error'] !== UPLOAD_ERR_OK) {
    $msg = "Upload failed.";
  } else {
    $allowed_ext = ['txt','csv','json','xml','log'];
    $orig = $_FILES['file']['name'];
    $tmp = $_FILES['file']['tmp_name'];
    $size = (int)$_FILES['file']['size'];

    $ext = strtolower(pathinfo($orig, PATHINFO_EXTENSION));
    if (!in_array($ext, $allowed_ext, true)) $msg = "Invalid file type.";
    elseif ($size > 8*1024*1024) $msg = "Max 8MB.";
    else {
      $sha = hash_file('sha256', $tmp);
      $dir = __DIR__ . "/uploads/tool_outputs";
      if (!is_dir($dir)) @mkdir($dir, 0755, true);

      $stored_name = date('Ymd_His') . "_" . bin2hex(random_bytes(6)) . "." . $ext;
      $stored_path = $dir . "/" . $stored_name;

      if (!move_uploaded_file($tmp, $stored_path)) {
        $msg = "Failed to store file.";
      } else {
        $mime = $_FILES['file']['type'] ?? '';
        $preview = @file_get_contents($stored_path, false, null, 0, 20000);

        $stmt = $conn->prepare("
          INSERT INTO oneinseclabs_recon_files (run_id, original_name, stored_name, mime_type, file_size, sha256, stored_path, preview_text)
          VALUES (?,?,?,?,?,?,?,?)
        ");
        $stmt->bind_param("isssssss", $run_id, $orig, $stored_name, $mime, $size, $sha, $stored_path, $preview);
        $stmt->execute();

        $conn->query("UPDATE oneinseclabs_recon_runs SET status='uploaded', ended_at=NOW() WHERE id={$run_id}");

        // Parse & store
        $parsed_summary = parse_and_store($project_id, $run_id, (string)$tool['slug'], $stored_path);
        $conn->query("UPDATE oneinseclabs_recon_runs SET status='parsed' WHERE id={$run_id}");

        audit_log((int)$_SESSION['user_id'], 'upload', "Uploaded tool output: {$orig}", 'recon_run', $run_id, $project_id);
        $msg = "Uploaded & parsed.";
      }
    }
  }
}

audit_log((int)$_SESSION['user_id'], 'view', "Opened run for tool: ".$tool['name'], 'tool', $tool_id, $project_id);
?>
<div class="card">
  <h2 style="margin:0 0 10px 0;"><?= h($tool['name']) ?> — Run</h2>
  <div style="opacity:.75">Project #<?= (int)$project_id ?> | Run #<?= (int)$run_id ?> | Tool slug: <code><?= h($tool['slug']) ?></code></div>
</div>

<div class="card" style="margin-top:14px">
  <h3 style="margin:0 0 10px 0;">Step-by-step Commands</h3>
  <div style="opacity:.7;margin-bottom:10px">Replace variables like <code>{domain}</code>, run in Kali, then upload output.</div>

  <?php while($c=$cmds->fetch_assoc()): ?>
    <div style="border:1px solid #e5e7eb;border-radius:12px;padding:12px;margin:10px 0;background:#fff">
      <div style="font-weight:800">Step <?= (int)$c['step_number'] ?></div>
      <pre id="cmd<?= (int)$c['id'] ?>" style="white-space:pre-wrap;margin:8px 0;background:#0b1220;color:#e5e7eb;padding:10px;border-radius:10px"><?= h($c['command_text']) ?></pre>
      <button type="button" onclick="copyCmd('cmd<?= (int)$c['id'] ?>')">Copy</button>
      <?php if(!empty($c['expected_output'])): ?>
        <div style="margin-top:8px;opacity:.7"><b>Expected:</b> <?= h($c['expected_output']) ?></div>
      <?php endif; ?>
      <?php if(!empty($c['notes'])): ?>
        <div style="margin-top:6px;opacity:.7"><b>Notes:</b> <?= h($c['notes']) ?></div>
      <?php endif; ?>
    </div>
  <?php endwhile; ?>
</div>

<div class="card" style="margin-top:14px">
  <h3 style="margin:0 0 10px 0;">Parsing Techniques (recommended output formats)</h3>
  <ul style="margin:0;padding-left:18px;opacity:.8;line-height:1.6">
    <li><b>dnsx:</b> use <code>-resp</code> to include IPs (ex: <code>sub.example.com [1.2.3.4]</code>) for host linking.</li>
    <li><b>httpx:</b> include <code>-status-code -title</code> so URLs store status/title.</li>
    <li><b>waybackurls/gau:</b> plain URL lines are parsed automatically.</li>
    <li><b>nmap:</b> XML (<code>-oX</code>) supports services + ports + host mapping.</li>
  </ul>
  <div class="muted" style="margin-top:8px">Tip: if a tool outputs JSON lines, export to text/CSV or add a <code>jq -r '.url'</code> style extractor.</div>
</div>

<div class="card" style="margin-top:14px">
  <h3 style="margin:0 0 10px 0;">Upload Tool Output</h3>
  <?php if($msg) echo "<div style='margin:10px 0;color:#065f46;font-weight:800'>".h($msg)."</div>"; ?>
  <form method="post" enctype="multipart/form-data">
    <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
    <input type="file" name="file" required>
    <div style="margin-top:10px">
      <button name="upload_output" value="1">Upload & Parse</button>
    </div>
  </form>

  <?php if(is_array($parsed_summary)): ?>
    <div style="margin-top:12px">
      <b>Parsed:</b>
      <ul>
        <li>Subdomains: <?= (int)$parsed_summary['subdomains'] ?></li>
        <li>URLs: <?= (int)$parsed_summary['urls'] ?></li>
        <li>Ports: <?= (int)$parsed_summary['ports'] ?></li>
      </ul>
    </div>
  <?php endif; ?>

  <div style="margin-top:10px;opacity:.75">
    View stored data:
    <a href="search.php?q=project:<?= (int)$project_id ?>">Search Project</a> |
    <a href="mindmap.php?project_id=<?= (int)$project_id ?>">Mindmap</a>
  </div>
</div>

<script>
function copyCmd(id){
  const el=document.getElementById(id);
  navigator.clipboard.writeText(el.innerText);
}
</script>

<?php require_once __DIR__ . '/footer.php'; ?>
