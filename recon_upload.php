<?php
require_once __DIR__ . '/header.php';
require_once __DIR__ . '/includes/csrf.php';
require_once __DIR__ . '/includes/parser_subdomains.php';
require_once __DIR__ . '/includes/parser_nmap.php';
require_once __DIR__ . '/includes/audit.php';

$conn = db();
$message=""; $result_summary=null;

// project list
$projects = $conn->query("
  SELECT p.id, p.title, c.domains
  FROM oneinseclabs_projects p
  JOIN oneinseclabs_companies c ON c.id=p.company_id
  ORDER BY p.id DESC
");

function project_roots(mysqli $conn, int $project_id): array {
  $stmt = $conn->prepare("
    SELECT c.domains
    FROM oneinseclabs_projects p
    JOIN oneinseclabs_companies c ON c.id=p.company_id
    WHERE p.id=? LIMIT 1
  ");
  $stmt->bind_param("i",$project_id);
  $stmt->execute();
  $domains = $stmt->get_result()->fetch_assoc()['domains'] ?? '';
  $arr = preg_split('/[\s,]+/', trim($domains));
  $out=[];
  foreach($arr as $d){ $d=trim($d); if($d!=='') $out[]=$d; }
  return array_values(array_unique($out));
}

$UPLOAD_DIR = dirname(__DIR__) . "/oneinseclabs_uploads/tool_outputs";
if (!is_dir($UPLOAD_DIR)) @mkdir($UPLOAD_DIR, 0755, true);

if ($_SERVER['REQUEST_METHOD']==='POST') {
  csrf_verify();

  $project_id = max(1,(int)($_POST['project_id'] ?? 0));
  $scan_type  = $_POST['scan_type'] ?? 'custom';
  $tool_name  = trim($_POST['tool_name'] ?? 'upload');
  $force_root = trim($_POST['force_root'] ?? '');

  if ($project_id < 1) $message="Select project";
  elseif (!isset($_FILES['file']) || $_FILES['file']['error']!==UPLOAD_ERR_OK) $message="Upload failed";
  else {
    $root_domains = project_roots($conn, $project_id);

    $orig = basename($_FILES['file']['name']);
    $tmp  = $_FILES['file']['tmp_name'];
    $size = (int)$_FILES['file']['size'];
    $ext  = strtolower(pathinfo($orig, PATHINFO_EXTENSION));

    $allowed = ['txt','xml','json','csv'];
    if (!in_array($ext,$allowed,true)) $message="Invalid file type";
    elseif ($size > 15*1024*1024) $message="File too large (max 15MB)";
    else {
      $stored_name = bin2hex(random_bytes(16)).".".$ext;
      $stored_path = $UPLOAD_DIR."/".$stored_name;

      if (!move_uploaded_file($tmp,$stored_path)) $message="Could not store file";
      else {
        $sha = hash_file('sha256',$stored_path);
        $db_path = "tool_outputs/".$stored_name;

        $stmt = $conn->prepare("
          INSERT IGNORE INTO oneinseclabs_scans
          (project_id, scan_type, tool_name, original_filename, stored_path, sha256, file_size)
          VALUES (?,?,?,?,?,?,?)
        ");
        $stmt->bind_param("isssssi",$project_id,$scan_type,$tool_name,$orig,$db_path,$sha,$size);
        $stmt->execute();

        $scan_id = (int)$conn->insert_id;
        if ($scan_id === 0) {
          $stmt2=$conn->prepare("SELECT id FROM oneinseclabs_scans WHERE project_id=? AND sha256=? LIMIT 1");
          $stmt2->bind_param("is",$project_id,$sha);
          $stmt2->execute();
          $scan_id = (int)($stmt2->get_result()->fetch_assoc()['id'] ?? 0);
        }

        $content = file_get_contents($stored_path);

        if ($scan_type === 'subdomains') {
          $result_summary = parse_subdomains_txt($project_id, $tool_name, $content, $root_domains);
        } elseif ($scan_type === 'nmap') {
          $result_summary = parse_nmap_xml($project_id, $scan_id, $content, $root_domains, $force_root ?: null);
        } else {
          $result_summary = ['ok'=>true,'note'=>'Stored only (parser not enabled for this type yet).'];
        }

        $summary_json = json_encode($result_summary, JSON_UNESCAPED_UNICODE);
        $stmt3=$conn->prepare("UPDATE oneinseclabs_scans SET parsed_summary=? WHERE id=?");
        $stmt3->bind_param("si",$summary_json,$scan_id);
        $stmt3->execute();

        audit_log((int)$_SESSION['user_id'], 'Upload', "Uploaded $scan_type ($tool_name) to project=$project_id");

        $message="✅ Uploaded + parsed";
      }
    }
  }
}
?>
<style>
  .wrap{max-width:1100px;margin:20px auto;padding:16px}
  .card{background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.08);border-radius:14px;padding:14px;margin-bottom:12px}
  input,select{width:100%;padding:10px;border-radius:10px;border:1px solid rgba(255,255,255,.12);background:rgba(255,255,255,.06);color:#fff}
  button{padding:10px 12px;border-radius:10px;border:0;background:#ff5800;color:#fff;font-weight:800;cursor:pointer;width:100%}
  .grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
  @media(max-width:900px){.grid{grid-template-columns:1fr}}
  pre{white-space:pre-wrap;background:rgba(0,0,0,.35);padding:12px;border-radius:12px;border:1px solid rgba(255,255,255,.08)}
</style>

<div class="wrap">
  <div class="card">
    <h2 style="margin:0 0 6px 0;">📤 Recon Upload & Parsing</h2>
    <div style="color:#9ca3af">Upload <b>subdomains.txt</b> or <b>nmap.xml</b> to build graph nodes.</div>
    <?php if($message): ?><div style="margin-top:10px"><?= htmlspecialchars($message) ?></div><?php endif; ?>

    <form method="POST" enctype="multipart/form-data" style="margin-top:12px">
      <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">

      <label>Project</label>
      <select name="project_id" required>
        <option value="">-- Select Project --</option>
        <?php while($p=$projects->fetch_assoc()): ?>
          <option value="<?= (int)$p['id'] ?>"><?= htmlspecialchars($p['title']) ?></option>
        <?php endwhile; ?>
      </select>

      <div class="grid" style="margin-top:10px">
        <div>
          <label>Scan Type</label>
          <select name="scan_type" required>
            <option value="subdomains">subdomains</option>
            <option value="nmap">nmap</option>
            <option value="httpx">httpx (store only)</option>
            <option value="wayback">wayback (store only)</option>
            <option value="custom">custom</option>
          </select>
        </div>
        <div>
          <label>Tool Name</label>
          <input name="tool_name" placeholder="subfinder / nmap / httpx ..." required>
        </div>
      </div>

      <label style="margin-top:10px">Optional: Force Root Domain (when Nmap XML has no hostnames)</label>
      <input name="force_root" placeholder="example.com">

      <label style="margin-top:10px">File</label>
      <input type="file" name="file" required>

      <button style="margin-top:12px">Upload & Parse</button>
    </form>

    <?php if($result_summary): ?>
      <h3 style="margin-top:14px">Parsed Summary</h3>
      <pre><?= htmlspecialchars(json_encode($result_summary, JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE)) ?></pre>
      <div style="margin-top:10px">
        <a href="/visualization.php" style="color:#93c5fd">Open 3D Graph</a>
      </div>
    <?php endif; ?>
  </div>
</div>

<?php require_once __DIR__ . '/footer.php'; ?>
