<?php
require_once __DIR__ . '/includes/header.php';
$conn = db();
$uid = current_user_id();

$id = (int)($_GET['id'] ?? 0);
$stmt = $conn->prepare("SELECT * FROM oneinseclabs_companies WHERE id=?");
$stmt->bind_param("i",$id);
$stmt->execute();
$company = $stmt->get_result()->fetch_assoc();
if(!$company){ http_response_code(404); exit("Company not found"); }

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  csrf_check();

  if (isset($_POST['add_scope'])) {
    $type = $_POST['scope_type'] ?? 'domain';
    $val  = trim($_POST['scope_value'] ?? '');
    $note = trim($_POST['notes'] ?? '');
    if ($val !== '') {
      $st = $conn->prepare("INSERT INTO oneinseclabs_company_scopes (company_id, scope_type, scope_value, notes) VALUES (?,?,?,?)");
      $st->bind_param("isss",$id,$type,$val,$note);
      $st->execute();
      audit_log($uid,'scope_add',"Added scope to company #$id");
    }
    redirect("company.php?id=$id");
  }

  if (isset($_POST['create_project'])) {
    $title = trim($_POST['title'] ?? '');
    $desc  = trim($_POST['description'] ?? '');
    if ($title !== '') {
      $st = $conn->prepare("INSERT INTO oneinseclabs_projects (company_id, title, description, created_by) VALUES (?,?,?,?)");
      $st->bind_param("issi",$id,$title,$desc,$uid);
      $st->execute();
      audit_log($uid,'project_create',"Created project under company #$id");
    }
    redirect("company.php?id=$id");
  }
}

$scopes = $conn->prepare("SELECT * FROM oneinseclabs_company_scopes WHERE company_id=? ORDER BY created_at DESC");
$scopes->bind_param("i",$id);
$scopes->execute();
$scopes = $scopes->get_result();

$projects = $conn->prepare("SELECT * FROM oneinseclabs_projects WHERE company_id=? ORDER BY created_at DESC");
$projects->bind_param("i",$id);
$projects->execute();
$projects = $projects->get_result();
?>
<div class="card">
  <h2><?= e($company['name']) ?></h2>
  <div class="muted"><?= e($company['organization_details'] ?? '') ?></div>
</div>

<div class="grid">
  <div class="card col-6">
    <h3>Add Scope</h3>
    <form method="post">
      <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
      <select name="scope_type">
        <option value="domain">domain</option>
        <option value="ip">ip</option>
        <option value="cidr">cidr</option>
        <option value="asn">asn</option>
        <option value="url">url</option>
      </select>
      <input name="scope_value" placeholder="example.com / 1.1.1.1 / 1.1.1.0/24" required>
      <input name="notes" placeholder="notes (optional)">
      <button class="btn primary" name="add_scope" value="1">Add</button>
    </form>

    <hr>
    <h3>Scopes</h3>
    <table class="table">
      <thead><tr><th>Type</th><th>Value</th><th>Notes</th><th>Added</th></tr></thead>
      <tbody>
        <?php while($s=$scopes->fetch_assoc()): ?>
          <tr>
            <td><span class="badge"><?= e($s['scope_type']) ?></span></td>
            <td><?= e($s['scope_value']) ?></td>
            <td class="muted"><?= e($s['notes'] ?? '') ?></td>
            <td class="muted"><?= e($s['created_at']) ?></td>
          </tr>
        <?php endwhile; ?>
      </tbody>
    </table>
  </div>

  <div class="card col-6">
    <h3>Create Project</h3>
    <form method="post">
      <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
      <input name="title" placeholder="Project title" required>
      <textarea name="description" placeholder="Project notes / scope summary"></textarea>
      <button class="btn orange" name="create_project" value="1">Create</button>
    </form>

    <hr>
    <h3>Projects</h3>
    <table class="table">
      <thead><tr><th>Title</th><th>Status</th><th>Created</th><th></th></tr></thead>
      <tbody>
        <?php while($p=$projects->fetch_assoc()): ?>
          <tr>
            <td><strong><?= e($p['title']) ?></strong><div class="muted"><?= e(mb_substr($p['description'] ?? '',0,70)) ?></div></td>
            <td><span class="badge"><?= e($p['status']) ?></span></td>
            <td class="muted"><?= e($p['created_at']) ?></td>
            <td><a class="btn" href="project.php?id=<?= (int)$p['id'] ?>">Open</a></td>
          </tr>
        <?php endwhile; ?>
      </tbody>
    </table>
  </div>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
