<?php
require_once __DIR__ . '/includes/header.php';
$conn = db();
$uid = current_user_id();

$msg = '';

$companies = $conn->query("SELECT id,name FROM oneinseclabs_companies ORDER BY name ASC");

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  csrf_check();

  if (isset($_POST['create'])) {
    $company_id = (int)($_POST['company_id'] ?? 0);
    $title = trim($_POST['title'] ?? '');
    $desc  = trim($_POST['desc'] ?? '');
    $profile = $_POST['scan_profile'] ?? 'medium';

    if ($company_id > 0 && $title !== '') {
      $st = $conn->prepare("INSERT INTO oneinseclabs_projects (company_id, title, description, created_by, scan_profile) VALUES (?,?,?,?,?)");
      $st->bind_param("issis", $company_id, $title, $desc, $uid, $profile);
      $st->execute();
      audit_log($uid,'project_create','Project created: '.$title);
      $msg = '✅ Project created';
    }
  }

  if (isset($_POST['delete_id'])) {
    $id = (int)$_POST['delete_id'];
    $conn->query("DELETE FROM oneinseclabs_projects WHERE id=$id");
    audit_log($uid,'project_delete','Project deleted id='.$id);
    $msg = '✅ Project deleted';
  }
}

$rows = $conn->query("
  SELECT p.*, c.name AS company_name
  FROM oneinseclabs_projects p
  JOIN oneinseclabs_companies c ON c.id=p.company_id
  ORDER BY p.id DESC
");
?>
<div class="card">
  <h2>📁 Projects</h2>
  <?php if($msg): ?><div class="badge"><?= e($msg) ?></div><?php endif; ?>
</div>

<div class="grid">
  <div class="card col-6">
    <h3>➕ Create Project</h3>
    <form method="POST">
      <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">

      <label class="muted">Company</label>
      <select name="company_id" required>
        <option value="">-- select --</option>
        <?php while($c=$companies->fetch_assoc()): ?>
          <option value="<?= (int)$c['id'] ?>"><?= e($c['name']) ?></option>
        <?php endwhile; ?>
      </select>

      <label class="muted">Title</label>
      <input name="title" required>

      <label class="muted">Description</label>
      <textarea name="desc" rows="3"></textarea>

      <label class="muted">Scan Profile</label>
      <select name="scan_profile">
        <option value="low">low</option>
        <option value="medium" selected>medium</option>
        <option value="high">high</option>
        <option value="aggressive">aggressive</option>
      </select>

      <button class="btn orange" name="create" value="1" style="margin-top:10px">Create</button>
    </form>
  </div>

  <div class="card col-6">
    <h3>📄 Project List</h3>
    <table class="table">
      <thead><tr><th>ID</th><th>Company</th><th>Title</th><th>Status</th><th></th></tr></thead>
      <tbody>
      <?php while($r=$rows->fetch_assoc()): ?>
        <tr>
          <td><?= (int)$r['id'] ?></td>
          <td><?= e($r['company_name']) ?></td>
          <td><a class="btn" href="project.php?id=<?= (int)$r['id'] ?>"><?= e($r['title']) ?></a></td>
          <td class="muted"><?= e($r['status']) ?></td>
          <td>
            <form method="POST" onsubmit="return confirm('Delete project?');">
              <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
              <input type="hidden" name="delete_id" value="<?= (int)$r['id'] ?>">
              <button class="btn danger">Delete</button>
            </form>
          </td>
        </tr>
      <?php endwhile; ?>
      </tbody>
    </table>
  </div>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
