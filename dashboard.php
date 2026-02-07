<?php
require_once __DIR__ . '/includes/header.php';
$conn = db();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  csrf_check();
  $uid = current_user_id();

  if (isset($_POST['create_company'])) {
    $name = trim($_POST['name'] ?? '');
    $details = trim($_POST['details'] ?? '');

    if ($name !== '') {
      $stmt = $conn->prepare("INSERT INTO oneinseclabs_companies (name, organization_details, created_by) VALUES (?,?,?)");
      $stmt->bind_param("ssi", $name, $details, $uid);
      $stmt->execute();
      audit_log($uid, 'company_create', "Created company: $name");
    }
    redirect('dashboard.php');
  }

  if (isset($_POST['create_project'])) {
    $company_id = (int)($_POST['company_id'] ?? 0);
    $title = trim($_POST['title'] ?? '');
    $desc = trim($_POST['description'] ?? '');

    if ($company_id > 0 && $title !== '') {
      $stmt = $conn->prepare("INSERT INTO oneinseclabs_projects (company_id, title, description, created_by) VALUES (?,?,?,?)");
      $stmt->bind_param("issi", $company_id, $title, $desc, $uid);
      $stmt->execute();
      audit_log($uid, 'project_create', "Created project: $title");
    }
    redirect('dashboard.php');
  }
}

$companies = $conn->query("SELECT c.*, (SELECT COUNT(*) FROM oneinseclabs_projects p WHERE p.company_id=c.id) AS projects
                           FROM oneinseclabs_companies c ORDER BY c.created_at DESC");
?>
<div class="grid">
  <div class="card col-6">
    <h2>Create Company</h2>
    <form method="post">
      <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
      <label class="muted">Company Name</label>
      <input name="name" placeholder="Example: Acme Corp" required>
      <label class="muted">Organization Details</label>
      <textarea name="details" placeholder="Scope notes, program links, internal notes..."></textarea>
      <button class="btn orange" name="create_company" value="1">Create Company</button>
    </form>
  </div>

  <div class="card col-6">
    <h2>Create Project</h2>
    <form method="post">
      <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
      <label class="muted">Select Company</label>
      <select name="company_id" required>
        <option value="">Choose...</option>
        <?php
        $c2 = $conn->query("SELECT id,name FROM oneinseclabs_companies ORDER BY name ASC");
        while($r=$c2->fetch_assoc()){
          echo "<option value='".(int)$r['id']."'>".e($r['name'])."</option>";
        }
        ?>
      </select>
      <label class="muted">Project Title</label>
      <input name="title" placeholder="Example: Web App Bug Bounty" required>
      <label class="muted">Description</label>
      <textarea name="description" placeholder="Goal, timeline, scope summary..."></textarea>
      <button class="btn primary" name="create_project" value="1">Create Project</button>
    </form>
  </div>

  <div class="card col-12">
    <h2>Companies</h2>
    <table class="table">
      <thead><tr><th>Name</th><th>Projects</th><th>Created</th><th></th></tr></thead>
      <tbody>
        <?php while($c=$companies->fetch_assoc()): ?>
          <tr>
            <td><strong><?= e($c['name']) ?></strong><div class="muted"><?= e(mb_substr($c['organization_details'] ?? '',0,80)) ?></div></td>
            <td><span class="badge"><?= (int)$c['projects'] ?></span></td>
            <td class="muted"><?= e($c['created_at']) ?></td>
            <td><a class="btn" href="company.php?id=<?= (int)$c['id'] ?>">Open</a></td>
          </tr>
        <?php endwhile; ?>
      </tbody>
    </table>
  </div>
</div>
<?php require_once __DIR__ . '/includes/footer.php'; ?>
