<?php
require_once __DIR__ . '/includes/header.php';
$conn = db();
$uid = current_user_id();

$msg = '';

function split_list(string $raw): array {
  $parts = preg_split('/[\r\n,]+/', $raw);
  $parts = array_map('trim', $parts ?: []);
  $parts = array_filter($parts, fn($x)=>$x!=='');
  return array_values(array_unique($parts));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  csrf_check();

  if (isset($_POST['create'])) {
    $name = trim($_POST['name'] ?? '');
    $org  = trim($_POST['org'] ?? '');
    $domains = trim($_POST['domains'] ?? '');
    $ip_ranges = trim($_POST['ip_ranges'] ?? '');

    if ($name !== '') {
      $st = $conn->prepare("INSERT INTO oneinseclabs_companies (name, organization_details, created_by) VALUES (?,?,?)");
      $st->bind_param("ssi", $name, $org, $uid);
      $st->execute();
      $cid = (int)$conn->insert_id;

      // Insert domain scopes
      $domainList = split_list($domains);
      foreach ($domainList as $d) {
        $d = strtolower($d);
        $d = preg_replace('#^https?://#','',$d);
        $d = preg_replace('#/.*$#','',$d);
        $d = preg_replace('/^\*\./','',$d);
        $d = rtrim($d,'.');
        if ($d==='') continue;
        $type = 'domain';

        $s = $conn->prepare("INSERT INTO oneinseclabs_company_scopes (company_id, scope_type, scope_value, notes) VALUES (?,?,?,?)");
        $note = 'imported';
        $s->bind_param("isss", $cid, $type, $d, $note);
        @$s->execute();
      }

      // Insert IP / CIDR scopes
      $ipList = split_list($ip_ranges);
      foreach ($ipList as $ip) {
        $ip = trim($ip);
        if ($ip==='') continue;
        $type = (strpos($ip,'/')!==false) ? 'cidr' : 'ip';
        $s = $conn->prepare("INSERT INTO oneinseclabs_company_scopes (company_id, scope_type, scope_value, notes) VALUES (?,?,?,?)");
        $note = 'imported';
        $s->bind_param("isss", $cid, $type, $ip, $note);
        @$s->execute();
      }

      audit_log($uid, 'company_create', 'Company created: '.$name);
      $msg = '✅ Company created';
    }
  }

  if (isset($_POST['delete_id'])) {
    $id = (int)$_POST['delete_id'];
    $conn->query("DELETE FROM oneinseclabs_companies WHERE id=$id");
    audit_log($uid, 'company_delete', 'Company deleted id='.$id);
    $msg = '✅ Company deleted';
  }
}

$rows = $conn->query("
  SELECT c.*,
         (SELECT COUNT(*) FROM oneinseclabs_projects p WHERE p.company_id=c.id) AS projects_count
  FROM oneinseclabs_companies c
  ORDER BY c.id DESC
");
?>
<div class="card">
  <h2>🏢 Companies</h2>
  <?php if($msg): ?><div class="badge"><?= htmlspecialchars($msg) ?></div><?php endif; ?>
</div>

<div class="grid">
  <div class="card col-6">
    <h3>➕ Create Company</h3>
    <form method="POST">
      <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">

      <label class="muted">Company Name</label>
      <input name="name" required>

      <label class="muted">Organization Details</label>
      <textarea name="org" rows="3"></textarea>

      <label class="muted">Root Domains (comma/newline)</label>
      <textarea name="domains" rows="4" placeholder="example.com&#10;example.org"></textarea>

      <label class="muted">IP / CIDR list (optional)</label>
      <textarea name="ip_ranges" rows="3" placeholder="1.2.3.4&#10;1.2.3.0/24"></textarea>

      <button class="btn orange" name="create" value="1" style="margin-top:10px">Create</button>
    </form>
  </div>

  <div class="card col-6">
    <h3>📄 Company List</h3>
    <table class="table">
      <thead><tr><th>ID</th><th>Name</th><th>Projects</th><th></th></tr></thead>
      <tbody>
      <?php while($r=$rows->fetch_assoc()): ?>
        <tr>
          <td><?= (int)$r['id'] ?></td>
          <td><a class="btn" href="company.php?id=<?= (int)$r['id'] ?>"><?= e($r['name']) ?></a></td>
          <td class="muted"><?= (int)$r['projects_count'] ?></td>
          <td>
            <form method="POST" onsubmit="return confirm('Delete company?');">
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
