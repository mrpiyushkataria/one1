<?php
require_once __DIR__ . '/includes/header.php';
$conn = db();

$limit = 30;
$page = max(1, (int)($_GET['page'] ?? 1));
$offset = ($page-1)*$limit;

$total = (int)($conn->query("SELECT COUNT(*) c FROM oneinseclabs_audit_log")->fetch_assoc()['c'] ?? 0);
$pages = max(1, (int)ceil($total / $limit));

$stmt = $conn->prepare("SELECT * FROM oneinseclabs_audit_log ORDER BY created_at DESC LIMIT ? OFFSET ?");
$stmt->bind_param("ii",$limit,$offset);
$stmt->execute();
$logs = $stmt->get_result();

audit_log(current_user_id(),'view_logs','Opened logs page');
?>
<div class="card">
  <h2>Logs</h2>
  <table class="table">
    <thead><tr><th>User</th><th>Action</th><th>Description</th><th>IP / Location</th><th>Time</th></tr></thead>
    <tbody>
      <?php while($l=$logs->fetch_assoc()): ?>
        <tr>
          <td>#<?= (int)$l['user_id'] ?></td>
          <td><span class="badge"><?= e($l['action']) ?></span></td>
          <td><?= e($l['description'] ?? '') ?></td>
          <td class="muted"><?= e($l['ip_address'] ?? '') ?><br><?= e(trim(($l['city'] ?? '').' '.($l['country'] ?? ''))) ?></td>
          <td class="muted"><?= e($l['created_at']) ?></td>
        </tr>
      <?php endwhile; ?>
    </tbody>
  </table>
  <div style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end">
    <?php for($i=1;$i<=$pages;$i++): ?>
      <a class="btn <?= $i===$page ? 'primary':'' ?>" href="?page=<?= $i ?>"><?= $i ?></a>
    <?php endfor; ?>
  </div>
</div>
<?php require_once __DIR__ . '/includes/footer.php'; ?>
