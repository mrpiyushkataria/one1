<?php
require_once __DIR__ . '/includes/header.php';
$conn = db();
$uid = current_user_id();

if($_SERVER['REQUEST_METHOD']==='POST'){
  csrf_check();

  if(isset($_POST['add_item'])){
    $text = trim($_POST['item_text'] ?? '');
    $category = trim($_POST['category'] ?? 'general');
    $project_id = (int)($_POST['project_id'] ?? 0);
    if($text!==''){
      $st = $conn->prepare("INSERT INTO oneinseclabs_checklist_items (user_id, project_id, category, item_text) VALUES (?,?,?,?)");
      $st->bind_param("iiss",$uid,$project_id,$category,$text);
      $st->execute();
      audit_log($uid,'checklist_add',"Checklist item added");
    }
    redirect("checklist.php");
  }

  if(isset($_POST['toggle'])){
    $item_id = (int)($_POST['item_id'] ?? 0);
    $st = $conn->prepare("UPDATE oneinseclabs_checklist_items SET completed = IF(completed=1,0,1), completed_at = IF(completed=1,NULL,NOW()) WHERE id=? AND user_id=?");
    $st->bind_param("ii",$item_id,$uid);
    $st->execute();
    audit_log($uid,'checklist_toggle',"Checklist item toggled");
    redirect("checklist.php");
  }
}

$items = $conn->query("SELECT * FROM oneinseclabs_checklist_items WHERE user_id=$uid ORDER BY completed ASC, created_at DESC LIMIT 200");
$projects = $conn->query("SELECT id,title FROM oneinseclabs_projects ORDER BY created_at DESC");
?>
<div class="grid">
  <div class="card col-6">
    <h2>Add Checklist Item</h2>
    <form method="post">
      <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
      <input name="item_text" placeholder="Example: Run subfinder --all --recursive" required>
      <select name="category">
        <option value="general">general</option>
        <option value="recon">recon</option>
        <option value="web">web</option>
        <option value="api">api</option>
        <option value="android">android</option>
      </select>
      <select name="project_id">
        <option value="0">No project</option>
        <?php while($p=$projects->fetch_assoc()): ?>
          <option value="<?= (int)$p['id'] ?>"><?= e($p['title']) ?></option>
        <?php endwhile; ?>
      </select>
      <button class="btn primary" name="add_item" value="1">Add</button>
    </form>
  </div>

  <div class="card col-6">
    <h2>My Checklist</h2>
    <table class="table">
      <thead><tr><th>Done</th><th>Item</th><th>Category</th><th>Project</th><th>Time</th></tr></thead>
      <tbody>
      <?php while($it=$items->fetch_assoc()): ?>
        <tr>
          <td>
            <form method="post" style="margin:0">
              <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
              <input type="hidden" name="item_id" value="<?= (int)$it['id'] ?>">
              <button class="btn" name="toggle" value="1"><?= (int)$it['completed'] ? '✅' : '⬜' ?></button>
            </form>
          </td>
          <td><?= e($it['item_text']) ?></td>
          <td><span class="badge"><?= e($it['category']) ?></span></td>
          <td class="muted">#<?= (int)$it['project_id'] ?></td>
          <td class="muted"><?= e($it['created_at']) ?></td>
        </tr>
      <?php endwhile; ?>
      </tbody>
    </table>
  </div>
</div>
<?php require_once __DIR__ . '/includes/footer.php'; ?>
