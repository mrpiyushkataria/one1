<?php
require_once __DIR__ . '/header.php';
csrf_check();
$conn=db();

$project_id=(int)($_GET['project_id'] ?? ($_SESSION['active_project_id'] ?? 0));
if($project_id<=0){ echo "<div class='card'>Set active project first.</div>"; require 'footer.php'; exit(); }

$template_id=(int)($_GET['template_id'] ?? 1);

// Toggle tick
if($_SERVER['REQUEST_METHOD']==='POST' && isset($_POST['toggle_item'])){
  $item_id=(int)$_POST['item_id'];
  $uid=(int)$_SESSION['user_id'];

  $row=$conn->query("SELECT completed FROM oneinseclabs_checklist_ticks WHERE project_id=$project_id AND item_id=$item_id")->fetch_assoc();
  $new = empty($row) ? 1 : ((int)$row['completed'] ? 0 : 1);

  $stmt=$conn->prepare("
    INSERT INTO oneinseclabs_checklist_ticks (project_id,item_id,user_id,completed,completed_at)
    VALUES (?,?,?,?,IF(?,NOW(),NULL))
    ON DUPLICATE KEY UPDATE completed=VALUES(completed), user_id=VALUES(user_id), completed_at=IF(VALUES(completed)=1,NOW(),NULL)
  ");
  $stmt->bind_param("iiiii",$project_id,$item_id,$uid,$new,$new);
  @$stmt->execute();
  audit_log($uid,'update','Checklist tick updated','checklist_item',$item_id,$project_id);
}

$tpl=$conn->query("SELECT * FROM oneinseclabs_checklist_templates WHERE id=$template_id")->fetch_assoc();
$items=$conn->query("
  SELECT i.*, t.completed
  FROM oneinseclabs_checklist_items i
  LEFT JOIN oneinseclabs_checklist_ticks t
    ON t.item_id=i.id AND t.project_id=$project_id
  WHERE i.template_id=$template_id
  ORDER BY i.sort_order ASC, i.id ASC
");
?>
<div class="card">
  <h2 style="margin:0 0 10px 0;">Checklist — <?= h($tpl['name'] ?? 'Template') ?></h2>
  <div style="opacity:.75">Project #<?= (int)$project_id ?></div>
</div>

<div class="card" style="margin-top:14px">
  <?php while($it=$items->fetch_assoc()): $done=(int)($it['completed'] ?? 0)===1; ?>
    <form method="post" style="display:flex;gap:10px;align-items:center;border-bottom:1px solid #e5e7eb;padding:10px 0">
      <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
      <input type="hidden" name="item_id" value="<?= (int)$it['id'] ?>">
      <button name="toggle_item" value="1" style="background:<?= $done?'#16a34a':'#2563eb' ?>"><?= $done?'Done':'Mark' ?></button>
      <div>
        <div style="font-weight:800"><?= h($it['item_text']) ?></div>
        <div style="opacity:.7;font-size:12px"><?= h($it['category'] ?? '') ?></div>
      </div>
    </form>
  <?php endwhile; ?>
</div>

<?php require_once __DIR__ . '/footer.php'; ?>
