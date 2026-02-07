<?php
require_once __DIR__ . '/includes/header.php';
$conn = db();
$uid = current_user_id();

if($_SERVER['REQUEST_METHOD']==='POST'){
  csrf_check();
  $title = trim($_POST['title'] ?? '');
  $content = trim($_POST['content'] ?? '');
  $category = trim($_POST['category'] ?? 'general');
  $project_id = (int)($_POST['project_id'] ?? 0);
  $is_template = isset($_POST['is_template']) ? 1 : 0;
  $template_name = $is_template ? trim($_POST['template_name'] ?? '') : null;

  if($content !== ''){
    $st = $conn->prepare("INSERT INTO oneinseclabs_notes (user_id, project_id, category, title, content, is_template, template_name)
                          VALUES (?,?,?,?,?,?,?)");
    $st->bind_param("iisssis",$uid,$project_id,$category,$title,$content,$is_template,$template_name);
    $st->execute();
    audit_log($uid,'note_create',"Created note");
  }
  redirect("notes.php");
}

$notes = $conn->query("SELECT id, title, category, project_id, is_template, created_at FROM oneinseclabs_notes WHERE user_id=$uid ORDER BY created_at DESC LIMIT 100");
$projects = $conn->query("SELECT id,title FROM oneinseclabs_projects ORDER BY created_at DESC");
?>
<div class="grid">
  <div class="card col-6">
    <h2>Create Note / Template</h2>
    <form method="post">
      <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
      <input name="title" placeholder="Title (optional)">
      <select name="category">
        <option value="general">general</option>
        <option value="recon">recon</option>
        <option value="exploitation">exploitation</option>
        <option value="android">android</option>
        <option value="api">api</option>
      </select>
      <select name="project_id">
        <option value="0">No project</option>
        <?php while($p=$projects->fetch_assoc()): ?>
          <option value="<?= (int)$p['id'] ?>"><?= e($p['title']) ?></option>
        <?php endwhile; ?>
      </select>
      <textarea name="content" placeholder="Write your note..."></textarea>
      <label class="muted"><input type="checkbox" name="is_template"> Save as template</label>
      <input name="template_name" placeholder="Template name (if template)">
      <button class="btn primary">Save</button>
    </form>
  </div>

  <div class="card col-6">
    <h2>Recent Notes</h2>
    <table class="table">
      <thead><tr><th>Title</th><th>Category</th><th>Project</th><th>Type</th><th>Time</th></tr></thead>
      <tbody>
      <?php while($n=$notes->fetch_assoc()): ?>
        <tr>
          <td><strong><?= e($n['title'] ?: 'Untitled') ?></strong></td>
          <td><span class="badge"><?= e($n['category']) ?></span></td>
          <td class="muted">#<?= (int)$n['project_id'] ?></td>
          <td><span class="badge"><?= (int)$n['is_template'] ? 'template' : 'note' ?></span></td>
          <td class="muted"><?= e($n['created_at']) ?></td>
        </tr>
      <?php endwhile; ?>
      </tbody>
    </table>
  </div>
</div>
<?php require_once __DIR__ . '/includes/footer.php'; ?>
