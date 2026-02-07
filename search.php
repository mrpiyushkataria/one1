<?php
require_once __DIR__ . '/includes/header.php';
$conn = db();
$q = trim($_GET['q'] ?? '');
$res = ['companies'=>[], 'projects'=>[], 'subdomains'=>[], 'urls'=>[], 'notes'=>[]];

if ($q !== '') {
  $like = "%$q%";

  $st = $conn->prepare("SELECT id,name FROM oneinseclabs_companies WHERE name LIKE ? ORDER BY name LIMIT 20");
  $st->bind_param("s",$like); $st->execute(); $res['companies'] = $st->get_result()->fetch_all(MYSQLI_ASSOC);

  $st = $conn->prepare("SELECT id,title FROM oneinseclabs_projects WHERE title LIKE ? ORDER BY created_at DESC LIMIT 20");
  $st->bind_param("s",$like); $st->execute(); $res['projects'] = $st->get_result()->fetch_all(MYSQLI_ASSOC);

  $st = $conn->prepare("SELECT project_id,subdomain FROM oneinseclabs_subdomains WHERE subdomain LIKE ? LIMIT 20");
  $st->bind_param("s",$like); $st->execute(); $res['subdomains'] = $st->get_result()->fetch_all(MYSQLI_ASSOC);

  $st = $conn->prepare("SELECT project_id,url,source FROM oneinseclabs_urls WHERE url LIKE ? LIMIT 20");
  $st->bind_param("s",$like); $st->execute(); $res['urls'] = $st->get_result()->fetch_all(MYSQLI_ASSOC);

  $st = $conn->prepare("SELECT id,title,project_id FROM oneinseclabs_notes WHERE content LIKE ? OR title LIKE ? LIMIT 20");
  $st->bind_param("ss",$like,$like); $st->execute(); $res['notes'] = $st->get_result()->fetch_all(MYSQLI_ASSOC);

  audit_log(current_user_id(), 'search', "Search: $q");
}
?>
<div class="card">
  <h2>Global Search</h2>
  <form method="get">
    <input name="q" value="<?= e($q) ?>" placeholder="Search companies, projects, notes, subdomains, urls..." autofocus>
    <button class="btn primary" style="margin-top:10px">Search</button>
  </form>
</div>

<?php if($q!==''): ?>
<div class="grid">
  <div class="card col-6">
    <h3>Companies</h3>
    <?php foreach($res['companies'] as $r): ?>
      <div><a class="btn" href="company.php?id=<?= (int)$r['id'] ?>"><?= e($r['name']) ?></a></div>
    <?php endforeach; if(!count($res['companies'])) echo "<div class='muted'>No results</div>"; ?>
  </div>

  <div class="card col-6">
    <h3>Projects</h3>
    <?php foreach($res['projects'] as $r): ?>
      <div><a class="btn" href="project.php?id=<?= (int)$r['id'] ?>"><?= e($r['title']) ?></a></div>
    <?php endforeach; if(!count($res['projects'])) echo "<div class='muted'>No results</div>"; ?>
  </div>

  <div class="card col-6">
    <h3>Subdomains</h3>
    <?php foreach($res['subdomains'] as $r): ?>
      <div class="badge"><?= e($r['subdomain']) ?> <span class="muted">(#<?= (int)$r['project_id'] ?>)</span></div>
    <?php endforeach; if(!count($res['subdomains'])) echo "<div class='muted'>No results</div>"; ?>
  </div>

  <div class="card col-6">
    <h3>URLs</h3>
    <?php foreach($res['urls'] as $r): ?>
      <div class="badge"><?= e(mb_substr($r['url'],0,70)) ?> <span class="muted">(<?= e($r['source']) ?>)</span></div>
    <?php endforeach; if(!count($res['urls'])) echo "<div class='muted'>No results</div>"; ?>
  </div>

  <div class="card col-12">
    <h3>Notes</h3>
    <?php foreach($res['notes'] as $r): ?>
      <div class="badge"><?= e($r['title'] ?? 'Note') ?> <span class="muted">(project #<?= (int)$r['project_id'] ?>)</span></div>
    <?php endforeach; if(!count($res['notes'])) echo "<div class='muted'>No results</div>"; ?>
  </div>
</div>
<?php endif; ?>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
