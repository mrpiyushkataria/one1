<?php
require_once __DIR__ . '/includes/db.php';

$conn = db();
$exists = (int)($conn->query("SELECT COUNT(*) c FROM oneinseclabs_users")->fetch_assoc()['c'] ?? 0);

$msg = '';
if ($exists > 0) { die("Users already exist. Delete install.php now."); }

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $u = trim($_POST['username'] ?? '');
  $p = trim($_POST['password'] ?? '');
  $e = trim($_POST['email'] ?? '');

  if (strlen($u) < 3 || strlen($p) < 8) $msg = "Username min 3 chars, password min 8 chars.";
  else {
    $hash = password_hash($p, PASSWORD_DEFAULT);
    $stmt = $conn->prepare("INSERT INTO oneinseclabs_users (username,email,password_hash,role) VALUES (?,?,?, 'admin')");
    $stmt->bind_param("sss", $u, $e, $hash);
    if ($stmt->execute()) {
      echo "Admin created. DELETE install.php now. <a href='index.php'>Go login</a>";
      exit();
    }
    $msg = "Failed: maybe username/email already used.";
  }
}
?>
<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Install - OneInSecLabs</title></head>
<body style="font-family:Arial;max-width:520px;margin:40px auto">
<h2>OneInSecLabs Install</h2>
<p style="color:#b00;"><?= h($msg) ?></p>
<form method="post">
  <label>Username</label><br><input name="username" required style="width:100%;padding:10px"><br><br>
  <label>Email (optional)</label><br><input name="email" style="width:100%;padding:10px"><br><br>
  <label>Password (min 8 chars)</label><br><input type="password" name="password" required style="width:100%;padding:10px"><br><br>
  <button style="padding:10px 16px">Create Admin</button>
</form>
</body></html>
