<?php
require_once __DIR__ . '/../config.php';

if (($_GET['token'] ?? '') !== SETUP_TOKEN) {
  http_response_code(403);
  die("Forbidden");
}

$conn = db();
$exists = (int)($conn->query("SELECT COUNT(*) c FROM oneinseclabs_login")->fetch_assoc()['c'] ?? 0);
if ($exists > 0) die("Admin already exists. Delete this file now.");

$user = 'admin';
$pass = 'ChangeThisPassword!';
$hash = password_hash($pass, PASSWORD_DEFAULT);

$stmt = $conn->prepare("INSERT INTO oneinseclabs_login (username, email, password_hash, role) VALUES (?,?,?, 'admin')");
$email = 'admin@local';
$stmt->bind_param("sss", $user, $email, $hash);
$stmt->execute();

echo "✅ Created admin user.<br>";
echo "Username: <b>admin</b><br>";
echo "Password: <b>ChangeThisPassword!</b><br><br>";
echo "<b>IMPORTANT:</b> Login now and change password in Settings, then DELETE /setup/ folder.";
