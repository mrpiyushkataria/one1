<?php
// public_html/one.inseclabs.com/settings.php

declare(strict_types=1);
ini_set('display_errors', '0');
error_reporting(E_ALL);

require_once __DIR__ . '/includes/header.php';
require_once __DIR__ . '/includes/shodan_lib.php';

$conn = db();
$uid  = (int)current_user_id();
$msg  = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  csrf_check();

  // Update username/password
  if (isset($_POST['save_account'])) {
    $new_user = trim((string)($_POST['username'] ?? ''));
    $new_pass = trim((string)($_POST['password'] ?? ''));

    if ($new_user !== '' && $new_pass !== '') {
      $hash = password_hash($new_pass, PASSWORD_DEFAULT);
      $st = $conn->prepare("UPDATE oneinseclabs_users SET username=?, password_hash=? WHERE id=?");
      $st->bind_param("ssi", $new_user, $hash, $uid);
      $st->execute();

      $_SESSION['username'] = $new_user;
      $msg = "Account updated ✅";
      audit_log($uid, 'settings_update', 'Updated account credentials');
    } else {
      $msg = "Fill both username + password";
    }
  }

  // Save Shodan API key
  if (isset($_POST['save_shodan_key'])) {
    $key = trim((string)($_POST['shodan_api_key'] ?? ''));
    if ($key !== '') {
      shodan_set_api_key($conn, $uid, $key);
      $msg = "Shodan API saved ✅";
      audit_log($uid, 'settings_shodan_key', 'Saved Shodan API key');
    } else {
      $msg = "Paste Shodan API key";
    }
  }
}

$has_key = (shodan_get_api_key($conn, $uid) !== '');
?>
<div class="card">
  <h2>Settings</h2>
  <?php if ($msg): ?><div class="badge"><?= e($msg) ?></div><?php endif; ?>

  <form method="post" style="margin-top:12px">
    <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
    <label class="muted">New Username</label>
    <input name="username" value="<?= e($_SESSION['username'] ?? '') ?>" required>

    <label class="muted">New Password</label>
    <input type="password" name="password" required>

    <button class="btn orange" name="save_account" value="1">Update</button>
  </form>
</div>

<div class="card" style="margin-top:14px">
  <h2>Shodan API</h2>
  <div class="muted">Stored encrypted per-user in DB.</div>

  <form method="post" style="margin-top:12px">
    <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
    <label class="muted">Shodan API Key</label>
    <input type="password" name="shodan_api_key"
           placeholder="<?= $has_key ? 'Key saved (enter to replace)' : 'Paste your Shodan API key' ?>"
           autocomplete="off">
    <button class="btn orange" name="save_shodan_key" value="1" style="margin-top:10px">Save</button>
  </form>

  <?php if ($has_key): ?>
    <div class="badge" style="margin-top:10px">✅ Key is saved</div>
  <?php else: ?>
    <div class="badge" style="margin-top:10px">⚠️ Key not set</div>
  <?php endif; ?>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
