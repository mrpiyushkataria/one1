<?php
require_once __DIR__ . '/includes/auth.php';
start_secure_session();

if (!empty($_SESSION['user_id'])) redirect('dashboard.php');

$conn = db();
$error = '';

function recaptcha_verify(string $token): bool {
  if (!defined('RECAPTCHA_SECRET') || RECAPTCHA_SECRET === '' || RECAPTCHA_SECRET === 'YOUR_SECRET_KEY') {
    // If you didn’t set keys yet, allow login (change to false if you want hard-block).
    return true;
  }
  $data = http_build_query([
    'secret' => RECAPTCHA_SECRET,
    'response' => $token,
    'remoteip' => get_real_ip()
  ]);
  $opts = ['http'=>['method'=>'POST','header'=>"Content-type: application/x-www-form-urlencoded\r\n",'content'=>$data,'timeout'=>8]];
  $resp = @file_get_contents('https://www.google.com/recaptcha/api/siteverify', false, stream_context_create($opts));
  if (!$resp) return false;
  $j = json_decode($resp,true);
  return !empty($j['success']);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $user = trim($_POST['username'] ?? '');
  $pass = trim($_POST['password'] ?? '');
  $token = $_POST['g-recaptcha-response'] ?? '';

  if ($user === '' || $pass === '') {
    $error = 'Missing username/password';
  } elseif (!recaptcha_verify($token)) {
    $error = 'CAPTCHA failed';
  } else {
    $stmt = $conn->prepare("SELECT id, username, password_hash, is_active FROM oneinseclabs_users WHERE username=? LIMIT 1");
    $stmt->bind_param("s", $user);
    $stmt->execute();
    $u = $stmt->get_result()->fetch_assoc();

    $ok = ($u && (int)$u['is_active'] === 1 && password_verify($pass, $u['password_hash']));
    $ip = get_real_ip();
    $loc = ipinfo_lookup($ip);

    $uid = $u ? (int)$u['id'] : null;
    $stmt2 = $conn->prepare("INSERT INTO oneinseclabs_login (user_id, username, ip_address, user_agent, city, country, success) VALUES (?,?,?,?,?,?,?)");
    $ua = substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 255);
    $success = $ok ? 1 : 0;
    $stmt2->bind_param("isssssi", $uid, $user, $ip, $ua, $loc['city'], $loc['country'], $success);
    $stmt2->execute();

    if ($ok) {
      $_SESSION['user_id'] = (int)$u['id'];
      $_SESSION['username'] = $u['username'];

      $conn->query("UPDATE oneinseclabs_users SET last_login=NOW() WHERE id=".(int)$u['id']);
      audit_log((int)$u['id'], 'login', 'User logged in');
      redirect('dashboard.php');
    } else {
      $error = 'Invalid credentials';
      audit_log($uid, 'login_failed', 'Failed login attempt');
    }
  }
}
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Login - OneInSecLabs</title>
  <style>
    body{margin:0;display:grid;place-items:center;height:100vh;background:#050914;color:#e5e7eb;font-family:Segoe UI,system-ui,Arial}
    .box{width:min(420px,92vw);padding:26px;border-radius:18px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08)}
    h1{margin:0 0 14px}
    input{width:100%;padding:12px;border-radius:12px;border:1px solid rgba(255,255,255,.12);background:rgba(0,0,0,.25);color:#e5e7eb;margin:8px 0 12px}
    button{width:100%;padding:12px;border-radius:12px;border:none;background:linear-gradient(90deg,#ff5800,#ff7633);color:#fff;font-weight:700;cursor:pointer}
    .err{color:#fecaca;margin:0 0 10px}
  </style>
  <script src="https://www.google.com/recaptcha/api.js?render=<?= e(RECAPTCHA_SITE_KEY) ?>"></script>
</head>
<body>
  <div class="box">
    <h1>Secure Login</h1>
    <?php if($error): ?><p class="err"><?= e($error) ?></p><?php endif; ?>
    <form method="post" id="f">
      <input name="username" placeholder="Username" required>
      <input name="password" type="password" placeholder="Password" required>
      <input type="hidden" name="g-recaptcha-response" id="g">
      <button type="button" onclick="go()">Login</button>
    </form>
  </div>

<script>
function go(){
  const siteKey = "<?= e(RECAPTCHA_SITE_KEY) ?>";
  if(!siteKey || siteKey === "YOUR_SITE_KEY"){
    document.getElementById('f').submit();
    return;
  }
  grecaptcha.ready(function(){
    grecaptcha.execute(siteKey, {action:'login'}).then(function(token){
      document.getElementById('g').value = token;
      document.getElementById('f').submit();
    });
  });
}
</script>
</body>
</html>
