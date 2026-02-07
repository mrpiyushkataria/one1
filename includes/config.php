<?php
declare(strict_types=1);

date_default_timezone_set('Asia/Kolkata');

define('DB_HOST', 'localhost');
define('DB_USER', 'inseclabs_admin');
define('DB_PASS', 'Mr.inseclabs@123456');
define('DB_NAME', 'inseclabs_db');

define('SITE_NAME', 'OneInSecLabs');
define('SESSION_TIMEOUT', 1800); // 30 min

// reCAPTCHA (your existing keys can go here)
define('RECAPTCHA_SITE_KEY', '6LcSel4sAAAAAJ5cPAdqWIZmDRXx1JmF5Xosll6J');
define('RECAPTCHA_SECRET_KEY', '6LcSel4sAAAAAPiH7wkFcgFVnlTv3COFcvwzR8KQ');

// Optional: IPInfo token (or leave blank)
define('IPINFO_TOKEN', '');

// Secure sessions
$secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
session_set_cookie_params([
  'lifetime' => 0,
  'path' => '/',
  'domain' => '',
  'secure' => $secure,
  'httponly' => true,
  'samesite' => 'Lax',
]);

if (session_status() !== PHP_SESSION_ACTIVE) session_start();

// Session timeout (only if logged in)
if (!empty($_SESSION['user_id'])) {
  $last = $_SESSION['LAST_ACTIVITY'] ?? time();
  if ((time() - (int)$last) > SESSION_TIMEOUT) {
    session_unset();
    session_destroy();
    header("Location: index.php");
    exit();
  }
  $_SESSION['LAST_ACTIVITY'] = time();
}
