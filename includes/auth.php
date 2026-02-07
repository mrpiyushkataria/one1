<?php
require_once __DIR__ . '/util.php';

function start_secure_session() {
  if (session_status() === PHP_SESSION_ACTIVE) return;

  $secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');

  if (PHP_VERSION_ID >= 70300) {
    session_set_cookie_params([
      'lifetime' => 0,
      'path' => '/',
      'secure' => $secure,
      'httponly' => true,
      'samesite' => 'Lax'
    ]);
  } else {
    session_set_cookie_params(0, '/; samesite=Lax', '', $secure, true);
  }

  session_name('ONEINSECLABSSESS');
  session_start();

  // timeout
  $now = time();
  if (isset($_SESSION['last_seen']) && ($now - (int)$_SESSION['last_seen']) > SESSION_TIMEOUT_SECONDS) {
    session_unset();
    session_destroy();
    redirect('index.php?timeout=1');
  }
  $_SESSION['last_seen'] = $now;
}

function require_login() {
  start_secure_session();
  if (empty($_SESSION['user_id'])) redirect('index.php');
}

function current_user_id(): ?int {
  start_secure_session();
  return isset($_SESSION['user_id']) ? (int)$_SESSION['user_id'] : null;
}

/**
 * ✅ Unified CSRF system:
 * - Supports both "csrf" and "csrf_token" POST names.
 * - Stores one token but also mirrors it to old session key for compatibility.
 */
function csrf_token(): string {
  start_secure_session();

  // If old session key exists, migrate it
  if (empty($_SESSION['csrf']) && !empty($_SESSION['csrf_token']) && is_string($_SESSION['csrf_token'])) {
    $_SESSION['csrf'] = $_SESSION['csrf_token'];
  }

  if (empty($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(32));
  }

  // Mirror to old key so legacy pages still work
  $_SESSION['csrf_token'] = $_SESSION['csrf'];

  return $_SESSION['csrf'];
}

function csrf_check(): void {
  start_secure_session();

  // Accept both parameter names
  $t = $_POST['csrf'] ?? ($_POST['csrf_token'] ?? '');

  if (!$t || empty($_SESSION['csrf']) || !hash_equals($_SESSION['csrf'], $t)) {
    http_response_code(403);
    exit('CSRF check failed');
  }
}
