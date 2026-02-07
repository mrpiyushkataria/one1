<?php
require_once __DIR__ . '/includes/auth.php';
start_secure_session();
$uid = current_user_id();
audit_log($uid, 'logout', 'User logged out');
session_destroy();
header("Location: index.php");
exit();
