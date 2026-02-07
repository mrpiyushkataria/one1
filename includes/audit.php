<?php
// includes/audit.php
require_once __DIR__ . '/../config.php';

function audit_log(?int $user_id, string $action, string $desc = ''): void {
  $conn = db();
  $ip = get_real_ip();
  $loc = ip_location($ip);

  $stmt = $conn->prepare("
    INSERT INTO oneinseclabs_audit_log (user_id, action, description, ip_address, city, country, created_at)
    VALUES (?, ?, ?, ?, ?, ?, NOW())
  ");
  $stmt->bind_param("isssss", $user_id, $action, $desc, $ip, $loc['city'], $loc['country']);
  $stmt->execute();
}
