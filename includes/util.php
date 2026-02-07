<?php
require_once __DIR__ . '/db.php';

if (!function_exists('str_ends_with')) {
  function str_ends_with(string $haystack, string $needle): bool {
    if ($needle === '') return true;
    $len = strlen($needle);
    return substr($haystack, -$len) === $needle;
  }
}

function e($s): string { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }

function redirect(string $url) {
  header("Location: $url");
  exit();
}

function get_real_ip(): string {
  return $_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

function ipinfo_lookup(string $ip): array {
  if (!defined('IPINFO_TOKEN') || IPINFO_TOKEN === '') return ['city'=>null,'country'=>null];
  $token = IPINFO_TOKEN;
  $resp = @file_get_contents("https://ipinfo.io/{$ip}?token={$token}");
  if (!$resp) return ['city'=>null,'country'=>null];
  $j = json_decode($resp, true);
  return ['city'=>$j['city'] ?? null, 'country'=>$j['country'] ?? null];
}

function audit_log(?int $user_id, string $action, string $desc='') {
  $c = db();
  $ip = get_real_ip();
  $loc = ipinfo_lookup($ip);
  $stmt = $c->prepare("INSERT INTO oneinseclabs_audit_log (user_id, action, description, ip_address, city, country) VALUES (?,?,?,?,?,?)");
  $stmt->bind_param("isssss", $user_id, $action, $desc, $ip, $loc['city'], $loc['country']);
  $stmt->execute();
}
