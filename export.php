<?php
require_once __DIR__ . '/includes/auth.php';
require_login();
$conn = db();

$project_id = (int)($_GET['project_id'] ?? 0);
$type = $_GET['type'] ?? 'subdomains';

if ($project_id <= 0) { http_response_code(400); exit("project_id required"); }

$filename = "project_{$project_id}_{$type}.txt";
header('Content-Type: text/plain; charset=utf-8');
header('Content-Disposition: attachment; filename="'.$filename.'"');

if ($type === 'subdomains') {
  $rs = $conn->query("SELECT subdomain FROM oneinseclabs_subdomains WHERE project_id=$project_id ORDER BY subdomain ASC");
  while($r=$rs->fetch_assoc()) echo $r['subdomain']."\n";
  exit;
}

if ($type === 'ips') {
  $rs = $conn->query("SELECT DISTINCT ip_address FROM oneinseclabs_dns_records WHERE project_id=$project_id ORDER BY ip_address ASC");
  while($r=$rs->fetch_assoc()) echo $r['ip_address']."\n";
  exit;
}

if ($type === 'urls') {
  $rs = $conn->query("SELECT url FROM oneinseclabs_urls WHERE project_id=$project_id ORDER BY id DESC LIMIT 20000");
  while($r=$rs->fetch_assoc()) echo $r['url']."\n";
  exit;
}

http_response_code(400);
echo "Unknown type";
