<?php
/**
 * public_html/one.inseclabs.com/api/shodan_export.php
 * Export filtered shodan services as CSV.
 */

declare(strict_types=1);
require_once __DIR__ . '/../includes/header.php';

$conn = db();
$uid  = (int)current_user_id();
if ($uid <= 0) { http_response_code(401); exit("unauthorized"); }

$project_id = (int)($_GET['project_id'] ?? 0);
if ($project_id <= 0) { http_response_code(400); exit("project_id required"); }

/* Filters */
$q  = trim((string)($_GET['q'] ?? ''));
$org= trim((string)($_GET['org'] ?? ''));
$product = trim((string)($_GET['product'] ?? ''));
$vuln = trim((string)($_GET['vuln'] ?? ''));
$port = (int)($_GET['port'] ?? 0);

$sql = "SELECT s.ip, s.port, s.transport, s.product, s.version, s.org, s.country, s.city, s.vulns, s.hostnames
        FROM oneinseclabs_shodan_services s
        WHERE s.project_id=? ";
$params = [$project_id];
$types = "i";

if ($q !== '') {
  $sql .= " AND (s.ip LIKE CONCAT('%',?,'%') OR s.hostnames LIKE CONCAT('%',?,'%') OR s.banner LIKE CONCAT('%',?,'%'))";
  $types .= "sss";
  $params[]=$q; $params[]=$q; $params[]=$q;
}
if ($org !== '') { $sql .= " AND s.org LIKE CONCAT('%',?,'%')"; $types.="s"; $params[]=$org; }
if ($product !== '') { $sql .= " AND s.product LIKE CONCAT('%',?,'%')"; $types.="s"; $params[]=$product; }
if ($port > 0) { $sql .= " AND s.port=?"; $types.="i"; $params[]=$port; }
if ($vuln !== '') { $sql .= " AND s.vulns LIKE CONCAT('%',?,'%')"; $types.="s"; $params[]=$vuln; }

$sql .= " ORDER BY s.updated_at DESC LIMIT 50000";

$st = $conn->prepare($sql);
$st->bind_param($types, ...$params);
$st->execute();
$rs = $st->get_result();

header('Content-Type: text/csv; charset=utf-8');
header('Content-Disposition: attachment; filename="shodan_export_'.$project_id.'.csv"');

$out = fopen('php://output', 'w');
fputcsv($out, ['ip','port','transport','product','version','org','country','city','vulns','hostnames']);

while ($row = $rs->fetch_assoc()) {
  fputcsv($out, [
    $row['ip'], $row['port'], $row['transport'], $row['product'], $row['version'],
    $row['org'], $row['country'], $row['city'], $row['vulns'], $row['hostnames']
  ]);
}
fclose($out);
exit;
