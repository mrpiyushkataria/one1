<?php
/**
 * public_html/one.inseclabs.com/api/shodan_graph.php
 * Returns a 3D force-graph JSON: {nodes:[], links:[]}
 *
 * Graph model:
 *  root (domain) -> ip -> ip:port -> vuln (CVE-xxxx) [optional]
 *
 * Requires:
 * - includes/header.php: db(), current_user_id(), e(), redirect(), csrf_check() (not needed here)
 * - tables:
 *   oneinseclabs_project_domains(project_id, root_domain)
 *   oneinseclabs_shodan_services(project_id, ip, port, transport, product, version, org, country, city, vulns)
 */

declare(strict_types=1);
if (!defined('ONEINSECLABS_API')) define('ONEINSECLABS_API', true);

ini_set('display_errors','0');
error_reporting(E_ALL);
ob_start();

function api_json_exit(int $code, array $payload): void {
  if (ob_get_length()) ob_clean();
  http_response_code($code);
  header('Content-Type: application/json; charset=utf-8');
  echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
  exit;
}

set_error_handler(function($severity, $message, $file, $line){
  api_json_exit(500, ['ok'=>false,'error'=>"PHP: $message in $file:$line"]);
});
set_exception_handler(function(Throwable $e){
  api_json_exit(500, ['ok'=>false,'error'=>"EX: ".$e->getMessage()]);
});

require_once __DIR__ . '/../includes/header.php';

if (ob_get_length()) ob_clean();

$conn = db();
$uid  = (int)current_user_id();
if ($uid <= 0) api_json_exit(401, ['ok'=>false,'error'=>'unauthorized']);

$project_id = (int)($_GET['project_id'] ?? 0);
if ($project_id <= 0) api_json_exit(400, ['ok'=>false,'error'=>'project_id required']);

// ✅ Ownership check (if your projects table has user_id/owner_id. If not, remove this block.)
$own_ok = true;
$rs = $conn->query("SHOW COLUMNS FROM oneinseclabs_projects LIKE 'user_id'");
if ($rs && $rs->num_rows > 0) {
  $st = $conn->prepare("SELECT id FROM oneinseclabs_projects WHERE id=? AND user_id=? LIMIT 1");
  $st->bind_param("ii", $project_id, $uid);
  $st->execute();
  $row = $st->get_result()->fetch_assoc();
  $own_ok = (bool)$row;
}
if (!$own_ok) api_json_exit(403, ['ok'=>false,'error'=>'forbidden']);

// params
$limit_services = (int)($_GET['limit'] ?? 1500);
if ($limit_services < 200) $limit_services = 200;
if ($limit_services > 8000) $limit_services = 8000;

$include_vulns = (int)($_GET['vulns'] ?? 1) === 1;
$root_hint     = trim((string)($_GET['root'] ?? '')); // optional root context (for linking)

// Fetch roots
$roots = [];
$st = $conn->prepare("SELECT root_domain FROM oneinseclabs_project_domains WHERE project_id=? ORDER BY root_domain ASC");
$st->bind_param("i", $project_id);
$st->execute();
$res = $st->get_result();
while ($r = $res->fetch_assoc()) {
  $d = trim((string)$r['root_domain']);
  if ($d !== '') $roots[] = $d;
}

// Pick a root node to attach (best-effort)
$root_node = $root_hint !== '' ? $root_hint : ($roots[0] ?? ('project-'.$project_id));

// Fetch shodan services
$st = $conn->prepare("
  SELECT ip, port, transport, product, version, org, country, city, vulns
  FROM oneinseclabs_shodan_services
  WHERE project_id=?
  ORDER BY created_at DESC
  LIMIT ?
");
$st->bind_param("ii", $project_id, $limit_services);
$st->execute();
$res = $st->get_result();

$nodes = [];
$links = [];
$nodeSeen = [];
$linkSeen = [];

// helpers
$addNode = function(string $id, string $type, string $label, array $extra = []) use (&$nodes, &$nodeSeen) {
  if (isset($nodeSeen[$id])) return;
  $nodeSeen[$id] = true;
  $n = array_merge([
    'id'    => $id,
    'type'  => $type,        // root_domain|ip_address|service|vulnerability
    'name'  => $label,       // for label
    'group' => $type         // for color grouping in graph JS
  ], $extra);
  $nodes[] = $n;
};

$addLink = function(string $src, string $dst, string $rel='') use (&$links, &$linkSeen) {
  $k = $src.'->'.$dst.'|'.$rel;
  if (isset($linkSeen[$k])) return;
  $linkSeen[$k] = true;
  $links[] = [
    'source' => $src,
    'target' => $dst,
    'rel'    => $rel
  ];
};

// Root node
$addNode('root:'.$root_node, 'root_domain', $root_node, ['project_id'=>$project_id]);

while ($row = $res->fetch_assoc()) {
  $ip = trim((string)($row['ip'] ?? ''));
  $port = (int)($row['port'] ?? 0);
  if ($ip === '' || $port <= 0) continue;

  $transport = strtolower(trim((string)($row['transport'] ?? 'tcp'))) ?: 'tcp';

  $product = trim((string)($row['product'] ?? ''));
  $version = trim((string)($row['version'] ?? ''));
  $org     = trim((string)($row['org'] ?? ''));
  $country = trim((string)($row['country'] ?? ''));
  $city    = trim((string)($row['city'] ?? ''));
  $vulns   = trim((string)($row['vulns'] ?? ''));

  // IP node
  $ipId = 'ip:'.$ip;
  $ipLabel = $ip;
  $addNode($ipId, 'ip_address', $ipLabel, [
    'org' => $org,
    'country' => $country,
    'city' => $city
  ]);
  $addLink('root:'.$root_node, $ipId, 'has_ip');

  // Service node
  $svcId = 'svc:'.$ip.':'.$port.'/'.$transport;
  $svcLabel = $ip.':'.$port.'/'.$transport;

  $svcMeta = trim($product.' '.$version);
  $addNode($svcId, 'service', $svcLabel, [
    'port' => $port,
    'transport' => $transport,
    'product' => $product,
    'version' => $version,
    'org' => $org,
    'country' => $country,
    'city' => $city,
    'meta' => $svcMeta,
    'vuln_count' => $vulns === '' ? 0 : count(array_filter(preg_split('/\s*,\s*/', $vulns) ?: [])),
    'has_vuln' => $vulns !== ''
  ]);
  $addLink($ipId, $svcId, 'open_port');

  // Vuln nodes
  if ($include_vulns && $vulns !== '') {
    $parts = preg_split('/\s*,\s*/', $vulns) ?: [];
    $parts = array_slice(array_values(array_filter($parts)), 0, 60); // safety
    foreach ($parts as $cve) {
      $cve = strtoupper(trim($cve));
      if ($cve === '') continue;

      $vId = 'vuln:'.$cve;
      $addNode($vId, 'vulnerability', $cve);
      $addLink($svcId, $vId, 'vuln');
    }
  }
}

api_json_exit(200, [
  'ok' => true,
  'project_id' => $project_id,
  'nodes' => $nodes,
  'links' => $links
]);
