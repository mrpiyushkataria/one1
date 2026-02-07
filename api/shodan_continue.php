<?php
/**
 * public_html/one.inseclabs.com/api/shodan_continue.php
 *
 * FIXES:
 * 1) STRICT ROOT FILTER:
 *    - Saves only hostnames/domains that are exactly root OR end with .root
 *    - If match doesn't contain any root/subdomain => SKIP saving completely
 *
 * 2) FK SAFETY:
 *    - Writes source_run_id only when recon_run_id > 0
 *
 * 3) Services store filtered hostnames/domains only
 */

declare(strict_types=1);
if (!defined('ONEINSECLABS_API')) define('ONEINSECLABS_API', true);

ini_set('display_errors', '0');
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
  api_json_exit(500, ['ok'=>false, 'error'=>"PHP: $message in $file:$line"]);
});
set_exception_handler(function(Throwable $e){
  api_json_exit(500, ['ok'=>false, 'error'=>"EX: ".$e->getMessage()]);
});

require_once __DIR__ . '/../includes/header.php';
require_once __DIR__ . '/../includes/shodan_lib.php';

if (ob_get_length()) ob_clean();

$conn = db();
$uid  = (int)current_user_id();
if ($uid <= 0) api_json_exit(401, ['ok'=>false,'error'=>'unauthorized']);

if ($_SERVER['REQUEST_METHOD'] === 'GET' || $_SERVER['REQUEST_METHOD'] === 'HEAD') {
  api_json_exit(200, ['ok'=>true, 'ping'=>true]);
}
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
  api_json_exit(200, ['ok'=>true]);
}

csrf_check();

$run_id = (int)($_POST['run_id'] ?? 0);
$step_pages = (int)($_POST['step_pages'] ?? 1);
if ($step_pages < 1) $step_pages = 1;
if ($step_pages > 3) $step_pages = 3;

if ($run_id <= 0) api_json_exit(400, ['ok'=>false,'error'=>'run_id required']);

// -------------------- Schema helpers --------------------
function table_exists(mysqli $conn, string $table): bool {
  $t = $conn->real_escape_string($table);
  $rs = $conn->query("SHOW TABLES LIKE '{$t}'");
  return $rs && $rs->num_rows > 0;
}
function col_exists(mysqli $conn, string $table, string $col): bool {
  $t = $conn->real_escape_string($table);
  $c = $conn->real_escape_string($col);
  $rs = $conn->query("SHOW COLUMNS FROM `{$t}` LIKE '{$c}'");
  return $rs && $rs->num_rows > 0;
}

// -------------------- Root filter helpers --------------------
function norm_host_str(string $h): string {
  $h = strtolower(trim($h));
  $h = preg_replace('#^https?://#','',$h);
  $h = preg_replace('#/.*$#','',$h);
  $h = preg_replace('/:\d+$/','',$h);
  $h = rtrim($h,'.');
  // remove leading wildcard.
  $h = preg_replace('/^\*\./','',$h);
  return $h;
}
function host_in_root(string $host, string $root): bool {
  $host = norm_host_str($host);
  $root = norm_host_str($root);
  if ($host === '' || $root === '') return false;
  if ($host === $root) return true;
  return str_ends_with($host, '.' . $root);
}
function filter_hosts_for_root(array $hosts, string $root): array {
  $out = [];
  foreach ($hosts as $h) {
    if (!is_string($h)) continue;
    $hh = norm_host_str($h);
    if ($hh !== '' && host_in_root($hh, $root)) $out[] = $hh;
  }
  $out = array_values(array_unique($out));
  return $out;
}

// -------------------- Load shodan run --------------------
$st = $conn->prepare("SELECT * FROM oneinseclabs_shodan_runs WHERE id=? AND user_id=? LIMIT 1");
$st->bind_param("ii", $run_id, $uid);
$st->execute();
$run = $st->get_result()->fetch_assoc();
if (!$run) api_json_exit(404, ['ok'=>false,'error'=>'run not found']);
if (($run['status'] ?? '') !== 'running') {
  api_json_exit(200, ['ok'=>true, 'status'=>$run['status'], 'message'=>'not running']);
}

$project_id = (int)$run['project_id'];
$query      = (string)$run['query'];
$max_results= (int)$run['max_results'];
$next_page  = (int)($run['next_page'] ?? 1);

// ✅ IMPORTANT: strict root is taken from the run
$root = norm_host_str((string)($run['root_domain'] ?? ''));
// If you want to force root always:
if ($root === '') {
  api_json_exit(400, ['ok'=>false, 'error'=>'root_domain is empty for this run. Select a root domain.']);
}

$api_key = shodan_get_api_key($conn, $uid);
if ($api_key === '') api_json_exit(400, ['ok'=>false,'error'=>'Shodan API key not set']);

// -------------------- Get/ensure recon_run_id (source_run_id) --------------------
$recon_run_id = 0;
if (isset($run['source_run_id'])) $recon_run_id = (int)$run['source_run_id'];

if ($recon_run_id <= 0 && table_exists($conn, 'oneinseclabs_shodan_run_map')) {
  $m = $conn->prepare("SELECT source_run_id FROM oneinseclabs_shodan_run_map WHERE shodan_run_id=? LIMIT 1");
  $m->bind_param("i", $run_id);
  $m->execute();
  $recon_run_id = (int)($m->get_result()->fetch_assoc()['source_run_id'] ?? 0);
}

// Create recon run if missing
if ($recon_run_id <= 0 && table_exists($conn, 'oneinseclabs_recon_runs')) {
  $hasRunRoot  = col_exists($conn, 'oneinseclabs_recon_runs', 'root_domain');
  $hasTarget   = col_exists($conn, 'oneinseclabs_recon_runs', 'target_label');

  $tool_key = 'shodan';
  $tool_name = 'Shodan';
  $category = 'web';
  $notes = 'Auto-created for Shodan run #'.$run_id.' | query: '.$query;

  if ($hasRunRoot && $hasTarget) {
    $target = 'Shodan query';
    $stx = $conn->prepare("INSERT INTO oneinseclabs_recon_runs (project_id, root_domain, target_label, tool_key, tool_name, category, notes, created_by)
                           VALUES (?,?,?,?,?,?,?,?)");
    $stx->bind_param("issssssi", $project_id, $root, $target, $tool_key, $tool_name, $category, $notes, $uid);
  } elseif ($hasRunRoot) {
    $stx = $conn->prepare("INSERT INTO oneinseclabs_recon_runs (project_id, root_domain, tool_key, tool_name, category, notes, created_by)
                           VALUES (?,?,?,?,?,?,?)");
    $stx->bind_param("isssssi", $project_id, $root, $tool_key, $tool_name, $category, $notes, $uid);
  } else {
    $stx = $conn->prepare("INSERT INTO oneinseclabs_recon_runs (project_id, tool_key, tool_name, category, notes, created_by)
                           VALUES (?,?,?,?,?,?)");
    $stx->bind_param("issssi", $project_id, $tool_key, $tool_name, $category, $notes, $uid);
  }
  $stx->execute();
  $recon_run_id = (int)$conn->insert_id;

  // persist
  if (col_exists($conn, 'oneinseclabs_shodan_runs', 'source_run_id')) {
    $u = $conn->prepare("UPDATE oneinseclabs_shodan_runs SET source_run_id=? WHERE id=?");
    $u->bind_param("ii", $recon_run_id, $run_id);
    $u->execute();
  } elseif (table_exists($conn, 'oneinseclabs_shodan_run_map')) {
    $u = $conn->prepare("INSERT INTO oneinseclabs_shodan_run_map (shodan_run_id, source_run_id) VALUES (?,?)");
    $u->bind_param("ii", $run_id, $recon_run_id);
    @$u->execute();
  }
}

// -------------------- Table/column availability --------------------
$have_hosts    = table_exists($conn, 'oneinseclabs_hosts');
$have_ports    = table_exists($conn, 'oneinseclabs_ports');
$have_services = table_exists($conn, 'oneinseclabs_shodan_services');

$hosts_has_ip      = $have_hosts && col_exists($conn, 'oneinseclabs_hosts', 'ip');
$hosts_has_ip_addr = $have_hosts && col_exists($conn, 'oneinseclabs_hosts', 'ip_address');
$hosts_has_source  = $have_hosts && col_exists($conn, 'oneinseclabs_hosts', 'source_run_id');

$ports_has_service_name = $have_ports && col_exists($conn, 'oneinseclabs_ports', 'service_name');
$ports_has_service      = $have_ports && col_exists($conn, 'oneinseclabs_ports', 'service');
$ports_has_source       = $have_ports && col_exists($conn, 'oneinseclabs_ports', 'source_run_id');

// -------------------- Upserts --------------------
function upsert_host(mysqli $conn, int $project_id, string $ip, string $hostname, int $source_run_id,
  bool $has_ip, bool $has_ip_address, bool $use_source): int {

  $ip = trim($ip);
  if ($ip === '') return 0;
  $hostname = trim($hostname);

  $cols = ['project_id'];
  $vals = ['?'];
  $types = 'i';
  $params = [$project_id];

  if ($has_ip) { $cols[] = 'ip'; $vals[] = '?'; $types .= 's'; $params[] = $ip; }
  if ($has_ip_address) { $cols[] = 'ip_address'; $vals[] = '?'; $types .= 's'; $params[] = $ip; }

  $cols[] = 'hostname'; $vals[]='?'; $types .= 's'; $params[] = $hostname;

  if (col_exists($conn,'oneinseclabs_hosts','first_seen')) {
    $cols[]='first_seen';
    $vals[]='NOW()';
  }

  if ($use_source) {
    $cols[]='source_run_id';
    $vals[]='?';
    $types .= 'i';
    $params[] = $source_run_id;
  }

  $sql = "INSERT INTO oneinseclabs_hosts (".implode(',',$cols).") VALUES (".implode(',',$vals).")";
  $updates = [];
  if ($hostname !== '') $updates[] = "hostname=IF(VALUES(hostname)='', hostname, VALUES(hostname))";
  if ($use_source) $updates[] = "source_run_id=VALUES(source_run_id)";
  $sql .= " ON DUPLICATE KEY UPDATE ".implode(',', $updates ?: ['hostname=hostname']);

  $st = $conn->prepare($sql);
  $st->bind_param($types, ...$params);
  @$st->execute();

  $id = (int)$conn->insert_id;
  if ($id > 0) return $id;

  if ($has_ip_address) {
    $st2 = $conn->prepare("SELECT id FROM oneinseclabs_hosts WHERE project_id=? AND ip_address=? LIMIT 1");
  } else {
    $st2 = $conn->prepare("SELECT id FROM oneinseclabs_hosts WHERE project_id=? AND ip=? LIMIT 1");
  }
  $st2->bind_param("is", $project_id, $ip);
  $st2->execute();
  $row = $st2->get_result()->fetch_assoc();
  return (int)($row['id'] ?? 0);
}

function upsert_port(mysqli $conn, int $project_id, int $host_id, int $port, string $protocol, string $service,
  string $product, string $version, int $source_run_id,
  bool $ports_has_service, bool $ports_has_service_name, bool $use_source): void {

  if ($project_id<=0 || $host_id<=0 || $port<=0) return;

  $protocol = strtolower(trim($protocol ?: 'tcp'));
  $service  = trim($service);
  $product  = trim($product);
  $version  = trim($version);

  $svc_col = $ports_has_service ? 'service' : ($ports_has_service_name ? 'service_name' : 'service');

  $cols = ['project_id','host_id','port','protocol','state',$svc_col,'product','version','extrainfo'];
  $vals = ['?','?','?','?','open','?','?','?',''];
  $types = 'iiissss';
  $params = [$project_id, $host_id, $port, $protocol, $service, $product, $version];

  if ($use_source) {
    $cols[] = 'source_run_id';
    $vals[] = '?';
    $types .= 'i';
    $params[] = $source_run_id;
  }
  if (col_exists($conn,'oneinseclabs_ports','created_at')) {
    $cols[] = 'created_at';
    $vals[] = 'NOW()';
  }

  $sql = "INSERT INTO oneinseclabs_ports (".implode(',',$cols).") VALUES (".implode(',',$vals).")\n";
  $sql .= "ON DUPLICATE KEY UPDATE\n";
  $sql .= "$svc_col=IF(VALUES($svc_col)='', $svc_col, VALUES($svc_col)),\n";
  $sql .= "product=IF(VALUES(product)='', product, VALUES(product)),\n";
  $sql .= "version=IF(VALUES(version)='', version, VALUES(version))";
  if ($use_source) $sql .= ", source_run_id=VALUES(source_run_id)";

  $st = $conn->prepare($sql);
  $st->bind_param($types, ...$params);
  @$st->execute();
}

function save_service(mysqli $conn, int $run_id, int $project_id, array $row): int {
  $ip = '';
  if (!empty($row['ip_str'])) $ip = (string)$row['ip_str'];
  elseif (!empty($row['ip'])) $ip = is_numeric($row['ip']) ? long2ip((int)$row['ip']) : (string)$row['ip'];
  $ip = trim($ip);

  $port = (int)($row['port'] ?? 0);
  if ($ip === '' || $port <= 0) return 0;

  $transport = (string)($row['transport'] ?? 'tcp');

  // ✅ store ONLY filtered hosts/domains
  $filtered = $row['_oneinseclabs_filtered_hosts'] ?? null;
  if (is_array($filtered) && count($filtered) > 0) {
    $hostnames = implode(", ", $filtered);
    $domains = $hostnames;
  } else {
    $hostnames = (!empty($row['hostnames']) && is_array($row['hostnames'])) ? implode(", ", $row['hostnames']) : '';
    $domains   = (!empty($row['domains']) && is_array($row['domains'])) ? implode(", ", $row['domains']) : '';
  }

  $org     = (string)($row['org'] ?? '');
  $isp     = (string)($row['isp'] ?? '');
  $asn     = (string)($row['asn'] ?? '');
  $country = (string)($row['location']['country_name'] ?? '');
  $city    = (string)($row['location']['city'] ?? '');

  $product = (string)($row['product'] ?? '');
  $version = (string)($row['version'] ?? '');
  $banner  = isset($row['data']) ? (string)$row['data'] : '';

  $ssl_cn     = (string)($row['ssl']['cert']['subject']['CN'] ?? '');
  $ssl_issuer = (string)($row['ssl']['cert']['issuer']['CN'] ?? '');

  $vulns = '';
  if (!empty($row['vulns']) && is_array($row['vulns'])) $vulns = implode(", ", array_keys($row['vulns']));

  $first_seen = isset($row['timestamp']) ? date('Y-m-d H:i:s', strtotime((string)$row['timestamp'])) : null;
  $last_seen  = $first_seen;

  $raw_json = json_encode($row, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

  $st = $conn->prepare("
    INSERT INTO oneinseclabs_shodan_services
      (run_id, project_id, ip, port, transport, hostnames, domains, org, isp, asn, country, city,
       product, version, banner, ssl_cn, ssl_issuer, vulns, raw_json, first_seen, last_seen, created_at, updated_at)
    VALUES
      (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?, NOW(), NOW())
    ON DUPLICATE KEY UPDATE
      run_id=VALUES(run_id),
      hostnames=VALUES(hostnames),
      domains=VALUES(domains),
      org=VALUES(org),
      isp=VALUES(isp),
      asn=VALUES(asn),
      country=VALUES(country),
      city=VALUES(city),
      product=VALUES(product),
      version=VALUES(version),
      banner=VALUES(banner),
      ssl_cn=VALUES(ssl_cn),
      ssl_issuer=VALUES(ssl_issuer),
      vulns=VALUES(vulns),
      raw_json=VALUES(raw_json),
      last_seen=VALUES(last_seen),
      updated_at=NOW()
  ");

  $st->bind_param(
    "iisisssssssssssssssss",
    $run_id, $project_id, $ip, $port, $transport, $hostnames, $domains, $org, $isp, $asn,
    $country, $city, $product, $version, $banner, $ssl_cn, $ssl_issuer, $vulns, $raw_json, $first_seen, $last_seen
  );
  $st->execute();

  $sid = (int)$conn->insert_id;
  if ($sid > 0) return $sid;

  $st2 = $conn->prepare("SELECT id FROM oneinseclabs_shodan_services WHERE project_id=? AND ip=? AND port=? AND transport=? LIMIT 1");
  $st2->bind_param("isis", $project_id, $ip, $port, $transport);
  $st2->execute();
  $row2 = $st2->get_result()->fetch_assoc();
  return (int)($row2['id'] ?? 0);
}

function save_vulns(mysqli $conn, int $project_id, int $service_id, array $row): int {
  if ($service_id <= 0) return 0;
  if (empty($row['vulns']) || !is_array($row['vulns'])) return 0;
  $rs = $conn->query("SHOW TABLES LIKE 'oneinseclabs_shodan_service_vulns'");
  if (!$rs || $rs->num_rows === 0) return 0;

  $count = 0;
  $st = $conn->prepare("
    INSERT INTO oneinseclabs_shodan_service_vulns (project_id, service_id, vuln_id, verified)
    VALUES (?,?,?,?)
    ON DUPLICATE KEY UPDATE verified=VALUES(verified)
  ");

  foreach ($row['vulns'] as $vulnId => $vdata) {
    $vid = strtoupper(trim((string)$vulnId));
    if ($vid === '') continue;
    $verified = 0;
    if (is_array($vdata) && isset($vdata['verified'])) $verified = (int)((bool)$vdata['verified']);
    $st->bind_param("iisi", $project_id, $service_id, $vid, $verified);
    $st->execute();
    $count++;
  }
  return $count;
}

// -------------------- Fetch pages --------------------
$total_saved = 0;
$total_vulns = 0;
$total_found = (int)($run['total_found'] ?? 0);

for ($i=0; $i<$step_pages; $i++) {
  if ($total_saved >= $max_results) break;

  $res = shodan_search($api_key, $query, $next_page);

  if (!$res['ok'] && (int)($res['code'] ?? 0) === 429) {
    $hb = col_exists($conn,'oneinseclabs_shodan_runs','last_heartbeat') ? ", last_heartbeat=NOW()" : "";
    $conn->query("UPDATE oneinseclabs_shodan_runs SET status='error', error_text='Rate limited (429). Try again later.'$hb WHERE id=".(int)$run_id);
    api_json_exit(200, ['ok'=>true, 'status'=>'error', 'error'=>'rate_limited']);
  }

  if (!$res['ok'] || !is_array($res['json'])) break;

  $json = $res['json'];
  $total_found = (int)($json['total'] ?? $total_found);

  $matches = $json['matches'] ?? [];
  if (!is_array($matches) || count($matches) === 0) break;

  foreach ($matches as $m) {
    if (!is_array($m)) continue;
    if ((int)($run['total_saved'] ?? 0) + $total_saved >= $max_results) break;

    // ---- Extract IP ----
    $ip = '';
    if (!empty($m['ip_str'])) $ip = (string)$m['ip_str'];
    elseif (!empty($m['ip'])) $ip = is_numeric($m['ip']) ? long2ip((int)$m['ip']) : (string)$m['ip'];
    $ip = trim($ip);

    // ---- Collect candidate hostnames/domains/CN ----
    $hlist = [];
    if (!empty($m['hostnames']) && is_array($m['hostnames'])) $hlist = array_merge($hlist, $m['hostnames']);
    if (!empty($m['domains']) && is_array($m['domains'])) $hlist = array_merge($hlist, $m['domains']);
    $cn = (string)($m['ssl']['cert']['subject']['CN'] ?? '');
    if ($cn !== '') $hlist[] = $cn;

    // ✅ STRICT FILTER: if none matches selected root -> SKIP saving
    $filtered_hosts = filter_hosts_for_root($hlist, $root);
    if (count($filtered_hosts) === 0) {
      continue;
    }

    // ✅ Save service with filtered hostnames only
    $service_id = 0;
    if ($have_services) {
      $m['_oneinseclabs_filtered_hosts'] = $filtered_hosts;
      $service_id = save_service($conn, $run_id, $project_id, $m);
    }

    $total_saved++;
    $total_vulns += ($have_services ? save_vulns($conn, $project_id, $service_id, $m) : 0);

    // ✅ Save host + ports only for in-scope root
    if ($have_hosts && $ip !== '') {
      $hostname_best = $filtered_hosts[0] ?? '';

      $host_id = upsert_host(
        $conn,
        $project_id,
        $ip,
        $hostname_best,
        $recon_run_id,
        $hosts_has_ip,
        $hosts_has_ip_addr,
        ($hosts_has_source && $recon_run_id > 0)
      );

      if ($have_ports && $host_id > 0) {
        $port = (int)($m['port'] ?? 0);
        $proto = (string)($m['transport'] ?? 'tcp');
        $service = (string)($m['_shodan']['module'] ?? '');
        $product = (string)($m['product'] ?? '');
        $version = (string)($m['version'] ?? '');
        if ($service === '') $service = $product;

        upsert_port(
          $conn,
          $project_id,
          $host_id,
          $port,
          $proto,
          $service,
          $product,
          $version,
          $recon_run_id,
          $ports_has_service,
          $ports_has_service_name,
          ($ports_has_source && $recon_run_id > 0)
        );
      }
    }
  }

  $next_page++;
  if ($next_page > 50) break;
}

// Update run progress
$hb = col_exists($conn,'oneinseclabs_shodan_runs','last_heartbeat') ? ', last_heartbeat=NOW()' : '';
$conn->query("
  UPDATE oneinseclabs_shodan_runs
  SET total_found=".(int)$total_found.",
      total_saved=COALESCE(total_saved,0) + ".(int)$total_saved.",
      next_page=".(int)$next_page.",
      updated_at=NOW()$hb
  WHERE id=".(int)$run_id."
");

// Determine done
$st = $conn->prepare("SELECT total_saved, max_results FROM oneinseclabs_shodan_runs WHERE id=?");
$st->bind_param("i", $run_id);
$st->execute();
$rr = $st->get_result()->fetch_assoc();

$done = false;
if ($rr) {
  $saved_now = (int)$rr['total_saved'];
  $maxr = (int)$rr['max_results'];
  if ($saved_now >= $maxr) $done = true;
}

if ($done) {
  $fin = col_exists($conn,'oneinseclabs_shodan_runs','finished_at') ? ', finished_at=NOW()' : '';
  $conn->query("UPDATE oneinseclabs_shodan_runs SET status='done'$fin WHERE id=".(int)$run_id);
  api_json_exit(200, ['ok'=>true, 'status'=>'done', 'saved'=>$total_saved, 'vulns'=>$total_vulns, 'total_found'=>$total_found]);
}

api_json_exit(200, [
  'ok'=>true,
  'status'=>'running',
  'saved'=>$total_saved,
  'vulns'=>$total_vulns,
  'total_found'=>$total_found,
  'next_page'=>$next_page,
  'source_run_id'=>$recon_run_id,
  'root'=>$root
]);
