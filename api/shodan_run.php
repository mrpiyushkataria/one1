<?php
/**
 * public_html/one.inseclabs.com/api/shodan_run.php
 * Start Shodan run(s) and return run_id(s).
 *
 * Upgrade (2026-02-05):
 * - Creates a corresponding record in oneinseclabs_recon_runs for each Shodan run.
 * - Persists the recon run id into oneinseclabs_shodan_runs.source_run_id (if the column exists)
 *   or into oneinseclabs_shodan_run_map (if the table exists).
 * - Fixes FK failures when inserting into oneinseclabs_hosts / oneinseclabs_ports.
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

csrf_check();

// -------------------- Input --------------------
$project_id  = (int)($_POST['project_id'] ?? 0);
$mode        = (string)($_POST['mode'] ?? 'search');      // search|host
$query       = trim((string)($_POST['query'] ?? ''));
$root_domain = trim((string)($_POST['root_domain'] ?? ''));
$max_results = (int)($_POST['max_results'] ?? 200);

$batch       = (int)($_POST['batch'] ?? 0);               // 1 => batch
$queries_text= (string)($_POST['queries_text'] ?? '');    // newline queries
$ip_list     = (string)($_POST['ip_list'] ?? '');

if ($project_id <= 0) api_json_exit(400, ['ok'=>false,'error'=>'project_id required']);
if ($max_results < 1) $max_results = 50;
if ($max_results > 1000) $max_results = 1000;

// API key
$api_key = shodan_get_api_key($conn, $uid);
if ($api_key === '') api_json_exit(400, ['ok'=>false,'error'=>'Shodan API key not set']);

// -------------------- Helpers --------------------
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

function create_recon_run(mysqli $conn, int $uid, int $project_id, string $root_domain, string $query, string $mode, int $max_results): int {
  if (!table_exists($conn, 'oneinseclabs_recon_runs')) return 0;

  $hasRunRoot  = col_exists($conn, 'oneinseclabs_recon_runs', 'root_domain');
  $hasTarget   = col_exists($conn, 'oneinseclabs_recon_runs', 'target_label');

  $tool_key  = 'shodan';
  $tool_name = 'Shodan';
  $category  = 'web';

  // Keep notes short & useful
  $notes = "mode={$mode}; max={$max_results}; q=" . $query;
  if (strlen($notes) > 2000) $notes = substr($notes, 0, 2000);

  $target_label = "Shodan: {$query}";

  if ($hasRunRoot && $hasTarget) {
    $st = $conn->prepare("INSERT INTO oneinseclabs_recon_runs (project_id, root_domain, target_label, tool_key, tool_name, category, notes, created_by)
                          VALUES (?,?,?,?,?,?,?,?)");
    $st->bind_param("issssssi", $project_id, $root_domain, $target_label, $tool_key, $tool_name, $category, $notes, $uid);
  } elseif ($hasRunRoot) {
    $st = $conn->prepare("INSERT INTO oneinseclabs_recon_runs (project_id, root_domain, tool_key, tool_name, category, notes, created_by)
                          VALUES (?,?,?,?,?,?,?)");
    $st->bind_param("isssssi", $project_id, $root_domain, $tool_key, $tool_name, $category, $notes, $uid);
  } else {
    $st = $conn->prepare("INSERT INTO oneinseclabs_recon_runs (project_id, tool_key, tool_name, category, notes, created_by)
                          VALUES (?,?,?,?,?,?)");
    $st->bind_param("issssi", $project_id, $tool_key, $tool_name, $category, $notes, $uid);
  }

  $st->execute();
  return (int)$conn->insert_id;
}

function persist_shodan_run_map(mysqli $conn, int $shodan_run_id, int $recon_run_id): void {
  if ($shodan_run_id <= 0 || $recon_run_id <= 0) return;

  if (col_exists($conn, 'oneinseclabs_shodan_runs', 'source_run_id')) {
    $st = $conn->prepare("UPDATE oneinseclabs_shodan_runs SET source_run_id=? WHERE id=?");
    $st->bind_param("ii", $recon_run_id, $shodan_run_id);
    $st->execute();
    return;
  }

  if (table_exists($conn, 'oneinseclabs_shodan_run_map')) {
    $st = $conn->prepare("INSERT INTO oneinseclabs_shodan_run_map (shodan_run_id, source_run_id)
                          VALUES (?,?)
                          ON DUPLICATE KEY UPDATE source_run_id=VALUES(source_run_id)");
    $st->bind_param("ii", $shodan_run_id, $recon_run_id);
    $st->execute();
  }
}

function create_search_run(mysqli $conn, int $uid, int $project_id, string $root_domain, string $query, int $max_results): int {
  // Compatible with both older and newer schemas
  $has_next = col_exists($conn, 'oneinseclabs_shodan_runs', 'next_page');
  $has_hb   = col_exists($conn, 'oneinseclabs_shodan_runs', 'last_heartbeat');

  if ($has_next && $has_hb) {
    $st = $conn->prepare("
      INSERT INTO oneinseclabs_shodan_runs
        (user_id, project_id, root_domain, mode, query, max_results, status, next_page, last_heartbeat)
      VALUES
        (?,?,?,?,?,?, 'running', 1, NOW())
    ");
    $mode = 'search';
    $st->bind_param("iisssi", $uid, $project_id, $root_domain, $mode, $query, $max_results);
    $st->execute();
    return (int)$conn->insert_id;
  }

  if ($has_next) {
    $st = $conn->prepare("
      INSERT INTO oneinseclabs_shodan_runs
        (user_id, project_id, root_domain, mode, query, max_results, status, next_page)
      VALUES
        (?,?,?,?,?,?, 'running', 1)
    ");
    $mode = 'search';
    $st->bind_param("iisssi", $uid, $project_id, $root_domain, $mode, $query, $max_results);
    $st->execute();
    return (int)$conn->insert_id;
  }

  // Fallback minimal schema
  $st = $conn->prepare("
    INSERT INTO oneinseclabs_shodan_runs
      (user_id, project_id, root_domain, mode, query, max_results, status)
    VALUES
      (?,?,?,?,?,?, 'running')
  ");
  $mode = 'search';
  $st->bind_param("iisssi", $uid, $project_id, $root_domain, $mode, $query, $max_results);
  $st->execute();
  return (int)$conn->insert_id;
}

function finish_run_ok(mysqli $conn, int $run_id, int $found, int $saved): void {
  $has_fin = col_exists($conn, 'oneinseclabs_shodan_runs', 'finished_at');
  if ($has_fin) {
    $st = $conn->prepare("UPDATE oneinseclabs_shodan_runs SET status='done', total_found=?, total_saved=?, finished_at=NOW() WHERE id=?");
    $st->bind_param("iii", $found, $saved, $run_id);
    $st->execute();
    return;
  }
  $st = $conn->prepare("UPDATE oneinseclabs_shodan_runs SET status='done', total_found=?, total_saved=? WHERE id=?");
  $st->bind_param("iii", $found, $saved, $run_id);
  $st->execute();
}

// -------------------- HOST MODE (immediate) --------------------
if ($mode === 'host') {
  $shodan_run_id = create_search_run($conn, $uid, $project_id, $root_domain, 'host_lookup', $max_results);
  $recon_run_id  = create_recon_run($conn, $uid, $project_id, $root_domain, 'host_lookup', 'host', $max_results);
  persist_shodan_run_map($conn, $shodan_run_id, $recon_run_id);

  $ips = preg_split("/\r\n|\n|\r/", $ip_list) ?: [];
  $ips = array_values(array_unique(array_filter(array_map('trim', $ips))));
  $ips = array_slice($ips, 0, 50); // safety limit

  $found = 0;
  $saved = 0;

  foreach ($ips as $ip) {
    $res = shodan_host($api_key, $ip);
    if (!$res['ok'] || !is_array($res['json'])) continue;
    $found++;
  }

  finish_run_ok($conn, $shodan_run_id, $found, $saved);
  api_json_exit(200, ['ok'=>true, 'mode'=>'host', 'run_id'=>$shodan_run_id, 'source_run_id'=>$recon_run_id, 'total_found'=>$found, 'total_saved'=>$saved]);
}

// -------------------- SEARCH MODE (start run(s) only) --------------------
$queries = [];

if ($batch === 1) {
  $lines = preg_split("/\r\n|\n|\r/", (string)$queries_text);
  foreach ($lines as $ln) {
    $q = trim((string)$ln);
    if ($q !== '') $queries[] = $q;
  }
  $queries = array_values(array_unique($queries));
  $queries = array_slice($queries, 0, 10); // safety
  if (!$queries) api_json_exit(400, ['ok'=>false,'error'=>'No queries in batch']);
} else {
  if ($query === '') api_json_exit(400, ['ok'=>false,'error'=>'Query empty']);
  $queries = [$query];
}

$items = [];
foreach ($queries as $q) {
  $shodan_run_id = create_search_run($conn, $uid, $project_id, $root_domain, $q, $max_results);
  $recon_run_id  = create_recon_run($conn, $uid, $project_id, $root_domain, $q, 'search', $max_results);
  persist_shodan_run_map($conn, $shodan_run_id, $recon_run_id);

  $items[] = [
    'run_id'        => $shodan_run_id,
    'source_run_id' => $recon_run_id,
    'query'         => $q,
    'status'        => 'running'
  ];
}

if ($batch === 1) {
  api_json_exit(200, ['ok'=>true, 'mode'=>'search', 'batch'=>true, 'items'=>$items]);
}

api_json_exit(200, [
  'ok'=>true,
  'mode'=>'search',
  'batch'=>false,
  'run_id'=>$items[0]['run_id'],
  'source_run_id'=>$items[0]['source_run_id'],
  'status'=>'running'
]);
