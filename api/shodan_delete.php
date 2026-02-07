<?php
/**
 * public_html/one.inseclabs.com/api/shodan_delete.php
 *
 * Deletes a Shodan run AND its related stored results:
 * - oneinseclabs_shodan_findings (by run->services or run_id if present)
 * - oneinseclabs_shodan_service_vulns
 * - oneinseclabs_shodan_services
 * - oneinseclabs_shodan_run_map (if exists)
 * - oneinseclabs_shodan_runs
 *
 * Optional:
 * - delete_assets=1 will ALSO delete ports/hosts that were inserted with source_run_id = recon_run_id
 *   (ports first, then hosts). This only affects rows having source_run_id == recon_run_id.
 *
 * Security:
 * - Requires logged-in user
 * - Requires CSRF token
 * - Only the owner (user_id) can delete their shodan run
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

if (ob_get_length()) ob_clean();

$conn = db();
$uid  = (int)current_user_id();
if ($uid <= 0) api_json_exit(401, ['ok'=>false, 'error'=>'unauthorized']);

if ($_SERVER['REQUEST_METHOD'] === 'GET' || $_SERVER['REQUEST_METHOD'] === 'HEAD') {
  api_json_exit(200, ['ok'=>true, 'ping'=>true]);
}
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
  api_json_exit(405, ['ok'=>false, 'error'=>'POST only']);
}

csrf_check();

$shodan_run_id = (int)($_POST['shodan_run_id'] ?? 0);
$delete_assets = (int)($_POST['delete_assets'] ?? 0);

if ($shodan_run_id <= 0) api_json_exit(400, ['ok'=>false, 'error'=>'shodan_run_id required']);

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

$have_run_map   = table_exists($conn, 'oneinseclabs_shodan_run_map');
$have_services  = table_exists($conn, 'oneinseclabs_shodan_services');
$have_findings  = table_exists($conn, 'oneinseclabs_shodan_findings');
$have_vulns     = table_exists($conn, 'oneinseclabs_shodan_service_vulns');
$have_hosts     = table_exists($conn, 'oneinseclabs_hosts');
$have_ports     = table_exists($conn, 'oneinseclabs_ports');

$st = $conn->prepare("SELECT * FROM oneinseclabs_shodan_runs WHERE id=? LIMIT 1");
$st->bind_param("i", $shodan_run_id);
$st->execute();
$run = $st->get_result()->fetch_assoc();
if (!$run) api_json_exit(404, ['ok'=>false, 'error'=>'shodan run not found']);

// Ownership check
if ((int)($run['user_id'] ?? 0) !== $uid) {
  api_json_exit(403, ['ok'=>false, 'error'=>'forbidden']);
}

$project_id  = (int)($run['project_id'] ?? 0);

// Determine recon_run_id / source_run_id for optional host/port cleanup
$recon_run_id = 0;
if (isset($run['source_run_id'])) $recon_run_id = (int)$run['source_run_id'];

if ($recon_run_id <= 0 && $have_run_map) {
  $m = $conn->prepare("SELECT source_run_id FROM oneinseclabs_shodan_run_map WHERE shodan_run_id=? LIMIT 1");
  $m->bind_param("i", $shodan_run_id);
  $m->execute();
  $recon_run_id = (int)($m->get_result()->fetch_assoc()['source_run_id'] ?? 0);
}

$conn->begin_transaction();

try {
  $deleted = [
    'findings' => 0,
    'service_vulns' => 0,
    'services' => 0,
    'ports' => 0,
    'hosts' => 0,
    'run_map' => 0,
    'shodan_run' => 0
  ];

  // 1) Delete findings (best: by service_ids from this run)
  $service_ids = [];
  if ($have_services) {
    $q = $conn->prepare("SELECT id FROM oneinseclabs_shodan_services WHERE run_id=?");
    $q->bind_param("i", $shodan_run_id);
    $q->execute();
    $rs = $q->get_result();
    while ($r = $rs->fetch_assoc()) $service_ids[] = (int)$r['id'];
  }

  if ($have_findings && count($service_ids) > 0) {
    // delete findings by service_id IN (...)
    $chunks = array_chunk($service_ids, 500);
    foreach ($chunks as $chunk) {
      $placeholders = implode(',', array_fill(0, count($chunk), '?'));
      $types = str_repeat('i', count($chunk));
      $sql = "DELETE FROM oneinseclabs_shodan_findings WHERE service_id IN ($placeholders)";
      $stmt = $conn->prepare($sql);
      $stmt->bind_param($types, ...$chunk);
      $stmt->execute();
      $deleted['findings'] += $stmt->affected_rows;
    }
  } elseif ($have_findings && col_exists($conn, 'oneinseclabs_shodan_findings', 'run_id')) {
    // fallback if your findings table has run_id
    $stmt = $conn->prepare("DELETE FROM oneinseclabs_shodan_findings WHERE run_id=?");
    $stmt->bind_param("i", $shodan_run_id);
    $stmt->execute();
    $deleted['findings'] = $stmt->affected_rows;
  }

  // 2) Delete vulns for services of this run
  if ($have_vulns && count($service_ids) > 0) {
    $chunks = array_chunk($service_ids, 500);
    foreach ($chunks as $chunk) {
      $placeholders = implode(',', array_fill(0, count($chunk), '?'));
      $types = str_repeat('i', count($chunk));
      $sql = "DELETE FROM oneinseclabs_shodan_service_vulns WHERE service_id IN ($placeholders)";
      $stmt = $conn->prepare($sql);
      $stmt->bind_param($types, ...$chunk);
      $stmt->execute();
      $deleted['service_vulns'] += $stmt->affected_rows;
    }
  }

  // 3) Delete services of this run
  if ($have_services) {
    $stmt = $conn->prepare("DELETE FROM oneinseclabs_shodan_services WHERE run_id=?");
    $stmt->bind_param("i", $shodan_run_id);
    $stmt->execute();
    $deleted['services'] = $stmt->affected_rows;
  }

  // 4) Optional: delete ports/hosts inserted by this shodan's recon_run_id (source_run_id)
  if ($delete_assets === 1 && $recon_run_id > 0) {
    // delete ports first (FK to hosts)
    if ($have_ports && col_exists($conn, 'oneinseclabs_ports', 'source_run_id')) {
      $stmt = $conn->prepare("DELETE FROM oneinseclabs_ports WHERE project_id=? AND source_run_id=?");
      $stmt->bind_param("ii", $project_id, $recon_run_id);
      $stmt->execute();
      $deleted['ports'] = $stmt->affected_rows;
    }
    if ($have_hosts && col_exists($conn, 'oneinseclabs_hosts', 'source_run_id')) {
      $stmt = $conn->prepare("DELETE FROM oneinseclabs_hosts WHERE project_id=? AND source_run_id=?");
      $stmt->bind_param("ii", $project_id, $recon_run_id);
      $stmt->execute();
      $deleted['hosts'] = $stmt->affected_rows;
    }
  }

  // 5) Delete run map (if exists)
  if ($have_run_map) {
    $stmt = $conn->prepare("DELETE FROM oneinseclabs_shodan_run_map WHERE shodan_run_id=?");
    $stmt->bind_param("i", $shodan_run_id);
    $stmt->execute();
    $deleted['run_map'] = $stmt->affected_rows;
  }

  // 6) Delete shodan run
  $stmt = $conn->prepare("DELETE FROM oneinseclabs_shodan_runs WHERE id=? AND user_id=?");
  $stmt->bind_param("ii", $shodan_run_id, $uid);
  $stmt->execute();
  $deleted['shodan_run'] = $stmt->affected_rows;

  $conn->commit();

  api_json_exit(200, [
    'ok' => true,
    'deleted' => $deleted,
    'shodan_run_id' => $shodan_run_id,
    'source_run_id' => $recon_run_id,
    'delete_assets' => ($delete_assets === 1)
  ]);

} catch (Throwable $e) {
  $conn->rollback();
  api_json_exit(500, ['ok'=>false, 'error'=>$e->getMessage()]);
}
