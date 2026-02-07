<?php
/**
 * public_html/one.inseclabs.com/api/shodan_delete_project.php
 *
 * Deletes ALL Shodan data for a project:
 * - oneinseclabs_shodan_findings (via service_ids, or run_id if exists)
 * - oneinseclabs_shodan_service_vulns
 * - oneinseclabs_shodan_services
 * - oneinseclabs_shodan_run_map
 * - oneinseclabs_shodan_runs
 *
 * Optional:
 * - delete_assets=1 also deletes:
 *   - oneinseclabs_ports where (project_id = ?) AND (source_run_id IN recon_run_ids)
 *   - oneinseclabs_hosts where (project_id = ?) AND (source_run_id IN recon_run_ids)
 *
 * Security:
 * - requires logged-in user
 * - requires CSRF
 * - requires access: project.created_by == current user OR user.role == 'admin'
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

set_exception_handler(function(Throwable $e){
  api_json_exit(500, ['ok'=>false, 'error'=>$e->getMessage()]);
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

$project_id    = (int)($_POST['project_id'] ?? 0);
$delete_assets = (int)($_POST['delete_assets'] ?? 0);

if ($project_id <= 0) api_json_exit(400, ['ok'=>false, 'error'=>'project_id required']);

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

$has_runs      = table_exists($conn, 'oneinseclabs_shodan_runs');
$has_services  = table_exists($conn, 'oneinseclabs_shodan_services');
$has_findings  = table_exists($conn, 'oneinseclabs_shodan_findings');
$has_vulns     = table_exists($conn, 'oneinseclabs_shodan_service_vulns');
$has_run_map   = table_exists($conn, 'oneinseclabs_shodan_run_map');
$has_hosts     = table_exists($conn, 'oneinseclabs_hosts');
$has_ports     = table_exists($conn, 'oneinseclabs_ports');

if (!$has_runs) api_json_exit(200, ['ok'=>true, 'deleted'=>[], 'note'=>'no shodan tables found']);

# --- Authorization: project owner OR admin role ---
$st = $conn->prepare("SELECT id, created_by FROM oneinseclabs_projects WHERE id=? LIMIT 1");
$st->bind_param("i", $project_id);
$st->execute();
$proj = $st->get_result()->fetch_assoc();
if (!$proj) api_json_exit(404, ['ok'=>false, 'error'=>'project not found']);

$is_admin = false;
$ru = $conn->prepare("SELECT role FROM oneinseclabs_users WHERE id=? LIMIT 1");
$ru->bind_param("i", $uid);
$ru->execute();
$ur = $ru->get_result()->fetch_assoc();
if ($ur && ($ur['role'] ?? '') === 'admin') $is_admin = true;

if (!$is_admin && (int)($proj['created_by'] ?? 0) !== $uid) {
  api_json_exit(403, ['ok'=>false, 'error'=>'forbidden']);
}

# --- Collect all shodan_run_ids for project ---
$run_ids = [];
$recon_run_ids = []; // source_run_id values for optional assets cleanup

$st = $conn->prepare("SELECT id, source_run_id FROM oneinseclabs_shodan_runs WHERE project_id=?");
$st->bind_param("i", $project_id);
$st->execute();
$rs = $st->get_result();
while ($r = $rs->fetch_assoc()) {
  $run_ids[] = (int)$r['id'];
  if (isset($r['source_run_id']) && (int)$r['source_run_id'] > 0) $recon_run_ids[] = (int)$r['source_run_id'];
}

# If run_map exists, also collect source_run_id from there
if ($has_run_map && count($run_ids) > 0) {
  $chunks = array_chunk($run_ids, 500);
  foreach ($chunks as $chunk) {
    $placeholders = implode(',', array_fill(0, count($chunk), '?'));
    $types = str_repeat('i', count($chunk));
    $sql = "SELECT source_run_id FROM oneinseclabs_shodan_run_map WHERE shodan_run_id IN ($placeholders)";
    $q = $conn->prepare($sql);
    $q->bind_param($types, ...$chunk);
    $q->execute();
    $rr = $q->get_result();
    while ($row = $rr->fetch_assoc()) {
      $sid = (int)($row['source_run_id'] ?? 0);
      if ($sid > 0) $recon_run_ids[] = $sid;
    }
  }
}

$recon_run_ids = array_values(array_unique(array_filter($recon_run_ids, fn($x)=>$x>0)));

$conn->begin_transaction();

try {
  $deleted = [
    'findings' => 0,
    'service_vulns' => 0,
    'services' => 0,
    'run_map' => 0,
    'shodan_runs' => 0,
    'ports' => 0,
    'hosts' => 0
  ];

  if (count($run_ids) === 0) {
    $conn->commit();
    api_json_exit(200, ['ok'=>true, 'deleted'=>$deleted, 'note'=>'No shodan runs in this project']);
  }

  # --- Collect all service_ids for these runs ---
  $service_ids = [];
  if ($has_services) {
    $chunks = array_chunk($run_ids, 500);
    foreach ($chunks as $chunk) {
      $placeholders = implode(',', array_fill(0, count($chunk), '?'));
      $types = str_repeat('i', count($chunk));
      $sql = "SELECT id FROM oneinseclabs_shodan_services WHERE run_id IN ($placeholders)";
      $q = $conn->prepare($sql);
      $q->bind_param($types, ...$chunk);
      $q->execute();
      $rr = $q->get_result();
      while ($row = $rr->fetch_assoc()) $service_ids[] = (int)$row['id'];
    }
  }
  $service_ids = array_values(array_unique(array_filter($service_ids, fn($x)=>$x>0)));

  # --- Delete findings ---
  if ($has_findings && count($service_ids) > 0) {
    $chunks = array_chunk($service_ids, 500);
    foreach ($chunks as $chunk) {
      $placeholders = implode(',', array_fill(0, count($chunk), '?'));
      $types = str_repeat('i', count($chunk));
      $sql = "DELETE FROM oneinseclabs_shodan_findings WHERE service_id IN ($placeholders)";
      $q = $conn->prepare($sql);
      $q->bind_param($types, ...$chunk);
      $q->execute();
      $deleted['findings'] += $q->affected_rows;
    }
  } elseif ($has_findings && col_exists($conn, 'oneinseclabs_shodan_findings', 'run_id')) {
    $chunks = array_chunk($run_ids, 500);
    foreach ($chunks as $chunk) {
      $placeholders = implode(',', array_fill(0, count($chunk), '?'));
      $types = str_repeat('i', count($chunk));
      $sql = "DELETE FROM oneinseclabs_shodan_findings WHERE run_id IN ($placeholders)";
      $q = $conn->prepare($sql);
      $q->bind_param($types, ...$chunk);
      $q->execute();
      $deleted['findings'] += $q->affected_rows;
    }
  }

  # --- Delete service vulns ---
  if ($has_vulns && count($service_ids) > 0) {
    $chunks = array_chunk($service_ids, 500);
    foreach ($chunks as $chunk) {
      $placeholders = implode(',', array_fill(0, count($chunk), '?'));
      $types = str_repeat('i', count($chunk));
      $sql = "DELETE FROM oneinseclabs_shodan_service_vulns WHERE service_id IN ($placeholders)";
      $q = $conn->prepare($sql);
      $q->bind_param($types, ...$chunk);
      $q->execute();
      $deleted['service_vulns'] += $q->affected_rows;
    }
  }

  # --- Delete services ---
  if ($has_services) {
    $chunks = array_chunk($run_ids, 500);
    foreach ($chunks as $chunk) {
      $placeholders = implode(',', array_fill(0, count($chunk), '?'));
      $types = str_repeat('i', count($chunk));
      $sql = "DELETE FROM oneinseclabs_shodan_services WHERE run_id IN ($placeholders)";
      $q = $conn->prepare($sql);
      $q->bind_param($types, ...$chunk);
      $q->execute();
      $deleted['services'] += $q->affected_rows;
    }
  }

  # --- Optional: delete created hosts/ports by recon source_run_id list ---
  if ($delete_assets === 1 && count($recon_run_ids) > 0) {
    // delete ports first
    if ($has_ports && col_exists($conn, 'oneinseclabs_ports', 'source_run_id')) {
      $chunks = array_chunk($recon_run_ids, 500);
      foreach ($chunks as $chunk) {
        $placeholders = implode(',', array_fill(0, count($chunk), '?'));
        $types = 'i' . str_repeat('i', count($chunk));
        $sql = "DELETE FROM oneinseclabs_ports WHERE project_id=? AND source_run_id IN ($placeholders)";
        $q = $conn->prepare($sql);
        $q->bind_param($types, $project_id, ...$chunk);
        $q->execute();
        $deleted['ports'] += $q->affected_rows;
      }
    }

    if ($has_hosts && col_exists($conn, 'oneinseclabs_hosts', 'source_run_id')) {
      $chunks = array_chunk($recon_run_ids, 500);
      foreach ($chunks as $chunk) {
        $placeholders = implode(',', array_fill(0, count($chunk), '?'));
        $types = 'i' . str_repeat('i', count($chunk));
        $sql = "DELETE FROM oneinseclabs_hosts WHERE project_id=? AND source_run_id IN ($placeholders)";
        $q = $conn->prepare($sql);
        $q->bind_param($types, $project_id, ...$chunk);
        $q->execute();
        $deleted['hosts'] += $q->affected_rows;
      }
    }
  }

  # --- Delete run map ---
  if ($has_run_map) {
    $chunks = array_chunk($run_ids, 500);
    foreach ($chunks as $chunk) {
      $placeholders = implode(',', array_fill(0, count($chunk), '?'));
      $types = str_repeat('i', count($chunk));
      $sql = "DELETE FROM oneinseclabs_shodan_run_map WHERE shodan_run_id IN ($placeholders)";
      $q = $conn->prepare($sql);
      $q->bind_param($types, ...$chunk);
      $q->execute();
      $deleted['run_map'] += $q->affected_rows;
    }
  }

  # --- Delete runs (only the user's or admin’s project runs) ---
  // Project access is already validated; now delete all shodan runs for this project
  $chunks = array_chunk($run_ids, 500);
  foreach ($chunks as $chunk) {
    $placeholders = implode(',', array_fill(0, count($chunk), '?'));
    $types = str_repeat('i', count($chunk));
    $sql = "DELETE FROM oneinseclabs_shodan_runs WHERE id IN ($placeholders)";
    $q = $conn->prepare($sql);
    $q->bind_param($types, ...$chunk);
    $q->execute();
    $deleted['shodan_runs'] += $q->affected_rows;
  }

  $conn->commit();

  api_json_exit(200, [
    'ok' => true,
    'project_id' => $project_id,
    'delete_assets' => ($delete_assets === 1),
    'recon_source_run_ids' => $recon_run_ids,
    'deleted' => $deleted
  ]);

} catch (Throwable $e) {
  $conn->rollback();
  api_json_exit(500, ['ok'=>false, 'error'=>$e->getMessage()]);
}
