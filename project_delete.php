<?php
/**
 * public_html/one.inseclabs.com/project_delete.php
 * - delete_project_data: wipes recon data for project (keeps project)
 * - delete_project_full: wipes recon data + deletes project row
 */

declare(strict_types=1);
ini_set('display_errors', '0');
error_reporting(E_ALL);

require_once __DIR__ . '/includes/header.php';
$conn = db();
$uid  = current_user_id();

function table_exists(mysqli $conn, string $table): bool {
  $t = $conn->real_escape_string($table);
  $rs = $conn->query("SHOW TABLES LIKE '{$t}'");
  return $rs && $rs->num_rows > 0;
}
function column_exists(mysqli $conn, string $table, string $col): bool {
  $t = $conn->real_escape_string($table);
  $c = $conn->real_escape_string($col);
  $rs = $conn->query("SHOW COLUMNS FROM `{$t}` LIKE '{$c}'");
  return $rs && $rs->num_rows > 0;
}
function del_by_project(mysqli $conn, string $table, int $project_id): int {
  if (!table_exists($conn, $table)) return 0;
  if (!column_exists($conn, $table, 'project_id')) return 0;
  $st = $conn->prepare("DELETE FROM `$table` WHERE project_id=?");
  $st->bind_param("i", $project_id);
  $st->execute();
  return $st->affected_rows;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
  http_response_code(405);
  exit("POST only");
}
csrf_check();

$project_id = (int)($_POST['project_id'] ?? 0);
if ($project_id <= 0) redirect('dashboard.php');

$do_full_delete = isset($_POST['delete_project_full']) && (string)$_POST['delete_project_full'] === '1';
$do_data_delete = isset($_POST['delete_project_data']) && (string)$_POST['delete_project_data'] === '1';

// If button name differs, still proceed as "data delete"
if (!$do_full_delete && !$do_data_delete) $do_data_delete = true;

$stats = [];

try {
  $conn->begin_transaction();

  // -----------------------
  // 1) Find runs table name
  // -----------------------
  $runs_table = null;
  foreach (['oneinseclabs_recon_runs','oneinseclabs_runs','oneinseclabs_scan_runs'] as $t) {
    if (table_exists($conn, $t) && column_exists($conn, $t, 'project_id')) { $runs_table = $t; break; }
  }

  // Collect run IDs
  $run_ids = [];
  if ($runs_table) {
    $st = $conn->prepare("SELECT id FROM `$runs_table` WHERE project_id=?");
    $st->bind_param("i", $project_id);
    $st->execute();
    $rs = $st->get_result();
    while ($r = $rs->fetch_assoc()) $run_ids[] = (int)$r['id'];
  }

  // Helper delete by run_id
  $del_by_run_ids = function(string $table, string $col='run_id') use ($conn, &$run_ids, &$stats) {
    if (!$run_ids) return;
    if (!table_exists($conn, $table)) return;
    if (!column_exists($conn, $table, $col)) return;

    $in = implode(',', array_fill(0, count($run_ids), '?'));
    $types = str_repeat('i', count($run_ids));
    $sql = "DELETE FROM `$table` WHERE `$col` IN ($in)";
    $st = $conn->prepare($sql);
    $st->bind_param($types, ...$run_ids);
    $st->execute();
    $stats[$table] = ($stats[$table] ?? 0) + $st->affected_rows;
  };

  // -----------------------
  // 2) Delete "run children" first
  // -----------------------
  // Files
  $del_by_run_ids('oneinseclabs_recon_files', 'run_id');
  $del_by_run_ids('oneinseclabs_run_files', 'run_id');

  // Link tables
  $del_by_run_ids('oneinseclabs_run_hosts', 'run_id');
  $del_by_run_ids('oneinseclabs_run_ports', 'run_id');

  // Some schemas store ports directly by run_id
  $del_by_run_ids('oneinseclabs_ports', 'source_run_id');
  $del_by_run_ids('oneinseclabs_urls', 'source_run_id');
  $del_by_run_ids('oneinseclabs_subdomains', 'source_run_id');
  $del_by_run_ids('oneinseclabs_dns_records', 'source_run_id');
  $del_by_run_ids('oneinseclabs_hosts', 'source_run_id');

  // -----------------------
  // 3) Delete assets by project_id (if column exists)
  // -----------------------
  foreach ([
    'oneinseclabs_subdomains',
    'oneinseclabs_dns_records',
    'oneinseclabs_hosts',
    'oneinseclabs_ports',
    'oneinseclabs_urls',
    'oneinseclabs_params',
    'oneinseclabs_wayback_urls'
  ] as $t) {
    $stats[$t] = ($stats[$t] ?? 0) + del_by_project($conn, $t, $project_id);
  }

  // -----------------------
  // 4) Delete roots (project domains)
  // -----------------------
  $stats['oneinseclabs_project_domains'] = ($stats['oneinseclabs_project_domains'] ?? 0) + del_by_project($conn, 'oneinseclabs_project_domains', $project_id);

  // -----------------------
  // 5) Delete runs table rows at end
  // -----------------------
  if ($runs_table) {
    $st = $conn->prepare("DELETE FROM `$runs_table` WHERE project_id=?");
    $st->bind_param("i", $project_id);
    $st->execute();
    $stats[$runs_table] = ($stats[$runs_table] ?? 0) + $st->affected_rows;
  }

  // -----------------------
  // 6) FULL project delete (project row + any project-owned tables)
  // -----------------------
  if ($do_full_delete) {
    // delete other project-owned tables if present
    foreach ([
      'oneinseclabs_recon_steps',
      'oneinseclabs_notes',
      'oneinseclabs_project_members'
    ] as $t) {
      $stats[$t] = ($stats[$t] ?? 0) + del_by_project($conn, $t, $project_id);
    }

    // finally delete project itself
    if (table_exists($conn,'oneinseclabs_projects')) {
      $st = $conn->prepare("DELETE FROM oneinseclabs_projects WHERE id=?");
      $st->bind_param("i", $project_id);
      $st->execute();
      $stats['oneinseclabs_projects'] = ($stats['oneinseclabs_projects'] ?? 0) + $st->affected_rows;
    }
  }

  $conn->commit();
  audit_log($uid, $do_full_delete ? 'project_delete_full' : 'project_delete_data', "project_id=$project_id stats=" . json_encode($stats));

} catch (Throwable $e) {
  $conn->rollback();
  audit_log($uid, 'project_delete_failed', "project_id=$project_id err=".$e->getMessage());
  http_response_code(500);
  echo "<div class='card'><h2>Delete failed</h2><div class='muted'>".htmlspecialchars($e->getMessage())."</div></div>";
  require_once __DIR__ . '/includes/footer.php';
  exit;
}

// Redirect: if full delete -> dashboard, else project page
if ($do_full_delete) {
  redirect("dashboard.php");
} else {
  redirect("project.php?id=".$project_id);
}
