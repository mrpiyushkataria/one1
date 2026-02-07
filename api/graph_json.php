<?php
require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/graph_builder.php';

require_login();
$conn = db();

$project_id = max(1, (int)($_GET['project_id'] ?? 0));
if ($project_id < 1) { http_response_code(400); die("Missing project_id"); }

$stmt = $conn->prepare("SELECT graph_json FROM oneinseclabs_graph_cache WHERE project_id=? LIMIT 1");
$stmt->bind_param("i",$project_id);
$stmt->execute();
$row = $stmt->get_result()->fetch_assoc();

if (!$row) {
  rebuild_graph_cache($project_id);
  $stmt->execute();
  $row = $stmt->get_result()->fetch_assoc();
}

header('Content-Type: application/json; charset=utf-8');
echo $row ? $row['graph_json'] : json_encode(['nodes'=>[],'links'=>[]]);
