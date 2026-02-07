<?php
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/graph_builder.php';

require_login();

$project_id = max(1, (int)($_GET['project_id'] ?? 0));
if ($project_id < 1) { http_response_code(400); die("Missing project_id"); }

$r = rebuild_graph_cache($project_id);
header('Content-Type: application/json; charset=utf-8');
echo json_encode($r, JSON_UNESCAPED_UNICODE);
