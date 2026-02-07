<?php
// includes/parser_assets.php
require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/util.php';

function ensure_asset(mysqli $conn, int $project_id, string $type, string $value, ?int $parent_id, ?string $source_tool): int {
  $value = trim($value);
  $norm  = ($type === 'ip') ? $value : normalize_domain($value);

  $stmt = $conn->prepare("SELECT id FROM oneinseclabs_assets WHERE project_id=? AND asset_type=? AND normalized_value=? LIMIT 1");
  $stmt->bind_param("iss", $project_id, $type, $norm);
  $stmt->execute();
  $res = $stmt->get_result();
  if ($row = $res->fetch_assoc()) return (int)$row['id'];

  if ($parent_id === null) {
    $stmt2 = $conn->prepare("INSERT INTO oneinseclabs_assets (project_id, parent_asset_id, asset_type, asset_value, normalized_value, source_tool)
                             VALUES (?, NULL, ?, ?, ?, ?)");
    $stmt2->bind_param("issss", $project_id, $type, $value, $norm, $source_tool);
    $stmt2->execute();
  } else {
    $stmt2 = $conn->prepare("INSERT INTO oneinseclabs_assets (project_id, parent_asset_id, asset_type, asset_value, normalized_value, source_tool)
                             VALUES (?, ?, ?, ?, ?, ?)");
    $stmt2->bind_param("iissss", $project_id, $parent_id, $type, $value, $norm, $source_tool);
    $stmt2->execute();
  }
  return (int)$conn->insert_id;
}

function ensure_link(mysqli $conn, int $project_id, int $from_id, int $to_id, string $type): void {
  $stmt = $conn->prepare("INSERT IGNORE INTO oneinseclabs_asset_links (project_id, from_asset_id, to_asset_id, link_type)
                          VALUES (?, ?, ?, ?)");
  $stmt->bind_param("iiis", $project_id, $from_id, $to_id, $type);
  $stmt->execute();
}
