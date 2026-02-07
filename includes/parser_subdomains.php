<?php
// includes/parser_subdomains.php
require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/util.php';
require_once __DIR__ . '/parser_assets.php';

function parse_subdomains_txt(int $project_id, string $tool_name, string $content, array $root_domains): array {
  $conn = db();
  $lines = preg_split("/\r\n|\n|\r/", $content);

  $created = 0; $skipped = 0;

  foreach ($lines as $line) {
    $d = normalize_domain($line);
    if ($d === '' || str_contains($d, ' ')) { $skipped++; continue; }

    $root = match_root_domain($d, $root_domains);
    if (!$root) { $skipped++; continue; }

    $root_id = ensure_asset($conn, $project_id, 'root_domain', $root, null, 'scope');
    $sub_id  = ensure_asset($conn, $project_id, 'subdomain', $d, $root_id, $tool_name);
    ensure_link($conn, $project_id, $root_id, $sub_id, 'contains');

    $created++;
  }
  return ['ok'=>true,'created'=>$created,'skipped'=>$skipped];
}
