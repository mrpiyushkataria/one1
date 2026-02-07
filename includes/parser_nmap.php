<?php
// includes/parser_nmap.php
require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/util.php';
require_once __DIR__ . '/parser_assets.php';

function parse_nmap_xml(int $project_id, int $scan_id, string $xml_content, array $root_domains, ?string $force_root = null): array {
  $conn = db();

  libxml_use_internal_errors(true);
  if (function_exists('libxml_disable_entity_loader')) {
    $prev = libxml_disable_entity_loader(true);
  }
  $xml = simplexml_load_string($xml_content, 'SimpleXMLElement', LIBXML_NONET | LIBXML_NOCDATA);
  if (function_exists('libxml_disable_entity_loader')) {
    libxml_disable_entity_loader($prev);
  }
  if (!$xml || $xml->getName() !== 'nmaprun') return ['ok'=>false,'error'=>'Invalid Nmap XML'];

  $hosts_up=0; $ports_added=0; $links_added=0;

  $forced_root_id = null;
  if ($force_root) {
    $force_root = normalize_domain($force_root);
    if ($force_root !== '') {
      $forced_root_id = ensure_asset($conn, $project_id, 'root_domain', $force_root, null, 'scope');
    }
  }

  foreach ($xml->host as $host) {
    $state = (string)($host->status['state'] ?? '');
    if ($state !== 'up') continue;
    $hosts_up++;

    $ip = null;
    foreach ($host->address as $addr) {
      $t = (string)$addr['addrtype'];
      if ($t === 'ipv4' || $t === 'ipv6') { $ip = (string)$addr['addr']; break; }
    }
    if (!$ip || !is_ip($ip)) continue;

    $ip_id = ensure_asset($conn, $project_id, 'ip', $ip, null, 'nmap');

    // If user forced root domain, link root -> ip as "related" (useful when hostnames absent)
    if ($forced_root_id) {
      ensure_link($conn, $project_id, $forced_root_id, $ip_id, 'related');
    }

    // hostnames
    $hostnames = [];
    if (isset($host->hostnames->hostname)) {
      foreach ($host->hostnames->hostname as $hn) {
        $name = normalize_domain((string)$hn['name']);
        if ($name !== '') $hostnames[] = $name;
      }
    }

    foreach (array_unique($hostnames) as $hn) {
      $root = match_root_domain($hn, $root_domains);
      if (!$root) continue;

      $root_id = ensure_asset($conn, $project_id, 'root_domain', $root, null, 'scope');
      $sub_id  = ensure_asset($conn, $project_id, 'subdomain', $hn, $root_id, 'nmap');

      ensure_link($conn, $project_id, $root_id, $sub_id, 'contains');
      ensure_link($conn, $project_id, $sub_id, $ip_id, 'resolves_to');
      $links_added++;
    }

    // ports
    if (!isset($host->ports->port)) continue;
    foreach ($host->ports->port as $p) {
      $proto = (string)$p['protocol'];
      $port  = (int)$p['portid'];
      $pstate = (string)($p->state['state'] ?? 'unknown');

      $svc = $p->service ?? null;
      $service_name = $svc ? (string)$svc['name'] : null;
      $product      = $svc ? (string)$svc['product'] : null;
      $version      = $svc ? (string)$svc['version'] : null;
      $extrainfo    = $svc ? (string)$svc['extrainfo'] : null;
      $tunnel       = $svc ? (string)$svc['tunnel'] : null;
      $cpe          = ($svc && isset($svc->cpe)) ? (string)$svc->cpe : null;

      $scripts = [];
      if (isset($p->script)) {
        foreach ($p->script as $s) {
          $scripts[] = ['id'=>(string)$s['id'], 'output'=>(string)$s['output']];
        }
      }
      $script_json = $scripts ? json_encode($scripts, JSON_UNESCAPED_UNICODE) : null;

      $stmt = $conn->prepare("
        INSERT IGNORE INTO oneinseclabs_ports
        (project_id, scan_id, ip_asset_id, port, protocol, state, service_name, product, version, extrainfo, tunnel, cpe, script_json)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
      ");
      $stmt->bind_param(
        "iiiisssssssss",
        $project_id, $scan_id, $ip_id, $port,
        $proto, $pstate, $service_name, $product, $version, $extrainfo, $tunnel, $cpe, $script_json
      );
      $stmt->execute();
      if ($stmt->affected_rows > 0) $ports_added++;
    }
  }

  return ['ok'=>true,'hosts_up'=>$hosts_up,'ports_added'=>$ports_added,'links_added'=>$links_added];
}
