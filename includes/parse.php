<?php
declare(strict_types=1);
require_once __DIR__ . '/db.php';

function upsert_host(mysqli $conn, int $project_id, string $ip, string $hostname = ''): int {
  $ip = trim($ip);
  if ($ip === '') return 0;

  $stmt = $conn->prepare("SELECT id, hostname FROM oneinseclabs_hosts WHERE project_id=? AND ip_address=? LIMIT 1");
  $stmt->bind_param("is", $project_id, $ip);
  $stmt->execute();
  $row = $stmt->get_result()->fetch_assoc();
  if ($row) {
    $host_id = (int)$row['id'];
    if ($hostname !== '' && $row['hostname'] !== $hostname) {
      $up = $conn->prepare("UPDATE oneinseclabs_hosts SET hostname=? WHERE id=?");
      $up->bind_param("si", $hostname, $host_id);
      $up->execute();
    }
    return $host_id;
  }

  $insert = $conn->prepare("INSERT INTO oneinseclabs_hosts (project_id, ip_address, hostname) VALUES (?,?,?)");
  $insert->bind_param("iss", $project_id, $ip, $hostname);
  if (@$insert->execute()) {
    return (int)$insert->insert_id;
  }
  return 0;
}

function insert_subdomain(mysqli $conn, int $project_id, string $subdomain, int $run_id): void {
  $subdomain = trim($subdomain);
  if ($subdomain === '') return;
  $stmt = $conn->prepare("
    INSERT INTO oneinseclabs_subdomains (project_id, subdomain, source_run_id)
    VALUES (?,?,?)
    ON DUPLICATE KEY UPDATE last_seen=NOW(), source_run_id=VALUES(source_run_id)
  ");
  $stmt->bind_param("isi", $project_id, $subdomain, $run_id);
  @$stmt->execute();
}

function insert_url(mysqli $conn, int $project_id, int $run_id, string $url, string $source = '', ?int $status = null, string $title = ''): void {
  $stmt = $conn->prepare("
    INSERT INTO oneinseclabs_urls (project_id, url, source, status_code, title, source_run_id)
    VALUES (?,?,?,?,?,?)
    ON DUPLICATE KEY UPDATE source=VALUES(source), status_code=VALUES(status_code), title=VALUES(title), source_run_id=VALUES(source_run_id)
  ");
  $status_code = $status ?? null;
  $stmt->bind_param("issisi", $project_id, $url, $source, $status_code, $title, $run_id);
  @$stmt->execute();
}

function parse_and_store(int $project_id, int $run_id, string $tool_slug, string $file_path): array {
  $conn = db();
  $stored = ['subdomains'=>0,'urls'=>0,'ports'=>0];

  $contents = @file_get_contents($file_path);
  if ($contents === false) return $stored;

  // Nmap XML
  if (str_contains($contents, '<nmaprun')) {
    libxml_use_internal_errors(true);
    $xml = simplexml_load_string($contents);
    if ($xml && isset($xml->host)) {
      foreach ($xml->host as $host) {
        $addr = (string)($host->address['addr'] ?? '');
        if (!$addr) continue;
        $host_id = upsert_host($conn, $project_id, $addr, '');
        if (isset($host->ports->port)) {
          foreach ($host->ports->port as $p) {
            $port = (int)($p['portid'] ?? 0);
            $proto = (string)($p['protocol'] ?? 'tcp');
            $state = (string)($p->state['state'] ?? '');
            $service = (string)($p->service['name'] ?? '');
            $product = (string)($p->service['product'] ?? '');
            $version = (string)($p->service['version'] ?? '');

            if ($port > 0) {
              $stmt = $conn->prepare("
                INSERT INTO oneinseclabs_ports (project_id, host_id, port, protocol, state, service, product, version, source_run_id)
                VALUES (?,?,?,?,?,?,?,?,?)
                ON DUPLICATE KEY UPDATE state=VALUES(state), service=VALUES(service), product=VALUES(product), version=VALUES(version), source_run_id=VALUES(source_run_id)
              ");
              $stmt->bind_param("iiisssssi", $project_id, $host_id, $port, $proto, $state, $service, $product, $version, $run_id);
              if (@$stmt->execute()) $stored['ports']++;
            }
          }
        }
      }
    }
    return $stored;
  }

  // Text line parsing
  $lines = preg_split("/\r\n|\n|\r/", $contents);
  foreach ($lines as $line) {
    $line = trim($line);
    if ($line === '') continue;

    // dnsx style: subdomain [ip, ip]
    if (preg_match('/^([a-z0-9][a-z0-9\.\-\*]+[a-z0-9])\s+\[([^\]]+)\]$/i', $line, $m)) {
      $sub = ltrim($m[1], '*.');
      insert_subdomain($conn, $project_id, $sub, $run_id);
      $stored['subdomains']++;
      $ips = preg_split('/\s*,\s*/', $m[2]);
      foreach ($ips as $ip) {
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
          upsert_host($conn, $project_id, $ip, $sub);
        }
      }
      continue;
    }

    // URL (httpx/wayback/gau). Capture status + title if available.
    if (preg_match('#https?://\S+#i', $line, $um)) {
      $url = $um[0];
      $status = null;
      if (preg_match('/\[(\d{3})\]/', $line, $sm)) {
        $status = (int)$sm[1];
      }
      $title = '';
      if (preg_match('/\]\s*(?:\[(.*?)\])\s*$/', $line, $tm)) {
        $title = trim($tm[1]);
      } elseif (preg_match('/\]\s*([^\\[]+)$/', $line, $tm)) {
        $title = trim($tm[1]);
      }
      insert_url($conn, $project_id, $run_id, $url, $tool_slug, $status, $title);
      $stored['urls']++;
      continue;
    }

    // Subdomain-ish
    if (preg_match('/^[a-z0-9][a-z0-9\.\-\*]+[a-z0-9]$/i', $line) && str_contains($line, '.')) {
      $line = ltrim($line, '*.');
      insert_subdomain($conn, $project_id, $line, $run_id);
      $stored['subdomains']++;
      continue;
    }
  }

  return $stored;
}
