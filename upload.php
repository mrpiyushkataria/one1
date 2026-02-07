<?php
/**
 * public_html/one.inseclabs.com/upload.php
 * Professional multi-tool uploader + ZIP bundle importer
 */

ini_set('display_errors','1');
ini_set('display_startup_errors','1');
error_reporting(E_ALL);
date_default_timezone_set('Asia/Kolkata');

require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/util.php';
require_once __DIR__ . '/includes/parsers.php';
require_once __DIR__ . '/includes/parsers_bundle.php'; // NEW

require_login();

/** ---- polyfills (safe on PHP 8+) ---- */
if (!function_exists('str_starts_with')) {
  function str_starts_with(string $haystack, string $needle): bool {
    return $needle === '' || strpos($haystack, $needle) === 0;
  }
}
if (!function_exists('str_ends_with')) {
  function str_ends_with(string $haystack, string $needle): bool {
    if ($needle === '') return true;
    $len = strlen($needle);
    return substr($haystack, -$len) === $needle;
  }
}

function fail500(string $msg, ?Throwable $e=null): void {
  $dir = __DIR__ . '/uploads/_errors';
  if (!is_dir($dir)) @mkdir($dir, 0755, true);
  $log = $dir . '/upload_errors.log';
  $line = "[" . date('Y-m-d H:i:s') . "] " . $msg;
  if ($e) $line .= " | " . $e->getMessage();
  $line .= "\n";
  @file_put_contents($log, $line, FILE_APPEND);
  http_response_code(500);
  echo "<h3>Upload error</h3><p>Check <code>uploads/_errors/upload_errors.log</code></p>";
  exit;
}

function db_name(mysqli $conn): string {
  $rs = $conn->query("SELECT DATABASE() AS db");
  if (!$rs) return '';
  $row = $rs->fetch_assoc();
  return (string)($row['db'] ?? '');
}

function table_exists(mysqli $conn, string $table): bool {
  $db = db_name($conn);
  if ($db === '') return false;
  $st = $conn->prepare("SELECT 1 FROM information_schema.TABLES WHERE TABLE_SCHEMA=? AND TABLE_NAME=? LIMIT 1");
  $st->bind_param("ss", $db, $table);
  $st->execute();
  $r = $st->get_result();
  return ($r && $r->num_rows > 0);
}

function column_exists(mysqli $conn, string $table, string $col): bool {
  $db = db_name($conn);
  if ($db === '') return false;
  $st = $conn->prepare("SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=? AND TABLE_NAME=? AND COLUMN_NAME=? LIMIT 1");
  $st->bind_param("sss", $db, $table, $col);
  $st->execute();
  $r = $st->get_result();
  return ($r && $r->num_rows > 0);
}

function detect_tool_key(string $raw): string {
  $s = strtolower($raw);
  if (strpos($s, '<nmaprun') !== false) return 'nmap';
  if (strpos($s, 'nmap scan report for') !== false) return 'nmap';
  if (preg_match('/\[(\d{3})\]/', $raw) && preg_match('#^https?://#m', $raw)) return 'httpx';
  if (preg_match('#^https?://#m', $raw)) return 'wayback';
  if (preg_match('/^[a-z0-9.-]+\.[a-z]{2,}.*\b\d{1,3}(?:\.\d{1,3}){3}\b/m', $raw)) return 'dnsx';
  return 'subdomains';
}

function norm_root(string $d): string {
  $d = strtolower(trim($d));
  $d = preg_replace('#^https?://#','',$d);
  $d = trim($d,'/');
  $d = rtrim($d,'.');
  return $d;
}

try {
  if ($_SERVER['REQUEST_METHOD'] !== 'POST') { http_response_code(405); exit("POST only"); }
  csrf_check();

  mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
  $conn = db();
  $conn->set_charset("utf8mb4");

  $project_id = (int)($_POST['project_id'] ?? 0);
  if ($project_id <= 0) throw new Exception("Invalid project_id");

  $project_roots = load_project_roots($conn, $project_id);

  $tool_key  = trim((string)($_POST['tool_key'] ?? 'other'));
  $category  = trim((string)($_POST['category'] ?? 'recon'));
  $tool_name = trim((string)($_POST['tool_name'] ?? 'Tool'));
  $notes     = trim((string)($_POST['notes'] ?? ''));
  $return_to = trim((string)($_POST['return_to'] ?? ''));

  $root_ctx  = norm_root((string)($_POST['root_domain'] ?? ''));
  if ($root_ctx !== '' && $project_roots) {
    $m = match_project_root($root_ctx, $project_roots);
    if ($m) $root_ctx = $m;
  }

  $paste_text = trim((string)($_POST['paste_text'] ?? ''));

  // dirs
  $baseDir = __DIR__ . '/uploads/tool_outputs';
  if (!is_dir($baseDir)) @mkdir($baseDir, 0755, true);
  $projDir = $baseDir . "/p{$project_id}";
  if (!is_dir($projDir)) @mkdir($projDir, 0755, true);

  // normalize files
  $files = [];
  if (isset($_FILES['file'])) {
    if (is_array($_FILES['file']['name'])) {
      for ($i=0; $i<count($_FILES['file']['name']); $i++) {
        if (empty($_FILES['file']['tmp_name'][$i])) continue;
        $files[] = [
          'name'=>$_FILES['file']['name'][$i],
          'tmp'=>$_FILES['file']['tmp_name'][$i],
          'type'=>$_FILES['file']['type'][$i] ?? 'application/octet-stream',
          'size'=>(int)($_FILES['file']['size'][$i] ?? 0),
          'err'=>(int)($_FILES['file']['error'][$i] ?? 0),
        ];
      }
    } else {
      $files[] = [
        'name'=>$_FILES['file']['name'],
        'tmp'=>$_FILES['file']['tmp_name'],
        'type'=>$_FILES['file']['type'] ?? 'application/octet-stream',
        'size'=>(int)($_FILES['file']['size'] ?? 0),
        'err'=>(int)($_FILES['file']['error'] ?? 0),
      ];
    }
  }

  if (!count($files) && $paste_text === '') throw new Exception("No file uploaded and paste is empty");

  $uid = (int)current_user_id();

  $split_runs = (int)($_POST['split_runs'] ?? 0);
  if ($split_runs === 0 && count($files) > 1 && ($tool_key === 'nmap' || $tool_key === 'auto')) $split_runs = 1;

  // schema presence
  $hasRunRoot  = column_exists($conn, 'oneinseclabs_recon_runs', 'root_domain');
  $hasTarget   = column_exists($conn, 'oneinseclabs_recon_runs', 'target_label');
  $hasRunHosts = table_exists($conn, 'oneinseclabs_run_hosts');
  $hasRunPorts = table_exists($conn, 'oneinseclabs_run_ports');

  $hasFindings = table_exists($conn, 'oneinseclabs_findings');
  $hasEndpoints = table_exists($conn, 'oneinseclabs_endpoints');
  $hasParams = table_exists($conn, 'oneinseclabs_params');
  $hasShots = table_exists($conn, 'oneinseclabs_screenshots');

  $createRun = function(string $finalToolKey, string $toolName, string $category, string $notes, string $root_ctx, string $target_label)
    use ($conn, $project_id, $uid, $hasRunRoot, $hasTarget) : int {

    if ($hasRunRoot && $hasTarget) {
      $st = $conn->prepare("INSERT INTO oneinseclabs_recon_runs (project_id, root_domain, target_label, tool_key, tool_name, category, notes, created_by)
                            VALUES (?,?,?,?,?,?,?,?)");
      $st->bind_param("issssssi", $project_id, $root_ctx, $target_label, $finalToolKey, $toolName, $category, $notes, $uid);
    } elseif ($hasRunRoot) {
      $st = $conn->prepare("INSERT INTO oneinseclabs_recon_runs (project_id, root_domain, tool_key, tool_name, category, notes, created_by)
                            VALUES (?,?,?,?,?,?,?)");
      $st->bind_param("isssssi", $project_id, $root_ctx, $finalToolKey, $toolName, $category, $notes, $uid);
    } else {
      $st = $conn->prepare("INSERT INTO oneinseclabs_recon_runs (project_id, tool_key, tool_name, category, notes, created_by)
                            VALUES (?,?,?,?,?,?)");
      $st->bind_param("issssi", $project_id, $finalToolKey, $toolName, $category, $notes, $uid);
    }
    $st->execute();
    return (int)$conn->insert_id;
  };

  // unified findings insert helper
  $insertFinding = function(int $run_id, string $tool, string $severity, ?string $template_id, string $target, ?string $title, string $raw)
    use ($conn, $project_id, $hasFindings) : void {
    if (!$hasFindings) return;
    $st = $conn->prepare("INSERT INTO oneinseclabs_findings (project_id, run_id, tool, severity, template_id, target, title, raw)
                          VALUES (?,?,?,?,?,?,?,?)
                          ON DUPLICATE KEY UPDATE severity=VALUES(severity), run_id=VALUES(run_id), title=VALUES(title), raw=VALUES(raw)");
    $tpl = $template_id ?? '';
    $ttl = $title ?? '';
    $st->bind_param("iissssss", $project_id, $run_id, $tool, $severity, $tpl, $target, $ttl, $raw);
    try { $st->execute(); } catch(Throwable $e) {}
  };

  $processBlob = function(
    int $run_id,
    string $origName,
    string $raw,
    string $mimeGuess,
    int $sizeGuess,
    string $forced_tool_key,
    string $root_ctx
  ) use (
    $conn, $project_id, $projDir, $hasRunHosts, $hasRunPorts, $project_roots,
    $hasFindings, $hasEndpoints, $hasParams, $hasShots,
    $insertFinding
  ) : array {

    $final_tool_key = ($forced_tool_key === 'auto') ? detect_tool_key($raw) : $forced_tool_key;

    $sha = hash('sha256', $raw);
    $sha8 = substr($sha, 0, 8);
    $safeName = preg_replace('/[^a-zA-Z0-9._-]/','_', basename($origName));
    if ($safeName === '') $safeName = "upload.txt";

    $stored = $projDir . "/" . date('Ymd_His') . "_{$run_id}_{$sha8}_" . $safeName;
    if (@file_put_contents($stored, $raw) === false) throw new Exception("Failed to write file: $stored");
    $stored_rel = "uploads/tool_outputs/p{$project_id}/" . basename($stored);

    $summary = ['tool_key'=>$final_tool_key,'parsed'=>false];

    // -------------------------
    // SUBDOMAINS (subfinder/amass/assetfinder/etc)
    // -------------------------
    if ($final_tool_key === 'subdomains') {
      $subs = parse_subdomains_text($raw);
      $cnt = 0;
      foreach ($subs as $sub) {
        $root = match_project_root($sub, $project_roots);
        if (!$root && $root_ctx !== '' && ($sub === $root_ctx || str_ends_with($sub, '.' . $root_ctx))) $root = $root_ctx;
        if (!$root) $root = guess_root_domain($sub);

        $st = $conn->prepare("INSERT INTO oneinseclabs_subdomains (project_id, root_domain, subdomain, source_run_id)
                              VALUES (?,?,?,?)
                              ON DUPLICATE KEY UPDATE last_seen=NOW(), root_domain=VALUES(root_domain)");
        $st->bind_param("issi", $project_id, $root, $sub, $run_id);
        $st->execute();
        $cnt++;
      }
      $summary = ['tool_key'=>'subdomains','parsed'=>true,'subdomains_added'=>$cnt];
    }

    // DNSX
    if ($final_tool_key === 'dnsx') {
      $pairs = parse_dnsx_resolved($raw);
      $cnt = 0;
      foreach ($pairs as $p) {
        $sub = $p['subdomain']; $ip = $p['ip'];
        $st = $conn->prepare("INSERT INTO oneinseclabs_dns_records (project_id, subdomain, ip_address, source_run_id)
                              VALUES (?,?,?,?)
                              ON DUPLICATE KEY UPDATE last_seen=NOW()");
        $st->bind_param("issi", $project_id, $sub, $ip, $run_id);
        $st->execute();
        $cnt++;
      }
      $summary = ['tool_key'=>'dnsx','parsed'=>true,'dns_pairs_added'=>$cnt];
    }

    // WAYBACK / URL list
    if ($final_tool_key === 'wayback') {
      $urls = parse_wayback_urls($raw);
      $cnt = 0;
      foreach ($urls as $u) {
        $params = null;
        $q = parse_url($u, PHP_URL_QUERY);
        if ($q) { parse_str($q, $pairs); $params = json_encode(array_keys($pairs)); }

        $sha1 = sha1($u);
        if (column_exists($conn, 'oneinseclabs_urls', 'url_sha1')) {
          $st = $conn->prepare("INSERT INTO oneinseclabs_urls (project_id, url, url_sha1, source, params_json, source_run_id)
                                VALUES (?,?,?,?,?,?)
                                ON DUPLICATE KEY UPDATE source_run_id=VALUES(source_run_id)");
          $src = 'wayback';
          $st->bind_param("issssi", $project_id, $u, $sha1, $src, $params, $run_id);
        } else {
          $st = $conn->prepare("INSERT INTO oneinseclabs_urls (project_id, url, source, params_json, source_run_id)
                                VALUES (?,?,?,?,?)");
          $src = 'wayback';
          $st->bind_param("isssi", $project_id, $u, $src, $params, $run_id);
        }
        try { $st->execute(); $cnt++; } catch(Throwable $e) {}
      }
      $summary = ['tool_key'=>'wayback','parsed'=>true,'urls_added'=>$cnt];
    }

    // HTTPX
    if ($final_tool_key === 'httpx') {
      $items = parse_httpx_lines($raw);
      $cnt = 0;
      foreach ($items as $it) {
        $params = null;
        $q = parse_url($it['url'], PHP_URL_QUERY);
        if ($q) { parse_str($q, $pairs); $params = json_encode(array_keys($pairs)); }

        $sha1 = sha1($it['url']);
        if (column_exists($conn, 'oneinseclabs_urls', 'url_sha1')) {
          $st = $conn->prepare("INSERT INTO oneinseclabs_urls (project_id, url, url_sha1, source, status_code, title, params_json, source_run_id)
                                VALUES (?,?,?,?,?,?,?,?)
                                ON DUPLICATE KEY UPDATE status_code=VALUES(status_code), title=VALUES(title), source_run_id=VALUES(source_run_id)");
          $src = 'httpx';
          $status = (int)$it['status'];
          $title = (string)$it['title'];
          $st->bind_param("isssissi", $project_id, $it['url'], $sha1, $src, $status, $title, $params, $run_id);
        } else {
          $st = $conn->prepare("INSERT INTO oneinseclabs_urls (project_id, url, source, status_code, title, params_json, source_run_id)
                                VALUES (?,?,?,?,?,?,?)");
          $src = 'httpx';
          $status = (int)$it['status'];
          $title = (string)$it['title'];
          $st->bind_param("ississi", $project_id, $it['url'], $src, $status, $title, $params, $run_id);
        }
        try { $st->execute(); $cnt++; } catch(Throwable $e) {}
      }
      $summary = ['tool_key'=>'httpx','parsed'=>true,'urls_added'=>$cnt];
    }

    // NAABU -> run_ports only
    if ($final_tool_key === 'naabu') {
      $items = parse_naabu_ports($raw);
      $cnt = 0;

      $stRunPort = null;
      if ($hasRunPorts) {
        $stRunPort = $conn->prepare("INSERT IGNORE INTO oneinseclabs_run_ports
          (run_id, project_id, ip_address, port, protocol, state, service, product, version, extrainfo)
          VALUES (?,?,?,?,?,?,?,?,?,?)");
      }

      foreach ($items as $it) {
        $host  = (string)$it['host'];
        $port  = (int)$it['port'];
        $proto = (string)($it['proto'] ?? 'tcp');

        if ($stRunPort) {
          $state='open'; $svc=''; $prod=''; $ver=''; $extra='';
          $stRunPort->bind_param("iisissssss", $run_id, $project_id, $host, $port, $proto, $state, $svc, $prod, $ver, $extra);
          try { $stRunPort->execute(); $cnt++; } catch(Throwable $e) {}
        }
      }

      $summary = ['tool_key'=>'naabu','parsed'=>true,'open_ports'=>$cnt];
    }

    // KATANA / GAU / WAYBACKURLS -> URL lists
    if (in_array($final_tool_key, ['katana','gau','waybackurls'], true)) {
      $urls = parse_urls_generic($raw);
      $cnt = 0;
      foreach ($urls as $u) {
        $params = null;
        $q = parse_url($u, PHP_URL_QUERY);
        if ($q) { parse_str($q, $pairs); $params = json_encode(array_keys($pairs)); }

        $sha1 = sha1($u);
        $src = $final_tool_key;

        if (column_exists($conn, 'oneinseclabs_urls', 'url_sha1')) {
          $st = $conn->prepare("INSERT INTO oneinseclabs_urls (project_id, url, url_sha1, source, params_json, source_run_id)
                                VALUES (?,?,?,?,?,?)
                                ON DUPLICATE KEY UPDATE source_run_id=VALUES(source_run_id)");
          $st->bind_param("issssi", $project_id, $u, $sha1, $src, $params, $run_id);
        } else {
          $st = $conn->prepare("INSERT INTO oneinseclabs_urls (project_id, url, source, params_json, source_run_id)
                                VALUES (?,?,?,?,?)");
          $st->bind_param("isssi", $project_id, $u, $src, $params, $run_id);
        }

        try { $st->execute(); $cnt++; } catch(Throwable $e) {}
      }
      $summary = ['tool_key'=>$final_tool_key,'parsed'=>true,'urls_added'=>$cnt];
    }

    // -------------------------
    // NEW: FFUF endpoints -> oneinseclabs_endpoints
    // -------------------------
    if ($final_tool_key === 'ffuf') {
      $added = 0;
      if ($hasEndpoints) {
        $items = parse_ffuf_json($raw);
        $st = $conn->prepare("INSERT INTO oneinseclabs_endpoints
          (project_id, run_id, url, url_sha1, source, status_code, word_count, line_count, size_bytes, content_type)
          VALUES (?,?,?,?,?,?,?,?,?,?)
          ON DUPLICATE KEY UPDATE status_code=VALUES(status_code), word_count=VALUES(word_count), line_count=VALUES(line_count),
                                  size_bytes=VALUES(size_bytes), content_type=VALUES(content_type)");
        foreach ($items as $it) {
          $url = (string)$it['url'];
          $sha1 = sha1($url);
          $src = 'ffuf';
          $status = $it['status'] ?? null;
          $words  = $it['words'] ?? null;
          $lines  = $it['lines'] ?? null;
          $size   = $it['size'] ?? null;
          $ctype  = $it['type'] ?? null;
          // bind as strings for nullable safety
          $status_i = is_null($status) ? null : (int)$status;
          $words_i  = is_null($words) ? null : (int)$words;
          $lines_i  = is_null($lines) ? null : (int)$lines;
          $size_i   = is_null($size) ? null : (int)$size;
          $ctype_s  = is_null($ctype) ? null : (string)$ctype;

          $st->bind_param("iissssiiii", $project_id, $run_id, $url, $sha1, $src, $src, $status_i, $words_i, $lines_i, $size_i);
          // ↑ MariaDB bind_param can't accept null in i easily on some builds; safest is:
          // We'll do a simpler approach: store only what we have by casting to int and using 0 when null
        }
        // safer approach: insert without null-int headaches
        foreach ($items as $it) {
          $url = (string)$it['url'];
          $sha1 = sha1($url);
          $src = 'ffuf';
          $status = isset($it['status']) ? (int)$it['status'] : null;
          $words  = isset($it['words']) ? (int)$it['words'] : null;
          $lines  = isset($it['lines']) ? (int)$it['lines'] : null;
          $size   = isset($it['size']) ? (int)$it['size'] : null;
          $ctype  = isset($it['type']) ? (string)$it['type'] : null;

          $st2 = $conn->prepare("INSERT INTO oneinseclabs_endpoints
            (project_id, run_id, url, url_sha1, source, status_code, word_count, line_count, size_bytes, content_type)
            VALUES (?,?,?,?,?,?,?,?,?,?)
            ON DUPLICATE KEY UPDATE status_code=VALUES(status_code), word_count=VALUES(word_count), line_count=VALUES(line_count),
                                    size_bytes=VALUES(size_bytes), content_type=VALUES(content_type)");
          $st2->bind_param("iisssiiiis", $project_id, $run_id, $url, $sha1, $src,
            $status, $words, $lines, $size, $ctype);
          try { $st2->execute(); $added++; } catch(Throwable $e) {}
        }
      }
      $summary = ['tool_key'=>'ffuf','parsed'=>true,'endpoints_added'=>$added,'note'=>$hasEndpoints?'':'oneinseclabs_endpoints missing'];
    }

    // -------------------------
    // NEW: DIRSEARCH endpoints -> oneinseclabs_endpoints
    // -------------------------
    if ($final_tool_key === 'dirsearch') {
      $added = 0;
      if ($hasEndpoints) {
        $ext = strtolower(pathinfo($origName, PATHINFO_EXTENSION));
        $items = parse_dirsearch($raw, $ext);
        foreach ($items as $it) {
          $url = (string)$it['url'];
          if ($url==='') continue;
          $sha1 = sha1($url);
          $src = 'dirsearch';
          $status = isset($it['status']) ? (int)$it['status'] : null;
          $size   = isset($it['size']) ? (int)$it['size'] : null;
          $ctype  = isset($it['type']) ? (string)$it['type'] : null;

          $st = $conn->prepare("INSERT INTO oneinseclabs_endpoints
            (project_id, run_id, url, url_sha1, source, status_code, size_bytes, content_type)
            VALUES (?,?,?,?,?,?,?,?)
            ON DUPLICATE KEY UPDATE status_code=VALUES(status_code), size_bytes=VALUES(size_bytes), content_type=VALUES(content_type)");
          $st->bind_param("iisssiis", $project_id, $run_id, $url, $sha1, $src, $status, $size, $ctype);
          try { $st->execute(); $added++; } catch(Throwable $e) {}
        }
      }
      $summary = ['tool_key'=>'dirsearch','parsed'=>true,'endpoints_added'=>$added,'note'=>$hasEndpoints?'':'oneinseclabs_endpoints missing'];
    }

    // -------------------------
    // NEW: ARJUN / PARAMSPIDER -> oneinseclabs_params
    // -------------------------
    if (in_array($final_tool_key, ['arjun','paramspider'], true)) {
      $added = 0;
      if ($hasParams) {
        $items = ($final_tool_key === 'arjun') ? parse_arjun($raw) : parse_paramspider($raw);
        foreach ($items as $it) {
          $host = (string)($it['host'] ?? '');
          $url  = (string)($it['url'] ?? '');
          $param = (string)($it['param'] ?? '');
          if ($param === '') continue;
          $src = (string)($it['source'] ?? $final_tool_key);

          $st = $conn->prepare("INSERT INTO oneinseclabs_params (project_id, run_id, host, url, param_name, source)
                                VALUES (?,?,?,?,?,?)
                                ON DUPLICATE KEY UPDATE run_id=VALUES(run_id)");
          $st->bind_param("iissss", $project_id, $run_id, $host, $url, $param, $src);
          try { $st->execute(); $added++; } catch(Throwable $e) {}
        }
      }
      $summary = ['tool_key'=>$final_tool_key,'parsed'=>true,'params_added'=>$added,'note'=>$hasParams?'':'oneinseclabs_params missing'];
    }

    // -------------------------
    // NEW: GOWITNESS -> oneinseclabs_screenshots
    // NOTE: image_path stored as inside-zip path; later you can map it to a served path if you extract images
    // -------------------------
    if ($final_tool_key === 'gowitness') {
      $added = 0;
      if ($hasShots) {
        $items = parse_gowitness_json($raw);
        foreach ($items as $it) {
          $url = (string)$it['url'];
          $img = (string)$it['image_path'];
          if ($url==='' || $img==='') continue;

          $sha1 = sha1($url);
          $title = (string)($it['title'] ?? '');
          $status = isset($it['status']) ? (int)$it['status'] : null;

          $st = $conn->prepare("INSERT INTO oneinseclabs_screenshots (project_id, run_id, url, url_sha1, image_path, title, status_code)
                                VALUES (?,?,?,?,?,?,?)
                                ON DUPLICATE KEY UPDATE title=VALUES(title), status_code=VALUES(status_code), run_id=VALUES(run_id)");
          $st->bind_param("iissssi", $project_id, $run_id, $url, $sha1, $img, $title, $status);
          try { $st->execute(); $added++; } catch(Throwable $e) {}
        }
      }
      $summary = ['tool_key'=>'gowitness','parsed'=>true,'screenshots_added'=>$added,'note'=>$hasShots?'':'oneinseclabs_screenshots missing'];
    }

    // -------------------------
    // NEW: SUBJACK / SQLMAP / XSSTRIKE -> findings
    // -------------------------
    if ($final_tool_key === 'subjack') {
      $items = parse_subjack($raw);
      foreach ($items as $f) {
        $insertFinding($run_id, $f['tool'], $f['severity'], $f['template'], $f['target'], $f['title'], $f['raw']);
      }
      $summary = ['tool_key'=>'subjack','parsed'=>true,'findings_added'=>count($items),'note'=>$hasFindings?'':'oneinseclabs_findings missing'];
    }

    if (in_array($final_tool_key, ['sqlmap','xsstrike'], true)) {
      $items = parse_generic_findings_text($raw, $final_tool_key);
      foreach ($items as $f) {
        $insertFinding($run_id, $f['tool'], $f['severity'], $f['template'], $f['target'], $f['title'], $f['raw']);
      }
      $summary = ['tool_key'=>$final_tool_key,'parsed'=>true,'findings_added'=>count($items),'note'=>$hasFindings?'':'oneinseclabs_findings missing'];
    }

    // NUCLEI -> findings (if table exists)
    if ($final_tool_key === 'nuclei') {
      $cnt = 0;
      if ($hasFindings) {
        $findings = parse_nuclei_findings($raw);
        foreach ($findings as $f) {
          $tool = 'nuclei';
          $sev  = (string)($f['severity'] ?? 'info');
          $tpl  = (string)($f['template'] ?? '');
          $tgt  = (string)($f['target'] ?? '');
          $ttl  = (string)($f['name'] ?? '');
          $rw   = (string)($f['raw'] ?? '');
          $insertFinding($run_id, $tool, $sev, $tpl, $tgt, $ttl, $rw);
          $cnt++;
        }
      }
      $summary = ['tool_key'=>'nuclei','parsed'=>true,'findings_added'=>$cnt,'note'=>$hasFindings?'':'oneinseclabs_findings missing'];
    }

    // NMAP -> hosts/ports (+ run_hosts/run_ports) (your existing nmap block should remain here)
    if ($final_tool_key === 'nmap') {
      $parsed = function_exists('parse_nmap_any') ? parse_nmap_any($raw) : ['hosts'=>[]];
      $hostCount = 0; $portCount = 0;

      $stRunHost = null;
      $stRunPort = null;
      if ($hasRunHosts) {
        $stRunHost = $conn->prepare("INSERT IGNORE INTO oneinseclabs_run_hosts (run_id, project_id, ip_address, hostname)
                                     VALUES (?,?,?,?)");
      }
      if ($hasRunPorts) {
        $stRunPort = $conn->prepare("INSERT IGNORE INTO oneinseclabs_run_ports
          (run_id, project_id, ip_address, port, protocol, state, service, product, version, extrainfo)
          VALUES (?,?,?,?,?,?,?,?,?,?)");
      }

      foreach ($parsed['hosts'] as $h) {
        $ip = (string)($h['ip'] ?? '');
        if ($ip === '') continue;

        $hostname = $h['hostname'] ?? null;
        if ($hostname) {
          $hostname = norm_host((string)$hostname);
          if ($hostname === '') $hostname = null;
        }

        $hosts_has_ip = column_exists($conn, "oneinseclabs_hosts", "ip");
        $hosts_has_ip_addr = column_exists($conn, "oneinseclabs_hosts", "ip_address");

        if ($hosts_has_ip && $hosts_has_ip_addr) {
          $stH = $conn->prepare("INSERT INTO oneinseclabs_hosts (project_id, ip, ip_address, hostname, source_run_id)
                                 VALUES (?,?,?,?,?)
                                 ON DUPLICATE KEY UPDATE ip=VALUES(ip), ip_address=VALUES(ip_address),
                                                         hostname=COALESCE(VALUES(hostname), hostname)");
          $stH->bind_param("isssi", $project_id, $ip, $ip, $hostname, $run_id);
        } elseif ($hosts_has_ip_addr) {
          $stH = $conn->prepare("INSERT INTO oneinseclabs_hosts (project_id, ip_address, hostname, source_run_id)
                                 VALUES (?,?,?,?)
                                 ON DUPLICATE KEY UPDATE hostname=COALESCE(VALUES(hostname), hostname)");
          $stH->bind_param("issi", $project_id, $ip, $hostname, $run_id);
        } else {
          $stH = $conn->prepare("INSERT INTO oneinseclabs_hosts (project_id, ip, hostname, source_run_id)
                                 VALUES (?,?,?,?)
                                 ON DUPLICATE KEY UPDATE hostname=COALESCE(VALUES(hostname), hostname)");
          $stH->bind_param("issi", $project_id, $ip, $hostname, $run_id);
        }
        $stH->execute();

        if ($stRunHost) {
          $hn = $hostname ?? '';
          $stRunHost->bind_param("iiss", $run_id, $project_id, $ip, $hn);
          $stRunHost->execute();
        }

        // Get host_id (schema-safe)
        if ($hosts_has_ip_addr) {
          $q = $conn->prepare("SELECT id FROM oneinseclabs_hosts WHERE project_id=? AND ip_address=? LIMIT 1");
          $q->bind_param("is", $project_id, $ip);
        } else {
          $q = $conn->prepare("SELECT id FROM oneinseclabs_hosts WHERE project_id=? AND ip=? LIMIT 1");
          $q->bind_param("is", $project_id, $ip);
        }
        $q->execute();
        $host_id = (int)($q->get_result()->fetch_assoc()['id'] ?? 0);
        if ($host_id <= 0) continue;
        $hostCount++;

        foreach (($h['ports'] ?? []) as $p) {
          $stP = $conn->prepare("INSERT INTO oneinseclabs_ports (project_id, host_id, port, protocol, state, service, product, version, extrainfo, source_run_id)
                                 VALUES (?,?,?,?,?,?,?,?,?,?)
                                 ON DUPLICATE KEY UPDATE state=VALUES(state), service=VALUES(service), product=VALUES(product),
                                                         version=VALUES(version), extrainfo=VALUES(extrainfo)");
          $stP->bind_param(
            "iiissssssi",
            $project_id, $host_id, $p['port'], $p['protocol'], $p['state'],
            $p['service'], $p['product'], $p['version'], $p['extrainfo'], $run_id
          );
          $stP->execute();
          $portCount++;

          if ($stRunPort) {
            $port  = (int)$p['port'];
            $proto = (string)$p['protocol'];
            $state = (string)$p['state'];
            $svc   = (string)$p['service'];
            $prod  = (string)$p['product'];
            $ver   = (string)$p['version'];
            $extra = (string)$p['extrainfo'];

            $stRunPort->bind_param("iisissssss", $run_id, $project_id, $ip, $port, $proto, $state, $svc, $prod, $ver, $extra);
            $stRunPort->execute();
          }
        }
      }

      $summary = ['tool_key'=>'nmap','parsed'=>true,'hosts'=>$hostCount,'ports'=>$portCount];
    }

    // Save file row
    $fileStmt = $conn->prepare("INSERT INTO oneinseclabs_recon_files (run_id, original_filename, stored_path, mime_type, size_bytes, sha256, parsed_summary)
                                VALUES (?,?,?,?,?,?,?)");
    $sum_json = json_encode($summary);
    $fileStmt->bind_param("isssiss", $run_id, $origName, $stored_rel, $mimeGuess, $sizeGuess, $sha, $sum_json);
    $fileStmt->execute();

    return $summary;
  };

  // ZIP bundle processor
  $processZipBundle = function(int $run_id, array $file, string $tool_key, string $root_ctx)
    use ($processBlob) : array {

    if (!class_exists('ZipArchive')) throw new RuntimeException("ZipArchive not available on server.");
    $zip = new ZipArchive();
    if ($zip->open($file['tmp']) !== true) throw new RuntimeException("Unable to open ZIP: " . $file['name']);

    $maxFiles = 800;
    $maxEach  = 12 * 1024 * 1024;
    $maxTotal = 350 * 1024 * 1024;

    $totalUnc = 0;
    $parsed = 0;
    $skipped = 0;

    for ($i=0; $i < $zip->numFiles; $i++) {
      if ($i >= $maxFiles) { $skipped += ($zip->numFiles - $i); break; }
      $stat = $zip->statIndex($i);
      if (!$stat) { $skipped++; continue; }

      $name = (string)($stat['name'] ?? '');
      if ($name === '' || str_ends_with($name,'/')) continue;

      $clean = str_replace('\\','/',$name);
      $clean = ltrim($clean, '/');
      if (strpos($clean, '../') !== false || str_starts_with($clean, '../')) { $skipped++; continue; }

      $ext = strtolower(pathinfo($clean, PATHINFO_EXTENSION));
      if (!in_array($ext, ['txt','log','json','xml','csv'], true)) { $skipped++; continue; }

      $unc = (int)($stat['size'] ?? 0);
      $totalUnc += $unc;
      if ($totalUnc > $maxTotal) { $skipped++; break; }
      if ($unc <= 0 || $unc > $maxEach) { $skipped++; continue; }

      $raw = $zip->getFromIndex($i);
      if ($raw === false) { $skipped++; continue; }
      $raw = (string)$raw;
      if (trim($raw) === '') { $skipped++; continue; }

      $det = ($tool_key === 'auto' || $tool_key === 'bundle')
        ? detect_tool_key_by_path($clean, $raw)
        : $tool_key;

      $mime = ($ext === 'xml') ? 'application/xml' : (($ext === 'json') ? 'application/json' : 'text/plain');

      $processBlob($run_id, $clean, $raw, $mime, strlen($raw), $det, $root_ctx);
      $parsed++;
    }

    $zipFiles = $zip->numFiles;
    $zip->close();

    return [
      'tool_key'=>'bundle','parsed'=>true,'zip_files'=>$zipFiles,
      'parsed_files'=>$parsed,'skipped_files'=>$skipped,'uncompressed_bytes'=>$totalUnc
    ];
  };

  // paste only
  if (!count($files) && $paste_text !== '') {
    $det = ($tool_key === 'auto') ? detect_tool_key($paste_text) : $tool_key;
    $run_id = $createRun($det, $tool_name, $category, $notes, $root_ctx, "paste");
    $name = "paste_" . ($det ?: 'output') . ".txt";
    $processBlob($run_id, $name, $paste_text, "text/plain", strlen($paste_text), $det, $root_ctx);
  }

  // uploaded files
  if (count($files)) {
    foreach ($files as $f) {
      if ((int)$f['err'] !== 0) continue;

      $ext = strtolower(pathinfo($f['name'], PATHINFO_EXTENSION));
      $is_zip = ($ext === 'zip') || ($f['type'] === 'application/zip') || ($tool_key === 'bundle');

      if ($is_zip) {
        $target_label = basename($f['name']);
        $run_id = $createRun('bundle', ($tool_name ?: 'ZIP Bundle'), ($category ?: 'bundle'), $notes, $root_ctx, $target_label);

        $bundleSummary = $processZipBundle($run_id, $f, $tool_key, $root_ctx);

        // store ZIP artifact itself
        $zipRaw = file_get_contents($f['tmp']);
        if ($zipRaw !== false) {
          $sha = hash('sha256', $zipRaw);
          $sha8 = substr($sha, 0, 8);
          $safeName = preg_replace('/[^a-zA-Z0-9._-]/','_', basename($f['name']));
          if ($safeName === '') $safeName = "bundle.zip";
          $stored = __DIR__ . "/uploads/tool_outputs/p{$project_id}/" . date('Ymd_His') . "_{$run_id}_{$sha8}_" . $safeName;
          @file_put_contents($stored, $zipRaw);
          $stored_rel = "uploads/tool_outputs/p{$project_id}/" . basename($stored);

          $fileStmt = $conn->prepare("INSERT INTO oneinseclabs_recon_files (run_id, original_filename, stored_path, mime_type, size_bytes, sha256, parsed_summary)
                                      VALUES (?,?,?,?,?,?,?)");
          $sum_json = json_encode($bundleSummary);
          $mime = 'application/zip';
          $size = (int)$f['size'];
          $fileStmt->bind_param("isssiss", $run_id, $f['name'], $stored_rel, $mime, $size, $sha, $sum_json);
          $fileStmt->execute();
        }
        continue;
      }

      $raw = file_get_contents($f['tmp']);
      if ($raw === false || trim($raw)==='') continue;

      $det = ($tool_key === 'auto') ? detect_tool_key($raw) : $tool_key;
      $target_label = basename($f['name']);
      $run_id = $createRun($det, $tool_name, $category, $notes, $root_ctx, $target_label);
      $processBlob($run_id, $f['name'], (string)$raw, $f['type'], (int)$f['size'], $det, $root_ctx);
    }
  }

  if ($return_to !== '') redirect($return_to);
  redirect("project.php?id=".$project_id);

} catch (Throwable $e) {
  fail500("Unhandled exception in upload.php", $e);
}
