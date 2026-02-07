<?php
/**
 * public_html/one.inseclabs.com/includes/parsers.php
 * Full parsers pack for OneInSecLabs (subdomains, dnsx, wayback, httpx, nmap, naabu, nuclei)
 * + Bundle parsers: ffuf/dirsearch endpoints, gowitness screenshots, arjun/paramspider params,
 *   subjack takeover findings, sqlmap/xsstrike generic findings.
 */

require_once __DIR__ . '/util.php';

/** -----------------------------
 * Polyfills (safe to include)
 * ----------------------------- */
if (!function_exists('str_contains')) {
  function str_contains(string $haystack, string $needle): bool {
    return $needle === '' || strpos($haystack, $needle) !== false;
  }
}
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

/**
 * Normalize host/domain from any input line
 */
function norm_host(string $s): string {
  $s = trim(strtolower($s));
  if ($s === '') return '';
  $s = preg_replace('#^https?://#', '', $s);
  $s = preg_replace('#/.*$#', '', $s);
  $s = preg_replace('/^\*\./', '', $s);
  $s = rtrim($s, '.');
  return $s;
}

/**
 * Load project roots from DB
 */
function load_project_roots(mysqli $conn, int $project_id): array {
  $st = $conn->prepare("SELECT root_domain FROM oneinseclabs_project_domains WHERE project_id=?");
  $st->bind_param("i", $project_id);
  $st->execute();
  $rs = $st->get_result();
  $roots = [];
  while ($r = $rs->fetch_assoc()) {
    $d = norm_host($r['root_domain'] ?? '');
    if ($d !== '') $roots[] = $d;
  }

  // Sort by longest first so suffix match picks the best root
  usort($roots, fn($a,$b)=>strlen($b)<=>strlen($a));
  return array_values(array_unique($roots));
}

/**
 * Best root match using project roots (longest suffix wins).
 * Returns null if no match.
 */
function match_project_root(string $host, array $project_roots): ?string {
  $host = norm_host($host);
  if ($host === '') return null;

  foreach ($project_roots as $root) {
    if ($root === '') continue;
    if ($host === $root) return $root;
    if (str_ends_with($host, '.' . $root)) return $root;
  }
  return null;
}

/**
 * Improved fallback root guess (handles common multi-part TLDs).
 * Only used if project roots are not available/matching.
 */
function guess_root_domain(string $domain): string {
  $domain = norm_host($domain);
  $parts = explode('.', $domain);
  $n = count($parts);
  if ($n <= 2) return $domain;

  $tld = $parts[$n-1];
  $sld = $parts[$n-2];

  // common multi-part suffixes
  $multiSecond = ['co','com','net','org','gov','ac','edu','res'];
  $multiTld    = ['in','uk','au','jp','nz'];

  if (in_array($tld, $multiTld, true) && in_array($sld, $multiSecond, true) && $n >= 3) {
    return $parts[$n-3] . '.' . $sld . '.' . $tld;
  }

  return $sld . '.' . $tld;
}

/** ============================================================
 *  SUBDOMAINS parser (Upgraded: supports subfinder/amass etc.)
 * ============================================================ */
function parse_subdomains_text(string $text): array {
  $text = str_replace("\r", "\n", $text);
  $lines = preg_split("/\n+/", $text);
  $out = [];

  foreach ($lines as $l) {
    $l = trim($l);
    if ($l === '') continue;

    // strip common prefixes [*], [+], [INF], etc.
    $l = preg_replace('/^\[[^\]]+\]\s*/', '', $l);
    $l = preg_replace('/^\(\*\)\s*/', '', $l);
    $l = preg_replace('/^\+\s*/', '', $l);
    $l = preg_replace('/^-\s*/', '', $l);

    // extract any domain-like tokens inside line
    if (preg_match_all('/\b([a-z0-9][a-z0-9.-]+\.[a-z]{2,})\b/i', $l, $m)) {
      foreach ($m[1] as $d) {
        $h = norm_host($d);
        if ($h === '') continue;
        if (strpos($h, '..') !== false) continue;
        // keep it domainish
        if (!preg_match('/^[a-z0-9.-]+\.[a-z]{2,}$/', $h)) continue;
        $out[$h] = true;
      }
    }
  }
  return array_keys($out);
}

/**
 * dnsx -resp output parser (sub + ip pairs)
 */
function parse_dnsx_resolved(string $text): array {
  $lines = preg_split("/\r\n|\n|\r/", $text);
  $pairs = [];
  foreach ($lines as $l) {
    $l = trim($l);
    if ($l === '') continue;
    if (!preg_match('/^([a-z0-9.-]+\.[a-z]{2,})/i', $l, $m)) continue;
    $sub = norm_host($m[1]);
    if ($sub === '') continue;

    if (preg_match_all('/\b(\d{1,3}(?:\.\d{1,3}){3})\b/', $l, $ips)) {
      foreach ($ips[1] as $ip) {
        $pairs[] = ['subdomain'=>$sub, 'ip'=>$ip];
      }
    }
  }
  return $pairs;
}

function parse_wayback_urls(string $text): array {
  $lines = preg_split("/\r\n|\n|\r/", $text);
  $out = [];
  foreach ($lines as $l) {
    $l = trim($l);
    if ($l === '') continue;
    if (!preg_match('#^https?://#i', $l)) continue;
    $out[$l] = true;
  }
  return array_keys($out);
}

function parse_httpx_lines(string $text): array {
  $lines = preg_split("/\r\n|\n|\r/", $text);
  $out = [];
  foreach ($lines as $l) {
    $l = trim($l);
    if ($l === '') continue;
    if (!preg_match('#^https?://\S+#i', $l, $m)) continue;

    $url = $m[0];
    $status = null;
    if (preg_match('/\[(\d{3})\]/', $l, $s)) $status = (int)$s[1];

    $title = null;
    // httpx formats vary; keep safe
    if (preg_match('/\[(?:[^\]]*?)\]\s*\[(.*?)\]/', $l, $t)) {
      $title = mb_substr(trim($t[1]), 0, 255);
    }

    $out[] = ['url'=>$url, 'status'=>$status, 'title'=>$title];
  }
  return $out;
}

/** ============================================================
 *  Nmap parsers (XML / GNMAP / -oN)
 * ============================================================ */
function parse_nmap_xml(string $xml): array {
  libxml_use_internal_errors(true);
  $sx = simplexml_load_string($xml);
  if (!$sx) return ['hosts'=>[]];

  $hosts = [];
  foreach ($sx->host as $h) {
    $addr = '';
    if ($h->address) {
      foreach ($h->address as $a) {
        $t = (string)($a['addrtype'] ?? '');
        if ($t === 'ipv4') { $addr = (string)($a['addr'] ?? ''); break; }
      }
      if ($addr === '') $addr = (string)($h->address[0]['addr'] ?? '');
    }
    $addr = trim($addr);
    if ($addr === '') continue;

    $hostname = null;
    if ($h->hostnames && $h->hostnames->hostname) {
      $hostname = (string)($h->hostnames->hostname[0]['name'] ?? '');
      $hostname = $hostname ? norm_host($hostname) : null;
    }

    $ports = [];
    if ($h->ports && $h->ports->port) {
      foreach ($h->ports->port as $p) {
        $portid = (int)$p['portid'];
        $proto = (string)$p['protocol'];
        $state = (string)($p->state['state'] ?? '');
        $service = (string)($p->service['name'] ?? '');
        $product = (string)($p->service['product'] ?? '');
        $version = (string)($p->service['version'] ?? '');
        $extrainfo = (string)($p->service['extrainfo'] ?? '');
        $ports[] = [
          'port'=>$portid,'protocol'=>$proto,'state'=>$state,
          'service'=>$service,'product'=>$product,'version'=>$version,'extrainfo'=>$extrainfo
        ];
      }
    }

    $hosts[] = ['ip'=>$addr, 'hostname'=>$hostname, 'ports'=>$ports];
  }
  return ['hosts'=>$hosts];
}

function parse_nmap_gnmap(string $text): array {
  $lines = preg_split("/\r\n|\n|\r/", $text);
  $hosts = [];

  foreach ($lines as $l) {
    $l = trim($l);
    if ($l === '' || stripos($l, 'Host:') !== 0) continue;

    if (!preg_match('/^Host:\s+(\S+)\s+\((.*?)\)\s*(.*)$/i', $l, $m)) continue;
    $ip = trim($m[1]);
    $hn = trim($m[2]) ?: null;
    $rest = trim($m[3]);

    $ports = [];
    if (stripos($rest, 'Ports:') !== false) {
      $portsPart = preg_split('/\bPorts:\b/i', $rest, 2)[1] ?? '';
      $portsPart = preg_split('/\s+Ignored State:|\s+OS:|\s+Seq Index:|\s+Status:/i', $portsPart)[0];
      $entries = array_map('trim', explode(',', $portsPart));
      foreach ($entries as $e) {
        if ($e === '') continue;
        $bits = explode('/', $e);
        if (count($bits) < 3) continue;
        $port = (int)$bits[0];
        $state = $bits[1] ?? '';
        $proto = $bits[2] ?? '';
        $svc = $bits[4] ?? ($bits[3] ?? '');
        $svc = $svc ?: '';
        $ports[] = [
          'port'=>$port,
          'protocol'=>$proto,
          'state'=>$state,
          'service'=>$svc,
          'product'=>'',
          'version'=>'',
          'extrainfo'=>''
        ];
      }
    }

    $hosts[] = ['ip'=>$ip, 'hostname'=>$hn ? norm_host($hn) : null, 'ports'=>$ports];
  }

  return ['hosts'=>$hosts];
}

function parse_nmap_normal(string $text): array {
  $lines = preg_split("/\r\n|\n|\r/", $text);

  $hosts = [];
  $curIp = null;
  $curHost = null;
  $curPorts = [];
  $inPorts = false;

  $flush = function() use (&$hosts, &$curIp, &$curHost, &$curPorts, &$inPorts) {
    if ($curIp) $hosts[] = ['ip'=>$curIp, 'hostname'=>$curHost, 'ports'=>$curPorts];
    $curIp = null; $curHost = null; $curPorts = []; $inPorts = false;
  };

  foreach ($lines as $rawLine) {
    $l = rtrim($rawLine);

    if (preg_match('/^Nmap scan report for (.+)$/i', $l, $m)) {
      $flush();
      $target = trim($m[1]);

      if (preg_match('/^(.*?)\s+\((\d{1,3}(?:\.\d{1,3}){3})\)$/', $target, $m2)) {
        $curHost = norm_host(trim($m2[1]));
        $curIp   = $m2[2];
      } elseif (preg_match('/^(\d{1,3}(?:\.\d{1,3}){3})$/', $target, $m2)) {
        $curIp = $m2[1];
        $curHost = null;
      } else {
        $curHost = norm_host($target);
        $curIp = null;
      }
      continue;
    }

    if ($curIp === null && $curHost && preg_match('/\b(\d{1,3}(?:\.\d{1,3}){3})\b/', $l, $mip)) {
      $curIp = $mip[1];
    }

    if (preg_match('/^PORT\s+STATE\s+SERVICE/i', $l)) { $inPorts = true; continue; }

    if ($inPorts) {
      if ($l === '' || preg_match('/^Nmap done:/i', $l) || preg_match('/^Service detection performed/i', $l)) {
        $inPorts = false;
        continue;
      }

      if (preg_match('/^(\d+)\/([a-z0-9]+)\s+(\S+)\s+(\S+)\s*(.*)$/i', trim($l), $m)) {
        $port = (int)$m[1];
        $proto = strtolower($m[2]);
        $state = strtolower($m[3]);
        $svc = strtolower($m[4]);
        $rest = trim($m[5]);

        $curPorts[] = [
          'port'=>$port,'protocol'=>$proto,'state'=>$state,'service'=>$svc,
          'product'=>'','version'=>'','extrainfo'=>$rest
        ];
      }
    }
  }

  $flush();
  $hosts = array_values(array_filter($hosts, fn($h)=>!empty($h['ip'])));
  return ['hosts'=>$hosts];
}

function parse_nmap_any(string $raw): array {
  $s = strtolower($raw);
  if (strpos($s, '<nmaprun') !== false) return parse_nmap_xml($raw);
  if (strpos($s, 'host:') !== false) return parse_nmap_gnmap($raw);
  if (strpos($s, 'nmap scan report for') !== false) return parse_nmap_normal($raw);
  return ['hosts'=>[]];
}

/** ============================================================
 *  Naabu output parser
 * ============================================================ */
function parse_naabu_ports(string $text): array {
  $lines = preg_split("/\r\n|\n|\r/", $text);
  $out = [];
  foreach ($lines as $ln) {
    $ln = trim($ln);
    if ($ln === '' || $ln[0] === '#') continue;

    // normalize url -> host:port
    if (preg_match('#^https?://#i', $ln)) {
      $u = parse_url($ln);
      if (!$u || empty($u['host'])) continue;
      $host = strtolower($u['host']);
      $port = (int)($u['port'] ?? (strtolower($u['scheme'] ?? '') === 'https' ? 443 : 80));
      $out[] = ['host'=>$host,'port'=>$port,'proto'=>'tcp'];
      continue;
    }

    // host:port or host:port/tcp
    if (preg_match('/^([a-z0-9._-]+):(\d{1,5})(?:\/(tcp|udp))?$/i', $ln, $m)) {
      $host = strtolower($m[1]);
      $port = (int)$m[2];
      $proto = strtolower($m[3] ?? 'tcp');
      if ($port < 1 || $port > 65535) continue;
      $out[] = ['host'=>$host,'port'=>$port,'proto'=>$proto];
    }
  }
  return $out;
}

/**
 * Generic URL parser (katana/gau/waybackurls/etc) - one URL per line.
 */
function parse_urls_generic(string $text): array {
  $lines = preg_split("/\r\n|\n|\r/", $text);
  $urls = [];
  foreach ($lines as $ln) {
    $ln = trim($ln);
    if ($ln === '' || $ln[0] === '#') continue;
    if (!preg_match('#^https?://#i', $ln)) continue;
    $ln = preg_replace('/\s+.*$/', '', $ln);
    $urls[] = $ln;
  }
  return array_values(array_unique($urls));
}

/** ============================================================
 *  Nuclei output parser (JSONL + bracket format)
 * ============================================================ */
function parse_nuclei_findings(string $text): array {
  $lines = preg_split("/\r\n|\n|\r/", $text);
  $out = [];
  foreach ($lines as $ln) {
    $raw = trim($ln);
    if ($raw === '') continue;

    // JSONL
    if ($raw[0] === '{' && str_ends_with($raw, '}')) {
      $j = json_decode($raw, true);
      if (is_array($j)) {
        $out[] = [
          'target'   => (string)($j['matched-at'] ?? $j['host'] ?? $j['url'] ?? ''),
          'template' => (string)($j['template-id'] ?? $j['template'] ?? ''),
          'severity' => strtolower((string)($j['info']['severity'] ?? $j['severity'] ?? 'info')),
          'name'     => (string)($j['info']['name'] ?? $j['name'] ?? ''),
          'matcher'  => (string)($j['matcher-name'] ?? $j['matcher'] ?? ''),
          'raw'      => $raw
        ];
        continue;
      }
    }

    // bracket format
    preg_match_all('/\[(.*?)\]/', $raw, $bm);
    $br = $bm[1] ?? [];
    $target = '';
    if (preg_match('#https?://[^\s]+#i', $raw, $um)) $target = $um[0];

    $template = $br[0] ?? '';
    $severity = strtolower($br[1] ?? '');
    $name = '';

    // if first bracket is severity
    if ($severity === '' && isset($br[0]) && preg_match('/^(info|low|medium|high|critical)$/i', $br[0])) {
      $severity = strtolower($br[0]);
      $template = $br[1] ?? '';
    }
    if ($severity === '') $severity = 'info';

    $out[] = [
      'target'   => $target,
      'template' => $template,
      'severity' => $severity,
      'name'     => $name,
      'matcher'  => '',
      'raw'      => $raw
    ];
  }
  return $out;
}

/** ============================================================
 *  FFUF endpoints parser (JSON)
 * ============================================================ */
function parse_ffuf_json(string $raw): array {
  $j = json_decode($raw, true);
  if (!is_array($j)) return [];
  $results = $j['results'] ?? [];
  if (!is_array($results)) return [];

  $out = [];
  foreach ($results as $r) {
    if (!is_array($r)) continue;
    $url = (string)($r['url'] ?? '');
    if ($url === '') continue;

    $out[] = [
      'url'   => $url,
      'status'=> isset($r['status']) ? (int)$r['status'] : null,
      'words' => isset($r['words']) ? (int)$r['words'] : null,
      'lines' => isset($r['lines']) ? (int)$r['lines'] : null,
      'size'  => isset($r['length']) ? (int)$r['length'] : (isset($r['size']) ? (int)$r['size'] : null),
      'type'  => isset($r['content-type']) ? (string)$r['content-type'] : (isset($r['content_type']) ? (string)$r['content_type'] : null),
      'source'=> 'ffuf',
    ];
  }
  return $out;
}

/** ============================================================
 *  Dirsearch endpoints parser (JSON or CSV)
 * ============================================================ */
function parse_dirsearch(string $raw, string $ext=''): array {
  $ext = strtolower($ext);

  // JSON
  $j = json_decode($raw, true);
  if (is_array($j)) {
    $out = [];
    if (isset($j['results']) && is_array($j['results'])) {
      foreach ($j['results'] as $r) {
        if (!is_array($r)) continue;
        $url = (string)($r['url'] ?? '');
        if ($url === '') continue;
        $out[] = [
          'url'=>$url,
          'status'=> isset($r['status']) ? (int)$r['status'] : null,
          'size'=> isset($r['size']) ? (int)$r['size'] : null,
          'type'=> isset($r['content-type']) ? (string)$r['content-type'] : null,
          'words'=> null,
          'lines'=> null,
          'source'=>'dirsearch',
        ];
      }
      return $out;
    }
  }

  // CSV best-effort
  $out = [];
  $raw = str_replace("\r","\n",$raw);
  $lines = preg_split("/\n+/", $raw);
  foreach ($lines as $i=>$ln) {
    $ln = trim($ln);
    if ($ln === '') continue;
    if ($i===0 && stripos($ln,'url')!==false && stripos($ln,'status')!==false) continue;

    $cols = str_getcsv($ln);
    if (count($cols) < 2) continue;

    $url = (string)($cols[0] ?? '');
    $status = isset($cols[1]) ? (int)$cols[1] : null;
    $size = isset($cols[2]) ? (int)$cols[2] : null;

    if ($url !== '') {
      $out[] = ['url'=>$url,'status'=>$status,'size'=>$size,'words'=>null,'lines'=>null,'type'=>null,'source'=>'dirsearch'];
    }
  }
  return $out;
}

/** ============================================================
 *  Gowitness JSON parser (metadata)
 * ============================================================ */
function parse_gowitness_json(string $raw): array {
  $j = json_decode($raw, true);
  if (!is_array($j)) return [];

  $out = [];

  // allow wrapper {results:[...]} or direct [...]
  $arr = $j;
  if (isset($j['results']) && is_array($j['results'])) $arr = $j['results'];

  if (!is_array($arr)) return [];

  foreach ($arr as $r) {
    if (!is_array($r)) continue;
    $url = (string)($r['url'] ?? $r['uri'] ?? '');
    if ($url === '') continue;

    $shot = (string)($r['screenshot_path'] ?? $r['screenshot'] ?? $r['path'] ?? $r['filename'] ?? '');
    if ($shot === '') continue;

    $out[] = [
      'url' => $url,
      'title' => (string)($r['title'] ?? ''),
      'status' => isset($r['status_code']) ? (int)$r['status_code'] : (isset($r['status']) ? (int)$r['status'] : null),
      'image_path' => $shot,
      'source' => 'gowitness',
    ];
  }
  return $out;
}

/** ============================================================
 *  ParamSpider parser (URLs with query params)
 * ============================================================ */
function parse_paramspider(string $raw): array {
  $out = [];
  $raw = str_replace("\r","\n",$raw);
  foreach (preg_split("/\n+/", $raw) as $ln) {
    $ln = trim($ln);
    if ($ln === '' || stripos($ln,'http') !== 0) continue;
    $q = parse_url($ln, PHP_URL_QUERY);
    if (!$q) continue;
    parse_str($q, $pairs);
    foreach (array_keys($pairs) as $k) {
      $k = trim((string)$k);
      if ($k === '') continue;
      $out[] = ['url'=>$ln, 'host'=> (string)parse_url($ln, PHP_URL_HOST), 'param'=>$k, 'source'=>'paramspider'];
    }
  }
  return $out;
}

/** ============================================================
 *  Arjun parser (JSON map or text best-effort)
 * ============================================================ */
function parse_arjun(string $raw): array {
  $j = json_decode($raw, true);
  $out = [];

  // common: { "https://x/": ["a","b"] }
  if (is_array($j)) {
    foreach ($j as $url => $params) {
      if (!is_string($url)) continue;
      if (!is_array($params)) continue;
      foreach ($params as $p) {
        $p = trim((string)$p);
        if ($p==='') continue;
        $out[] = ['url'=>$url, 'host'=>(string)parse_url($url, PHP_URL_HOST), 'param'=>$p, 'source'=>'arjun'];
      }
    }
    if ($out) return $out;
  }

  // text fallback
  $raw = str_replace("\r","\n",$raw);
  $curUrl = '';
  foreach (preg_split("/\n+/", $raw) as $ln) {
    $ln = trim($ln);
    if ($ln === '') continue;

    if (preg_match('#^https?://#i', $ln)) {
      $curUrl = $ln;
      continue;
    }
    if (preg_match('/^\s*-\s*([a-z0-9_%-]+)\s*$/i', $ln, $m) && $curUrl !== '') {
      $out[] = ['url'=>$curUrl,'host'=>(string)parse_url($curUrl, PHP_URL_HOST),'param'=>$m[1],'source'=>'arjun'];
    }
  }
  return $out;
}

/** ============================================================
 *  Subjack parser -> possible takeover findings
 * ============================================================ */
function parse_subjack(string $raw): array {
  $out = [];
  $raw = str_replace("\r","\n",$raw);
  foreach (preg_split("/\n+/", $raw) as $ln) {
    $ln = trim($ln);
    if ($ln === '') continue;

    if (stripos($ln,'vulnerable') !== false) {
      if (preg_match('/\b([a-z0-9.-]+\.[a-z]{2,})\b/i', $ln, $m)) {
        $out[] = [
          'tool'=>'subjack',
          'severity'=>'high',
          'template'=>'subdomain-takeover',
          'target'=>$m[1],
          'title'=>'Possible Subdomain Takeover',
          'raw'=>$ln,
        ];
      }
    }
  }
  return $out;
}

/** ============================================================
 *  Generic findings parser (sqlmap / xsstrike etc.)
 * ============================================================ */
function parse_generic_findings_text(string $raw, string $tool): array {
  $out = [];
  $raw = str_replace("\r","\n",$raw);

  foreach (preg_split("/\n+/", $raw) as $ln) {
    $ln = trim($ln);
    if ($ln === '') continue;

    if (stripos($ln,'parameter') !== false || stripos($ln,'inject') !== false || stripos($ln,'vulnerable') !== false) {
      $target = '';
      if (preg_match('#https?://[^\s]+#i', $ln, $m)) $target = $m[0];
      if ($target === '') $target = $ln;

      $sev = 'medium';
      if (stripos($ln,'critical') !== false) $sev = 'critical';
      elseif (stripos($ln,'high') !== false) $sev = 'high';
      elseif (stripos($ln,'low') !== false) $sev = 'low';

      $out[] = [
        'tool'=>$tool,
        'severity'=>$sev,
        'template'=> null,
        'target'=>$target,
        'title'=> strtoupper($tool) . ' finding',
        'raw'=>$ln,
      ];
    }
  }
  return $out;
}

/** ============================================================
 *  Tool detection by path inside ZIP bundle
 * ============================================================ */
function detect_tool_key_by_path(string $relpath, string $content): string {
  $p = strtolower(str_replace('\\', '/', $relpath));
  $s = strtolower($content);

  // strong path matches
  if (strpos($p, 'nuclei') !== false) return 'nuclei';
  if (strpos($p, 'nmap') !== false) return 'nmap';
  if (strpos($p, 'naabu') !== false) return 'naabu';
  if (strpos($p, 'dnsx') !== false || strpos($p, 'resolved') !== false) return 'dnsx';
  if (strpos($p, 'httpx') !== false) return 'httpx';
  if (strpos($p, 'waybackurls') !== false) return 'waybackurls';
  if (strpos($p, 'katana') !== false) return 'katana';
  if (strpos($p, 'gau') !== false) return 'gau';
  if (strpos($p, 'wayback') !== false || strpos($p, 'urls') !== false || strpos($p, 'crawled') !== false) return 'wayback';

  if (strpos($p, 'ffuf') !== false) return 'ffuf';
  if (strpos($p, 'dirsearch') !== false) return 'dirsearch';
  if (strpos($p, 'gowitness') !== false) return 'gowitness';

  if (strpos($p, 'arjun') !== false) return 'arjun';
  if (strpos($p, 'paramspider') !== false) return 'paramspider';

  if (strpos($p, 'subjack') !== false) return 'subjack';
  if (strpos($p, 'sqlmap') !== false) return 'sqlmap';
  if (strpos($p, 'xsstrike') !== false) return 'xsstrike';

  // subdomains (many names)
  if (preg_match('/\b(subfinder|assetfinder|amass|subdomains?|subs?)\b/', $p)) return 'subdomains';
  if (str_contains($p,'all_subdomains') || str_contains($p,'subdomains.txt') || str_contains($p,'subs.txt')) return 'subdomains';

  // content hints
  if (str_ends_with($p, '.xml') && strpos($s, '<nmaprun') !== false) return 'nmap';
  if (strpos($s, 'nmap scan report for') !== false) return 'nmap';
  if (strpos($s, '"commandline"') !== false && strpos($s, 'ffuf') !== false) return 'ffuf';
  if (strpos($s, '"results"') !== false && str_ends_with($p, '.json') && strpos($s, '"url"') !== false) return 'ffuf';
  if (strpos($s, 'gowitness') !== false && str_ends_with($p, '.json')) return 'gowitness';
  if (preg_match('#^\s*https?://#m', $content) && preg_match('/\[(\d{3})\]/', $content)) return 'httpx';
  if (preg_match('#^\s*https?://#m', $content)) return 'wayback';

  // default heuristic
  return detect_tool_key($content);
}
