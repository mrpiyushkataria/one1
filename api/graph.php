<?php
require_once __DIR__ . '/../includes/auth.php';
require_login();
$conn = db();

$project_id = (int)($_GET['project_id'] ?? 0);
$view = $_GET['view'] ?? 'assets'; // assets | workflow
$rootFilter = trim($_GET['root'] ?? '');
$rootFilter = preg_replace('#^https?://#','',$rootFilter);
$rootFilter = trim($rootFilter,'/');

$include = trim($_GET['include'] ?? 'roots,subdomains,dns,hosts,ports,urls,shodan');
$inc = array_filter(array_map('trim', explode(',', $include)));
$inc = array_fill_keys($inc, true);

$category = strtolower(trim($_GET['category'] ?? 'all'));
if (!in_array($category, ['all','recon','dns','web','network'], true)) $category = 'all';

if ($category !== 'all') {
  $allow = [
    'recon'    => ['roots','subdomains','runs','files'],
    'dns'      => ['dns','hosts','runs','files'],
    'web'      => ['urls','shodan','runs','files'],
    'network'  => ['ports','hosts','runs','files'],
  ][$category] ?? [];
  $inc = array_intersect_key($inc, array_fill_keys($allow, true));
}

$max = (int)($_GET['max'] ?? 12000);
$max = max(1000, min(50000, $max));

header('Content-Type: application/json');

if ($project_id <= 0) { echo json_encode(['nodes'=>[],'links'=>[]]); exit; }

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

$hasRunRoot = table_exists($conn,'oneinseclabs_recon_runs') && column_exists($conn, 'oneinseclabs_recon_runs', 'root_domain');
$hasRunHosts = table_exists($conn, 'oneinseclabs_run_hosts');
$hasRunPorts = table_exists($conn, 'oneinseclabs_run_ports');

$nodes = [];
$links = [];
$linkSet = [];

function addNode(&$nodes, string $id, string $type, string $label, array $extra=[]){
  if(isset($nodes[$id])) return;
  $nodes[$id] = array_merge(['id'=>$id,'type'=>$type,'label'=>$label], $extra);
}
function addLink(&$links, &$linkSet, string $src, string $dst, string $rel){
  $k = $src . '|' . $dst . '|' . $rel;
  if(isset($linkSet[$k])) return;
  $linkSet[$k] = true;
  $links[] = ['source'=>$src,'target'=>$dst,'rel'=>$rel];
}
function host_from_url(string $url): ?string {
  $h = parse_url($url, PHP_URL_HOST);
  if (!$h) return null;
  return strtolower($h);
}
function guess_root_from_host(string $host): ?string {
  $host = strtolower(trim($host));
  $host = rtrim($host,'.');
  $parts = explode('.', $host);
  if(count($parts) < 2) return null;
  return $parts[count($parts)-2] . '.' . $parts[count($parts)-1];
}

/**
 * WORKFLOW VIEW
 */
if ($view === 'workflow') {
  addNode($nodes, "project:$project_id", "project", "Project #$project_id");

  if (!table_exists($conn,'oneinseclabs_recon_runs')) {
    echo json_encode(['nodes'=>array_values($nodes),'links'=>$links], JSON_UNESCAPED_SLASHES);
    exit;
  }

  if ($hasRunRoot && $rootFilter !== '') {
    $runs = $conn->prepare("SELECT id, tool_key, tool_name, root_domain, target_label, created_at
                            FROM oneinseclabs_recon_runs
                            WHERE project_id=? AND root_domain=?
                            ORDER BY created_at ASC LIMIT 1000");
    $runs->bind_param("is",$project_id,$rootFilter);
  } else {
    $runs = $conn->prepare("SELECT id, tool_key, tool_name, created_at
                            FROM oneinseclabs_recon_runs
                            WHERE project_id=?
                            ORDER BY created_at ASC LIMIT 1000");
    $runs->bind_param("i",$project_id);
  }

  $runs->execute();
  $rs = $runs->get_result();

  $prev = null;
  while($r=$rs->fetch_assoc()){
    $rid = (int)$r['id'];
    $nid = "run:$rid";

    $toolLabel = ($r['tool_name'] ?: $r['tool_key']);
    $label = $toolLabel . " • " . ($r['created_at'] ?? '');
    if ($hasRunRoot && isset($r['root_domain']) && $r['root_domain']) $label .= "\n[".$r['root_domain']."]";
    if (isset($r['target_label']) && $r['target_label']) $label .= "\n".$r['target_label'];

    addNode($nodes, $nid, "run", $label, ['tool_key'=>$r['tool_key'] ?? '']);
    addLink($links, $linkSet, "project:$project_id", $nid, "has_run");

    if ($prev) addLink($links, $linkSet, $prev, $nid, "next");
    $prev = $nid;

    if (!table_exists($conn,'oneinseclabs_recon_files')) continue;

    $fs = $conn->prepare("SELECT id, original_filename, stored_path, parsed_summary, size_bytes
                          FROM oneinseclabs_recon_files WHERE run_id=? ORDER BY id ASC LIMIT 200");
    $fs->bind_param("i",$rid);
    $fs->execute();
    $frs = $fs->get_result();

    while($f=$frs->fetch_assoc()){
      $fid = (int)$f['id'];
      $fn = $f['original_filename'] ?: ('file_'.$fid);
      $fileNode = "file:$fid";

      $sum = [];
      if (!empty($f['parsed_summary'])) {
        $tmp = json_decode($f['parsed_summary'], true);
        if (is_array($tmp)) $sum = $tmp;
      }

      $extraLine = '';
      if (($sum['tool_key'] ?? '') === 'nmap') {
        $extraLine = "hosts+".(int)($sum['hosts'] ?? 0)." ports+".(int)($sum['ports'] ?? 0);
      } elseif (($sum['tool_key'] ?? '') === 'subdomains') {
        $extraLine = "subs+".(int)($sum['subdomains_added'] ?? 0);
      } elseif (($sum['tool_key'] ?? '') === 'dnsx') {
        $extraLine = "dns+".(int)($sum['dns_pairs_added'] ?? 0);
      } elseif (in_array(($sum['tool_key'] ?? ''), ['httpx','wayback'], true)) {
        $extraLine = "urls+".(int)($sum['urls_added'] ?? 0);
      }

      $fileLabel = $fn . ($extraLine ? ("\n".$extraLine) : '');
      addNode($nodes, $fileNode, "file", $fileLabel, ['path'=>$f['stored_path'] ?? '']);
      addLink($links, $linkSet, $nid, $fileNode, "has_file");

      if ($extraLine) {
        $out = "out:$fid";
        addNode($nodes, $out, "output", $extraLine);
        addLink($links, $linkSet, $fileNode, $out, "produced");
      }
    }
  }

  echo json_encode(['nodes'=>array_values($nodes),'links'=>$links], JSON_UNESCAPED_SLASHES);
  exit;
}

/**
 * ASSETS VIEW
 */
$ip2subs = [];
$ip2roots = [];

/**
 * ROOTS
 */
if (isset($inc['roots']) && table_exists($conn,'oneinseclabs_project_domains')) {
  if ($rootFilter !== '') {
    addNode($nodes, "root:$rootFilter", "root", $rootFilter);
    addNode($nodes, "sub:$rootFilter", "subdomain", $rootFilter);
    addLink($links, $linkSet, "root:$rootFilter", "sub:$rootFilter", "root_host");
  } else {
    $roots = $conn->query("SELECT root_domain FROM oneinseclabs_project_domains WHERE project_id=$project_id");
    while($r=$roots->fetch_assoc()){
      $root = $r['root_domain'];
      addNode($nodes, "root:$root", "root", $root);
      addNode($nodes, "sub:$root", "subdomain", $root);
      addLink($links, $linkSet, "root:$root", "sub:$root", "root_host");
    }
  }
}

/**
 * SUBDOMAINS
 */
if (isset($inc['subdomains']) && table_exists($conn,'oneinseclabs_subdomains')) {
  $sql = "SELECT root_domain, subdomain FROM oneinseclabs_subdomains WHERE project_id=? ";
  if ($rootFilter !== '') $sql .= " AND root_domain=? ";
  $sql .= " ORDER BY last_seen DESC LIMIT $max";

  $st = $conn->prepare($sql);
  if ($rootFilter !== '') $st->bind_param("is",$project_id,$rootFilter);
  else $st->bind_param("i",$project_id);
  $st->execute();
  $rs = $st->get_result();

  while($s=$rs->fetch_assoc()){
    $root = $s['root_domain'];
    $sub  = $s['subdomain'];
    addNode($nodes, "root:$root", "root", $root);
    addNode($nodes, "sub:$sub", "subdomain", $sub);
    addLink($links, $linkSet, "root:$root", "sub:$sub", "has_subdomain");
  }
}

/**
 * DNS
 */
if (isset($inc['dns']) && table_exists($conn,'oneinseclabs_dns_records')) {
  $sql = "SELECT d.subdomain, d.ip_address, s.root_domain
          FROM oneinseclabs_dns_records d
          LEFT JOIN oneinseclabs_subdomains s ON s.project_id=d.project_id AND s.subdomain=d.subdomain
          WHERE d.project_id=? ";
  if ($rootFilter !== '') $sql .= " AND (s.root_domain=? OR d.subdomain LIKE ?) ";
  $sql .= " LIMIT $max";

  $st = $conn->prepare($sql);
  if ($rootFilter !== '') {
    $like = "%".$rootFilter;
    $st->bind_param("iss",$project_id,$rootFilter,$like);
  } else {
    $st->bind_param("i",$project_id);
  }
  $st->execute();
  $rs = $st->get_result();

  while($d=$rs->fetch_assoc()){
    $sub = strtolower($d['subdomain']);
    $ip  = $d['ip_address'];
    $root = $d['root_domain'] ?: guess_root_from_host($sub);

    addNode($nodes, "sub:$sub", "subdomain", $sub);
    addNode($nodes, "host:$ip", "host", $ip);
    addLink($links, $linkSet, "sub:$sub", "host:$ip", "resolves_to");

    if ($root) {
      addNode($nodes, "root:$root", "root", $root);
      addLink($links, $linkSet, "root:$root", "sub:$sub", "has_subdomain");
      addLink($links, $linkSet, "root:$root", "host:$ip", "has_host");
      $ip2roots[$ip][$root] = true;
    }
    $ip2subs[$ip][$sub] = true;
  }
}

/**
 * HOSTS
 */
if (isset($inc['hosts']) && table_exists($conn,'oneinseclabs_hosts')) {
  if ($rootFilter !== '') {
    $sql = "SELECT DISTINCT h.ip_address, h.hostname
            FROM oneinseclabs_hosts h
            LEFT JOIN oneinseclabs_dns_records d ON d.project_id=h.project_id AND d.ip_address=h.ip_address
            LEFT JOIN oneinseclabs_subdomains s ON s.project_id=d.project_id AND s.subdomain=d.subdomain
            WHERE h.project_id=?
              AND (s.root_domain=? OR h.hostname=? OR h.hostname LIKE CONCAT('%.', ?))
            LIMIT $max";
    $st = $conn->prepare($sql);
    $st->bind_param("isss", $project_id, $rootFilter, $rootFilter, $rootFilter);
  } else {
    $sql = "SELECT ip_address, hostname FROM oneinseclabs_hosts WHERE project_id=? LIMIT $max";
    $st = $conn->prepare($sql);
    $st->bind_param("i",$project_id);
  }

  $st->execute();
  $rs = $st->get_result();

  while($h=$rs->fetch_assoc()){
    $ip = $h['ip_address'];
    $hn = $h['hostname'] ? strtolower(trim($h['hostname'])) : null;
    if ($hn) $hn = rtrim($hn,'.');

    addNode($nodes, "host:$ip", "host", $ip);

    if ($hn) {
      addNode($nodes, "sub:$hn", "subdomain", $hn);
      addLink($links, $linkSet, "sub:$hn", "host:$ip", "nmap_hostname");
      $ip2subs[$ip][$hn] = true;

      $root = guess_root_from_host($hn);
      if ($root) {
        addNode($nodes, "root:$root", "root", $root);
        addLink($links, $linkSet, "root:$root", "sub:$hn", "has_subdomain");
        addLink($links, $linkSet, "root:$root", "host:$ip", "has_host");
        $ip2roots[$ip][$root] = true;
      }
    }
  }
}

/**
 * PORTS
 */
if (isset($inc['ports']) && table_exists($conn,'oneinseclabs_ports') && table_exists($conn,'oneinseclabs_hosts')) {
  if ($rootFilter !== '') {
    $sql = "SELECT DISTINCT h.ip_address, p.port, p.protocol, p.service, p.state
            FROM oneinseclabs_ports p
            JOIN oneinseclabs_hosts h ON h.id=p.host_id
            LEFT JOIN oneinseclabs_dns_records d ON d.project_id=h.project_id AND d.ip_address=h.ip_address
            LEFT JOIN oneinseclabs_subdomains s ON s.project_id=d.project_id AND s.subdomain=d.subdomain
            WHERE p.project_id=?
              AND (s.root_domain=? OR h.hostname=? OR h.hostname LIKE CONCAT('%.', ?))
            LIMIT $max";
    $st = $conn->prepare($sql);
    $st->bind_param("isss", $project_id, $rootFilter, $rootFilter, $rootFilter);
  } else {
    $sql = "SELECT h.ip_address, p.port, p.protocol, p.service, p.state
            FROM oneinseclabs_ports p
            JOIN oneinseclabs_hosts h ON h.id=p.host_id
            WHERE p.project_id=?
            LIMIT $max";
    $st = $conn->prepare($sql);
    $st->bind_param("i",$project_id);
  }

  $st->execute();
  $rs = $st->get_result();

  while($p=$rs->fetch_assoc()){
    $ip = $p['ip_address'];
    $port = (int)$p['port'];
    $proto = $p['protocol'];
    $svc = $p['service'] ?: 'service';
    $state = $p['state'] ?: '';
    $pid = "port:$ip:$proto:$port";

    addNode($nodes, "host:$ip", "host", $ip);
    addNode($nodes, $pid, "port", "$port/$proto $svc $state");
    addLink($links, $linkSet, "host:$ip", $pid, "open_port");

    if (isset($ip2subs[$ip])) {
      foreach ($ip2subs[$ip] as $sub => $_) {
        addNode($nodes, "sub:$sub", "subdomain", $sub);
        addLink($links, $linkSet, "sub:$sub", $pid, "has_port");
      }
    }
  }
}

/**
 * URLS
 */
if (isset($inc['urls']) && table_exists($conn,'oneinseclabs_urls')) {
  $sql = "SELECT url, source FROM oneinseclabs_urls WHERE project_id=? ";
  if ($rootFilter !== '') $sql .= " AND url LIKE ? ";
  $sql .= " ORDER BY id DESC LIMIT $max";

  $st = $conn->prepare($sql);
  if ($rootFilter !== '') {
    $like = "%".$rootFilter."%";
    $st->bind_param("is",$project_id,$like);
  } else {
    $st->bind_param("i",$project_id);
  }
  $st->execute();
  $rs = $st->get_result();

  while($u=$rs->fetch_assoc()){
    $url = $u['url'];
    $host = host_from_url($url);
    $id = "url:" . substr(sha1($url),0,14);

    $label = $host ? ($host." • ".mb_substr($url,0,70)) : mb_substr($url,0,80);
    addNode($nodes, $id, "url", $label, ['url'=>$url,'source'=>$u['source']]);

    if ($host) {
      $host = rtrim(strtolower($host),'.');
      $subNode = "sub:$host";
      if (isset($nodes[$subNode])) {
        addLink($links, $linkSet, $subNode, $id, "has_url");
      } else {
        $root = guess_root_from_host($host);
        if ($root) {
          addNode($nodes, "root:$root", "root", $root);
          addLink($links, $linkSet, "root:$root", $id, "has_url");
        }
      }
    }
  }
}

/**
 * SHODAN (services + optional CVEs)
 * Nodes:
 *  - svc:<ip>:<port>/<proto>   type=shodan_service
 *  - vuln:<CVE>               type=vuln
 * Links:
 *  - host -> svc (shodan_service)
 *  - root/sub -> host already exists via DNS/hosts (if present)
 *  - svc -> vuln (has_vuln)
 */
if (isset($inc['shodan']) && table_exists($conn,'oneinseclabs_shodan_services')) {
  $sql = "SELECT ip, port, transport, product, version, org, asn, country, city, hostnames, domains, vulns\n"
       . "FROM oneinseclabs_shodan_services WHERE project_id=? ";
  if ($rootFilter !== '') {
    // Rough filter: match root in hostnames/domains fields
    $sql .= " AND (hostnames LIKE ? OR domains LIKE ?) ";
  }
  $sql .= " ORDER BY updated_at DESC LIMIT $max";

  $st = $conn->prepare($sql);
  if ($rootFilter !== '') {
    $like = "%".$rootFilter."%";
    $st->bind_param("iss", $project_id, $like, $like);
  } else {
    $st->bind_param("i", $project_id);
  }
  $st->execute();
  $rs = $st->get_result();

  while ($s = $rs->fetch_assoc()) {
    $ip = (string)($s['ip'] ?? '');
    $port = (int)($s['port'] ?? 0);
    $proto = strtolower((string)($s['transport'] ?? 'tcp'));
    if ($ip === '' || $port <= 0) continue;

    $svcId = "svc:$ip:$proto:$port";
    $labelBits = [];
    $labelBits[] = "$port/$proto";
    $prod = trim((string)($s['product'] ?? ''));
    $ver  = trim((string)($s['version'] ?? ''));
    if ($prod !== '') $labelBits[] = $prod.($ver ? " $ver" : '');
    $org  = trim((string)($s['org'] ?? ''));
    if ($org !== '') $labelBits[] = $org;
    $label = implode(' • ', $labelBits);

    addNode($nodes, "host:$ip", "host", $ip);
    addNode($nodes, $svcId, "shodan_service", $label, [
      'ip'=>$ip,
      'port'=>$port,
      'transport'=>$proto,
      'country'=>$s['country'] ?? '',
      'city'=>$s['city'] ?? '',
      'asn'=>$s['asn'] ?? ''
    ]);
    addLink($links, $linkSet, "host:$ip", $svcId, "shodan_service");

    // Try to connect to a subdomain node if present
    $hostnames = trim((string)($s['hostnames'] ?? ''));
    if ($hostnames !== '') {
      $first = trim(explode(',', $hostnames)[0] ?? '');
      $first = rtrim(strtolower($first),'.');
      if ($first !== '') {
        addNode($nodes, "sub:$first", "subdomain", $first);
        addLink($links, $linkSet, "sub:$first", "host:$ip", "shodan_hostname");
      }
    }

    // CVEs (comma separated in vulns)
    $v = trim((string)($s['vulns'] ?? ''));
    if ($v !== '') {
      $ids = array_slice(array_values(array_filter(array_map('trim', explode(',', $v)))), 0, 30);
      foreach ($ids as $vid) {
        if ($vid === '') continue;
        $vnode = "vuln:".strtoupper($vid);
        addNode($nodes, $vnode, "vuln", strtoupper($vid));
        addLink($links, $linkSet, $svcId, $vnode, "has_vuln");
      }
    }
  }
}

echo json_encode(['nodes'=>array_values($nodes),'links'=>$links], JSON_UNESCAPED_SLASHES);
