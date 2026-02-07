<?php
require_once __DIR__ . '/header.php';
$conn = db();

$project_id = isset($_GET['project_id']) ? (int)$_GET['project_id'] : (int)($_SESSION['active_project_id'] ?? 0);
if ($project_id <= 0) {
  echo "<div class='card'>Set an active project first: <a href='projects.php'>Projects</a></div>";
  require_once __DIR__ . '/footer.php';
  exit();
}

$cats = $conn->query("SELECT * FROM oneinseclabs_tool_categories ORDER BY sort_order ASC, name ASC");
$tools = $conn->query("
  SELECT t.*, c.name cat_name
  FROM oneinseclabs_tools t
  LEFT JOIN oneinseclabs_tool_categories c ON c.id=t.category_id
  ORDER BY c.sort_order ASC, t.name ASC
");

$extra_tools = [
  [
    'name' => 'amass (passive)',
    'category' => 'Recon',
    'desc' => 'Deep subdomain discovery for large scopes.',
    'command' => 'amass enum -passive -d {root_domain} -o {out_dir}/subdomains_amass.txt',
    'parse' => 'Subdomain lines → upload as Subdomains'
  ],
  [
    'name' => 'naabu',
    'category' => 'Network',
    'desc' => 'Fast port scanner to build targets for Nmap.',
    'command' => 'naabu -list {alive_file} -o {out_dir}/naabu.txt',
    'parse' => 'host:port → upload to Ports (CSV/text)'
  ],
  [
    'name' => 'nuclei',
    'category' => 'Web',
    'desc' => 'Template-based vuln checks with rich output.',
    'command' => 'nuclei -l {alive_file} -json -o {out_dir}/nuclei.json',
    'parse' => 'Use jq -r .matched-at to extract URLs'
  ],
  [
    'name' => 'gau',
    'category' => 'Web',
    'desc' => 'URL collection from public sources.',
    'command' => 'gau {root_domain} | sort -u > {out_dir}/gau.txt',
    'parse' => 'URL lines → upload as URLs'
  ],
  [
    'name' => 'waybackurls',
    'category' => 'Web',
    'desc' => 'Pull archived URLs for recon.',
    'command' => 'cat {subdomains_file} | waybackurls | sort -u > {out_dir}/wayback.txt',
    'parse' => 'URL lines → upload as URLs'
  ],
  [
    'name' => 'ffuf',
    'category' => 'Web',
    'desc' => 'Content discovery with wordlists.',
    'command' => 'ffuf -u https://{root_domain}/FUZZ -w wordlist.txt -o {out_dir}/ffuf.json -of json',
    'parse' => 'Use jq -r .results[].url to extract URLs'
  ],
  [
    'name' => 'katana',
    'category' => 'Web',
    'desc' => 'Crawl endpoints across subdomains quickly.',
    'command' => 'katana -list {subdomains_file} -o {out_dir}/katana.txt',
    'parse' => 'URL lines → upload as URLs'
  ],
  [
    'name' => 'gospider',
    'category' => 'Web',
    'desc' => 'JavaScript-enabled crawling for URLs.',
    'command' => 'gospider -S {alive_file} -o {out_dir}/gospider -t 5',
    'parse' => 'Use grep -Eo "https?://[^ ]+" to extract URLs'
  ],
  [
    'name' => 'masscan',
    'category' => 'Network',
    'desc' => 'High-speed port scan for large ranges.',
    'command' => 'masscan -iL {alive_file} -p1-1000 --rate 1000 -oL {out_dir}/masscan.txt',
    'parse' => 'Extract ip:port pairs for ports import'
  ],
  [
    'name' => 'asnmap',
    'category' => 'Recon',
    'desc' => 'Discover CIDRs by ASN or org name.',
    'command' => 'asnmap -org "{root_domain}" -o {out_dir}/asnmap.txt',
    'parse' => 'CIDRs can seed port scans or IP lists'
  ],
  [
    'name' => 'shuffledns',
    'category' => 'DNS',
    'desc' => 'Bruteforce DNS with resolvers.',
    'command' => 'shuffledns -d {root_domain} -w wordlist.txt -r resolvers.txt -o {out_dir}/shuffledns.txt',
    'parse' => 'Subdomain lines → upload as Subdomains'
  ],
  [
    'name' => 'dnsx (PTR)',
    'category' => 'DNS',
    'desc' => 'Reverse DNS lookup on IP list.',
    'command' => 'cat {alive_file} | dnsx -silent -ptr -o {out_dir}/ptr.txt',
    'parse' => 'Use hostnames to enrich Hosts table'
  ],
  [
    'name' => 'whatweb',
    'category' => 'Web',
    'desc' => 'Fingerprint web tech stacks.',
    'command' => 'whatweb -i {alive_file} --log-verbose={out_dir}/whatweb.txt',
    'parse' => 'Use URL lines to update tech notes'
  ],
  [
    'name' => 'httpx (tech)',
    'category' => 'Web',
    'desc' => 'Enrich URLs with tech detection.',
    'command' => 'cat {subdomains_file} | httpx -silent -status-code -title -tech-detect -o {out_dir}/httpx_tech.txt',
    'parse' => 'Upload to URLs for status/title'
  ],
  [
    'name' => 'sslscan',
    'category' => 'Network',
    'desc' => 'TLS configuration checks on ports.',
    'command' => 'sslscan --targets={alive_file} > {out_dir}/sslscan.txt',
    'parse' => 'Attach findings to notes or logs'
  ],
  [
    'name' => 's3scanner',
    'category' => 'Cloud',
    'desc' => 'Find open S3 buckets from words.',
    'command' => 's3scanner -bucket-file wordlist.txt -o {out_dir}/s3scanner.txt',
    'parse' => 'URLs → upload as URLs'
  ],
  [
    'name' => 'cloud_enum',
    'category' => 'Cloud',
    'desc' => 'Enumerate public cloud assets.',
    'command' => 'cloud_enum -k {root_domain} -l {out_dir}/cloud_enum.txt',
    'parse' => 'URLs → upload as URLs'
  ],
];

audit_log((int)$_SESSION['user_id'], 'view', 'Opened tools', null, null, $project_id);
?>
<div class="card">
  <h2 style="margin:0 0 10px 0;">Tools & Workflows</h2>
  <div style="opacity:.75">Active project: <b>#<?= (int)$project_id ?></b> | Copy command → run on Kali → upload output → view parsed results.</div>
  <div style="margin-top:12px;display:flex;gap:12px;flex-wrap:wrap">
    <div class="pill">Total tools: <?= (int)($tools->num_rows ?? 0) ?></div>
    <div class="pill">Extras: <?= (int)count($extra_tools) ?></div>
  </div>
</div>

<div class="card" style="margin-top:14px">
  <div style="display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;align-items:center">
    <h3 style="margin:0 0 10px 0;">Tool List</h3>
    <input id="toolSearch" placeholder="Search tools or commands..." style="min-width:240px">
  </div>
  <table id="toolTable" style="width:100%;border-collapse:collapse">
    <thead><tr style="background:#f1f5f9">
      <th style="padding:10px;border-bottom:1px solid #e5e7eb">Category</th>
      <th style="padding:10px;border-bottom:1px solid #e5e7eb">Tool</th>
      <th style="padding:10px;border-bottom:1px solid #e5e7eb">Command Template</th>
      <th style="padding:10px;border-bottom:1px solid #e5e7eb">Run</th>
    </tr></thead>
    <tbody>
      <?php while($t=$tools->fetch_assoc()): ?>
      <tr>
        <td style="padding:10px;border-bottom:1px solid #e5e7eb"><?= h($t['cat_name'] ?? '-') ?></td>
        <td style="padding:10px;border-bottom:1px solid #e5e7eb"><b><?= h($t['name']) ?></b><br><small style="opacity:.7"><?= h($t['description']) ?></small></td>
        <td style="padding:10px;border-bottom:1px solid #e5e7eb"><code><?= h($t['command_template']) ?></code></td>
        <td style="padding:10px;border-bottom:1px solid #e5e7eb">
          <a href="run.php?project_id=<?= (int)$project_id ?>&tool_id=<?= (int)$t['id'] ?>">Open Run</a>
        </td>
      </tr>
      <?php endwhile; ?>
    </tbody>
  </table>
</div>

<div class="card" style="margin-top:14px">
  <h3 style="margin:0 0 10px 0;">Additional Tools (copy-ready)</h3>
  <div class="muted" style="margin-bottom:10px">Use these command templates to extend your recon. Replace placeholders like <code>{root_domain}</code> and <code>{out_dir}</code>.</div>
  <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px">
    <select id="extraFilter" style="max-width:200px">
      <option value="all" selected>All categories</option>
      <option value="recon">Recon</option>
      <option value="dns">DNS</option>
      <option value="web">Web</option>
      <option value="network">Network</option>
      <option value="cloud">Cloud</option>
    </select>
    <input id="extraSearch" placeholder="Search extras..." style="min-width:220px">
  </div>
  <div class="grid">
    <?php foreach($extra_tools as $tool): ?>
      <div class="card col-6" style="margin:0" data-cat="<?= h(strtolower($tool['category'])) ?>">
        <div style="display:flex;justify-content:space-between;gap:10px;align-items:flex-start">
          <div>
            <div class="badge"><?= h($tool['category']) ?></div>
            <h4 style="margin:6px 0 6px 0;"><?= h($tool['name']) ?></h4>
            <div class="muted"><?= h($tool['desc']) ?></div>
          </div>
          <button class="btn" type="button" onclick="copyCmd(this)">Copy</button>
        </div>
        <pre style="margin-top:10px;white-space:pre-wrap;background:rgba(0,0,0,.25);padding:12px;border-radius:12px;border:1px solid rgba(255,255,255,.08)"><?= h($tool['command']) ?></pre>
        <div class="muted" style="margin-top:8px"><b>Parsing:</b> <?= h($tool['parse']) ?></div>
      </div>
    <?php endforeach; ?>
  </div>
</div>

<script>
const searchInput = document.getElementById('toolSearch');
const toolTable = document.getElementById('toolTable');
if (searchInput && toolTable) {
  searchInput.addEventListener('input', () => {
    const q = searchInput.value.toLowerCase().trim();
    toolTable.querySelectorAll('tbody tr').forEach(row => {
      const text = row.innerText.toLowerCase();
      row.style.display = text.includes(q) ? '' : 'none';
    });
  });
}

const extraFilter = document.getElementById('extraFilter');
const extraSearch = document.getElementById('extraSearch');
const extraCards = document.querySelectorAll('.grid .card[data-cat]');
function filterExtras(){
  const cat = (extraFilter?.value || 'all').toLowerCase();
  const q = (extraSearch?.value || '').toLowerCase().trim();
  extraCards.forEach(card => {
    const cardCat = card.dataset.cat || '';
    const text = card.innerText.toLowerCase();
    const catMatch = cat === 'all' || cardCat === cat;
    const textMatch = text.includes(q);
    card.style.display = (catMatch && textMatch) ? '' : 'none';
  });
}
if (extraFilter) extraFilter.addEventListener('change', filterExtras);
if (extraSearch) extraSearch.addEventListener('input', filterExtras);

function copyCmd(btn){
  const code = btn.closest('.card').querySelector('pre');
  if (!code) return;
  navigator.clipboard.writeText(code.innerText).then(()=>{
    btn.textContent = 'Copied';
    setTimeout(()=>btn.textContent='Copy', 800);
  });
}
</script>
<?php require_once __DIR__ . '/footer.php'; ?>
