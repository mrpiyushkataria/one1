<?php
/**
 * public_html/one.inseclabs.com/shodan_graph.php
 * 3D Force Graph for Shodan results.
 */

declare(strict_types=1);
ini_set('display_errors','0');
error_reporting(E_ALL);

require_once __DIR__ . '/includes/header.php';

$conn = db();
$uid  = (int)current_user_id();
if ($uid <= 0) { header("Location: index.php"); exit; }

$project_id = (int)($_GET['project_id'] ?? 0);
if ($project_id <= 0) redirect('dashboard.php');

// Load project name for header
$st = $conn->prepare("SELECT title FROM oneinseclabs_projects WHERE id=? LIMIT 1");
$st->bind_param("i", $project_id);
$st->execute();
$p = $st->get_result()->fetch_assoc();
$title = $p ? (string)$p['title'] : ('Project #'.$project_id);

?>
<div class="top">
  <div class="title">
    <h2><?= e($title) ?> • Shodan 3D Graph</h2>
    <div class="muted">Root → IP → Port → CVE (if available)</div>
  </div>
  <div class="row">
    <a class="btn" href="shodan.php?project_id=<?= (int)$project_id ?>">← Back</a>
    <a class="btn" href="project.php?id=<?= (int)$project_id ?>">Project</a>
  </div>
</div>

<div class="grid">
  <div class="card col-12">
    <div style="display:flex;gap:14px;flex-wrap:wrap;align-items:flex-end">
      <div>
        <label class="muted">Max services</label>
        <input id="limit" value="1500">
      </div>
      <div>
        <label class="muted">Include CVEs</label>
        <select id="vulns">
          <option value="1" selected>Yes</option>
          <option value="0">No</option>
        </select>
      </div>
      <div>
        <label class="muted">Categories</label>
        <div style="display:flex;gap:10px;flex-wrap:wrap">
          <label style="display:flex;gap:6px;align-items:center">
            <input type="checkbox" id="filter-root" checked> Root
          </label>
          <label style="display:flex;gap:6px;align-items:center">
            <input type="checkbox" id="filter-ip" checked> IP
          </label>
          <label style="display:flex;gap:6px;align-items:center">
            <input type="checkbox" id="filter-service" checked> Service
          </label>
          <label style="display:flex;gap:6px;align-items:center">
            <input type="checkbox" id="filter-vuln" checked> CVE
          </label>
        </div>
      </div>
      <div>
        <label class="muted">Service filters</label>
        <div style="display:flex;gap:10px;flex-wrap:wrap">
          <label style="display:flex;gap:6px;align-items:center">
            <input type="checkbox" id="filter-vuln-only"> Only vulnerable services
          </label>
          <label style="display:flex;gap:6px;align-items:center">
            <input type="checkbox" id="filter-product-only"> Only services with product
          </label>
        </div>
      </div>
      <button class="btn primary" onclick="loadGraph()">Load Graph</button>
      <span class="muted" id="stat"></span>
    </div>
    <hr>
    <div id="graph" style="height:78vh; width:100%; border-radius:18px; overflow:hidden;"></div>
    <div class="muted" style="font-size:12px;margin-top:10px">
      Tip: click node to focus • drag to move • scroll to zoom
    </div>
  </div>
</div>

<script src="https://unpkg.com/3d-force-graph"></script>
<script>
let Graph;
let graphData = null;

const typeColors = {
  root_domain: '#5ad0ff',
  ip_address: '#76e3a6',
  service: '#f6c667',
  vulnerability: '#ff7a7a'
};

const typeSizes = {
  root_domain: 10,
  ip_address: 5,
  service: 6,
  vulnerability: 4
};

function nodeColor(n){
  // group-based colors (no hard-coded palette needed; you can change if you want)
  // We'll just map types to basic distinct strings; 3d-force-graph will color by group if you set nodeAutoColorBy.
  return typeColors[n.type] || '#9aa4b2';
}

function nodeLabel(n){
  const parts = [];
  parts.push(`<b>${escapeHtml(n.name || n.id)}</b>`);
  if (n.type) parts.push(`<div>Type: ${escapeHtml(n.type.replace(/_/g,' '))}</div>`);
  if (n.product || n.version) parts.push(`<div>${escapeHtml((n.product||'')+' '+(n.version||''))}</div>`);
  if (n.port && n.transport) parts.push(`<div>Port: ${escapeHtml(n.port+' / '+n.transport)}</div>`);
  if (n.org) parts.push(`<div>Org: ${escapeHtml(n.org)}</div>`);
  if (n.country || n.city) parts.push(`<div>${escapeHtml([n.city,n.country].filter(Boolean).join(', '))}</div>`);
  if (typeof n.vuln_count === 'number' && n.type === 'service') parts.push(`<div>CVEs: ${n.vuln_count}</div>`);
  if (n.meta) parts.push(`<div>${escapeHtml(n.meta)}</div>`);
  return parts.join('');
}

function escapeHtml(s){
  return String(s||'').replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
}

async function loadGraph(){
  const stat = document.getElementById('stat');
  stat.textContent = 'Loading…';

  const limit = (document.getElementById('limit').value || '1500').trim();
  const vulns = (document.getElementById('vulns').value || '1').trim();

  const url = `api/shodan_graph.php?project_id=<?= (int)$project_id ?>&limit=${encodeURIComponent(limit)}&vulns=${encodeURIComponent(vulns)}`;
  const r = await fetch(url);
  const j = await r.json();
  if (!j.ok) { stat.textContent = 'Error'; alert(j.error || 'Failed'); return; }

  graphData = { nodes: j.nodes, links: j.links };
  stat.textContent = `Nodes: ${j.nodes.length} • Links: ${j.links.length}`;

  if (!Graph){
    Graph = ForceGraph3D()(document.getElementById('graph'))
      .nodeColor(nodeColor)
      .nodeVal(n => typeSizes[n.type] || 4)
      .nodeLabel(nodeLabel)
      .linkLabel(l => l.rel || '')
      .linkDirectionalParticles(0)
      .backgroundColor('#0b1020');
  }

  applyFilters();
  
  // nice defaults
  Graph.d3Force('charge').strength(-80);

  Graph.onNodeClick(node => {
    // focus camera
    const dist = 140;
    const ratio = 1 + dist / Math.hypot(node.x, node.y, node.z);
    Graph.cameraPosition(
      { x: node.x * ratio, y: node.y * ratio, z: node.z * ratio },
      node,
      900
    );
  });
}
function getFilterState(){
  return {
    showRoot: document.getElementById('filter-root').checked,
    showIp: document.getElementById('filter-ip').checked,
    showService: document.getElementById('filter-service').checked,
    showVuln: document.getElementById('filter-vuln').checked,
    vulnOnly: document.getElementById('filter-vuln-only').checked,
    productOnly: document.getElementById('filter-product-only').checked
  };
}

function applyFilters(){
  if (!graphData) return;

  const state = getFilterState();
  const allowedTypes = new Set();
  if (state.showRoot) allowedTypes.add('root_domain');
  if (state.showIp) allowedTypes.add('ip_address');
  if (state.showService) allowedTypes.add('service');
  if (state.showVuln) allowedTypes.add('vulnerability');

  let nodes = graphData.nodes.filter(n => allowedTypes.has(n.type));

  if (state.vulnOnly) {
    nodes = nodes.filter(n => n.type !== 'service' || n.has_vuln);
  }
  if (state.productOnly) {
    nodes = nodes.filter(n => n.type !== 'service' || (n.product && String(n.product).trim() !== ''));
  }

  const allowedIds = new Set(nodes.map(n => n.id));
  let links = graphData.links.filter(l => allowedIds.has(l.source) && allowedIds.has(l.target));

  const linkedIds = new Set();
  links.forEach(l => {
    linkedIds.add(l.source);
    linkedIds.add(l.target);
  });
  nodes = nodes.filter(n => n.type === 'root_domain' || linkedIds.has(n.id));

  Graph.graphData({ nodes, links });
  document.getElementById('stat').textContent = `Nodes: ${nodes.length} • Links: ${links.length}`;
}

['filter-root','filter-ip','filter-service','filter-vuln','filter-vuln-only','filter-product-only'].forEach(id => {
  const el = document.getElementById(id);
  if (el) el.addEventListener('change', applyFilters);
});



loadGraph();
</script>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
