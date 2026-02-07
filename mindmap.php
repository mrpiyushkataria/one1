<?php
require_once __DIR__ . '/includes/header.php';
$conn = db();

$project_id = (int)($_GET['project_id'] ?? ($_SESSION['active_project_id'] ?? 0));
if($project_id<=0){ echo "<div class='card'>Set active project first.</div>"; require __DIR__ . '/includes/footer.php'; exit(); }

$roots = $conn->query("SELECT root_domain FROM oneinseclabs_project_domains WHERE project_id=$project_id ORDER BY created_at DESC");
$root_list = [];
while($r=$roots->fetch_assoc()) $root_list[] = $r['root_domain'];

audit_log((int)$_SESSION['user_id'],'view','Opened mindmap',null,null,$project_id);
?>
<div class="card">
  <div style="display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;align-items:center">
    <div>
      <h2 style="margin:0 0 6px 0;">3D Graph</h2>
      <div class="muted">Project #<?= (int)$project_id ?> — assets graph + workflow graph</div>
    </div>
    <div style="display:flex;gap:8px;flex-wrap:wrap">
      <a class="btn" href="project.php?id=<?= (int)$project_id ?>">Back</a>
      <a class="btn" href="assets.php?project_id=<?= (int)$project_id ?>&types=subdomains,hosts,ports,urls">Table View</a>
    </div>
  </div>
</div>

<div class="card" style="margin-top:12px">
  <div style="display:flex;gap:12px;flex-wrap:wrap;align-items:center">
    <label class="muted">View</label>
    <select id="view">
      <option value="assets">Assets Graph</option>
      <option value="workflow">Workflow Graph</option>
    </select>

    <label class="muted">Category</label>
    <select id="cat">
      <option value="all" selected>All</option>
      <option value="recon">Recon</option>
      <option value="dns">DNS</option>
      <option value="web">Web</option>
      <option value="network">Network</option>
    </select>

    <label class="muted">Types</label>
    <select id="types">
      <option value="roots,subdomains,dns,hosts,ports,urls,runs,files" selected>All</option>
      <option value="subdomains,hosts,ports,urls">Assets Only</option>
      <option value="runs,files">Runs/Files Only</option>
      <option value="subdomains">Subdomains</option>
      <option value="hosts">Hosts</option>
      <option value="ports">Ports</option>
      <option value="urls">URLs</option>
    </select>

    <label class="muted">Root filter</label>
    <select id="root">
      <option value="">All roots</option>
      <?php foreach($root_list as $rd): ?>
        <option value="<?= e($rd) ?>"><?= e($rd) ?></option>
      <?php endforeach; ?>
    </select>

    <label class="muted">Search</label>
    <input id="q" placeholder="subdomain / ip / port / url..." style="min-width:240px">

    <button class="btn primary" onclick="loadGraph()">Apply</button>
    <button class="btn" onclick="resetFocus()">Reset</button>
    <a class="btn" id="tableLink" href="#">Table View (filtered)</a>
  </div>
  <div style="display:flex;gap:12px;flex-wrap:wrap;align-items:center;margin-top:12px">
    <label class="muted">Node size</label>
    <input id="nodeSize" type="range" min="2" max="12" value="5" style="max-width:200px">
    <label class="muted">Link distance</label>
    <input id="linkDistance" type="range" min="30" max="160" value="90" style="max-width:200px">
    <label class="muted">Charge</label>
    <input id="charge" type="range" min="-200" max="-30" value="-110" style="max-width:200px">
    <label class="muted">Auto rotate</label>
    <input id="autoRotate" type="checkbox">
  </div>
</div>

<div class="card" style="margin-top:14px;padding:0;overflow:hidden">
  <div id="graph" style="height:720px;"></div>
</div>

<div class="card" style="margin-top:14px">
  <div style="display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;align-items:center">
    <div class="kv">
      <span class="badge" id="statNodes">Nodes: 0</span>
      <span class="badge" id="statLinks">Links: 0</span>
      <span class="badge">Tip: Click node to focus</span>
    </div>
    <div class="muted">Hover highlights connections, search jumps to first match.</div>
  </div>
</div>

<script src="https://unpkg.com/3d-force-graph"></script>
<script>
const projectId = <?= (int)$project_id ?>;
let lastData = null;
let Graph = null;
let highlightNodes = new Set();
let highlightLinks = new Set();

function apiUrl(){
  const view = document.getElementById('view').value;
  const root = document.getElementById('root').value;
  const types = document.getElementById('types').value;
  const cat = document.getElementById('cat').value;

  const params = new URLSearchParams({
    project_id: projectId,
    view,
    include: types,
    category: cat,
    max: "20000"
  });
  if(root) params.set("root", root);
  return "api/graph.php?" + params.toString();
}

function updateTableLink(){
  const root = document.getElementById('root').value;
  const cat  = document.getElementById('cat').value;
  const types= document.getElementById('types').value;
  const p = new URLSearchParams({project_id: projectId, root, category: cat, types});
  document.getElementById('tableLink').href = "assets.php?" + p.toString();
}

function initGraph(){
  Graph = ForceGraph3D()(document.getElementById('graph'))
    .backgroundColor('#0b1220')
    .nodeAutoColorBy('type')
    .nodeLabel(n => `${n.label}\n(${n.type})`)
    .linkLabel(l => l.rel || '')
    .linkDirectionalParticles(2)
    .linkDirectionalParticleWidth(2)
    .linkDirectionalParticleSpeed(0.007)
    .linkOpacity(0.4)
    .linkWidth(l => highlightLinks.has(l) ? 2.2 : 0.6)
    .nodeRelSize(4)
    .nodeVal(n => n.__degree ? Math.min(12, 2 + n.__degree / 2) : 3)
    .nodeColor(n => highlightNodes.has(n) ? '#f59e0b' : n.color)
    .onNodeClick(node => {
      if(!node) return;
      focusNode(node);
    })
    .onNodeHover(node => {
      highlightNodes.clear();
      highlightLinks.clear();
      if (node) {
        highlightNodes.add(node);
        (node.__links || []).forEach(l => highlightLinks.add(l));
      }
      Graph.nodeColor(Graph.nodeColor());
      Graph.linkWidth(Graph.linkWidth());
    });

  document.getElementById('q').addEventListener('keydown', (e)=>{
    if(e.key === 'Enter') findAndFocus();
  });

  document.getElementById('nodeSize').addEventListener('input', (e)=>{
    const base = parseInt(e.target.value, 10) || 5;
    Graph.nodeVal(n => base + (n.__degree || 0) / 3);
  });
  document.getElementById('linkDistance').addEventListener('input', (e)=>{
    const dist = parseInt(e.target.value, 10) || 90;
    Graph.d3Force('link').distance(dist);
  });
  document.getElementById('charge').addEventListener('input', (e)=>{
    const strength = parseInt(e.target.value, 10) || -110;
    Graph.d3Force('charge').strength(strength);
  });
  document.getElementById('autoRotate').addEventListener('change', (e)=>{
    const controls = Graph.controls();
    controls.autoRotate = e.target.checked;
    controls.autoRotateSpeed = 0.6;
  });
}

function loadGraph(){
  updateTableLink();
  fetch(apiUrl())
    .then(r=>r.json())
    .then(data=>{
      lastData = data;
      annotateGraph(data);
      Graph.graphData(data);
      document.getElementById('statNodes').textContent = `Nodes: ${data.nodes.length}`;
      document.getElementById('statLinks').textContent = `Links: ${data.links.length}`;
      setTimeout(()=>Graph.zoomToFit(500, 70), 300);
    });
}

function annotateGraph(data){
  const nodeMap = new Map();
  data.nodes.forEach(n => {
    n.__degree = 0;
    n.__links = [];
    nodeMap.set(n.id, n);
  });
  data.links.forEach(l => {
    const source = typeof l.source === 'object' ? l.source : nodeMap.get(l.source);
    const target = typeof l.target === 'object' ? l.target : nodeMap.get(l.target);
    if (source) {
      source.__degree = (source.__degree || 0) + 1;
      source.__links.push(l);
    }
    if (target) {
      target.__degree = (target.__degree || 0) + 1;
      target.__links.push(l);
    }
  });
}

function focusNode(node){
  const dist = 160;
  const distRatio = 1 + dist/Math.hypot(node.x, node.y, node.z);
  Graph.cameraPosition(
    { x: node.x*distRatio, y: node.y*distRatio, z: node.z*distRatio },
    node,
    900
  );
}

function resetFocus(){
  if(!Graph) return;
  Graph.zoomToFit(600, 80);
}

function findAndFocus(){
  const q = (document.getElementById('q').value || '').toLowerCase().trim();
  if(!q || !lastData) return;
  const node = lastData.nodes.find(n => (n.label||'').toLowerCase().includes(q) || (n.id||'').toLowerCase().includes(q));
  if(node) focusNode(node);
}

initGraph();
loadGraph();
</script>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
