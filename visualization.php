<?php
require_once __DIR__ . '/header.php';
$conn = db();
$projects = $conn->query("SELECT id, title FROM oneinseclabs_projects ORDER BY id DESC");
?>
<style>
  .top{display:flex;gap:10px;align-items:center;padding:12px}
  select,input{padding:10px;border-radius:10px;border:1px solid rgba(255,255,255,.12);background:rgba(255,255,255,.06);color:#fff}
  button{padding:10px 12px;border-radius:10px;border:0;background:#ff5800;color:#fff;font-weight:800;cursor:pointer}
  .layout{display:grid;grid-template-columns:1fr 360px;height:calc(100vh - 62px)}
  #graph{width:100%;height:100%}
  .side{border-left:1px solid rgba(255,255,255,.08);padding:12px;background:rgba(255,255,255,.03);overflow:auto}
  .card{padding:12px;border:1px solid rgba(255,255,255,.08);border-radius:14px;background:rgba(255,255,255,.05);margin-bottom:10px}
  .muted{color:#9ca3af;font-size:13px}
  .k{font-weight:800}
  @media(max-width:980px){.layout{grid-template-columns:1fr}.side{display:none}}
</style>

<div class="top">
  <select id="project">
    <option value="">-- Select Project --</option>
    <?php while($p=$projects->fetch_assoc()): ?>
      <option value="<?= (int)$p['id'] ?>"><?= htmlspecialchars($p['title']) ?></option>
    <?php endwhile; ?>
  </select>
  <input id="search" placeholder="Search node label (domain/ip/port)">
  <button onclick="loadGraph()">Load</button>
  <button onclick="rebuild()">Rebuild</button>
  <span class="muted">Click nodes to inspect • Scroll to zoom</span>
</div>

<div class="layout">
  <div id="graph"></div>
  <div class="side">
    <div class="card">
      <div class="k">Node Inspector</div>
      <div class="muted">Root → Subdomain → IP → Ports</div>
    </div>
    <div class="card" id="info"><div class="muted">No node selected.</div></div>
  </div>
</div>

<script src="https://unpkg.com/three/build/three.min.js"></script>
<script src="https://unpkg.com/3d-force-graph"></script>
<script>
let Graph = ForceGraph3D()(document.getElementById('graph'))
  .backgroundColor('#070b14')
  .nodeAutoColorBy('type')
  .nodeLabel(n => `${n.type}: ${n.label}`)
  .linkLabel(l => l.type)
  .linkDirectionalArrowLength(4)
  .linkDirectionalArrowRelPos(1)
  .linkOpacity(0.55)
  .onNodeClick(node => {
    const info=document.getElementById('info');
    info.innerHTML = `
      <div><span class="k">Type:</span> ${escapeHtml(node.type)}</div>
      <div style="margin-top:6px"><span class="k">Label:</span> ${escapeHtml(node.label)}</div>
      <pre style="margin-top:10px;white-space:pre-wrap;background:rgba(0,0,0,.35);padding:10px;border-radius:12px;border:1px solid rgba(255,255,255,.08)">${escapeHtml(JSON.stringify(node.meta||{},null,2))}</pre>
    `;
    const distance=160;
    const distRatio=1+distance/Math.hypot(node.x,node.y,node.z);
    Graph.cameraPosition({x:node.x*distRatio,y:node.y*distRatio,z:node.z*distRatio}, node, 900);
  });

let graphData=null;

function escapeHtml(s){return String(s).replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[m]));}

async function loadGraph(){
  const pid=document.getElementById('project').value;
  if(!pid) return alert("Select project");
  const r=await fetch(`/api/graph_json.php?project_id=${encodeURIComponent(pid)}`);
  graphData=await r.json();
  Graph.graphData(graphData);
  Graph.d3VelocityDecay(0.22);
  Graph.d3Force('charge').strength(-90);
}

async function rebuild(){
  const pid=document.getElementById('project').value;
  if(!pid) return alert("Select project");
  await fetch(`/api/rebuild_graph.php?project_id=${encodeURIComponent(pid)}`);
  await loadGraph();
}

document.getElementById('search').addEventListener('input', () => {
  if(!graphData) return;
  const q=document.getElementById('search').value.trim().toLowerCase();
  if(!q) return;
  const node=graphData.nodes.find(n => (n.label||'').toLowerCase().includes(q));
  if(node){
    const distance=160;
    const distRatio=1+distance/Math.hypot(node.x,node.y,node.z);
    Graph.cameraPosition({x:node.x*distRatio,y:node.y*distRatio,z:node.z*distRatio}, node, 900);
  }
});
</script>

<?php require_once __DIR__ . '/footer.php'; ?>
