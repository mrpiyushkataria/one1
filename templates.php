<?php
require_once __DIR__ . '/header.php';
require_once __DIR__ . '/config.php';

$conn = db();
$projects = $conn->query("
  SELECT p.id, p.title, p.project_slug, c.name company, c.domains
  FROM oneinseclabs_projects p
  JOIN oneinseclabs_companies c ON c.id=p.company_id
  ORDER BY p.id DESC
");

$templates = $conn->query("SELECT * FROM oneinseclabs_command_templates WHERE is_active=1 ORDER BY category, subcategory, name");
?>
<style>
  .wrap{max-width:1200px;margin:20px auto;padding:16px}
  .card{background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.08);border-radius:14px;padding:14px;margin-bottom:12px}
  select,input,textarea{width:100%;padding:10px;border-radius:10px;border:1px solid rgba(255,255,255,.12);background:rgba(255,255,255,.06);color:#fff}
  .grid{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px}
  @media(max-width:1000px){.grid{grid-template-columns:1fr}}
  .tpl{padding:12px;border-radius:12px;border:1px solid rgba(255,255,255,.08);background:rgba(0,0,0,.25);margin-top:10px}
  button{padding:10px 12px;border-radius:10px;border:0;background:#ff5800;color:#fff;font-weight:800;cursor:pointer}
  .muted{color:#9ca3af}
</style>

<div class="wrap">
  <div class="card">
    <h2 style="margin:0 0 8px 0;">🧩 Command Templates</h2>
    <div class="muted">Placeholders: <b>{root_domain}</b> <b>{target}</b> <b>{out_dir}</b> <b>{project_slug}</b></div>

    <div class="grid" style="margin-top:10px">
      <div>
        <label>Project</label>
        <select id="projectSelect">
          <option value="">-- select project --</option>
          <?php while($p=$projects->fetch_assoc()): ?>
            <option
              value="<?= (int)$p['id'] ?>"
              data-slug="<?= htmlspecialchars($p['project_slug']) ?>"
              data-domains="<?= htmlspecialchars($p['domains'] ?? '') ?>"
            >
              <?= htmlspecialchars($p['title'].' ('.$p['company'].')') ?>
            </option>
          <?php endwhile; ?>
        </select>
      </div>
      <div>
        <label>Root Domain</label>
        <select id="rootDomain"></select>
      </div>
      <div>
        <label>Target (domain / subdomain / ip)</label>
        <input id="target" placeholder="example.com / api.example.com / 1.2.3.4">
      </div>
    </div>

    <label style="margin-top:10px">Output directory on Kali</label>
    <input id="outDir" placeholder="/home/kali/recon/{project_slug}">
  </div>

  <div class="card">
    <h3 style="margin:0 0 8px 0;">Templates</h3>
    <input id="search" placeholder="Search template..." style="margin-bottom:10px">

    <div id="tplList">
      <?php while($t=$templates->fetch_assoc()): ?>
        <div class="tpl" data-text="<?= htmlspecialchars($t['template_text']) ?>" data-name="<?= htmlspecialchars($t['name']) ?>" data-cat="<?= htmlspecialchars($t['category'].' '.$t['subcategory']) ?>">
          <div><b><?= htmlspecialchars($t['category']) ?></b> / <?= htmlspecialchars($t['subcategory'] ?? '') ?></div>
          <div style="margin-top:4px"><b><?= htmlspecialchars($t['name']) ?></b></div>
          <div class="muted" style="margin-top:4px"><?= htmlspecialchars($t['description'] ?? '') ?></div>

          <textarea rows="2" class="rendered" style="margin-top:10px" readonly><?= htmlspecialchars($t['template_text']) ?></textarea>

          <div style="display:flex;gap:10px;margin-top:10px;flex-wrap:wrap">
            <button type="button" onclick="renderOne(this)">Render</button>
            <button type="button" style="background:#374151" onclick="copyOne(this)">Copy</button>
          </div>
        </div>
      <?php endwhile; ?>
    </div>
  </div>
</div>

<script>
const projectSelect = document.getElementById('projectSelect');
const rootDomain = document.getElementById('rootDomain');
const target = document.getElementById('target');
const outDir = document.getElementById('outDir');
const search = document.getElementById('search');

function parseDomains(raw){
  const parts = raw.split(/[\n,]+/).map(x => x.trim()).filter(Boolean);
  return [...new Set(parts)];
}

function refreshRoots(){
  rootDomain.innerHTML = '';
  const opt = projectSelect.options[projectSelect.selectedIndex];
  const domains = parseDomains(opt?.dataset?.domains || '');
  const first = domains[0] || '';
  domains.forEach(d => {
    const o = document.createElement('option');
    o.value = d; o.textContent = d;
    rootDomain.appendChild(o);
  });
  if (!target.value && first) target.value = first;
  const slug = opt?.dataset?.slug || '';
  if (slug && !outDir.value) outDir.value = `/home/kali/recon/${slug}`;
}

function renderText(tpl){
  const opt = projectSelect.options[projectSelect.selectedIndex];
  const slug = opt?.dataset?.slug || '';
  return tpl
    .replaceAll('{project_slug}', slug)
    .replaceAll('{root_domain}', rootDomain.value || '')
    .replaceAll('{target}', target.value || '')
    .replaceAll('{out_dir}', outDir.value || '');
}

function renderOne(btn){
  const box = btn.closest('.tpl');
  const tpl = box.dataset.text;
  box.querySelector('.rendered').value = renderText(tpl);
}

function copyOne(btn){
  const box = btn.closest('.tpl');
  const ta = box.querySelector('.rendered');
  ta.select();
  document.execCommand('copy');
  btn.textContent = 'Copied ✓';
  setTimeout(()=>btn.textContent='Copy',1000);
}

projectSelect.addEventListener('change', () => { outDir.value=''; refreshRoots(); });
search.addEventListener('input', () => {
  const q = search.value.toLowerCase().trim();
  document.querySelectorAll('.tpl').forEach(x => {
    const hay = (x.dataset.name + ' ' + x.dataset.cat + ' ' + x.dataset.text).toLowerCase();
    x.style.display = hay.includes(q) ? '' : 'none';
  });
});

refreshRoots();
</script>

<?php require_once __DIR__ . '/footer.php'; ?>
