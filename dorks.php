<?php
// public_html/one.inseclabs.com/dorks_v3.php
// SMART Google Dork Launcher - Reduces 6800+ dorks to 50-100 with intelligence

declare(strict_types=1);
ini_set('display_errors', '0');
error_reporting(E_ALL);

require_once __DIR__ . '/includes/header.php';

$conn = db();
$uid  = function_exists('current_user_id') ? (int)current_user_id() : (int)($_SESSION['user_id'] ?? 0);
if ($uid <= 0) { header("Location: index.php"); exit; }

// CSRF protection
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

function h(string $s): string { return htmlspecialchars($s, ENT_QUOTES, 'UTF-8'); }

function norm_domain(string $d): string {
    $d = trim($d);
    $d = preg_replace('~^https?://~i', '', $d);
    $d = preg_replace('~^www\.~i', '', $d);
    $d = rtrim($d, "/");
    $d = preg_replace('~[^a-z0-9\.\-\*]~i', '', $d);
    return $d ?: '';
}

function build_google_url(string $q): string {
    return "https://www.google.com/search?q=" . rawurlencode($q);
}

/**
 * SMART GROUPING: Intelligent domain grouping
 * Groups similar domains together (subdomains of same root)
 */
function smart_group_domains(array $roots, array $subs): array {
    $groups = [];
    
    // Group subdomains under their roots
    foreach ($roots as $root) {
        $root_parts = explode('.', $root);
        $tld = array_pop($root_parts);
        $domain = array_pop($root_parts);
        $base_pattern = "$domain.$tld";
        
        $group = [$root];
        foreach ($subs as $sub) {
            if (strpos($sub, $base_pattern) !== false) {
                $group[] = $sub;
            }
        }
        
        if (count($group) > 1) {
            $groups[] = $group;
            // Remove used subs
            $subs = array_diff($subs, $group);
        } else {
            $groups[] = [$root];
        }
    }
    
    // Add remaining subs as individual groups
    foreach ($subs as $sub) {
        $groups[] = [$sub];
    }
    
    return $groups;
}

/**
 * SMART CHUNKING: Better than simple chunk_targets
 */
function smart_chunk_domains(array $targets, int $max_length = 1500): array {
    // Sort by length (shortest first for better packing)
    usort($targets, function($a, $b) {
        return strlen($a) <=> strlen($b);
    });
    
    $chunks = [];
    $current = [];
    $current_length = 0;
    
    foreach ($targets as $target) {
        $target_length = strlen('site:' . $target) + 4; // " OR "
        
        if ($current && ($current_length + $target_length) > $max_length) {
            $chunks[] = $current;
            $current = [];
            $current_length = 0;
        }
        
        $current[] = $target;
        $current_length += $target_length;
    }
    
    if ($current) {
        $chunks[] = $current;
    }
    
    return $chunks;
}

/**
 * PRIORITIZED DORKS: Not all dorks are equal
 */
function get_prioritized_dorks(): array {
    return [
        // HIGH PRIORITY (Most likely to find sensitive info)
        'high' => [
            'Configuration Files' => [
                'site:{t} (ext:env OR ext:ini OR ext:conf OR ext:config)',
                'site:{t} ("DB_PASSWORD" OR "DB_USERNAME" OR "API_KEY" OR "SECRET_KEY" OR "AWS_ACCESS_KEY_ID")',
            ],
            'Backup Files' => [
                'site:{t} (ext:sql OR ext:sqlite OR ext:db OR ext:dump OR ext:bak)',
                'site:{t} (ext:zip OR ext:tar.gz OR ext:7z) backup',
            ],
            'Source Code Repos' => [
                'site:{t} inurl:/.git/HEAD',
                'site:{t} inurl:/.svn/entries',
            ],
        ],
        
        // MEDIUM PRIORITY (Good reconnaissance)
        'medium' => [
            'Directory Listings' => [
                'site:{t} intitle:"index of"',
                'site:{t} "parent directory" intitle:"index of"',
            ],
            'Login & Admin Pages' => [
                'site:{t} (inurl:login OR inurl:signin OR inurl:auth)',
                'site:{t} (inurl:admin OR intitle:admin)',
            ],
            'Documentation & Logs' => [
                'site:{t} (ext:pdf OR ext:doc OR ext:docx) (confidential OR internal)',
                'site:{t} (ext:log OR ext:txt) (error OR debug)',
            ],
        ],
        
        // LOW PRIORITY (Broad reconnaissance)
        'low' => [
            'Common Files' => [
                'site:{t} inurl:robots.txt',
                'site:{t} inurl:sitemap.xml',
            ],
            'Technology Specific' => [
                'site:{t} inurl:wp-content',
                'site:{t} inurl:wp-admin',
            ],
        ],
    ];
}

/**
 * THIRD-PARTY DORKS (already optimized)
 */
function get_thirdparty_dorks(): array {
    return [
        'GitHub/GitLab' => [
            'site:github.com "{root}"',
            'site:gitlab.com "{root}"',
            '"{root}" (password OR secret OR token OR key) site:github.com',
        ],
        'Paste Sites' => [
            'site:pastebin.com "{root}"',
            'site:ghostbin.com "{root}"',
        ],
        'Cloud Storage' => [
            '"{root}" ("s3.amazonaws.com" OR "storage.googleapis.com")',
        ],
    ];
}

// -------------------------
// PROJECT IMPORT (optimized single query)
// -------------------------
$project_id = (int)($_GET['project_id'] ?? ($_GET['id'] ?? 0));
$import_mode = ($_GET['mode'] ?? 'smart'); // smart|all|roots|subs

$project_data = ['roots' => [], 'subs' => [], 'company' => ''];

if ($project_id > 0) {
    // SINGLE QUERY - Much faster
    $stmt = $conn->prepare("
        SELECT 
            p.title,
            c.name as company_name,
            pd.root_domain,
            s.subdomain
        FROM oneinseclabs_projects p
        LEFT JOIN oneinseclabs_companies c ON c.id = p.company_id
        LEFT JOIN oneinseclabs_project_domains pd ON p.id = pd.project_id
        LEFT JOIN oneinseclabs_subdomains s ON p.id = s.project_id
        WHERE p.id = ?
        ORDER BY pd.root_domain ASC, s.subdomain ASC
    ");
    $stmt->bind_param("i", $project_id);
    $stmt->execute();
    $result = $stmt->get_result();
    
    $roots = [];
    $subs = [];
    
    while ($row = $result->fetch_assoc()) {
        if (!empty($row['company_name'])) {
            $project_data['company'] = $row['company_name'];
        }
        
        if (!empty($row['root_domain'])) {
            $rd = norm_domain($row['root_domain']);
            if ($rd) $roots[$rd] = true;
        }
        
        if (!empty($row['subdomain'])) {
            $sd = norm_domain($row['subdomain']);
            if ($sd) $subs[$sd] = true;
        }
    }
    
    $project_data['roots'] = array_keys($roots);
    $project_data['subs'] = array_keys($subs);
}

// -------------------------
// FORM HANDLING
// -------------------------
$root = norm_domain($_POST['root_domain'] ?? '');
$keyword = trim($_POST['org_keyword'] ?? '');
$priority = $_POST['priority'] ?? 'high'; // high|medium|low|all
$group_mode = $_POST['group_mode'] ?? 'smart'; // smart|simple|perhost
$include_thirdparty = isset($_POST['include_thirdparty']);

if ($_SERVER['REQUEST_METHOD'] !== 'POST' && $project_id > 0) {
    // Auto-fill from project
    if (empty($root) && !empty($project_data['roots'])) {
        $root = $project_data['roots'][0];
    }
    if (empty($keyword) && !empty($project_data['company'])) {
        $keyword = $project_data['company'];
    }
}

// Get target domains
$targets = [];
if (!empty($root)) {
    $targets[] = $root;
    
    // Auto-add relevant subdomains if in smart mode
    if ($group_mode === 'smart' && !empty($project_data['subs'])) {
        foreach ($project_data['subs'] as $sub) {
            if (strpos($sub, $root) !== false) {
                $targets[] = $sub;
            }
        }
    }
}

$targets = array_values(array_unique($targets));

// -------------------------
// GENERATE DORKS (SMART MODE)
// -------------------------
$generated = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($root) && !empty($_POST['csrf_token']) && 
    hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
    
    $dorks = get_prioritized_dorks();
    
    // Select priority level
    $selected_dorks = [];
    if ($priority === 'all') {
        foreach ($dorks as $priority_level => $categories) {
            foreach ($categories as $cat => $queries) {
                $selected_dorks[$cat] = $queries;
            }
        }
    } else {
        $selected_dorks = $dorks[$priority] ?? $dorks['high'];
    }
    
    // Group domains based on mode
    if ($group_mode === 'perhost') {
        // Old style (6800+ dorks)
        foreach ($targets as $t) {
            foreach ($selected_dorks as $cat => $queries) {
                foreach ($queries as $q) {
                    $qq = str_replace(['{t}', '{root}', '{kw}'], [$t, $root, $keyword], $q);
                    $qq = trim(preg_replace('/\s+/', ' ', $qq));
                    $generated[] = [
                        'cat' => $cat,
                        'target' => $t,
                        'query' => $qq,
                        'url' => build_google_url($qq),
                        'priority' => $priority
                    ];
                }
            }
        }
    } else {
        // SMART GROUPED MODE (50-100 dorks)
        if ($group_mode === 'smart') {
            $domain_groups = smart_group_domains([$root], array_slice($targets, 1));
            $chunks = [];
            foreach ($domain_groups as $group) {
                $chunks = array_merge($chunks, smart_chunk_domains($group, 1400));
            }
        } else {
            // Simple grouping
            $chunks = smart_chunk_domains($targets, 1800);
        }
        
        // Generate grouped dorks
        foreach ($selected_dorks as $cat => $queries) {
            foreach ($queries as $q) {
                foreach ($chunks as $idx => $chunk) {
                    if (count($chunk) === 1) {
                        $site_expr = 'site:' . $chunk[0];
                    } else {
                        $parts = array_map(fn($t) => 'site:' . $t, $chunk);
                        $site_expr = '(' . implode(' OR ', $parts) . ')';
                    }
                    
                    $qq = str_replace('site:{t}', $site_expr, $q);
                    $qq = str_replace(['{root}', '{kw}'], [$root, $keyword], $qq);
                    $qq = trim(preg_replace('/\s+/', ' ', $qq));
                    
                    $generated[] = [
                        'cat' => $cat,
                        'target' => 'group ' . ($idx + 1) . ' (' . count($chunk) . ' domains)',
                        'query' => $qq,
                        'url' => build_google_url($qq),
                        'priority' => $priority
                    ];
                }
            }
        }
    }
    
    // Add third-party dorks
    if ($include_thirdparty) {
        $thirdparty_dorks = get_thirdparty_dorks();
        foreach ($thirdparty_dorks as $cat => $queries) {
            foreach ($queries as $q) {
                $qq = str_replace(['{root}', '{kw}'], [$root, $keyword], $q);
                $qq = trim(preg_replace('/\s+/', ' ', $qq));
                $generated[] = [
                    'cat' => '3rd-party: ' . $cat,
                    'target' => 'external',
                    'query' => $qq,
                    'url' => build_google_url($qq),
                    'priority' => 'medium'
                ];
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Smart Dork Launcher</title>
    <style>
        :root {
            --bg-primary: #0b1020;
            --bg-secondary: #121a33;
            --bg-tertiary: #0f1630;
            --text-primary: #e7eaf3;
            --text-secondary: #93c5fd;
            --accent: #3b82f6;
            --accent-secondary: #263255;
            --border: rgba(255,255,255,0.08);
        }
        
        body {
            font-family: system-ui, -apple-system, sans-serif;
            margin: 0;
            background: var(--bg-primary);
            color: var(--text-primary);
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .card {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 20px;
            margin-bottom: 16px;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 12px;
            margin: 16px 0;
        }
        
        .stat-box {
            background: var(--bg-tertiary);
            border-radius: 10px;
            padding: 12px;
            text-align: center;
        }
        
        .stat-value {
            font-size: 24px;
            font-weight: bold;
            color: var(--accent);
        }
        
        .stat-label {
            font-size: 12px;
            opacity: 0.8;
            margin-top: 4px;
        }
        
        .priority-badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .priority-high { background: rgba(239, 68, 68, 0.2); border: 1px solid rgba(239, 68, 68, 0.3); }
        .priority-medium { background: rgba(245, 158, 11, 0.2); border: 1px solid rgba(245, 158, 11, 0.3); }
        .priority-low { background: rgba(34, 197, 94, 0.2); border: 1px solid rgba(34, 197, 94, 0.3); }
        
        .dork-row {
            border-bottom: 1px solid var(--border);
            padding: 12px 0;
            display: grid;
            grid-template-columns: 40px 180px 150px 1fr 100px;
            gap: 12px;
            align-items: start;
        }
        
        .dork-row:last-child {
            border-bottom: none;
        }
        
        .query-box {
            font-family: ui-monospace, monospace;
            font-size: 12px;
            background: var(--bg-tertiary);
            padding: 8px;
            border-radius: 6px;
            word-break: break-word;
        }
        
        .actions-bar {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            margin: 20px 0;
        }
        
        .btn {
            background: var(--accent);
            color: white;
            border: none;
            border-radius: 10px;
            padding: 10px 16px;
            cursor: pointer;
            font-weight: 600;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }
        
        .btn-secondary {
            background: var(--accent-secondary);
            border: 1px solid rgba(255,255,255,0.14);
        }
        
        .btn-sm {
            padding: 6px 12px;
            font-size: 13px;
        }
        
        input, select, textarea {
            background: var(--bg-tertiary);
            border: 1px solid var(--border);
            color: var(--text-primary);
            border-radius: 10px;
            padding: 10px;
            width: 100%;
            box-sizing: border-box;
        }
        
        .grid-2 {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px;
        }
        
        .grid-3 {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 16px;
        }
    </style>
</head>
<body>
<div class="container">
    <!-- Header Card -->
    <div class="card">
        <h1 style="margin: 0 0 8px 0;">🚀 Smart Dork Launcher</h1>
        <p style="opacity: 0.8; margin: 0; font-size: 14px;">
            Transforms 6800+ dorks into 50-100 intelligent searches
        </p>
        
        <?php if ($project_id > 0): ?>
        <div style="margin-top: 16px; padding: 12px; background: var(--bg-tertiary); border-radius: 10px;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <strong>Project #<?= $project_id ?></strong> • 
                    <?= count($project_data['roots']) ?> roots • 
                    <?= count($project_data['subs']) ?> subdomains
                </div>
                <div>
                    <select id="quickMode" style="width: auto; padding: 6px 12px; font-size: 13px;">
                        <option value="smart">Smart Mode (Recommended)</option>
                        <option value="high">High Priority Only</option>
                        <option value="all">All Dorks</option>
                        <option value="perhost">Per Host (Legacy)</option>
                    </select>
                    <button onclick="applyQuickMode()" class="btn btn-sm">Quick Apply</button>
                </div>
            </div>
        </div>
        <?php endif; ?>
    </div>
    
    <!-- Form Card -->
    <div class="card">
        <form method="post" autocomplete="off">
            <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
            
            <div class="grid-3">
                <div>
                    <label style="display: block; margin-bottom: 6px; font-size: 13px;">Root Domain</label>
                    <?php if (!empty($project_data['roots'])): ?>
                    <select name="root_domain" required>
                        <?php foreach ($project_data['roots'] as $rd): ?>
                        <option value="<?= h($rd) ?>" <?= $root === $rd ? 'selected' : '' ?>>
                            <?= h($rd) ?>
                        </option>
                        <?php endforeach; ?>
                    </select>
                    <?php else: ?>
                    <input type="text" name="root_domain" placeholder="example.com" value="<?= h($root) ?>" required>
                    <?php endif; ?>
                </div>
                
                <div>
                    <label style="display: block; margin-bottom: 6px; font-size: 13px;">Organization Keyword</label>
                    <input type="text" name="org_keyword" placeholder="Company/Brand" value="<?= h($keyword) ?>">
                </div>
                
                <div>
                    <label style="display: block; margin-bottom: 6px; font-size: 13px;">Priority Level</label>
                    <select name="priority">
                        <option value="high" <?= $priority === 'high' ? 'selected' : '' ?>>High Priority (Fastest)</option>
                        <option value="medium" <?= $priority === 'medium' ? 'selected' : '' ?>>Medium Priority</option>
                        <option value="low" <?= $priority === 'low' ? 'selected' : '' ?>>Low Priority</option>
                        <option value="all" <?= $priority === 'all' ? 'selected' : '' ?>>All Dorks</option>
                    </select>
                </div>
            </div>
            
            <div class="grid-2" style="margin-top: 16px;">
                <div>
                    <label style="display: block; margin-bottom: 6px; font-size: 13px;">Grouping Mode</label>
                    <select name="group_mode">
                        <option value="smart" <?= $group_mode === 'smart' ? 'selected' : '' ?>>Smart Grouping (Recommended)</option>
                        <option value="simple" <?= $group_mode === 'simple' ? 'selected' : '' ?>>Simple Grouping</option>
                        <option value="perhost" <?= $group_mode === 'perhost' ? 'selected' : '' ?>>Per Host (6800+ dorks)</option>
                    </select>
                </div>
                
                <div style="display: flex; align-items: flex-end;">
                    <label style="display: flex; align-items: center; gap: 8px; font-size: 14px;">
                        <input type="checkbox" name="include_thirdparty" <?= $include_thirdparty ? 'checked' : '' ?>>
                        Include 3rd-party sources (GitHub, Pastebin, etc.)
                    </label>
                </div>
            </div>
            
            <div class="actions-bar">
                <button type="submit" class="btn">
                    🔍 Generate Smart Dorks
                </button>
                <div style="flex-grow: 1;"></div>
                <button type="button" class="btn-secondary" onclick="selectAllDorks(true)">
                    📋 Select All
                </button>
                <button type="button" class="btn-secondary" onclick="selectAllDorks(false)">
                    📋 Clear All
                </button>
            </div>
        </form>
    </div>
    
    <?php if (!empty($generated)): ?>
    <!-- Results Card -->
    <div class="card">
        <!-- Stats -->
        <div class="stats-grid">
            <div class="stat-box">
                <div class="stat-value"><?= count($generated) ?></div>
                <div class="stat-label">Total Dorks</div>
            </div>
            <div class="stat-box">
                <div class="stat-value"><?= count($targets) ?></div>
                <div class="stat-label">Domains</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">
                    <?= round(count($generated) / max(1, count($targets)), 1) ?>
                </div>
                <div class="stat-label">Dorks per Domain</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">
                    <?php 
                    $unique_cats = array_unique(array_column($generated, 'cat'));
                    echo count($unique_cats);
                    ?>
                </div>
                <div class="stat-label">Categories</div>
            </div>
        </div>
        
        <!-- Action Bar -->
        <div class="actions-bar">
            <button class="btn" onclick="openSelected()">
                ↗️ Open Selected (<?= count($generated) ?> tabs)
            </button>
            <button class="btn-secondary" onclick="copySelected()">
                📝 Copy Queries
            </button>
            <button class="btn-secondary" onclick="exportToCSV()">
                📥 Export CSV
            </button>
            <button class="btn-secondary" onclick="saveAsPreset()">
                💾 Save as Preset
            </button>
        </div>
        
        <!-- Dorks Table -->
        <div style="margin-top: 20px; border: 1px solid var(--border); border-radius: 10px; overflow: hidden;">
            <!-- Header -->
            <div class="dork-row" style="font-weight: bold; background: var(--bg-tertiary);">
                <div>✓</div>
                <div>Category</div>
                <div>Target</div>
                <div>Query</div>
                <div>Action</div>
            </div>
            
            <!-- Rows -->
            <?php foreach ($generated as $idx => $dork): ?>
            <div class="dork-row">
                <div>
                    <input type="checkbox" class="dork-check" 
                           data-url="<?= h($dork['url']) ?>" 
                           data-query="<?= h($dork['query']) ?>"
                           checked>
                </div>
                <div>
                    <span class="priority-badge priority-<?= $dork['priority'] ?>">
                        <?= $dork['priority'] ?>
                    </span><br>
                    <span style="font-size: 12px; opacity: 0.9;"><?= h($dork['cat']) ?></span>
                </div>
                <div style="font-size: 12px; opacity: 0.9;"><?= h($dork['target']) ?></div>
                <div class="query-box"><?= h($dork['query']) ?></div>
                <div>
                    <a href="<?= h($dork['url']) ?>" target="_blank" 
                       style="color: var(--text-secondary); text-decoration: none; font-size: 13px;">
                        Open ↗
                    </a>
                </div>
            </div>
            <?php endforeach; ?>
        </div>
    </div>
    <?php endif; ?>
</div>

<script>
// Quick mode for projects
function applyQuickMode() {
    const mode = document.getElementById('quickMode').value;
    const form = document.querySelector('form');
    
    switch(mode) {
        case 'smart':
            form.querySelector('[name="priority"]').value = 'high';
            form.querySelector('[name="group_mode"]').value = 'smart';
            break;
        case 'high':
            form.querySelector('[name="priority"]').value = 'high';
            form.querySelector('[name="group_mode"]').value = 'simple';
            break;
        case 'all':
            form.querySelector('[name="priority"]').value = 'all';
            form.querySelector('[name="group_mode"]').value = 'simple';
            break;
        case 'perhost':
            form.querySelector('[name="priority"]').value = 'high';
            form.querySelector('[name="group_mode"]').value = 'perhost';
            break;
    }
    
    alert('Settings applied. Click "Generate Smart Dorks" to continue.');
}

// Dork management
function selectAllDorks(checked) {
    document.querySelectorAll('.dork-check').forEach(cb => cb.checked = checked);
}

function getSelectedDorks() {
    return Array.from(document.querySelectorAll('.dork-check:checked'));
}

async function openSelected() {
    const selected = getSelectedDorks();
    if (selected.length === 0) {
        alert('Please select at least one dork.');
        return;
    }
    
    if (selected.length > 30 && !confirm(`About to open ${selected.length} tabs. Continue?`)) {
        return;
    }
    
    // Open in batches to avoid browser blocking
    const BATCH_SIZE = 5;
    const DELAY = 1000;
    
    let index = 0;
    const openBatch = () => {
        const end = Math.min(index + BATCH_SIZE, selected.length);
        for (; index < end; index++) {
            const url = selected[index].dataset.url;
            window.open(url, '_blank', 'noopener,noreferrer,popup');
        }
        
        if (index < selected.length) {
            setTimeout(openBatch, DELAY);
        } else {
            alert(`Opened ${selected.length} tabs.`);
        }
    };
    
    openBatch();
}

async function copySelected() {
    const selected = getSelectedDorks();
    if (selected.length === 0) {
        alert('Please select at least one dork.');
        return;
    }
    
    const queries = selected.map(d => d.dataset.query).join('\n\n');
    
    try {
        await navigator.clipboard.writeText(queries);
        alert(`Copied ${selected.length} queries to clipboard.`);
    } catch (err) {
        const textarea = document.createElement('textarea');
        textarea.value = queries;
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
        alert(`Copied ${selected.length} queries (fallback).`);
    }
}

function exportToCSV() {
    const selected = getSelectedDorks();
    if (selected.length === 0) {
        alert('Please select at least one dork.');
        return;
    }
    
    let csv = 'Category,Target,Query,URL\n';
    selected.forEach(dork => {
        const row = document.querySelector(`.dork-check[data-url="${dork.dataset.url}"]`)
            .closest('.dork-row');
        const cat = row.querySelector('span[style*="font-size: 12px"]').textContent;
        const target = row.querySelector('div:nth-child(3)').textContent;
        
        csv += `"${cat}","${target}","${dork.dataset.query}","${dork.dataset.url}"\n`;
    });
    
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `dorks-${new Date().toISOString().split('T')[0]}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
}

function saveAsPreset() {
    alert('Feature coming soon: Save this configuration as a reusable preset.');
}
</script>
</body>
</html>