<?php
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/audit.php';
require_login();
?>
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title><?= htmlspecialchars(APP_NAME) ?></title>
  <style>
    body{margin:0;font-family:Segoe UI,Tahoma,sans-serif;background:#070b14;color:#e5e7eb}
    .nav{display:flex;gap:10px;align-items:center;padding:10px 12px;background:rgba(255,255,255,.06);border-bottom:1px solid rgba(255,255,255,.08)}
    .nav a{color:#e5e7eb;text-decoration:none;padding:8px 10px;border-radius:10px}
    .nav a:hover{background:rgba(255,255,255,.08)}
    .right{margin-left:auto;display:flex;gap:10px;align-items:center}
    .pill{background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.10);padding:6px 10px;border-radius:999px;font-size:13px}
    .btn{background:#ff5800;border:0;color:#fff;font-weight:700;padding:8px 12px;border-radius:10px;cursor:pointer}
  </style>
</head>
<body>
<div class="nav">
  <a href="/dashboard.php">Dashboard</a>
  <a href="/companies.php">Companies</a>
  <a href="/projects.php">Projects</a>
  <a href="/templates.php">Templates</a>
  <a href="/recon_upload.php">Recon Upload</a>
  <a href="/visualization.php">3D Graph</a>
  <a href="/logs.php">Logs</a>
  <div class="right">
    <div class="pill">👤 <?= htmlspecialchars($_SESSION['username']) ?></div>
    <a class="btn" href="/settings.php" style="text-decoration:none">Settings</a>
    <a class="btn" href="/logout.php" style="text-decoration:none;background:#374151">Logout</a>
  </div>
</div>
