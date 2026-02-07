<?php
require_once __DIR__ . '/auth.php';
require_login();
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>OneInSecLabs</title>
  <link rel="stylesheet" href="assets/css/app.css">
</head>
<body>
<div class="app">
  <aside class="sidebar">
    <div class="brand">OneInSecLabs</div>
    <nav>
      <a href="dashboard.php">Dashboard</a>
      <a href="search.php">Search</a>
      <a href="notes.php">Notes</a>
      <a href="checklist.php">Checklist</a>
      <a href="logs.php">Logs</a>
      <a href="settings.php">Settings</a>
      <a href="logout.php" class="danger">Logout</a>
    </nav>
  </aside>
  <main class="main">
    <div class="topbar">
      <div class="muted">Personal Bug Bounty Workspace</div>
      <div class="pill">User #<?= (int)current_user_id() ?></div>
    </div>
