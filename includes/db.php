<?php
require_once __DIR__ . '/../config.php';

function db(): mysqli {
  static $conn = null;
  if ($conn instanceof mysqli) return $conn;

  mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
  $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
  $conn->set_charset('utf8mb4');
  return $conn;
}
