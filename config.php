<?php
// === CONFIG ===
date_default_timezone_set('Asia/Kolkata');

define('DB_HOST', 'localhost');
define('DB_USER', 'inseclabs_admin');
define('DB_PASS', 'Mr.inseclabs@123456');
define('DB_NAME', 'inseclabs_db');

// reCAPTCHA v3 (invisible). Put your keys here.
define('RECAPTCHA_SITE_KEY', '6LcSel4sAAAAAJ5cPAdqWIZmDRXx1JmF5Xosll6J');
define('RECAPTCHA_SECRET', '6LcSel4sAAAAAPiH7wkFcgFVnlTv3COFcvwzR8KQ');
define('ONEINSECLABS_APP_KEY', 'EDc2s28BmL4o5BSbJRCAxMITQ5SXULda');


// Optional: ipinfo token (for city/country). Leave empty to disable.
define('IPINFO_TOKEN', '');

// Upload storage
define('UPLOAD_DIR', __DIR__ . '/uploads/tool_outputs');
define('UPLOAD_MAX_BYTES', 15 * 1024 * 1024); // 15 MB

// Session security
define('SESSION_TIMEOUT_SECONDS', 60 * 60); // 1 hour
