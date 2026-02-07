<?php
/**
 * ✅ Compatibility wrapper:
 * Older pages include includes/csrf.php and use:
 * - csrf_token()
 * - csrf_verify()
 *
 * We now centralize logic in includes/auth.php (csrf_check).
 */
require_once __DIR__ . '/auth.php';

if (!function_exists('csrf_verify')) {
  function csrf_verify(): void {
    csrf_check();
  }
}
