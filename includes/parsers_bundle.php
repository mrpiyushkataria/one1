<?php
declare(strict_types=1);

/**
 * public_html/one.inseclabs.com/includes/parsers_bundle.php
 * Bundle/ZIP helpers only (NO duplicate function names).
 *
 * This file is optional. It must NOT redeclare anything that already exists
 * in includes/parsers.php.
 */

require_once __DIR__ . '/parsers.php';

/**
 * Detect tool key for bundle file path + content.
 * If parsers.php already has detect_tool_key_by_path(), we will use it.
 * Otherwise we define a fallback here.
 */
if (!function_exists('detect_tool_key_by_path')) {
  function detect_tool_key_by_path(string $relpath, string $content): string {
    $p = strtolower(str_replace('\\', '/', $relpath));

    if (str_ends_with($p, '.xml') && strpos(strtolower($content), '<nmaprun') !== false) return 'nmap';
    if (preg_match('#/(subdomains|subs?)/#', $p) || str_contains($p,'all_subdomains.txt') || str_contains($p,'subdomains.txt')) return 'subdomains';
    if (str_contains($p, 'resolved') || str_contains($p,'dnsx')) return 'dnsx';
    if (str_contains($p,'httpx')) return 'httpx';
    if (str_contains($p,'wayback') || str_contains($p,'gau') || str_contains($p,'katana') || str_contains($p,'urls') || str_contains($p,'crawled')) return 'wayback';
    if (str_contains($p,'naabu') || str_contains($p,'ports.txt')) return 'naabu';
    if (str_contains($p,'nuclei') || str_contains($p,'vuln') || str_contains($p,'vulnerabilities')) return 'nuclei';

    // fallback to generic content detection if available
    if (function_exists('detect_tool_key')) return detect_tool_key($content);
    return 'other';
  }
}

/**
 * OPTIONAL: bundle structure detection (helps when filenames are weird)
 */
if (!function_exists('bundle_detect_type')) {
  function bundle_detect_type(array $zipFileList): string {
    $hit = [
      'nuclei' => 0,
      'httpx' => 0,
      'naabu' => 0,
      'nmap' => 0,
      'gau' => 0,
      'katana' => 0,
      'wayback' => 0,
      'subdomains' => 0,
      'dnsx' => 0,
      'gowitness' => 0,
      'ffuf' => 0,
      'dirsearch' => 0,
    ];
    foreach ($zipFileList as $p) {
      $p = strtolower(str_replace('\\','/',$p));
      if (str_contains($p,'nuclei')) $hit['nuclei']++;
      if (str_contains($p,'httpx')) $hit['httpx']++;
      if (str_contains($p,'naabu')) $hit['naabu']++;
      if (str_contains($p,'nmap') || str_ends_with($p,'.xml')) $hit['nmap']++;
      if (str_contains($p,'gau')) $hit['gau']++;
      if (str_contains($p,'katana')) $hit['katana']++;
      if (str_contains($p,'wayback')) $hit['wayback']++;
      if (str_contains($p,'subdomain') || str_contains($p,'subs')) $hit['subdomains']++;
      if (str_contains($p,'dnsx') || str_contains($p,'resolved')) $hit['dnsx']++;
      if (str_contains($p,'gowitness')) $hit['gowitness']++;
      if (str_contains($p,'ffuf')) $hit['ffuf']++;
      if (str_contains($p,'dirsearch')) $hit['dirsearch']++;
    }
    arsort($hit);
    $top = array_key_first($hit);
    return $hit[$top] > 0 ? $top : 'generic';
  }
}
