<?php
declare(strict_types=1);

/**
 * public_html/one.inseclabs.com/includes/shodan_lib.php
 * - AES-256-GCM (authenticated encryption)
 * - Backward compatible with old AES-256-CBC blob
 */

function shodan_key_bytes(): string {
    if (!defined('ONEINSECLABS_APP_KEY')) throw new RuntimeException("APP_KEY missing");
    return hash('sha256', ONEINSECLABS_APP_KEY, true); // 32 bytes
}

/**
 * New format (GCM):
 * base64("GCM" + iv(12) + tag(16) + ciphertext)
 */
function shodan_encrypt(string $plain): string {
    $key = shodan_key_bytes();
    $iv  = random_bytes(12);
    $tag = '';
    $ct  = openssl_encrypt($plain, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
    if ($ct === false || $tag === '') throw new RuntimeException("Encrypt failed");
    return base64_encode("GCM" . $iv . $tag . $ct);
}

/**
 * - If blob starts with "GCM" → decrypt GCM
 * - else → try legacy CBC (your old format: base64(iv16 + ct))
 */
function shodan_decrypt(string $blob): string {
    $raw = base64_decode($blob, true);
    if ($raw === false || strlen($raw) < 17) return '';

    $key = shodan_key_bytes();

    // New GCM?
    if (strlen($raw) > 3 && substr($raw, 0, 3) === "GCM") {
        if (strlen($raw) < 3 + 12 + 16 + 1) return '';
        $iv  = substr($raw, 3, 12);
        $tag = substr($raw, 3 + 12, 16);
        $ct  = substr($raw, 3 + 12 + 16);
        $pt  = openssl_decrypt($ct, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
        return $pt === false ? '' : $pt;
    }

    // Legacy CBC fallback
    $iv = substr($raw, 0, 16);
    $ct = substr($raw, 16);
    $pt = openssl_decrypt($ct, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
    return $pt === false ? '' : $pt;
}

function shodan_get_api_key(mysqli $conn, int $user_id): string {
    $k = 'shodan_api';
    $st = $conn->prepare("SELECT secret_value FROM oneinseclabs_user_secrets WHERE user_id=? AND secret_key=? LIMIT 1");
    $st->bind_param("is", $user_id, $k);
    $st->execute();
    $row = $st->get_result()->fetch_assoc();
    if (!$row) return '';
    return shodan_decrypt((string)$row['secret_value']);
}

function shodan_set_api_key(mysqli $conn, int $user_id, string $api_key): void {
    $k = 'shodan_api';
    $enc = shodan_encrypt($api_key);
    $st = $conn->prepare("
        INSERT INTO oneinseclabs_user_secrets (user_id, secret_key, secret_value)
        VALUES (?,?,?)
        ON DUPLICATE KEY UPDATE secret_value=VALUES(secret_value), updated_at=NOW()
    ");
    $st->bind_param("iss", $user_id, $k, $enc);
    $st->execute();
}

function shodan_http_get(string $url, int $timeout = 25): array {
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_USERAGENT => 'InSecLabs-Shodan/2.0',
    ]);
    $body = curl_exec($ch);
    $err  = curl_error($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($body === false) return ['ok'=>false, 'code'=>0, 'error'=>$err ?: 'curl error', 'json'=>null, 'raw'=>null];

    $json = json_decode($body, true);
    $ok = ($code >= 200 && $code < 300);

    // Shodan rate limit can return 429
    if ($code === 429) $ok = false;

    return ['ok'=>$ok, 'code'=>$code, 'error'=>null, 'json'=>$json, 'raw'=>$body];
}

function shodan_search(string $api_key, string $query, int $page = 1): array {
    $q = rawurlencode($query);
    $url = "https://api.shodan.io/shodan/host/search?key=" . rawurlencode($api_key) . "&query={$q}&page={$page}";
    return shodan_http_get($url, 35);
}

function shodan_host(string $api_key, string $ip): array {
    $url = "https://api.shodan.io/shodan/host/" . rawurlencode($ip) . "?key=" . rawurlencode($api_key);
    return shodan_http_get($url, 35);
}
