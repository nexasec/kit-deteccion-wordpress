<?php
/**
 * Canary de respaldos: senuelo de deteccion temprana.
 *
 * Las rutas de respaldo que los escaneres prueban rutinariamente se reescriben
 * aqui via .htaccess (ver htaccess.ejemplo). Este script registra el intento
 * FUERA del web root, opcionalmente lo empuja a un webhook (n8n), y responde 404
 * para no revelar que es un senuelo: el escaner lo marca como "no encontrado" y
 * sigue de largo.
 *
 * Configuracion en el mismo config.json que los scripts de Python. Su ruta sale
 * de la variable NX_CONFIG (p. ej. `SetEnv NX_CONFIG /home/usuario/nx-kit/config.json`
 * en el .htaccess) o, si no esta, de <carpeta padre del web root>/nx-kit/config.json.
 * Claves: webhook_canary, throttle, headers, senuelo_critico, ip_cliente, dir_estado.
 */

const MAX_LOG_BYTES = 5242880; // 5 MB, tope anti-inundacion
const MAX_URI = 1000;

// Rangos publicados de Cloudflare (los mismos que usa escalador.py).
const NX_RANGOS_CLOUDFLARE = [
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
    '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
    '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
    '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
    '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
    '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
];

function nx_en_rango(string $ip, string $cidr): bool
{
    [$red, $bits] = explode('/', $cidr);
    $a = @inet_pton($ip);
    $b = @inet_pton($red);
    if ($a === false || $b === false || strlen($a) !== strlen($b)) {
        return false;
    }
    $bits = (int) $bits;
    $bytes = intdiv($bits, 8);
    if (substr($a, 0, $bytes) !== substr($b, 0, $bytes)) {
        return false;
    }
    $resto = $bits % 8;
    if ($resto === 0) {
        return true;
    }
    $mascara = chr((0xFF << (8 - $resto)) & 0xFF);
    return (($a[$bytes] & $mascara) === ($b[$bytes] & $mascara));
}

function nx_es_cloudflare(string $ip): bool
{
    foreach (NX_RANGOS_CLOUDFLARE as $cidr) {
        if (nx_en_rango($ip, $cidr)) {
            return true;
        }
    }
    return false;
}

/*
 * IP del cliente. Dos modos:
 *
 *  remote_addr (por defecto): REMOTE_ADDR, nunca las cabeceras. Sirve en los
 *  hosting que ya restauran la IP real en REMOTE_ADDR cuando la peticion llega
 *  desde Cloudflare, y que NO lo hacen si alguien le habla directo al origen con
 *  cabeceras inventadas. Hay que verificarlo en cada hosting antes de elegirlo.
 *  Fiarse de CF-Connecting-IP sin mas deja que un atacante elija la IP que queda
 *  registrada en las alertas.
 *
 *  cf_connecting_ip_si_viene_de_cloudflare: para hosting donde REMOTE_ADDR es la
 *  IP de Cloudflare. Se acepta la cabecera solo si REMOTE_ADDR esta en un rango
 *  publicado de Cloudflare y la cabecera es una IP valida.
 *
 * En ambos modos, una cabecera presente que no se acepta queda registrada como
 * falsificada: alguien le esta hablando al origen haciendose pasar por Cloudflare.
 */
function nx_ip_cliente(array $server, string $modo): array
{
    $remota = (string) ($server['REMOTE_ADDR'] ?? '-');
    $cabecera = trim((string) ($server['HTTP_CF_CONNECTING_IP'] ?? ''));

    if ($cabecera === '') {
        return ['ip' => $remota, 'via_cloudflare' => false, 'cabecera_falsificada' => false];
    }

    if ($modo === 'cf_connecting_ip_si_viene_de_cloudflare') {
        if (nx_es_cloudflare($remota) && filter_var($cabecera, FILTER_VALIDATE_IP) !== false) {
            return ['ip' => $cabecera, 'via_cloudflare' => true, 'cabecera_falsificada' => false];
        }
    } elseif ($cabecera === $remota) {
        // Trafico genuino de Cloudflare: el hosting ya restauro la IP real.
        return ['ip' => $remota, 'via_cloudflare' => true, 'cabecera_falsificada' => false];
    }

    return ['ip' => $remota, 'via_cloudflare' => false, 'cabecera_falsificada' => substr($cabecera, 0, 64)];
}

/*
 * Senuelo critico: la URL exacta de un archivo que estuvo expuesto (por ejemplo
 * un .wpress con sufijo aleatorio). Ese nombre no se adivina por fuerza bruta:
 * un golpe ahi significa que alguien capturo la URL mientras estuvo expuesta.
 * Eso no es ruido de escaner, es dirigido. Vacio = desactivado.
 */
function nx_es_critico(string $uri, string $senuelo): bool
{
    return $senuelo !== '' && strpos($uri, $senuelo) !== false;
}

function nx_expandir(string $ruta): string
{
    if (strncmp($ruta, '~/', 2) !== 0) {
        return $ruta;
    }
    $home = getenv('HOME');
    if (!$home && function_exists('posix_getpwuid')) {
        $home = posix_getpwuid(posix_geteuid())['dir'] ?? '';
    }
    return ($home ?: dirname(__DIR__)) . substr($ruta, 1);
}

if (defined('NX_CANARY_SOLO_FUNCIONES')) {
    return;
}

$configFile = getenv('NX_CONFIG') ?: dirname(__DIR__) . '/nx-kit/config.json';
$cfg = is_readable($configFile) ? json_decode((string) file_get_contents($configFile), true) : null;
$cfg = is_array($cfg) ? $cfg : [];

$webhook  = (string) ($cfg['webhook_canary'] ?? '');
$throttle = (int) ($cfg['throttle'] ?? 300);
// Cabeceras extra: p.ej. el service token de Cloudflare Access.
$headers  = is_array($cfg['headers'] ?? null) ? $cfg['headers'] : [];
$senuelo  = (string) ($cfg['senuelo_critico'] ?? '');
$modoIp   = (string) ($cfg['ip_cliente'] ?? 'remote_addr');

$dir = isset($cfg['dir_estado']) && $cfg['dir_estado'] !== ''
    ? nx_expandir((string) $cfg['dir_estado'])
    : dirname($configFile);
$logFile   = $dir . '/canary.log';
$stateFile = $dir . '/.throttle';

$cliente = nx_ip_cliente($_SERVER, $modoIp);
$ip = $cliente['ip'];

// Recortada: la URI la elige quien pide, y sin tope una sola peticion de varios KB infla el log y
// hace que la alerta supere el limite de Telegram.
$uri = substr($_SERVER['REQUEST_URI'] ?? '-', 0, MAX_URI);
$critico = nx_es_critico($uri, $senuelo);

$event = [
    'ts'        => gmdate('c'),
    'origen'    => 'nx-canary',
    'severidad' => $critico ? 'critico' : 'informativo',
    'host'      => substr($_SERVER['HTTP_HOST'] ?? '-', 0, 120),
    'uri'       => $uri,
    'metodo'    => substr($_SERVER['REQUEST_METHOD'] ?? '-', 0, 12),
    'ip'        => $ip,
    'via_cloudflare'       => $cliente['via_cloudflare'],
    'cabecera_falsificada' => $cliente['cabecera_falsificada'],
    'pais'      => substr($_SERVER['HTTP_CF_IPCOUNTRY'] ?? '-', 0, 8),
    'ua'        => substr($_SERVER['HTTP_USER_AGENT'] ?? '-', 0, 300),
    'referer'   => substr($_SERVER['HTTP_REFERER']    ?? '-', 0, 300),
    'cf_ray'    => substr($_SERVER['HTTP_CF_RAY']     ?? '-', 0, 40),
];

$linea = json_encode($event, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE) . "\n";

if (!is_dir($dir)) {
    @mkdir($dir, 0700, true);
}
// El tope evita que alguien llene el disco martillando el senuelo.
if (!is_file($logFile) || filesize($logFile) < MAX_LOG_BYTES) {
    @file_put_contents($logFile, $linea, FILE_APPEND | LOCK_EX);
}

if ($webhook !== '') {
    $ahora  = time();
    $estado = is_readable($stateFile)
        ? (json_decode((string) @file_get_contents($stateFile), true) ?: [])
        : [];

    foreach ($estado as $k => $t) {
        if ($t < $ahora - 86400) {
            unset($estado[$k]);
        }
    }

    // Un hit critico nunca se silencia; el ruido de escaner si se agrupa por IP.
    $enviar = $critico || !isset($estado[$ip]) || ($ahora - $estado[$ip]) >= $throttle;

    if ($enviar) {
        $estado[$ip] = $ahora;
        @file_put_contents($stateFile, json_encode($estado), LOCK_EX);

        $h = ['Content-Type: application/json'];
        foreach ($headers as $k => $v) {
            $h[] = $k . ': ' . $v;
        }

        $ch = curl_init($webhook);
        curl_setopt_array($ch, [
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => json_encode($event, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE),
            CURLOPT_HTTPHEADER     => $h,
            // Sin User-Agent explicito, el Browser Integrity Check de Cloudflare
            // responde 1010 y la alerta se pierde en silencio.
            CURLOPT_USERAGENT      => 'NexaSec-Canary/1.0 (+https://nexasec.cl)',
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 2,
            CURLOPT_TIMEOUT        => 4,
        ]);
        @curl_exec($ch);
    }
}

/*
 * Indistinguible de un 404 normal, pero explicitamente no cacheable.
 *
 * Sin esto, Cloudflare cachea el 404 de los senuelos .zip durante unos minutos:
 * el segundo intento de un escaner se sirve desde el borde, el origen no lo ve
 * y el canary no se dispara. Un senuelo que solo detecta el primer golpe cada
 * pocos minutos no sirve para medir insistencia.
 */
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('CDN-Cache-Control: no-store');
header('Cloudflare-CDN-Cache-Control: no-store');
header('Pragma: no-cache');

http_response_code(404);
header('Content-Type: text/html; charset=UTF-8');
exit;
