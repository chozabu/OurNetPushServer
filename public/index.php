<?php
declare(strict_types=1);

// Front controller: every request is routed here (see .htaccess).
require __DIR__ . '/../src/Db.php';
require __DIR__ . '/../src/Fcm.php';
require __DIR__ . '/../src/Server.php';

use OurNetPush\{Db, Fcm, Server};

header('Content-Type: application/json');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');

$configFile = getenv('OURNET_PUSH_CONFIG') ?: __DIR__ . '/../config.php';
if (!is_file($configFile)) {
    http_response_code(503);
    echo json_encode(['error' => 'Not configured: copy config.example.php to config.php']);
    exit;
}
$config = require $configFile;

try {
    $server = new Server(
        new Db($config['db']),
        new Fcm($config['service_account'] ?? '', $config['token_cache'], $config['fcm_mode'] ?? 'live'),
        $config,
    );
    $path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
    [$status, $body] = $server->handle(
        $_SERVER['REQUEST_METHOD'] ?? 'GET',
        $path,
        (string)file_get_contents('php://input', false, null, 0, 256 * 1024 + 1),
        $_SERVER['REMOTE_ADDR'] ?? '',
    );
} catch (Throwable $e) {
    error_log('ournet-push: ' . $e);
    [$status, $body] = [500, ['error' => 'Server error']];
}
http_response_code($status);
echo json_encode($body === [] ? new stdClass() : $body);
