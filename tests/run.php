<?php
declare(strict_types=1);

// Run with: php tests/run.php
require __DIR__ . '/../src/Db.php';
require __DIR__ . '/../src/Fcm.php';
require __DIR__ . '/../src/Server.php';

use OurNetPush\{Db, Fcm, Server};

$tmp = __DIR__ . '/tmp';
@mkdir($tmp);
array_map('unlink', glob("$tmp/*"));
$failures = 0;
function check(string $name, bool $ok, mixed $detail = null): void
{
    global $failures;
    echo ($ok ? 'ok   ' : 'FAIL ') . $name . ($ok || $detail === null ? '' : ': ' . json_encode($detail)) . "\n";
    if (!$ok) $failures++;
}

$db = new Db("$tmp/push.sqlite");
$fcm = new Fcm('', "$tmp/token.json", 'log');
$server = new Server($db, $fcm, ['limits' => ['grant_interval' => 5, 'device_per_hour' => 3, 'max_grants' => 4, 'ip_per_hour' => 20]]);
$t = 1_000_000;
$call = fn(string $path, array $body, string $ip = '1.1.1.1', ?int $now = null) =>
    $server->handle('POST', $path, json_encode($body), $ip, $now ?? $t);
$sha = fn(string $s) => hash('sha256', $s);
$sent = fn() => count(@file("$tmp/token.json.log") ?: []);

[$s, $b] = $server->handle('GET', '/', '', '1.1.1.1');
check('info', $s === 200 && $b['service'] === 'ournet-push');

[$s, $b] = $call('/v1/register', ['fcm' => 'fcm-token-1']);
check('register', $s === 201 && strlen($b['device']) === 22 && strlen($b['secret']) === 43, $b);
['device' => $device, 'secret' => $secret] = $b;

[$s, $b] = $call('/v1/register', ['fcm' => 'fcm-token-2', 'device' => $device, 'secret' => $secret]);
check('register updates the token', $s === 200 && $db->device($device)['fcm'] === 'fcm-token-2', $b);

[$s] = $call('/v1/register', ['fcm' => 'x', 'device' => $device, 'secret' => str_repeat('A', 43)]);
check('wrong secret refused', $s === 403);

$friends = ['friend-token-aaaaaaaa1', 'friend-token-bbbbbbbb2', 'friend-token-cccccccc3'];
[$s, $b] = $call('/v1/grants', ['device' => $device, 'secret' => $secret, 'add' => array_map($sha, $friends)]);
check('bulk grant', $s === 200 && $b['grants'] === 3, $b);

[$s, $b] = $call('/v1/grants', ['device' => $device, 'secret' => $secret, 'add' => array_map($sha, ['t-dddddddddddddd', 't-eeeeeeeeeeeeee'])]);
check('grant limit refuses the whole change', $s === 400 && $db->grantCount($device) === 3, $b);

[$s] = $call('/v1/grants', ['device' => $device, 'secret' => $secret, 'add' => ['NOTAHASH']]);
check('bad hash refused', $s === 400);

[$s] = $call('/v1/wake', ['device' => $device, 'token' => 'stranger-token-zzzz']);
check('stranger cannot wake', $s === 403);
[$s] = $call('/v1/wake', ['device' => 'AAAAAAAAAAAAAAAAAAAAAA', 'token' => $friends[0]]);
check('unknown device looks the same', $s === 403);
check('nothing sent', $sent() === 0);

[$s] = $call('/v1/wake', ['device' => $device, 'token' => $friends[0]]);
check('friend wakes', $s === 202 && $sent() === 1);
$msg = json_decode(file("$tmp/token.json.log")[0], true)['message'];
check('wake is data-only, high priority, to the current token',
    $msg['token'] === 'fcm-token-2' && $msg['data'] === ['ournet' => 'wake'] && $msg['android']['priority'] === 'HIGH' && !isset($msg['notification']), $msg);

[$s, $b] = $call('/v1/wake', ['device' => $device, 'token' => $friends[0]], now: $t + 2);
check('per-grant interval', $s === 429 && $b['retry'] === 3, $b);
[$s] = $call('/v1/wake', ['device' => $device, 'token' => $friends[1]], now: $t + 2);
check('another friend is not held up', $s === 202);
[$s] = $call('/v1/wake', ['device' => $device, 'token' => $friends[0]], now: $t + 6);
check('again after the interval', $s === 202);
[$s] = $call('/v1/wake', ['device' => $device, 'token' => $friends[2]], now: $t + 7);
check('per-device hourly cap', $s === 429 && $sent() === 3);
[$s] = $call('/v1/wake', ['device' => $device, 'token' => $friends[2]], now: $t + 3601);
check('cap resets after an hour', $s === 202);

// Calls skip the per-grant interval, expire quickly, and share a collapse key with their cancel.
[$s] = $call('/v1/wake', ['device' => $device, 'token' => $friends[2], 'kind' => 'call', 'call' => 'c1'], now: $t + 3602);
$msg = json_decode(file("$tmp/token.json.log")[$sent() - 1], true)['message'];
check('call rings straight after a wake', $s === 202
    && $msg['data'] === ['ournet' => 'call', 'call' => 'c1'] && $msg['android']['ttl'] === '30s' && $msg['android']['collapse_key'] === 'call', $msg);
[$s] = $call('/v1/wake', ['device' => $device, 'token' => $friends[2], 'kind' => 'cancel', 'call' => 'c1'], now: $t + 3602);
$msg = json_decode(file("$tmp/token.json.log")[$sent() - 1], true)['message'];
check('cancel follows at once', $s === 202 && $msg['data'] === ['ournet' => 'cancel', 'call' => 'c1'], $msg);
[$s] = $call('/v1/wake', ['device' => $device, 'token' => $friends[2], 'kind' => 'call'], now: $t + 3603);
check('call needs an ID', $s === 400);
[$s] = $call('/v1/wake', ['device' => $device, 'token' => $friends[2], 'kind' => 'ring', 'call' => 'c1'], now: $t + 3603);
check('unknown kind refused', $s === 400);
[$s, $b] = $call('/v1/wake', ['device' => $device, 'token' => $friends[2], 'kind' => 'call', 'call' => 'c2'], now: $t + 3603);
check('calls count toward the hourly cap', $s === 429, $b);

[$s, $b] = $call('/v1/grants', ['device' => $device, 'secret' => $secret, 'remove' => [$sha($friends[1])]]);
check('revoke one friend', $s === 200 && $b['grants'] === 2, $b);
[$s] = $call('/v1/wake', ['device' => $device, 'token' => $friends[1]], now: $t + 4000);
check('revoked friend refused', $s === 403);

[$s, $b] = $call('/v1/grants', ['device' => $device, 'secret' => $secret, 'replace' => [$sha($friends[1])]]);
check('replace sets the whole list', $s === 200 && $b['grants'] === 1
    && $db->grant($device, $sha($friends[1])) && !$db->grant($device, $sha($friends[0])), $b);

// FCM says the token is gone: the device is forgotten and senders told.
[$s, $b] = $call('/v1/register', ['fcm' => 'gone-token']);
$gone = $b['device'];
$call('/v1/grants', ['device' => $gone, 'secret' => $b['secret'], 'add' => [$sha($friends[0])]]);
[$s] = $call('/v1/wake', ['device' => $gone, 'token' => $friends[0]]);
check('gone token answers 410 and forgets the device', $s === 410 && $db->device($gone) === null);

[$s] = $call('/v1/unregister', ['device' => $device, 'secret' => $secret]);
check('unregister', $s === 200 && $db->device($device) === null && $db->grantCount($device) === 0);

for ($i = 0; $i < 25; $i++) [$s] = $call('/v1/register', ['fcm' => "f$i"], '9.9.9.9');
check('registrations limited per IP', $s === 429);

[$s] = $server->handle('POST', '/v1/wake', 'not json', '1.1.1.1');
check('bad JSON refused', $s === 400);
[$s] = $server->handle('PUT', '/v1/wake', '{}', '1.1.1.1');
check('POST only', $s === 405);

// The JWT used for Google's token endpoint verifies with the key's public half.
$key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
openssl_pkey_export($key, $pem);
$jwt = Fcm::jwt(['iss' => 'a@b', 'aud' => 'x'], $pem);
[$h, $p, $sig] = explode('.', $jwt);
$unb64 = fn($s) => base64_decode(strtr($s, '-_', '+/'));
check('JWT signs RS256', json_decode($unb64($h), true)['alg'] === 'RS256'
    && openssl_verify("$h.$p", $unb64($sig), openssl_pkey_get_details($key)['key'], OPENSSL_ALGO_SHA256) === 1);

echo $failures ? "\n$failures failed\n" : "\nAll passed\n";
exit($failures ? 1 : 0);
