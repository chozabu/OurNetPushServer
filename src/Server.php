<?php
declare(strict_types=1);

namespace OurNetPush;

/** Thrown to answer a request with an HTTP error. */
final class HttpError extends \RuntimeException
{
    public function __construct(public readonly int $status, string $message, public readonly array $extra = [])
    {
        parent::__construct($message);
    }
}

/**
 * The OurNet wake relay. A device registers its FCM token and gets an id
 * and admin secret. With the secret it grants wake tokens, one per friend
 * device, by their SHA-256 hashes. A friend holding a token can then ask
 * the server to wake the device, within rate limits. Wakes carry no
 * content: the woken device syncs with its friends directly.
 *
 * See README.md for the API.
 */
final class Server
{
    private const ID = '/^[A-Za-z0-9_-]{22}$/';
    private const SECRET = '/^[A-Za-z0-9_-]{43}$/';
    private const TOKEN = '/^[A-Za-z0-9_-]{16,128}$/';
    private const HASH = '/^[0-9a-f]{64}$/';
    private const CALL = '/^[A-Za-z0-9_-]{1,64}$/';

    /** @var array<string, int> */
    private array $limits;

    /** @param array<string, mixed> $config */
    public function __construct(private Db $db, private Fcm $fcm, array $config = [])
    {
        $this->limits = ($config['limits'] ?? []) + [
            // Seconds between wakes through one grant (one friend's device).
            'grant_interval' => 5,
            // Wakes a device accepts per hour, from all its friends.
            'device_per_hour' => 120,
            // Grants one device may hold.
            'max_grants' => 2000,
            // Registrations and admin calls per IP address per hour (generous: carrier NAT shares addresses).
            'ip_per_hour' => 300,
            // Devices not heard from for this long are forgotten.
            'forget_after' => 90 * 86400,
        ];
    }

    /**
     * Handles one request.
     *
     * @return array{int, array<string, mixed>} Status and JSON body.
     */
    public function handle(string $method, string $path, string $body, string $ip, ?int $now = null): array
    {
        $now ??= time();
        try {
            $path = '/' . trim($path, '/');
            if ($method === 'GET' && ($path === '/' || $path === '/v1')) {
                return [200, ['service' => 'ournet-push', 'version' => 1]];
            }
            if ($method !== 'POST') throw new HttpError(405, 'POST only');
            if (strlen($body) > 256 * 1024) throw new HttpError(413, 'Request too large');
            $json = json_decode($body, true);
            if (!is_array($json)) throw new HttpError(400, 'Expected a JSON object');
            return match ($path) {
                '/v1/register' => $this->register($json, $ip, $now),
                '/v1/grants' => $this->grants($json, $ip, $now),
                '/v1/unregister' => $this->unregister($json, $ip, $now),
                '/v1/wake' => $this->wake($json, $now),
                default => throw new HttpError(404, 'Unknown endpoint'),
            };
        } catch (HttpError $e) {
            return [$e->status, ['error' => $e->getMessage()] + $e->extra];
        }
    }

    /** @param array<string, mixed> $j */
    private function register(array $j, string $ip, int $now): array
    {
        $fcm = $j['fcm'] ?? null;
        if (!is_string($fcm) || $fcm === '' || strlen($fcm) > 4096 || !ctype_graph($fcm)) {
            throw new HttpError(400, 'fcm: the device\'s FCM registration token');
        }
        // An existing registration updates its token.
        if (isset($j['device']) || isset($j['secret'])) {
            $device = $this->admin($j, $ip, $now);
            $this->db->updateFcm($device['id'], $fcm, $now);
            return [200, ['device' => $device['id']]];
        }
        $this->limitIp($ip, $now);
        // Occasional housekeeping, on the least frequent call.
        if (random_int(0, 49) === 0) $this->db->prune($now, $this->limits['forget_after']);
        $id = self::random(16);
        $secret = self::random(32);
        $this->db->addDevice($id, hash('sha256', $secret), $fcm, $now);
        return [201, ['device' => $id, 'secret' => $secret]];
    }

    /** @param array<string, mixed> $j */
    private function grants(array $j, string $ip, int $now): array
    {
        $device = $this->admin($j, $ip, $now);
        $list = function (string $key) use ($j): ?array {
            if (!array_key_exists($key, $j)) return null;
            $v = $j[$key];
            if (!is_array($v) || !array_is_list($v) || count($v) > $this->limits['max_grants']) {
                throw new HttpError(400, "$key: a list of token hashes");
            }
            foreach ($v as $hash) {
                if (!is_string($hash) || !preg_match(self::HASH, $hash)) {
                    throw new HttpError(400, "$key: hashes are lowercase hex SHA-256 of each token");
                }
            }
            return array_values(array_unique($v));
        };
        $replace = $list('replace');
        $add = $list('add') ?? [];
        $remove = $list('remove') ?? [];
        $count = $this->db->changeGrants($device['id'], $replace, $add, $remove, $this->limits['max_grants']);
        if ($count === null) throw new HttpError(400, 'Too many grants', ['max' => $this->limits['max_grants']]);
        return [200, ['grants' => $count]];
    }

    /** @param array<string, mixed> $j */
    private function unregister(array $j, string $ip, int $now): array
    {
        $device = $this->admin($j, $ip, $now);
        $this->db->removeDevice($device['id']);
        return [200, []];
    }

    /** @param array<string, mixed> $j */
    private function wake(array $j, int $now): array
    {
        $id = $j['device'] ?? null;
        $token = $j['token'] ?? null;
        if (!is_string($id) || !preg_match(self::ID, $id) || !is_string($token) || !preg_match(self::TOKEN, $token)) {
            throw new HttpError(400, 'device and token');
        }
        $kind = $j['kind'] ?? 'wake';
        $call = $j['call'] ?? null;
        if (!in_array($kind, ['wake', 'call', 'cancel'], true)) throw new HttpError(400, 'kind: wake, call or cancel');
        if ($kind === 'wake' ? $call !== null : (!is_string($call) || !preg_match(self::CALL, $call))) {
            throw new HttpError(400, 'call: the call\'s ID, with kind call or cancel');
        }
        $device = $this->db->device($id);
        $hash = hash('sha256', $token);
        $grant = $device ? $this->db->grant($id, $hash) : null;
        // The same answer for an unknown device and a wrong token.
        if ($grant === null) throw new HttpError(403, 'Not allowed to wake this device');
        // A call must ring, and its cancel follow, whatever was just sent;
        // the hourly cap still holds.
        $wait = $kind === 'wake' ? $grant['last_wake'] + $this->limits['grant_interval'] - $now : 0;
        if ($wait > 0) throw new HttpError(429, 'Too soon', ['retry' => $wait]);
        $start = (int)$device['window_start'];
        $count = (int)$device['window_count'];
        if ($start <= $now - 3600) {
            $start = $now;
            $count = 0;
        }
        if ($count >= $this->limits['device_per_hour']) {
            throw new HttpError(429, 'Device is being woken too often', ['retry' => $start + 3600 - $now]);
        }
        try {
            $this->fcm->wake($device['fcm'], $kind, $call);
        } catch (TokenGone) {
            // The app was uninstalled or its token replaced without telling us.
            $this->db->removeDevice($id);
            throw new HttpError(410, 'Device is no longer registered');
        } catch (\RuntimeException $e) {
            throw new HttpError(502, $e->getMessage());
        }
        $this->db->noteWake($id, $kind === 'wake' ? $hash : null, $now, $start, $count + 1);
        return [202, []];
    }

    /**
     * The device [j] names, when its secret matches.
     *
     * @param array<string, mixed> $j
     * @return array<string, mixed>
     */
    private function admin(array $j, string $ip, int $now): array
    {
        $this->limitIp($ip, $now);
        $id = $j['device'] ?? null;
        $secret = $j['secret'] ?? null;
        if (!is_string($id) || !preg_match(self::ID, $id) || !is_string($secret) || !preg_match(self::SECRET, $secret)) {
            throw new HttpError(400, 'device and secret');
        }
        $device = $this->db->device($id);
        if ($device === null) throw new HttpError(404, 'Unknown device; register again');
        if (!hash_equals($device['secret_hash'], hash('sha256', $secret))) {
            throw new HttpError(403, 'Wrong secret');
        }
        $this->db->touch($id, $now);
        return $device;
    }

    private function limitIp(string $ip, int $now): void
    {
        if (!$this->db->allowIp($ip, $now, 3600, $this->limits['ip_per_hour'])) {
            throw new HttpError(429, 'Too many requests from this address', ['retry' => 3600]);
        }
    }

    private static function random(int $bytes): string
    {
        return rtrim(strtr(base64_encode(random_bytes($bytes)), '+/', '-_'), '=');
    }
}
