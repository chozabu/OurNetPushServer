<?php
declare(strict_types=1);

namespace OurNetPush;

/** Thrown when FCM says the registration token is no longer valid. */
final class TokenGone extends \RuntimeException {}

/**
 * Sends data-only, high-priority wake messages through FCM HTTP v1. The
 * OAuth access token is made from the service account key (an RS256 JWT)
 * and cached in a file for its hour of validity, so no Google library or
 * Composer is needed.
 */
final class Fcm
{
    private const SCOPE = 'https://www.googleapis.com/auth/firebase.messaging';

    /** @var array<string, mixed> */
    private array $account;

    /**
     * @param string $serviceAccount Path to the service account JSON key.
     * @param string $cacheFile Where the access token is cached.
     * @param string $mode 'live' sends; 'log' appends each message to [$cacheFile].log instead (tests).
     */
    public function __construct(string $serviceAccount, private string $cacheFile, private string $mode = 'live')
    {
        if ($mode === 'live') {
            $json = json_decode((string)@file_get_contents($serviceAccount), true);
            if (!is_array($json) || !isset($json['client_email'], $json['private_key'], $json['project_id'])) {
                throw new \RuntimeException('Service account key missing or invalid');
            }
            $this->account = $json;
        }
    }

    /** Wakes the device holding FCM [token]. */
    public function wake(string $token): void
    {
        $message = [
            'message' => [
                'token' => $token,
                // Data only, so OurNet's own service handles it and nothing
                // is shown by the system.
                'data' => ['ournet' => 'wake'],
                'android' => [
                    'priority' => 'HIGH',
                    // Wakes that pile up while the phone is offline arrive as one.
                    'collapse_key' => 'wake',
                    'ttl' => '600s',
                ],
            ],
        ];
        if ($this->mode === 'log') {
            if (str_starts_with($token, 'gone')) throw new TokenGone();
            file_put_contents($this->cacheFile . '.log', json_encode($message) . "\n", FILE_APPEND | LOCK_EX);
            return;
        }
        $url = 'https://fcm.googleapis.com/v1/projects/' . rawurlencode($this->account['project_id']) . '/messages:send';
        [$status, $body] = $this->post($url, json_encode($message), [
            'Content-Type: application/json',
            'Authorization: Bearer ' . $this->accessToken(),
        ]);
        if ($status === 200) return;
        $error = json_decode($body, true);
        $code = '';
        foreach ($error['error']['details'] ?? [] as $detail) {
            $code = $detail['errorCode'] ?? $code;
        }
        if ($status === 404 || $code === 'UNREGISTERED' || ($status === 400 && $code === 'INVALID_ARGUMENT')) {
            throw new TokenGone();
        }
        if ($status === 401) @unlink($this->cacheFile);
        throw new \RuntimeException("FCM refused ($status $code)");
    }

    private function accessToken(): string
    {
        $cached = json_decode((string)@file_get_contents($this->cacheFile), true);
        if (is_array($cached) && ($cached['expires'] ?? 0) > time() + 60) return $cached['token'];
        $now = time();
        $uri = $this->account['token_uri'] ?? 'https://oauth2.googleapis.com/token';
        $jwt = self::jwt([
            'iss' => $this->account['client_email'],
            'scope' => self::SCOPE,
            'aud' => $uri,
            'iat' => $now,
            'exp' => $now + 3600,
        ], $this->account['private_key']);
        [$status, $body] = $this->post($uri, http_build_query([
            'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'assertion' => $jwt,
        ]), ['Content-Type: application/x-www-form-urlencoded']);
        $reply = json_decode($body, true);
        if ($status !== 200 || !isset($reply['access_token'])) {
            throw new \RuntimeException("Google token refused ($status)");
        }
        $token = $reply['access_token'];
        $tmp = $this->cacheFile . '.' . bin2hex(random_bytes(4));
        file_put_contents($tmp, json_encode(['token' => $token, 'expires' => $now + (int)($reply['expires_in'] ?? 3600)]));
        chmod($tmp, 0600);
        rename($tmp, $this->cacheFile);
        return $token;
    }

    /** @param array<string, mixed> $claims */
    public static function jwt(array $claims, string $privateKey): string
    {
        $b64 = fn(string $s) => rtrim(strtr(base64_encode($s), '+/', '-_'), '=');
        $input = $b64(json_encode(['alg' => 'RS256', 'typ' => 'JWT'])) . '.' . $b64(json_encode($claims));
        if (!openssl_sign($input, $signature, $privateKey, OPENSSL_ALGO_SHA256)) {
            throw new \RuntimeException('Could not sign with the service account key');
        }
        return $input . '.' . $b64($signature);
    }

    /** @return array{int, string} */
    private function post(string $url, string $body, array $headers): array
    {
        $curl = curl_init($url);
        curl_setopt_array($curl, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $body,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_TIMEOUT => 10,
        ]);
        $response = curl_exec($curl);
        $status = (int)curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
        curl_close($curl);
        if ($response === false) throw new \RuntimeException('Could not reach Google');
        return [$status, (string)$response];
    }
}
