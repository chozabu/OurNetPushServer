<?php
// Copy to config.php (next to this file, outside the web root) and fill in.
return [
    // SQLite database; created on first use. Keep it outside public/.
    'db' => __DIR__ . '/data/push.sqlite',
    // Firebase service account key (Project settings > Service accounts >
    // Generate new private key). Keep it outside public/, mode 600.
    'service_account' => __DIR__ . '/data/service-account.json',
    // Where the Google access token is cached between requests.
    'token_cache' => __DIR__ . '/data/fcm-token.json',
    // 'live' sends through FCM; 'log' writes messages to token_cache.log (tests).
    'fcm_mode' => 'live',
    // Optional overrides; see Server::__construct for the defaults.
    'limits' => [
        // 'grant_interval' => 5,
        // 'device_per_hour' => 120,
        // 'max_grants' => 2000,
        // 'ip_per_hour' => 300,
    ],
];
