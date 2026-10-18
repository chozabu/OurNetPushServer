<?php
declare(strict_types=1);

namespace OurNetPush;

use PDO;

/** SQLite storage: devices, the wake grants each one issued, and limits. */
final class Db
{
    public readonly PDO $pdo;

    public function __construct(string $path)
    {
        $dir = dirname($path);
        if (!is_dir($dir)) mkdir($dir, 0700, true);
        $this->pdo = new PDO('sqlite:' . $path, null, null, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);
        $this->pdo->exec('PRAGMA journal_mode = WAL');
        $this->pdo->exec('PRAGMA busy_timeout = 5000');
        $this->pdo->exec('PRAGMA foreign_keys = ON');
        $this->migrate();
    }

    private function migrate(): void
    {
        $this->pdo->exec(<<<SQL
            CREATE TABLE IF NOT EXISTS devices (
                id TEXT PRIMARY KEY,
                secret_hash TEXT NOT NULL,
                fcm TEXT NOT NULL,
                created INTEGER NOT NULL,
                seen INTEGER NOT NULL,
                window_start INTEGER NOT NULL DEFAULT 0,
                window_count INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS grants (
                device TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
                token_hash TEXT NOT NULL,
                last_wake INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (device, token_hash)
            ) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS ip_limits (
                ip TEXT PRIMARY KEY,
                window_start INTEGER NOT NULL,
                count INTEGER NOT NULL
            ) WITHOUT ROWID;
            SQL);
    }

    /** @return array<string, mixed>|null */
    public function device(string $id): ?array
    {
        $q = $this->pdo->prepare('SELECT * FROM devices WHERE id = ?');
        $q->execute([$id]);
        return $q->fetch() ?: null;
    }

    public function addDevice(string $id, string $secretHash, string $fcm, int $now): void
    {
        $this->pdo->prepare(
            'INSERT INTO devices (id, secret_hash, fcm, created, seen) VALUES (?, ?, ?, ?, ?)'
        )->execute([$id, $secretHash, $fcm, $now, $now]);
    }

    public function updateFcm(string $id, string $fcm, int $now): void
    {
        $this->pdo->prepare('UPDATE devices SET fcm = ?, seen = ? WHERE id = ?')
            ->execute([$fcm, $now, $id]);
    }

    public function touch(string $id, int $now): void
    {
        $this->pdo->prepare('UPDATE devices SET seen = ? WHERE id = ?')->execute([$now, $id]);
    }

    public function removeDevice(string $id): void
    {
        $this->pdo->prepare('DELETE FROM devices WHERE id = ?')->execute([$id]);
    }

    public function grantCount(string $device): int
    {
        $q = $this->pdo->prepare('SELECT COUNT(*) FROM grants WHERE device = ?');
        $q->execute([$device]);
        return (int)$q->fetchColumn();
    }

    /**
     * Applies a bulk change to [device]'s grants in one transaction:
     * [replace] (when not null) becomes the whole set, then [add] and
     * [remove] apply. Fails without changing anything when the result
     * would exceed [max].
     *
     * @param list<string>|null $replace
     * @param list<string> $add
     * @param list<string> $remove
     */
    public function changeGrants(string $device, ?array $replace, array $add, array $remove, int $max): ?int
    {
        $this->pdo->beginTransaction();
        try {
            if ($replace !== null) {
                $keep = array_flip($replace);
                $q = $this->pdo->prepare('SELECT token_hash FROM grants WHERE device = ?');
                $q->execute([$device]);
                $delete = $this->pdo->prepare('DELETE FROM grants WHERE device = ? AND token_hash = ?');
                foreach ($q->fetchAll(PDO::FETCH_COLUMN) as $hash) {
                    if (!isset($keep[$hash])) $delete->execute([$device, $hash]);
                }
                $add = array_merge($replace, $add);
            }
            $insert = $this->pdo->prepare('INSERT OR IGNORE INTO grants (device, token_hash) VALUES (?, ?)');
            foreach ($add as $hash) $insert->execute([$device, $hash]);
            $delete = $this->pdo->prepare('DELETE FROM grants WHERE device = ? AND token_hash = ?');
            foreach ($remove as $hash) $delete->execute([$device, $hash]);
            $count = $this->grantCount($device);
            if ($count > $max) {
                $this->pdo->rollBack();
                return null;
            }
            $this->pdo->commit();
            return $count;
        } catch (\Throwable $e) {
            $this->pdo->rollBack();
            throw $e;
        }
    }

    /** @return array<string, mixed>|null */
    public function grant(string $device, string $tokenHash): ?array
    {
        $q = $this->pdo->prepare('SELECT * FROM grants WHERE device = ? AND token_hash = ?');
        $q->execute([$device, $tokenHash]);
        return $q->fetch() ?: null;
    }

    public function noteWake(string $device, ?string $tokenHash, int $now, int $windowStart, int $windowCount): void
    {
        if ($tokenHash !== null) {
            $this->pdo->prepare('UPDATE grants SET last_wake = ? WHERE device = ? AND token_hash = ?')
                ->execute([$now, $device, $tokenHash]);
        }
        $this->pdo->prepare('UPDATE devices SET window_start = ?, window_count = ? WHERE id = ?')
            ->execute([$windowStart, $windowCount, $device]);
    }

    /** Counts a request from [ip]; false once it has made [max] in [window] seconds. */
    public function allowIp(string $ip, int $now, int $window, int $max): bool
    {
        $q = $this->pdo->prepare('SELECT window_start, count FROM ip_limits WHERE ip = ?');
        $q->execute([$ip]);
        $row = $q->fetch();
        if (!$row || $row['window_start'] <= $now - $window) {
            $this->pdo->prepare('INSERT OR REPLACE INTO ip_limits (ip, window_start, count) VALUES (?, ?, 1)')
                ->execute([$ip, $now]);
            return true;
        }
        if ($row['count'] >= $max) return false;
        $this->pdo->prepare('UPDATE ip_limits SET count = count + 1 WHERE ip = ?')->execute([$ip]);
        return true;
    }

    /** Forgets devices not seen for [age] seconds and stale IP counters. */
    public function prune(int $now, int $age): void
    {
        $this->pdo->prepare('DELETE FROM devices WHERE seen < ?')->execute([$now - $age]);
        $this->pdo->prepare('DELETE FROM ip_limits WHERE window_start < ?')->execute([$now - 86400]);
    }
}
