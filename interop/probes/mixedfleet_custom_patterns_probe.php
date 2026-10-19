<?php

declare(strict_types=1);

/**
 * Mixed-fleet reader for the custom-pattern case of interop/run.py (guard-core
 * 5.0.0 writes patterns:custom_list next to the legacy patterns:custom).
 *
 * run.py mounts the PHP repo read-only at /app and this file from the interop
 * directory, so nothing is written into the PHP repo. The PHP engine restores
 * the custom patterns from the Redis prefix it is given and is held to what a
 * real v4.4.0 Python engine restored from the same state: the same pattern set
 * and the same verdicts.
 */

use RenzoFranceschini\GuardCore\Detection\SusPatterns;
use RenzoFranceschini\GuardCore\Redis\RedisHandler;

$root = getenv('GUARD_CORE_PHP_ROOT') ?: '/app';
if (is_file($root . '/vendor/autoload.php')) {
    require $root . '/vendor/autoload.php';
} else {
    // The engine has no runtime dependencies, so a checkout without vendor/ loads straight from src/.
    spl_autoload_register(static function (string $class) use ($root): void {
        $prefix = 'RenzoFranceschini\\GuardCore\\';
        if (str_starts_with($class, $prefix)) {
            $file = $root . '/src/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
            if (is_file($file)) {
                require $file;
            }
        }
    });
}

$incoming = json_decode((string) getenv('INTEROP_INPUT'), true);
if (! is_array($incoming)) {
    fwrite(STDERR, "INTEROP_INPUT is not valid JSON\n");
    exit(1);
}

putenv('REDIS_PREFIX=' . $incoming['prefix_root'] . 'mf_php:');
$redis = RedisHandler::fromEnv();
$redis->initialize();

$sus = new SusPatterns();
$sus->initializeRedis($redis);
$got = $sus->getCustomPatterns();
sort($got, SORT_STRING);
$want = json_decode($incoming['v440_patterns'], true);
$wantFlagged = json_decode($incoming['v440_flagged'], true);

$checks = [];
$record = static function (string $name, bool $ok, string $detail) use (&$checks): void {
    $checks[] = [
        'scenario' => 'custom_patterns_port_read',
        'direction' => 'py:php',
        'name' => $name,
        'passed' => $ok,
        'detail' => $detail,
    ];
    echo ($ok ? 'ok' : 'FAIL') . " - [custom_patterns_port_read] {$name} ({$detail})\n";
};
$gotJson = (string) json_encode($got, JSON_UNESCAPED_SLASHES);
$record('php restores the same custom pattern set as v4.4.0 Python', $got === $want, $gotJson);
foreach ($wantFlagged as $path => $wantThreat) {
    $verdict = $sus->detect((string) $path, '127.0.0.1', 'request_path');
    $record("php flags {$path} as v4.4.0 Python does", (bool) $verdict['is_threat'] === $wantThreat, (string) $path);
}

$failed = count(array_filter($checks, static fn (array $c): bool => ! $c['passed']));
file_put_contents((string) getenv('INTEROP_REPORT_FILE'), json_encode([
    'participant' => 'php',
    'phase' => 'php_custom_patterns_read',
    'passed' => count($checks) - $failed,
    'failed' => $failed,
    'checks' => $checks,
    'artifacts' => ['php_patterns' => $gotJson],
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
exit($failed > 0 ? 1 : 0);
