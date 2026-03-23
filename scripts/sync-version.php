<?php
declare(strict_types=1);

if (!function_exists('readProjectVersion')) {
    function readProjectVersion(string $rootDir): string
    {
        $versionFile = $rootDir . '/VERSION';
        if (!is_file($versionFile)) {
            throw new RuntimeException("VERSION file not found at {$versionFile}");
        }

        $version = trim((string) file_get_contents($versionFile));
        if ($version === '') {
            throw new RuntimeException('VERSION file is empty.');
        }

        return $version;
    }
}

if (!function_exists('replaceOrFail')) {
    function replaceOrFail(string $content, string $pattern, string $replacement, string $file): string
    {
        $updated = preg_replace($pattern, $replacement, $content, 1, $count);
        if ($updated === null || $count < 1) {
            throw new RuntimeException("Could not update version marker in {$file}");
        }

        return $updated;
    }
}

if (!function_exists('syncProjectVersion')) {
    function syncProjectVersion(string $rootDir): string
    {
        $version = readProjectVersion($rootDir);

        $targets = [
            'Core/Version.php' => [
                [
                    'pattern' => "/public const NUMBER = '[^']+';/",
                    'replacement' => "public const NUMBER = '{$version}';",
                ],
            ],
            'README.md' => [
                [
                    'pattern' => '/^# WP Diagnose PRO \(v[^\)]+\)$/m',
                    'replacement' => "# WP Diagnose PRO (v{$version})",
                ],
                [
                    'pattern' => '/^## .* Key Features \(v[^\)]+\)$/m',
                    'replacement' => "## Key Features (v{$version})",
                ],
            ],
            'docs/AUDIT_REPORT.md' => [
                [
                    'pattern' => '/^# WP Diagnose - Agentic Audit Report \(v[^\)]+\)$/m',
                    'replacement' => "# WP Diagnose - Agentic Audit Report (v{$version})",
                ],
            ],
            'specs/CONSTITUTION.md' => [
                [
                    'pattern' => '/^# WP Diagnose PRO - Standard Constitution \(v[^\)]+\)$/m',
                    'replacement' => "# WP Diagnose PRO - Standard Constitution (v{$version})",
                ],
                [
                    'pattern' => '/^As of version [^ ]+-PRO,/',
                    'replacement' => "As of version {$version}-PRO,",
                ],
            ],
        ];

        foreach ($targets as $relativePath => $replacements) {
            $absolutePath = $rootDir . '/' . $relativePath;
            if (!is_file($absolutePath)) {
                throw new RuntimeException("Sync target not found: {$relativePath}");
            }

            $content = (string) file_get_contents($absolutePath);
            foreach ($replacements as $replacement) {
                $content = replaceOrFail(
                    $content,
                    $replacement['pattern'],
                    $replacement['replacement'],
                    $relativePath
                );
            }

            file_put_contents($absolutePath, $content);
        }

        return $version;
    }
}

if (realpath($_SERVER['SCRIPT_FILENAME'] ?? '') === __FILE__) {
    $rootDir = dirname(__DIR__);
    $version = syncProjectVersion($rootDir);
    echo "Synchronized project version: {$version}" . PHP_EOL;
}
