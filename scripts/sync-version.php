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

if (!function_exists('normalizeLineEndings')) {
    function normalizeLineEndings(string $content): string
    {
        return str_replace(["\r\n", "\r"], "\n", $content);
    }
}

if (!function_exists('replaceOrFail')) {
    /**
     * @param string|array<int, string> $patterns
     */
    function replaceOrFail(string $content, $patterns, string $replacement, string $file): string
    {
        $patternList = is_array($patterns) ? $patterns : [$patterns];

        foreach ($patternList as $pattern) {
            $updated = preg_replace($pattern, $replacement, $content, 1, $count);
            if ($updated !== null && $count > 0) {
                return $updated;
            }
        }

        if (strpos($content, $replacement) !== false) {
            return $content;
        }

        $displayPattern = implode(' OR ', $patternList);
        throw new RuntimeException("Could not update version marker in {$file} using pattern {$displayPattern}");
    }
}

if (!function_exists('syncProjectVersion')) {
    function syncProjectVersion(string $rootDir): string
    {
        $version = readProjectVersion($rootDir);

        $targets = [
            'Core/Version.php' => [
                [
                    'patterns' => ["/public const NUMBER = '[^']+';/"],
                    'replacement' => "public const NUMBER = '{$version}';",
                ],
            ],
            'README.md' => [
                [
                    'patterns' => [
                        '/^# WP Diagnose PRO \(v[^)\r\n]+\)\r?$/m',
                    ],
                    'replacement' => "# WP Diagnose PRO (v{$version})",
                ],
                [
                    'patterns' => [
                        '/^## Key Features \(v[^)\r\n]+\)\r?$/m',
                        '/^## .*Key Features \(v[^)\r\n]+\)\r?$/m',
                    ],
                    'replacement' => "## Key Features (v{$version})",
                ],
            ],
            'docs/AUDIT_REPORT.md' => [
                [
                    'patterns' => [
                        '/^# WP Diagnose - Agentic Audit Report \(v[^)\r\n]+\)\r?$/m',
                    ],
                    'replacement' => "# WP Diagnose - Agentic Audit Report (v{$version})",
                ],
            ],
            'specs/CONSTITUTION.md' => [
                [
                    'patterns' => [
                        '/^# WP Diagnose PRO - Standard Constitution \(v[^)\r\n]+\)\r?$/m',
                    ],
                    'replacement' => "# WP Diagnose PRO - Standard Constitution (v{$version})",
                ],
                [
                    'patterns' => [
                        '/^\s*As of version [^ ]+-PRO,/m',
                    ],
                    'replacement' => "As of version {$version}-PRO,",
                ],
            ],
        ];

        foreach ($targets as $relativePath => $replacements) {
            $absolutePath = $rootDir . '/' . $relativePath;
            if (!is_file($absolutePath)) {
                throw new RuntimeException("Sync target not found: {$relativePath}");
            }

            $content = normalizeLineEndings((string) file_get_contents($absolutePath));
            foreach ($replacements as $replacement) {
                $content = replaceOrFail(
                    $content,
                    $replacement['patterns'],
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
