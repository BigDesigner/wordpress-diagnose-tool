<?php
declare(strict_types=1);

namespace WPDiagnose\Agents\CoreIntegrityAgent;

use WPDiagnose\Core\DiagnosticInterface;

/**
 * Class CoreIntegrityAgent (The Watchdog)
 * 
 * Verifies WordPress core files against the official WordPress.org Checksum API.
 * Detects modified, missing, and unknown files in wp-admin and wp-includes.
 */
class CoreIntegrityAgent implements DiagnosticInterface
{
    private array $results = [];
    private bool $isWpLoaded;

    public function __construct(bool $isWpLoaded = false)
    {
        $this->isWpLoaded = $isWpLoaded;
    }

    public function getName(): string
    {
        return 'CoreIntegrityAgent';
    }

    public function check(): array
    {
        $this->results = [];
        $version = $this->getWpVersion();

        if (!$version) {
            $this->results['checksum_scan'] = [
                'status' => 'ERROR',
                'info'   => 'Cannot determine WordPress version to fetch checksums.',
            ];
            return $this->results;
        }

        $checksums = $this->fetchChecksums($version);
        if (!$checksums) {
            $this->results['checksum_scan'] = [
                'status' => 'WARN',
                'info'   => "Could not fetch checksums from WordPress.org API for version $version.",
            ];
            return $this->results;
        }

        $mismatch = [];
        $missing  = [];
        foreach ($checksums as $file => $hash) {
            // Only check wp-admin and wp-includes to avoid wp-content false positives
            if (strpos($file, 'wp-admin/') !== 0 && strpos($file, 'wp-includes/') !== 0 && strpos($file, 'wp-') !== 0) {
                continue;
            }
            if ($file === 'wp-config-sample.php') continue;

            $path = ABSPATH . $file;
            if (!is_file($path)) {
                $missing[] = $file;
            } elseif (md5_file($path) !== $hash) {
                $mismatch[] = $file;
            }
        }

        $unknown = $this->findUnknownFiles($checksums);

        if (empty($mismatch) && empty($missing) && empty($unknown)) {
            $this->results['integrity'] = [
                'status' => 'OK',
                'info'   => "All core files match exactly with official WordPress $version.",
            ];
        } else {
            $this->results['mismatch_files'] = [
                'status' => empty($mismatch) ? 'OK' : 'ERROR',
                'info'   => count($mismatch) . " file(s) modified.",
                'data'   => $mismatch,
            ];
            $this->results['missing_files'] = [
                'status' => empty($missing) ? 'OK' : 'ERROR',
                'info'   => count($missing) . " file(s) missing.",
                'data'   => $missing,
            ];
            $this->results['unknown_files'] = [
                'status' => empty($unknown) ? 'OK' : 'WARN',
                'info'   => count($unknown) . " unexpected file(s) found in core directories.",
                'data'   => $unknown,
            ];
        }

        return $this->results;
    }

    public function fix(string $id): bool
    {
        return false; // Fix requires downloading WP core, handled by CoreOperationsAgent
    }

    public function report(): array
    {
        return $this->results ?: $this->check();
    }

    private function getWpVersion(): ?string
    {
        if ($this->isWpLoaded && function_exists('get_bloginfo')) {
            return get_bloginfo('version');
        }
        $versionFile = ABSPATH . 'wp-includes/version.php';
        if (is_file($versionFile)) {
            $wp_version = '';
            include $versionFile;
            return $wp_version !== '' ? $wp_version : null;
        }
        return null;
    }

    private function fetchChecksums(string $version): ?array
    {
        $url = "https://api.wordpress.org/core/checksums/1.0/?version={$version}&locale=en_US";
        
        $context = stream_context_create([
            'http' => ['timeout' => 5],
            'ssl'  => ['verify_peer' => false, 'verify_peer_name' => false]
        ]);

        $response = @file_get_contents($url, false, $context);
        if (!$response) return null;

        $data = json_decode($response, true);
        if (isset($data['checksums']) && is_array($data['checksums'])) {
            return $data['checksums'];
        }

        return null;
    }

    private function findUnknownFiles(array $checksums): array
    {
        $unknown = [];
        $dirs = ['wp-admin', 'wp-includes'];
        foreach ($dirs as $dir) {
            $path = ABSPATH . $dir;
            if (!is_dir($path)) continue;

            $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($path, \FilesystemIterator::SKIP_DOTS));
            foreach ($iterator as $fileInfo) {
                if ($fileInfo->isDir()) continue;
                $relPath = str_replace('\\', '/', str_replace(ABSPATH, '', $fileInfo->getPathname()));
                if (!isset($checksums[$relPath])) {
                    $unknown[] = $relPath;
                }
            }
        }
        // Check root wp-*.php files
        $iterator = new \DirectoryIterator(ABSPATH);
        foreach ($iterator as $fileInfo) {
            if ($fileInfo->isDot() || $fileInfo->isDir()) continue;
            $filename = $fileInfo->getFilename();
            if (strpos($filename, 'wp-') === 0 && preg_match('/\.php$/', $filename)) {
                if ($filename === 'wp-config.php' || $filename === 'wp-config-sample.php' || $filename === 'wp-diagnose.php' || $filename === 'wp-diagnose-pro.php') continue;
                if (!isset($checksums[$filename])) {
                    $unknown[] = $filename;
                }
            }
        }
        return $unknown;
    }
}
