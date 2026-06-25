<?php
declare(strict_types=1);

namespace WPDiagnose\Agents\IncidentSnapshotAgent {

    use WPDiagnose\Core\DiagnosticInterface;

    /**
     * Class IncidentSnapshotAgent
     * 
     * Takes snapshots of site integrity (configs, active plugins, entrypoint hashes) for incident response.
     */
    class IncidentSnapshotAgent implements DiagnosticInterface
    {
        private array $results = [];
        private bool $wpLoaded = false;
        private string $snapshotDir;
        private ?array $lastActionResult = null;

        public function __construct(bool $wpLoaded = false)
        {
            $this->wpLoaded = $wpLoaded;
            $baseDir = defined('ABSPATH') ? ABSPATH : dirname(__DIR__, 4) . '/';
            $this->snapshotDir = rtrim($baseDir, '/\\') . '/wp-content/uploads/wp-diagnose-backups/.snapshots';
        }

        public function getName(): string
        {
            return 'IncidentSnapshotAgent';
        }

        public function check(): array
        {
            $this->results = [];

            // List existing snapshots
            $snapshots = [];
            if (is_dir($this->snapshotDir)) {
                $files = scandir($this->snapshotDir);
                foreach ($files as $file) {
                    if ($file === '.' || $file === '..' || $file === '.htaccess') {
                        continue;
                    }
                    $filePath = $this->snapshotDir . '/' . $file;
                    if (is_file($filePath) && str_ends_with($file, '.json')) {
                        $snapshots[] = [
                            'filename' => $file,
                            'size' => round(filesize($filePath) / 1024, 2) . ' KB',
                            'created_at' => date('Y-m-d H:i:s', filemtime($filePath))
                        ];
                    }
                }
            }

            // Quick file change check (last 7 days)
            $recentChangesCount = 0;
            $baseDir = defined('ABSPATH') ? ABSPATH : dirname(__DIR__, 4) . '/';
            if (is_dir($baseDir)) {
                $recentChangesCount = $this->scanRecentChanges($baseDir);
            }

            $this->results['snapshots_list'] = [
                'status' => 'OK',
                'info' => sprintf('%d snapshot(s) stored on disk.', count($snapshots)),
                'data' => $snapshots
            ];

            $this->results['recent_file_changes'] = [
                'status' => $recentChangesCount > 0 ? 'WARN' : 'OK',
                'info' => sprintf('%d PHP files modified in the last 7 days.', $recentChangesCount)
            ];

            return $this->results;
        }

        public function fix(string $id): bool
        {
            $this->lastActionResult = null;

            if ($id === 'create_snapshot') {
                return $this->createSnapshot();
            }

            if (str_starts_with($id, 'delete_snapshot:')) {
                $filename = substr($id, 16);
                return $this->deleteSnapshotFile($filename);
            }

            return false;
        }

        public function getLastActionResult(): ?array
        {
            return $this->lastActionResult;
        }

        private function createSnapshot(): bool
        {
            if (!is_dir($this->snapshotDir)) {
                @mkdir($this->snapshotDir, 0755, true);
                @file_put_contents($this->snapshotDir . '/.htaccess', "Deny from all\n");
            }

            $baseDir = defined('ABSPATH') ? ABSPATH : dirname(__DIR__, 4) . '/';
            $snapshotData = [
                'created_at' => date('Y-m-d H:i:s'),
                'php_version' => PHP_VERSION,
                'wp_version' => $this->wpLoaded ? ($GLOBALS['wp_version'] ?? 'Unknown') : 'Unknown (Independent Mode)',
                'security_constants' => [
                    'DISALLOW_FILE_EDIT' => defined('DISALLOW_FILE_EDIT') ? DISALLOW_FILE_EDIT : 'undefined',
                    'DISALLOW_FILE_MODS' => defined('DISALLOW_FILE_MODS') ? DISALLOW_FILE_MODS : 'undefined',
                    'WP_DEBUG' => defined('WP_DEBUG') ? WP_DEBUG : 'undefined',
                    'FORCE_SSL_ADMIN' => defined('FORCE_SSL_ADMIN') ? FORCE_SSL_ADMIN : 'undefined'
                ],
                'critical_files' => []
            ];

            $criticalFiles = ['.htaccess', 'index.php', 'wp-config.php', 'wp-settings.php'];
            foreach ($criticalFiles as $file) {
                $path = $baseDir . $file;
                if (is_file($path)) {
                    $snapshotData['critical_files'][$file] = [
                        'hash' => md5_file($path),
                        'size' => filesize($path),
                        'mtime' => date('Y-m-d H:i:s', filemtime($path))
                    ];
                }
            }

            // Capture plugins and themes
            $snapshotData['plugins'] = [];
            $snapshotData['themes'] = [];

            if ($this->wpLoaded) {
                if (function_exists('get_plugins')) {
                    $plugins = get_plugins();
                    $activePlugins = get_option('active_plugins', []);
                    foreach ($plugins as $slug => $data) {
                        $snapshotData['plugins'][$slug] = [
                            'name' => $data['Name'] ?? $slug,
                            'version' => $data['Version'] ?? 'Unknown',
                            'active' => in_array($slug, $activePlugins)
                        ];
                    }
                }
                if (function_exists('wp_get_themes')) {
                    $themes = wp_get_themes();
                    $activeTheme = get_option('stylesheet');
                    foreach ($themes as $slug => $themeObj) {
                        $snapshotData['themes'][$slug] = [
                            'name' => $themeObj->get('Name'),
                            'version' => $themeObj->get('Version'),
                            'active' => ($slug === $activeTheme)
                        ];
                    }
                }
            }

            $filename = 'incident-snapshot-' . time() . '-' . bin2hex(random_bytes(4)) . '.json';
            $filePath = $this->snapshotDir . '/' . $filename;

            if (file_put_contents($filePath, json_encode($snapshotData, JSON_PRETTY_PRINT)) !== false) {
                $this->lastActionResult = ['success' => true, 'message' => "Incident snapshot created successfully as $filename."];
                return true;
            }

            $this->lastActionResult = ['success' => false, 'message' => 'Failed to write snapshot JSON file.'];
            return false;
        }

        private function deleteSnapshotFile(string $filename): bool
        {
            $filename = basename($filename);
            $filePath = $this->snapshotDir . '/' . $filename;
            if (is_file($filePath) && @unlink($filePath)) {
                $this->lastActionResult = ['success' => true, 'message' => "Snapshot file '$filename' deleted."];
                return true;
            }
            $this->lastActionResult = ['success' => false, 'message' => 'Failed to delete snapshot file.'];
            return false;
        }

        private function scanRecentChanges(string $dir): int
        {
            $count = 0;
            $sevenDaysAgo = time() - (7 * 24 * 60 * 60);

            try {
                $files = new \RecursiveIteratorIterator(
                    new \RecursiveDirectoryIterator($dir, \RecursiveDirectoryIterator::SKIP_DOTS),
                    \RecursiveIteratorIterator::LEAVES_ONLY
                );

                foreach ($files as $file) {
                    if ($file->isFile() && $file->getExtension() === 'php') {
                        if ($file->getMTime() > $sevenDaysAgo) {
                            $count++;
                        }
                    }
                }
            } catch (\Throwable $e) {
                // Return 0 if scan fails due to path errors
            }

            return $count;
        }
    }
}
