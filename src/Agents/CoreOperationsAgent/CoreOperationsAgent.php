<?php
declare(strict_types=1);

namespace WPDiagnose\Agents\CoreOperationsAgent;

use WPDiagnose\Core\DiagnosticInterface;

/**
 * Class CoreOperationsAgent (The Updater & God Mode)
 * 
 * Manages core updates, config toggles, and emergency features.
 */
class CoreOperationsAgent implements DiagnosticInterface
{
    private array $results = [];
    private bool $isWpLoaded;
    private array $lastActionResult = ['success' => true, 'message' => '', 'data' => null];

    public function __construct(bool $isWpLoaded = false)
    {
        $this->isWpLoaded = $isWpLoaded;
    }

    public function getName(): string
    {
        return 'CoreOperationsAgent';
    }

    public function check(): array
    {
        $this->results = [];

        // Check toggles from wp-config
        $configVars = $this->parseWpConfig();
        $logDiagnostics = $this->getDebugLogDiagnostics($this->resolveDebugLogPathFromConfig($configVars));
        
        $this->results['config_toggles'] = [
            'status' => 'OK',
            'info'   => 'Current wp-config.php debug/env settings.',
            'data'   => [
                'WP_DEBUG' => $configVars['WP_DEBUG'] ?? 'false',
                'WP_DEBUG_DISPLAY' => $configVars['WP_DEBUG_DISPLAY'] ?? 'false',
                'WP_DEBUG_LOG' => $configVars['WP_DEBUG_LOG'] ?? 'false',
                'DEBUG_LOG_FILE' => $logDiagnostics['active_path'],
                'DEBUG_LOG_STATUS' => $logDiagnostics['status'],
                'SAVEQUERIES' => $configVars['SAVEQUERIES'] ?? 'false',
                'WP_ENVIRONMENT_TYPE' => $configVars['WP_ENVIRONMENT_TYPE'] ?? 'production',
            ],
        ];

        // God Mode Tools status
        $this->results['god_mode_tools'] = [
            'status' => 'OK',
            'info'   => 'Emergency Quick Actions Available.',
            'data'   => [
                'maintenance_mode' => is_file(ABSPATH . '.maintenance') ? 'active' : 'inactive',
                'cache_clear'      => 'ready',
                'password_reset'   => 'ready',
                'core_update'      => $this->getCurrentWordPressVersion() ? 'ready' : 'unavailable',
                'debug_log_viewer' => $logDiagnostics['viewer_status'],
            ],
        ];

        return $this->results;
    }

    public function fix(string $id): bool
    {
        $this->lastActionResult = ['success' => false, 'message' => 'Unknown core operation.', 'data' => null];

        if ($id === 'toggle_wp_debug') {
            return $this->toggleWpDebugSuite();
        } elseif ($id === 'toggle_savequeries') {
            return $this->toggleConfig('SAVEQUERIES');
        } elseif ($id === 'toggle_maintenance') {
            return $this->toggleMaintenance();
        } elseif ($id === 'clear_cache') {
            return $this->clearCache();
        } elseif ($id === 'core_update' || $id === 'reinstall_core') {
            return $this->updateCore($id === 'reinstall_core');
        } elseif ($id === 'view_error_log') {
            $this->outputErrorLog();
            return true;
        } elseif (strpos($id, 'reset_admin:') === 0) {
            $username = substr($id, 12);
            return $this->resetPassword($username);
        }

        return false;
    }

    public function report(): array
    {
        return $this->results ?: $this->check();
    }

    public function getLastActionResult(): array
    {
        return $this->lastActionResult;
    }

    private function parseWpConfig(): array
    {
        $configPath = $this->locateWpConfigPath();
        if (!is_file($configPath)) return [];

        $content = (string) file_get_contents($configPath);
        $vars = [];

        foreach (['WP_DEBUG', 'WP_DEBUG_DISPLAY', 'WP_DEBUG_LOG', 'SAVEQUERIES', 'WP_ENVIRONMENT_TYPE'] as $constant) {
            $rawValue = $this->extractConfigConstantValue($content, $constant);
            if ($rawValue !== null) {
                $vars[$constant] = $this->normalizeConfigValueForDisplay($rawValue);
            }
        }

        return $vars;
    }

    private function toggleWpDebugSuite(): bool
    {
        $configPath = $this->locateWpConfigPath();
        if (!is_file($configPath) || !is_writable($configPath)) {
            $this->lastActionResult = [
                'success' => false,
                'message' => 'Config file is not writable for WP_DEBUG.',
                'data' => null,
            ];
            return false;
        }

        $content = (string) file_get_contents($configPath);
        $currentDebug = 'false';
        $rawCurrentDebug = $this->extractConfigConstantValue($content, 'WP_DEBUG');
        if ($rawCurrentDebug !== null) {
            $currentDebug = strtolower($this->normalizeConfigValueForDisplay($rawCurrentDebug));
        }

        $newDebug = $currentDebug === 'true' ? 'false' : 'true';
        $debugLogPath = $this->resolveDebugLogPath();

        $updated = false;
        $updated = $this->upsertConfigConstant($content, 'WP_DEBUG', $newDebug) || $updated;
        $updated = $this->upsertConfigConstant($content, 'WP_DEBUG_DISPLAY', 'false') || $updated;
        $updated = $this->upsertConfigConstant($content, 'WP_DEBUG_LOG', "'" . addslashes($debugLogPath) . "'") || $updated;

        if (!$updated) {
            $this->lastActionResult = [
                'success' => false,
                'message' => 'Failed to update WP_DEBUG settings in wp-config.php.',
                'data' => null,
            ];
            return false;
        }

        $written = file_put_contents($configPath, $content) !== false;
        $bootstrapResult = $newDebug === 'true' ? $this->bootstrapDebugLogFile($debugLogPath) : true;
        $success = $written && $bootstrapResult;
        $this->lastActionResult = [
            'success' => $success,
            'message' => $success
                ? ($newDebug === 'true'
                    ? "WP_DEBUG enabled. Logs will be written to {$debugLogPath} with display disabled."
                    : 'WP_DEBUG disabled. Display remains off and log target is preserved.')
                : ($written
                    ? "WP_DEBUG constants were updated, but the debug log file could not be prepared at {$debugLogPath}."
                    : 'Failed to write updated WP_DEBUG settings to wp-config.php.'),
            'data' => $written ? [
                'WP_DEBUG' => $newDebug,
                'WP_DEBUG_DISPLAY' => 'false',
                'WP_DEBUG_LOG' => $debugLogPath,
                'debug_log_bootstrap' => $bootstrapResult ? 'ready' : 'failed',
            ] : null,
        ];
        return $success;
    }

    private function upsertConfigConstant(string &$content, string $constant, string $valueExpression): bool
    {
        $pattern = '/^[ \t]*define\(\s*[\'"]' . preg_quote($constant, '/') . '[\'"]\s*,[^\r\n;]+?\)\s*;\s*$/mi';
        $replacement = "define('{$constant}', {$valueExpression});";
        $placeholder = "__WPD_{$constant}_PLACEHOLDER__";

        $updated = preg_replace($pattern, $placeholder, $content, 1, $replacements);
        if ($updated !== null && $replacements > 0) {
            $content = $updated;
            $content = preg_replace($pattern, '', $content);
            $content = preg_replace('/^[ \t]*' . preg_quote($placeholder, '/') . '[ \t]*$/m', $replacement, $content, 1);
            $content = preg_replace("/\n{3,}/", "\n\n", $content);
            return true;
        }

        $insert = $replacement . "\n";
        if (strpos($content, "/* That's all, stop editing!") !== false) {
            $content = str_replace("/* That's all, stop editing!", $insert . "/* That's all, stop editing!", $content, $count);
            return $count > 0;
        }

        $content = preg_replace('/(<\?php)/i', "$1\n" . $insert, $content, 1, $count);
        return $count > 0;
    }

    private function toggleConfig(string $constant): bool
    {
        $configPath = $this->locateWpConfigPath();
        if (!is_file($configPath) || !is_writable($configPath)) {
            $this->lastActionResult = [
                'success' => false,
                'message' => "Config file is not writable for {$constant}.",
                'data' => ['constant' => $constant],
            ];
            return false;
        }

        $content = (string) file_get_contents($configPath);
        $current = strtolower($this->normalizeConfigValueForDisplay($this->extractConfigConstantValue($content, $constant) ?? 'false'));
        $newVal = ($current === 'true') ? 'false' : 'true';
        $updated = $this->upsertConfigConstant($content, $constant, $newVal);

        if (!$updated) {
            $this->lastActionResult = [
                'success' => false,
                'message' => "Failed to update {$constant} in wp-config.php.",
                'data' => ['constant' => $constant],
            ];
            return false;
        }

        $written = file_put_contents($configPath, $content) !== false;
        $this->lastActionResult = [
            'success' => $written,
            'message' => $written ? "{$constant} set to {$newVal}." : "Failed to write wp-config.php for {$constant}.",
            'data' => ['constant' => $constant, 'value' => $newVal],
        ];
        return $written;
    }

    private function toggleMaintenance(): bool
    {
        $file = ABSPATH . '.maintenance';
        if (is_file($file)) {
            $result = unlink($file);
            $this->lastActionResult = [
                'success' => $result,
                'message' => $result ? 'Maintenance mode disabled.' : 'Failed to disable maintenance mode.',
                'data' => ['maintenance_mode' => $result ? 'inactive' : 'active'],
            ];
            return $result;
        } else {
            $result = file_put_contents($file, '<?php $upgrading = time(); ?>') !== false;
            $this->lastActionResult = [
                'success' => $result,
                'message' => $result ? 'Maintenance mode enabled.' : 'Failed to enable maintenance mode.',
                'data' => ['maintenance_mode' => $result ? 'active' : 'inactive'],
            ];
            return $result;
        }
    }

    private function clearCache(): bool
    {
        if ($this->isWpLoaded && function_exists('wp_cache_flush')) {
            wp_cache_flush();
            if (function_exists('flush_rewrite_rules')) {
                flush_rewrite_rules();
            }
        }
        
        // Clear common cache dirs manually
        $dirs = ['wp-content/cache', 'wp-content/w3tc-config', 'wp-content/advanced-cache.php', 'wp-content/object-cache.php'];
        foreach ($dirs as $d) {
            $path = ABSPATH . $d;
            if (is_file($path)) @unlink($path);
            elseif (is_dir($path)) {
                $files = new \RecursiveIteratorIterator(
                    new \RecursiveDirectoryIterator($path, \RecursiveDirectoryIterator::SKIP_DOTS),
                    \RecursiveIteratorIterator::CHILD_FIRST
                );
                foreach ($files as $fileinfo) {
                    $todo = ($fileinfo->isDir() ? 'rmdir' : 'unlink');
                    @$todo($fileinfo->getRealPath());
                }
                @rmdir($path);
            }
        }

        if (!$this->isWpLoaded) {
            global $DB;
            if ($DB) {
                $DB->mysqli->query("DELETE FROM `{$DB->prefix}options` WHERE `option_name` LIKE '_transient_%' OR `option_name` LIKE '_site_transient_%'");
            }
        } else {
            global $wpdb;
            $wpdb->query("DELETE FROM `{$wpdb->options}` WHERE `option_name` LIKE '_transient_%' OR `option_name` LIKE '_site_transient_%'");
        }

        $this->lastActionResult = [
            'success' => true,
            'message' => 'Cache flush routine completed.',
            'data' => null,
        ];
        return true;
    }

    private function updateCore(bool $forceReinstall = false): bool
    {
        $version = $this->getCurrentWordPressVersion();
        if (!$version) {
            $this->lastActionResult = [
                'success' => false,
                'message' => 'Unable to determine the installed WordPress version for repair.',
                'data' => null,
            ];
            return false;
        }

        if ($this->isWpLoaded && !$forceReinstall) {
            $nativeResult = $this->runNativeCoreUpdate();
            if ($nativeResult['success']) {
                $this->lastActionResult = $nativeResult;
                return true;
            }
        }

        $repairResult = $this->repairCoreFromPackage($version);
        $this->lastActionResult = $repairResult;
        return $repairResult['success'];
    }

    private function runNativeCoreUpdate(): array
    {
        $requiredFiles = [
            ABSPATH . 'wp-admin/includes/class-wp-upgrader.php',
            ABSPATH . 'wp-admin/includes/file.php',
            ABSPATH . 'wp-admin/includes/misc.php',
            ABSPATH . 'wp-admin/includes/update.php',
        ];

        foreach ($requiredFiles as $requiredFile) {
            if (!is_file($requiredFile)) {
                return [
                    'success' => false,
                    'message' => 'Required updater dependency is missing: ' . basename($requiredFile),
                    'data' => null,
                ];
            }

            require_once $requiredFile;
        }

        if (!function_exists('get_core_updates')) {
            return [
                'success' => false,
                'message' => 'WordPress updater APIs are unavailable.',
                'data' => null,
            ];
        }

        ob_start();
        $upgrader = new \Core_Upgrader(new \Automatic_Upgrader_Skin());
        $updates = get_core_updates(['dismissed' => false]);
        $target = $updates[0] ?? null;

        if ($target && $target->response === 'latest' && function_exists('find_core_update')) {
            $found = find_core_update($target->current, $target->locale);
            if ($found) {
                $target = $found;
            }
        }

        $result = false;
        if ($target) {
            $result = $upgrader->upgrade($target);
        }
        ob_end_clean();

        $success = !is_wp_error($result) && (bool) $result;
        return [
            'success' => $success,
            'message' => $success
                ? 'WordPress core update completed via native updater.'
                : 'Native core update was unavailable or failed. Falling back to package repair.',
            'data' => null,
        ];
    }

    private function repairCoreFromPackage(string $version): array
    {
        $workingDir = $this->createTempDirectory();

        try {
            $sourceDir = $this->downloadAndExtractWordPress($version, $workingDir);
            $copied = $this->syncCoreFiles($sourceDir, ABSPATH);

            return [
                'success' => $copied > 0,
                'message' => $copied > 0
                    ? "WordPress core files reinstalled from package {$version}. ({$copied} file(s) refreshed)"
                    : 'Core repair package was downloaded, but no files were refreshed.',
                'data' => [
                    'version' => $version,
                    'files_refreshed' => $copied,
                ],
            ];
        } catch (\Throwable $e) {
            return [
                'success' => false,
                'message' => 'Core repair failed: ' . $e->getMessage(),
                'data' => ['version' => $version],
            ];
        } finally {
            $this->removeDirectory($workingDir);
        }
    }

    private function downloadAndExtractWordPress(string $version, string $workingDir): string
    {
        if (class_exists(\ZipArchive::class)) {
            $zipUrl = "https://wordpress.org/wordpress-{$version}.zip";
            $zipPath = $workingDir . '/wordpress.zip';
            $this->downloadFile($zipUrl, $zipPath);

            $zip = new \ZipArchive();
            if ($zip->open($zipPath) !== true) {
                throw new \RuntimeException('Unable to open downloaded WordPress zip archive.');
            }

            if (!$zip->extractTo($workingDir)) {
                $zip->close();
                throw new \RuntimeException('Unable to extract downloaded WordPress zip archive.');
            }

            $zip->close();
        } elseif (class_exists(\PharData::class)) {
            $tarGzUrl = "https://wordpress.org/wordpress-{$version}.tar.gz";
            $tarGzPath = $workingDir . '/wordpress.tar.gz';
            $this->downloadFile($tarGzUrl, $tarGzPath);

            $tarPath = $workingDir . '/wordpress.tar';
            if (is_file($tarPath)) {
                @unlink($tarPath);
            }

            $archive = new \PharData($tarGzPath);
            $archive->decompress();

            $tar = new \PharData($tarPath);
            $tar->extractTo($workingDir, null, true);
        } else {
            throw new \RuntimeException('Neither ZipArchive nor PharData is available for package extraction.');
        }

        $sourceDir = $workingDir . '/wordpress';
        if (!is_dir($sourceDir)) {
            throw new \RuntimeException('Extracted WordPress package directory was not found.');
        }

        return $sourceDir;
    }

    private function downloadFile(string $url, string $destination): void
    {
        if ($this->isWpLoaded && function_exists('download_url')) {
            $tmpFile = download_url($url, 30);
            if (is_wp_error($tmpFile)) {
                throw new \RuntimeException($tmpFile->get_error_message());
            }

            if (!@rename($tmpFile, $destination)) {
                if (!@copy($tmpFile, $destination)) {
                    @unlink($tmpFile);
                    throw new \RuntimeException('Unable to move downloaded WordPress package into place.');
                }
                @unlink($tmpFile);
            }
            return;
        }

        if (function_exists('curl_init')) {
            $handle = curl_init($url);
            $fp = fopen($destination, 'wb');
            if ($handle === false || $fp === false) {
                throw new \RuntimeException('Unable to prepare remote download handles.');
            }

            curl_setopt_array($handle, [
                CURLOPT_FILE => $fp,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_TIMEOUT => 30,
                CURLOPT_FAILONERROR => true,
                CURLOPT_SSL_VERIFYPEER => false,
                CURLOPT_SSL_VERIFYHOST => false,
            ]);

            $result = curl_exec($handle);
            $error = curl_error($handle);
            curl_close($handle);
            fclose($fp);

            if ($result === false) {
                @unlink($destination);
                throw new \RuntimeException('Package download failed: ' . $error);
            }
            return;
        }

        $context = stream_context_create([
            'http' => ['timeout' => 30, 'follow_location' => 1],
            'ssl' => ['verify_peer' => false, 'verify_peer_name' => false],
        ]);
        $payload = @file_get_contents($url, false, $context);
        if ($payload === false || file_put_contents($destination, $payload) === false) {
            throw new \RuntimeException('Package download failed via file_get_contents.');
        }
    }

    private function syncCoreFiles(string $sourceDir, string $targetDir): int
    {
        $copied = 0;
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($sourceDir, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::SELF_FIRST
        );

        foreach ($iterator as $item) {
            $sourcePath = $item->getPathname();
            $relativePath = str_replace('\\', '/', substr($sourcePath, strlen($sourceDir) + 1));
            if ($relativePath === false || $relativePath === '') {
                continue;
            }

            if ($relativePath === 'wp-content' || strpos($relativePath, 'wp-content/') === 0) {
                continue;
            }

            $destinationPath = rtrim($targetDir, '/\\') . '/' . str_replace('/', DIRECTORY_SEPARATOR, $relativePath);

            if ($item->isDir()) {
                if (!is_dir($destinationPath) && !mkdir($destinationPath, 0755, true) && !is_dir($destinationPath)) {
                    throw new \RuntimeException("Unable to create directory: {$relativePath}");
                }
                continue;
            }

            $destinationDir = dirname($destinationPath);
            if (!is_dir($destinationDir) && !mkdir($destinationDir, 0755, true) && !is_dir($destinationDir)) {
                throw new \RuntimeException("Unable to prepare directory for {$relativePath}");
            }

            if (!@copy($sourcePath, $destinationPath)) {
                throw new \RuntimeException("Unable to restore core file: {$relativePath}");
            }

            $copied++;
        }

        return $copied;
    }

    private function createTempDirectory(): string
    {
        $dir = rtrim(sys_get_temp_dir(), '/\\') . '/wpdiagnose-core-' . bin2hex(random_bytes(6));
        if (!mkdir($dir, 0700, true) && !is_dir($dir)) {
            throw new \RuntimeException('Unable to create temporary working directory for core repair.');
        }

        return $dir;
    }

    private function removeDirectory(string $path): void
    {
        if (!is_dir($path)) {
            return;
        }

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($path, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST
        );

        foreach ($iterator as $item) {
            if ($item->isDir()) {
                @rmdir($item->getPathname());
            } else {
                @unlink($item->getPathname());
            }
        }

        @rmdir($path);
    }

    private function resetPassword(string $username): bool
    {
        $newPass = $this->generateTemporaryPassword();
        if ($this->isWpLoaded && function_exists('wp_set_password')) {
            $user = get_user_by('login', $username);
            if ($user) {
                wp_set_password($newPass, $user->ID);
                $this->lastActionResult = [
                    'success' => true,
                    'message' => "Temporary password generated for {$username}: {$newPass}",
                    'data' => ['username' => $username, 'temporary_password' => $newPass],
                ];
                return true;
            }
        } else {
            global $DB;
            if ($DB) {
                // Not using wp_hash_password, using standard MD5 as fallback which WP supports upgrading from
                $hash = md5($newPass);
                $stmt = $DB->mysqli->prepare("UPDATE `{$DB->prefix}users` SET `user_pass` = ? WHERE `user_login` = ?");
                $stmt->bind_param('ss', $hash, $username);
                $stmt->execute();
                $success = $stmt->affected_rows > 0;
                $this->lastActionResult = [
                    'success' => $success,
                    'message' => $success
                        ? "Temporary password generated for {$username}: {$newPass}"
                        : "Could not reset password for {$username}.",
                    'data' => $success ? ['username' => $username, 'temporary_password' => $newPass] : ['username' => $username],
                ];
                return $success;
            }
        }

        $this->lastActionResult = [
            'success' => false,
            'message' => "Could not reset password for {$username}.",
            'data' => ['username' => $username],
        ];
        return false;
    }

    private function getCurrentWordPressVersion(): ?string
    {
        if ($this->isWpLoaded && function_exists('get_bloginfo')) {
            $version = (string) get_bloginfo('version');
            if ($version !== '') {
                return $version;
            }
        }

        $versionFile = ABSPATH . 'wp-includes/version.php';
        if (!is_file($versionFile)) {
            return null;
        }

        $wp_version = null;
        include $versionFile;
        return is_string($wp_version) && $wp_version !== '' ? $wp_version : null;
    }

    private function resolveDebugLogPath(): string
    {
        return $this->resolveDebugLogPathFromConfig($this->parseWpConfig());
    }

    /**
     * @param array<string, string> $configVars
     */
    private function resolveDebugLogPathFromConfig(array $configVars): string
    {
        $configured = $configVars['WP_DEBUG_LOG'] ?? null;
        if (is_string($configured) && $configured !== '' && $configured !== 'true' && $configured !== 'false') {
            return $configured;
        }

        return rtrim(ABSPATH, '/\\') . '/wp-content/wp-diagnose-tool.log';
    }

    private function locateWpConfigPath(): string
    {
        $candidates = [
            ABSPATH . 'wp-config.php',
            dirname(rtrim(ABSPATH, '/\\')) . '/wp-config.php',
        ];

        foreach ($candidates as $candidate) {
            if (is_file($candidate)) {
                return $candidate;
            }
        }

        return ABSPATH . 'wp-config.php';
    }

    private function generateTemporaryPassword(): string
    {
        try {
            return 'Tmp_' . bin2hex(random_bytes(6)) . '!';
        } catch (\Throwable $e) {
            return 'Tmp_' . substr(sha1((string) microtime(true)), 0, 12) . '!';
        }
    }

    private function outputErrorLog(): void
    {
        $logFile = $this->findExistingDebugLogFile();
        if (!is_file($logFile)) {
            $diagnostics = $this->getDebugLogDiagnostics($this->resolveDebugLogPath());
            while (ob_get_level()) ob_end_clean();
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode([
                'success' => false,
                'message' => 'Debug log not found at the configured path. See diagnostics for writable directories and fallback locations.',
                'data' => $diagnostics,
            ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            exit;
        }

        $lines = file($logFile);
        $last100 = array_slice($lines, -100);
        
        while (ob_get_level()) ob_end_clean();
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode([
            'success' => true,
            'message' => 'Debug log loaded successfully.',
            'data' => [
                'path' => $logFile,
                'contents' => implode("", $last100),
            ],
        ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        exit;
    }

    private function extractConfigConstantValue(string $content, string $constant): ?string
    {
        if (preg_match('/define\(\s*[\'"]' . preg_quote($constant, '/') . '[\'"]\s*,\s*([^\r\n;]+)\s*\)\s*;/i', $content, $matches)) {
            return trim($matches[1]);
        }

        return null;
    }

    private function normalizeConfigValueForDisplay(string $rawValue): string
    {
        $trimmed = trim($rawValue);
        $trimmed = rtrim($trimmed, ',');

        if (preg_match('/^(true|false)$/i', $trimmed) === 1) {
            return strtolower($trimmed);
        }

        if (preg_match('/^[\'"](.*)[\'"]$/', $trimmed, $matches) === 1) {
            return (string) $matches[1];
        }

        return $trimmed;
    }

    private function bootstrapDebugLogFile(string $debugLogPath): bool
    {
        $directory = dirname($debugLogPath);
        if (!is_dir($directory) && !@mkdir($directory, 0755, true) && !is_dir($directory)) {
            return false;
        }

        $marker = '[' . gmdate('c') . '] WP Diagnose debug log bootstrap marker' . PHP_EOL;
        $written = @file_put_contents($debugLogPath, $marker, FILE_APPEND | LOCK_EX);
        if ($written === false) {
            @error_log(trim($marker), 3, $debugLogPath);
        }

        clearstatcache(true, $debugLogPath);
        return is_file($debugLogPath);
    }

    private function findExistingDebugLogFile(): string
    {
        $preferred = $this->resolveDebugLogPath();
        if (is_file($preferred)) {
            return $preferred;
        }

        $fallback = rtrim(ABSPATH, '/\\') . '/wp-content/debug.log';
        if (is_file($fallback)) {
            return $fallback;
        }

        return $preferred;
    }

    /**
     * @return array{active_path: string, fallback_path: string, status: string, viewer_status: string, active_exists: bool, fallback_exists: bool, directory: string, directory_writable: bool}
     */
    private function getDebugLogDiagnostics(string $activePath): array
    {
        $directory = dirname($activePath);
        $fallbackPath = rtrim(ABSPATH, '/\\') . '/wp-content/debug.log';
        $activeExists = is_file($activePath);
        $fallbackExists = is_file($fallbackPath);
        $directoryWritable = is_dir($directory) ? is_writable($directory) : is_writable(dirname($directory));

        return [
            'active_path' => $activePath,
            'fallback_path' => $fallbackPath,
            'status' => $activeExists ? 'ready' : ($directoryWritable ? 'awaiting_log_events' : 'directory_not_writable'),
            'viewer_status' => ($activeExists || $fallbackExists) ? 'ready' : 'waiting',
            'active_exists' => $activeExists,
            'fallback_exists' => $fallbackExists,
            'directory' => $directory,
            'directory_writable' => $directoryWritable,
        ];
    }
}
