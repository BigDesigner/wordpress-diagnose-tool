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
        
        $this->results['config_toggles'] = [
            'status' => 'OK',
            'info'   => 'Current wp-config.php debug/env settings.',
            'data'   => [
                'WP_DEBUG'    => $configVars['WP_DEBUG'] ?? 'false',
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
                'core_update'      => $this->isWpLoaded ? 'ready' : 'unavailable',
            ],
        ];

        return $this->results;
    }

    public function fix(string $id): bool
    {
        $this->lastActionResult = ['success' => false, 'message' => 'Unknown core operation.', 'data' => null];

        if ($id === 'toggle_wp_debug') {
            return $this->toggleConfig('WP_DEBUG');
        } elseif ($id === 'toggle_savequeries') {
            return $this->toggleConfig('SAVEQUERIES');
        } elseif ($id === 'toggle_maintenance') {
            return $this->toggleMaintenance();
        } elseif ($id === 'clear_cache') {
            return $this->clearCache();
        } elseif ($id === 'core_update' || $id === 'reinstall_core') {
            return $this->updateCore();
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

        $content = file_get_contents($configPath);
        $vars = [];
        
        if (preg_match("/define\(\s*['\"]WP_DEBUG['\"]\s*,\s*(true|false)\s*\)/i", $content, $matches)) {
            $vars['WP_DEBUG'] = strtolower($matches[1]);
        }
        if (preg_match("/define\(\s*['\"]SAVEQUERIES['\"]\s*,\s*(true|false)\s*\)/i", $content, $matches)) {
            $vars['SAVEQUERIES'] = strtolower($matches[1]);
        }
        if (preg_match("/define\(\s*['\"]WP_ENVIRONMENT_TYPE['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)/i", $content, $matches)) {
            $vars['WP_ENVIRONMENT_TYPE'] = $matches[1];
        }
        return $vars;
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

        $content = file_get_contents($configPath);
        $current = 'false';
        $newVal = 'true';
        $replacements = 0;
        
        if (preg_match("/define\(\s*['\"]{$constant}['\"]\s*,\s*(true|false)\s*\)/i", $content, $matches)) {
            $current = strtolower($matches[1]);
            $newVal = ($current === 'true') ? 'false' : 'true';
            $content = preg_replace(
                "/define\(\s*['\"]{$constant}['\"]\s*,\s*(true|false)\s*\)/i",
                "define('{$constant}', {$newVal})",
                $content,
                1,
                $replacements
            );
        } else {
            $insert = "define('{$constant}', true);\n";
            if (strpos($content, "/* That's all, stop editing!") !== false) {
                $content = str_replace("/* That's all, stop editing!", $insert . "/* That's all, stop editing!", $content);
                $replacements = 1;
            } else {
                $content = preg_replace('/(<\?php)/i', "$1\n$insert", $content, 1, $replacements);
            }
        }

        if ($replacements < 1) {
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

    private function updateCore(): bool
    {
        if (!$this->isWpLoaded) {
            $this->lastActionResult = [
                'success' => false,
                'message' => 'Core update requires a fully loaded WordPress environment.',
                'data' => null,
            ];
            return false;
        }

        $requiredFiles = [
            ABSPATH . 'wp-admin/includes/class-wp-upgrader.php',
            ABSPATH . 'wp-admin/includes/file.php',
            ABSPATH . 'wp-admin/includes/misc.php',
            ABSPATH . 'wp-admin/includes/update.php',
        ];

        foreach ($requiredFiles as $requiredFile) {
            if (!is_file($requiredFile)) {
                $this->lastActionResult = [
                    'success' => false,
                    'message' => 'Required updater dependency is missing: ' . basename($requiredFile),
                    'data' => null,
                ];
                return false;
            }

            require_once $requiredFile;
        }

        if (!function_exists('get_core_updates')) {
            $this->lastActionResult = [
                'success' => false,
                'message' => 'WordPress updater APIs are unavailable.',
                'data' => null,
            ];
            return false;
        }

        ob_start();
        $upgrader = new \Core_Upgrader(new \Automatic_Upgrader_Skin());
        $updates = get_core_updates(['dismissed' => false]);
        $target = $updates[0] ?? null;

        if ($target && $target->response === 'latest') {
            if (function_exists('find_core_update')) {
                $found = find_core_update($target->current, $target->locale);
                if ($found) $target = $found;
            }
        }

        $result = false;
        if ($target) {
            $result = $upgrader->upgrade($target);
        }
        ob_end_clean();

        $success = !is_wp_error($result) && $result;
        $this->lastActionResult = [
            'success' => $success,
            'message' => $success ? 'WordPress core update completed.' : 'WordPress core update failed or no update was available.',
            'data' => null,
        ];
        return $success;
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
        $logFile = ABSPATH . 'wp-content/debug.log';
        if (!is_file($logFile)) {
            echo json_encode(['success' => false, 'message' => 'debug.log not found.']);
            exit;
        }

        $lines = file($logFile);
        $last100 = array_slice($lines, -100);
        
        while (ob_get_level()) ob_end_clean();
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['success' => true, 'data' => implode("", $last100)], JSON_UNESCAPED_UNICODE);
        exit;
    }
}
