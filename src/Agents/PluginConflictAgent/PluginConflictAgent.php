<?php
declare(strict_types=1);

namespace WPDiagnose\Agents\PluginConflictAgent {

    use WPDiagnose\Core\DiagnosticInterface;

    /**
     * Class PluginConflictAgent
     * 
     * Facilitates plugin troubleshooting by saving and restoring active plugin states.
     */
    class PluginConflictAgent implements DiagnosticInterface
    {
        private array $results = [];
        private bool $wpLoaded = false;
        private ?array $lastActionResult = null;

        public function __construct(bool $wpLoaded = false)
        {
            $this->wpLoaded = $wpLoaded;
        }

        public function getName(): string
        {
            return 'PluginConflictAgent';
        }

        public function check(): array
        {
            $this->results = [];

            $dbConnection = $this->getDatabaseConnection();
            if (!$dbConnection) {
                $this->results['conflict_status'] = [
                    'status' => 'WARN',
                    'info' => 'No database connection. Cannot check plugins.'
                ];
                return $this->results;
            }

            // Check if there is an active plugins backup
            $hasBackup = false;
            $backupContent = null;
            $prefix = $this->getTablePrefix();

            if ($this->wpLoaded) {
                $backupContent = get_option('wpd_active_plugins_snapshot');
                $hasBackup = !empty($backupContent);
            } else {
                $stmt = $dbConnection->prepare("SELECT option_value FROM {$prefix}options WHERE option_name = 'wpd_active_plugins_snapshot' LIMIT 1");
                if ($stmt) {
                    $stmt->execute();
                    $stmt->bind_result($backupRaw);
                    $stmt->fetch();
                    $stmt->close();
                    $hasBackup = !empty($backupRaw);
                }
            }

            $this->results['conflict_debugging'] = [
                'status' => $hasBackup ? 'WARN' : 'OK',
                'info' => $hasBackup 
                    ? 'A plugin state snapshot exists. You can restore plugins to their original state.'
                    : 'No active conflict debug snapshot found. Ready to troubleshoot.',
                'data' => [
                    'has_snapshot' => $hasBackup
                ]
            ];

            return $this->results;
        }

        public function fix(string $id): bool
        {
            $this->lastActionResult = null;

            if ($id === 'deactivate_all_plugins') {
                return $this->deactivateAllPlugins();
            }

            if ($id === 'restore_plugins_snapshot') {
                return $this->restorePluginsSnapshot();
            }

            return false;
        }

        public function getLastActionResult(): ?array
        {
            return $this->lastActionResult;
        }

        private function deactivateAllPlugins(): bool
        {
            $dbConnection = $this->getDatabaseConnection();
            if (!$dbConnection) {
                $this->lastActionResult = ['success' => false, 'message' => 'No database connection.'];
                return false;
            }

            $prefix = $this->getTablePrefix();

            // Fetch current active plugins
            $activePlugins = '';
            if ($this->wpLoaded) {
                $activePlugins = serialize(get_option('active_plugins', []));
            } else {
                $stmt = $dbConnection->prepare("SELECT option_value FROM {$prefix}options WHERE option_name = 'active_plugins' LIMIT 1");
                if ($stmt) {
                    $stmt->execute();
                    $stmt->bind_result($activePlugins);
                    $stmt->fetch();
                    $stmt->close();
                }
            }

            if (empty($activePlugins) || $activePlugins === serialize([])) {
                $this->lastActionResult = ['success' => false, 'message' => 'No plugins are currently active to deactivate.'];
                return false;
            }

            // Save snapshot
            $saveSuccess = false;
            if ($this->wpLoaded) {
                $saveSuccess = update_option('wpd_active_plugins_snapshot', $activePlugins);
            } else {
                // Manual update or insert option
                $stmt = $dbConnection->prepare("SELECT option_id FROM {$prefix}options WHERE option_name = 'wpd_active_plugins_snapshot'");
                $stmt->execute();
                $stmt->store_result();
                $exists = $stmt->num_rows > 0;
                $stmt->close();

                if ($exists) {
                    $stmt = $dbConnection->prepare("UPDATE {$prefix}options SET option_value = ? WHERE option_name = 'wpd_active_plugins_snapshot'");
                } else {
                    $stmt = $dbConnection->prepare("INSERT INTO {$prefix}options (option_value, option_name, autoload) VALUES (?, 'wpd_active_plugins_snapshot', 'no')");
                }

                if ($stmt) {
                    $stmt->bind_param("s", $activePlugins);
                    $saveSuccess = $stmt->execute();
                    $stmt->close();
                }
            }

            if (!$saveSuccess) {
                $this->lastActionResult = ['success' => false, 'message' => 'Failed to save plugin snapshot. Action aborted.'];
                return false;
            }

            // Deactivate all
            $emptySerialized = serialize([]);
            $deactivateSuccess = false;
            if ($this->wpLoaded) {
                $deactivateSuccess = update_option('active_plugins', []);
            } else {
                $stmt = $dbConnection->prepare("UPDATE {$prefix}options SET option_value = ? WHERE option_name = 'active_plugins'");
                if ($stmt) {
                    $stmt->bind_param("s", $emptySerialized);
                    $deactivateSuccess = $stmt->execute();
                    $stmt->close();
                }
            }

            if ($deactivateSuccess) {
                $this->lastActionResult = ['success' => true, 'message' => 'All plugins have been deactivated. Active state snapshot is saved.'];
                return true;
            }

            $this->lastActionResult = ['success' => false, 'message' => 'Failed to deactivate plugins.'];
            return false;
        }

        private function restorePluginsSnapshot(): bool
        {
            $dbConnection = $this->getDatabaseConnection();
            if (!$dbConnection) {
                $this->lastActionResult = ['success' => false, 'message' => 'No database connection.'];
                return false;
            }

            $prefix = $this->getTablePrefix();
            $snapshotRaw = '';

            if ($this->wpLoaded) {
                $snapshotRaw = get_option('wpd_active_plugins_snapshot');
            } else {
                $stmt = $dbConnection->prepare("SELECT option_value FROM {$prefix}options WHERE option_name = 'wpd_active_plugins_snapshot' LIMIT 1");
                if ($stmt) {
                    $stmt->execute();
                    $stmt->bind_result($snapshotRaw);
                    $stmt->fetch();
                    $stmt->close();
                }
            }

            if (empty($snapshotRaw)) {
                $this->lastActionResult = ['success' => false, 'message' => 'No plugin snapshot found to restore.'];
                return false;
            }

            // Restore active_plugins
            $restoreSuccess = false;
            if ($this->wpLoaded) {
                $unserialized = @unserialize($snapshotRaw);
                $restoreSuccess = update_option('active_plugins', is_array($unserialized) ? $unserialized : []);
            } else {
                $stmt = $dbConnection->prepare("UPDATE {$prefix}options SET option_value = ? WHERE option_name = 'active_plugins'");
                if ($stmt) {
                    $stmt->bind_param("s", $snapshotRaw);
                    $restoreSuccess = $stmt->execute();
                    $stmt->close();
                }
            }

            if ($restoreSuccess) {
                // Delete snapshot
                if ($this->wpLoaded) {
                    delete_option('wpd_active_plugins_snapshot');
                } else {
                    $stmt = $dbConnection->prepare("DELETE FROM {$prefix}options WHERE option_name = 'wpd_active_plugins_snapshot'");
                    if ($stmt) {
                        $stmt->execute();
                        $stmt->close();
                    }
                }

                $this->lastActionResult = ['success' => true, 'message' => 'Plugin state successfully restored from snapshot.'];
                return true;
            }

            $this->lastActionResult = ['success' => false, 'message' => 'Failed to restore plugins from snapshot.'];
            return false;
        }

        private function getDatabaseConnection()
        {
            if ($this->wpLoaded) {
                global $wpdb;
                return $wpdb;
            }

            global $DB;
            if ($DB instanceof \WPD_DB && $DB->mysqli) {
                return $DB->mysqli;
            }

            return null;
        }

        private function getTablePrefix(): string
        {
            if ($this->wpLoaded) {
                global $wpdb;
                return $wpdb->prefix;
            }

            global $DB;
            if ($DB instanceof \WPD_DB && $DB->prefix) {
                return $DB->prefix;
            }

            return 'wp_';
        }
    }
}
