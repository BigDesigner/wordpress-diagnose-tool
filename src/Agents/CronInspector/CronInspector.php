<?php
declare(strict_types=1);

namespace WPDiagnose\Agents\CronInspector {

    use WPDiagnose\Core\DiagnosticInterface;

    /**
     * Class CronInspector
     * 
     * Inspects scheduled cron tasks and detects overdue or disabled execution paths.
     */
    class CronInspector implements DiagnosticInterface
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
            return 'CronInspector';
        }

        public function check(): array
        {
            $this->results = [];

            // Check if cron is disabled in wp-config
            $cronDisabled = defined('DISABLE_WP_CRON') && DISABLE_WP_CRON;
            $this->results['cron_status'] = [
                'status' => $cronDisabled ? 'WARN' : 'OK',
                'info' => $cronDisabled ? 'WP-Cron execution is disabled via wp-config (DISABLE_WP_CRON).' : 'WP-Cron execution is enabled.'
            ];

            // Inspect cron jobs list
            $overdueCount = 0;
            $overdueList = [];
            $cronJobs = $this->loadCronJobs();

            if (!empty($cronJobs)) {
                $now = time();
                foreach ($cronJobs as $timestamp => $hooks) {
                    if (!is_numeric($timestamp)) {
                        continue;
                    }
                    $timestamp = (int)$timestamp;
                    if ($timestamp < $now - 3600) { // Overdue by more than an hour
                        foreach ($hooks as $hook => $jobs) {
                            foreach ($jobs as $key => $job) {
                                $overdueCount++;
                                $overdueList[] = sprintf('%s (scheduled %s)', $hook, date('Y-m-d H:i:s', $timestamp));
                            }
                        }
                    }
                }
            }

            $this->results['overdue_cron_jobs'] = [
                'status' => $overdueCount > 5 ? 'WARN' : 'OK',
                'info' => sprintf('%d overdue cron tasks detected.', $overdueCount),
                'data' => $overdueList
            ];

            return $this->results;
        }

        public function fix(string $id): bool
        {
            $this->lastActionResult = null;

            if ($id === 'clear_overdue_crons') {
                return $this->clearOverdueCrons();
            }

            return false;
        }

        public function getLastActionResult(): ?array
        {
            return $this->lastActionResult;
        }

        private function loadCronJobs(): array
        {
            if ($this->wpLoaded) {
                $cron = _get_cron_array();
                return is_array($cron) ? $cron : [];
            }

            // Independent mode direct db fetch
            $dbConnection = $this->getDatabaseConnection();
            if ($dbConnection) {
                $prefix = $this->getTablePrefix();
                
                if ($this->wpLoaded) {
                    global $wpdb;
                    $cronRaw = $wpdb->get_var("SELECT option_value FROM {$prefix}options WHERE option_name = 'cron' LIMIT 1");
                } else {
                    $stmt = $dbConnection->prepare("SELECT option_value FROM {$prefix}options WHERE option_name = 'cron' LIMIT 1");
                    if ($stmt) {
                        $stmt->execute();
                        $stmt->bind_result($cronRaw);
                        $stmt->fetch();
                        $stmt->close();
                    }
                }

                if (!empty($cronRaw)) {
                    $unserialized = @unserialize($cronRaw);
                    return is_array($unserialized) ? $unserialized : [];
                }
            }

            return [];
        }

        private function clearOverdueCrons(): bool
        {
            $cronJobs = $this->loadCronJobs();
            if (empty($cronJobs)) {
                $this->lastActionResult = ['success' => true, 'message' => 'No cron tasks to clear.'];
                return true;
            }

            $now = time();
            $cleanedCron = [];
            $clearedCount = 0;

            foreach ($cronJobs as $timestamp => $hooks) {
                if (!is_numeric($timestamp)) {
                    $cleanedCron[$timestamp] = $hooks;
                    continue;
                }
                $timestamp = (int)$timestamp;
                if ($timestamp < $now - 3600) {
                    // Filter out overdue jobs
                    $clearedCount += count($hooks);
                } else {
                    $cleanedCron[$timestamp] = $hooks;
                }
            }

            if ($clearedCount === 0) {
                $this->lastActionResult = ['success' => true, 'message' => 'No overdue tasks found.'];
                return true;
            }

            // Save back
            if ($this->wpLoaded) {
                _set_cron_array($cleanedCron);
                $this->lastActionResult = ['success' => true, 'message' => "Cleared $clearedCount overdue cron tasks successfully."];
                return true;
            } else {
                $dbConnection = $this->getDatabaseConnection();
                if ($dbConnection) {
                    $prefix = $this->getTablePrefix();
                    $serialized = serialize($cleanedCron);
                    $stmt = $dbConnection->prepare("UPDATE {$prefix}options SET option_value = ? WHERE option_name = 'cron'");
                    if ($stmt) {
                        $stmt->bind_param("s", $serialized);
                        $result = $stmt->execute();
                        $stmt->close();
                        if ($result) {
                            $this->lastActionResult = ['success' => true, 'message' => "Cleared $clearedCount overdue tasks from database."];
                            return true;
                        }
                    }
                }
            }

            $this->lastActionResult = ['success' => false, 'message' => 'Failed to write updated cron array.'];
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
