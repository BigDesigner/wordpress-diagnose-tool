<?php
declare(strict_types=1);

namespace WPDiagnose\Agents\PerformanceAgent;

use WPDiagnose\Core\DiagnosticInterface;

/**
 * Class PerformanceAgent
 * 
 * Inspects performance metrics, autoload size hotspots, and transient bloat.
 */
class PerformanceAgent implements DiagnosticInterface
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
        return 'PerformanceAgent';
    }

    public function check(): array
    {
        $this->results = [];

        $dbConnection = $this->getDatabaseConnection();
        if (!$dbConnection) {
            $this->results['performance_status'] = [
                'status' => 'WARN',
                'info' => 'No active database connection. Performance analysis unavailable.'
            ];
            return $this->results;
        }

        $prefix = $this->getTablePrefix();

        // 1. Check Autoload Size
        $autoloadQuery = "SELECT SUM(LENGTH(option_value)) FROM {$prefix}options WHERE autoload = 'yes' OR autoload = 'on'";
        $autoloadSize = 0;

        if ($this->wpLoaded) {
            global $wpdb;
            $autoloadSize = (int)$wpdb->get_var($autoloadQuery);
        } else {
            $res = $dbConnection->query($autoloadQuery);
            $row = $res ? $res->fetch_row() : null;
            $autoloadSize = (int)($row[0] ?? 0);
        }

        $autoloadSizeKb = round($autoloadSize / 1024, 2);
        $this->results['autoload_bloat'] = [
            'status' => $autoloadSizeKb > 800 ? 'WARN' : 'OK',
            'info' => sprintf('Autoload size: %s KB (Recommended: < 800 KB).', $autoloadSizeKb)
        ];

        // 2. Count transients
        $transientsQuery = "SELECT COUNT(*) FROM {$prefix}options WHERE option_name LIKE '_transient_%' OR option_name LIKE '_site_transient_%'";
        $transientCount = 0;

        if ($this->wpLoaded) {
            global $wpdb;
            $transientCount = (int)$wpdb->get_var($transientsQuery);
        } else {
            $res = $dbConnection->query($transientsQuery);
            $row = $res ? $res->fetch_row() : null;
            $transientCount = (int)($row[0] ?? 0);
        }

        $this->results['transients_count'] = [
            'status' => $transientCount > 500 ? 'WARN' : 'OK',
            'info' => sprintf('%d transients found in options table.', $transientCount),
            'data' => [
                'count' => $transientCount,
                'cache_clear' => 'flush'
            ]
        ];

        return $this->results;
    }

    public function report(): array
    {
        return $this->results ?: $this->check();
    }

    public function fix(string $id): bool
    {
        $this->lastActionResult = null;

        if ($id === 'clear_transients') {
            return $this->clearTransients();
        }

        return false;
    }

    public function getLastActionResult(): ?array
    {
        return $this->lastActionResult;
    }

    private function clearTransients(): bool
    {
        $dbConnection = $this->getDatabaseConnection();
        if (!$dbConnection) {
            $this->lastActionResult = ['success' => false, 'message' => 'No database connection available.'];
            return false;
        }

        $prefix = $this->getTablePrefix();
        $deleteQuery = "DELETE FROM {$prefix}options WHERE option_name LIKE '_transient_%' OR option_name LIKE '_site_transient_%'";

        if ($this->wpLoaded) {
            global $wpdb;
            $rowsAffected = $wpdb->query($deleteQuery);
            $this->lastActionResult = ['success' => true, 'message' => "Successfully cleared $rowsAffected transient(s) from database."];
            return true;
        } else {
            $res = $dbConnection->query($deleteQuery);
            if ($res) {
                $rowsAffected = $dbConnection->affected_rows;
                $this->lastActionResult = ['success' => true, 'message' => "Successfully cleared $rowsAffected transient(s) from database."];
                return true;
            }
        }

        $this->lastActionResult = ['success' => false, 'message' => 'Failed to clear transients.'];
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
