<?php
declare(strict_types=1);

namespace WPDiagnose\Agents\DBHealth;

use WPDiagnose\Core\DiagnosticInterface;

/**
 * Class DBHealth
 * 
 * Inspects database health, specifically wp_options autoload size and table fragmentation.
 */
class DBHealth implements DiagnosticInterface
{
    private array $results = [];
    private bool $isWpLoaded = false;

    public function __construct(bool $isWpLoaded = false)
    {
        $this->isWpLoaded = $isWpLoaded;
    }

    public function getName(): string
    {
        return 'DBHealth';
    }

    public function check(): array
    {
        $this->results = [];

        $db = $this->getDatabaseConnection();
        if (!$db) {
            global $DB_ERR;
            $this->results['db_status'] = [
                'status' => 'WARN',
                'info'   => 'Database connection not available. ' . ($DB_ERR ?: 'Database metrics require WordPress/DB connection.'),
            ];
            return $this->results;
        }

        $prefix = $this->getTablePrefix();

        // Suppress notices/warnings from database calls
        $prevReporting = error_reporting(E_ERROR);

        try {
            // 1. Autoload Size Check
            $autoloadSize = null;
            if ($this->isWpLoaded) {
                $autoloadSize = $db->get_var("SELECT SUM(LENGTH(option_value)) FROM $db->options WHERE autoload = 'yes'");
            } else {
                $optionsTable = "`" . $prefix . "options`";
                $res = $db->query("SELECT SUM(LENGTH(option_value)) FROM $optionsTable WHERE autoload = 'yes'");
                if ($res) {
                    $row = $res->fetch_row();
                    $autoloadSize = $row[0] ?? null;
                    $res->free();
                }
            }

            $sizeMB = round((int)$autoloadSize / 1024 / 1024, 2);

            $this->results['autoload_size'] = [
                'status' => $sizeMB > 1.0 ? 'WARN' : 'OK',
                'info'   => "Total Autoload Size: {$sizeMB} MB (Recommended < 1.0MB)",
            ];

            // 2. Table Optimization Status
            $tables = [];
            if ($this->isWpLoaded) {
                $tables = $db->get_results('SHOW TABLE STATUS') ?? [];
            } else {
                $res = $db->query('SHOW TABLE STATUS');
                if ($res) {
                    while ($row = $res->fetch_object()) {
                        $tables[] = $row;
                    }
                    $res->free();
                }
            }

            $fragmented = [];
            foreach ($tables as $table) {
                if (isset($table->Data_free) && $table->Data_free > 0) {
                    $fragmented[] = $table->Name;
                }
            }

            $fragCount = count($fragmented);
            $this->results['table_fragmentation'] = [
                'status' => $fragCount > 5 ? 'WARN' : 'OK',
                'info'   => "{$fragCount} tables have overhead. " . ($fragCount > 0 ? 'Optimization recommended.' : 'Clean.'),
            ];

            $this->results['db_status'] = [
                'status' => 'OK',
                'info'   => 'Database connection established and healthy.',
            ];
        } catch (\Throwable $e) {
            $this->results['db_status'] = [
                'status' => 'ERROR',
                'info'   => 'Database query failed: ' . $e->getMessage(),
            ];
        }

        error_reporting($prevReporting); // Restore original error level
        return $this->results;
    }

    public function fix(string $id): bool
    {
        $db = $this->getDatabaseConnection();
        if (!$db) return false;

        if ($id === 'table_fragmentation') {
            try {
                $tables = [];
                if ($this->isWpLoaded) {
                    $tables = $db->get_results("SHOW TABLE STATUS") ?? [];
                } else {
                    $res = $db->query("SHOW TABLE STATUS");
                    if ($res) {
                        while ($row = $res->fetch_object()) {
                            $tables[] = $row;
                        }
                        $res->free();
                    }
                }

                foreach ($tables as $table) {
                    if (isset($table->Data_free) && $table->Data_free > 0) {
                        if ($this->isWpLoaded) {
                            $db->query("OPTIMIZE TABLE {$table->Name}");
                        } else {
                            $db->query("OPTIMIZE TABLE `{$table->Name}`");
                        }
                    }
                }
                return true;
            } catch (\Throwable $e) {
                return false;
            }
        }

        return false;
    }

    public function report(): array
    {
        return $this->results ?: $this->check();
    }

    private function getDatabaseConnection()
    {
        if ($this->isWpLoaded) {
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
        if ($this->isWpLoaded) {
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
