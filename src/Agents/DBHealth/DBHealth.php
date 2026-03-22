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

        if (!$this->isWpLoaded) {
            $this->results['db_status'] = [
                'status' => 'WARN',
                'info'   => 'Database metrics require WordPress/DB connection.',
            ];
            return $this->results;
        }

        // Suppress notices/warnings from wpdb calls so they never bleed into JSON output.
        $prevReporting = error_reporting(E_ERROR);

        global $wpdb;

        // 1. Autoload Size Check
        $autoloadSize = @$wpdb->get_var("SELECT SUM(LENGTH(option_value)) FROM $wpdb->options WHERE autoload = 'yes'");
        $sizeMB       = round((int)$autoloadSize / 1024 / 1024, 2);

        $this->results['autoload_size'] = [
            'status' => $sizeMB > 1.0 ? 'WARN' : 'OK',
            'info'   => "Total Autoload Size: {$sizeMB} MB (Recommended < 1.0MB)",
        ];

        // 2. Table Optimization Status
        $tables     = @$wpdb->get_results('SHOW TABLE STATUS') ?? [];
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

        error_reporting($prevReporting); // Restore original error level
        return $this->results;
    }

    public function fix(string $id): bool
    {
        if (!$this->isWpLoaded) return false;
        global $wpdb;

        if ($id === 'table_fragmentation') {
            $tables = $wpdb->get_results("SHOW TABLE STATUS");
            foreach ($tables as $table) {
                if ($table->Data_free > 0) {
                    $wpdb->query("OPTIMIZE TABLE {$table->Name}");
                }
            }
            return true;
        }

        return false;
    }

    public function report(): array
    {
        return $this->results ?: $this->check();
    }
}
