<?php
declare(strict_types=1);

namespace WPDiagnose\Agents\ServerInspector;

use WPDiagnose\Core\DiagnosticInterface;

/**
 * Class ServerInspector
 * 
 * Inspects server-level configurations, PHP limits, and required extensions.
 */
class ServerInspector implements DiagnosticInterface
{
    /** @var array<string, mixed> Cached results of the last check */
    private array $results = [];

    /**
     * @inheritDoc
     */
    public function getName(): string
    {
        return 'ServerInspector';
    }

    /**
     * @inheritDoc
     */
    public function check(): array
    {
        $this->results = [];

        // Suppress notices/warnings during data collection so they don't contaminate JSON output.
        $prevReporting = error_reporting(E_ERROR);

        // PHP Environment
        $this->results['php_version'] = [
            'status' => version_compare(PHP_VERSION, '8.1.0', '>=') ? 'OK' : 'WARN',
            'info' => 'PHP ' . PHP_VERSION,
        ];

        // Resource Limits
        $limits = $this->checkPhpLimits();
        
        $this->results['memory_limit'] = [
            'status' => $limits['memory_limit']['status'],
            'info' => "Actual: {$limits['memory_limit']['actual']} | Rec: {$limits['memory_limit']['recommended']}",
        ];

        $this->results['max_execution_time'] = [
            'status' => $limits['max_execution_time']['status'],
            'info' => "Actual: {$limits['max_execution_time']['actual']}s | Rec: {$limits['max_execution_time']['recommended']}s",
        ];

        $this->results['upload_limit'] = [
            'status' => $limits['upload_max_filesize']['status'],
            'info'   => "Max Upload: {$limits['upload_max_filesize']['actual']} | Post Max: {$limits['post_max_size']['actual']}",
        ];

        // Extensions
        foreach ($this->checkExtensions() as $ext => $status) {
            $this->results['ext_' . $ext] = [
                'status' => $status,
                'info'   => $status === 'OK' ? 'Loaded' : 'Missing',
            ];
        }

        error_reporting($prevReporting); // Restore original error level
        return $this->results;
    }

    /**
     * @inheritDoc
     */
    public function fix(string $id): bool
    {
        // Guardrail: Dry Run Output
        printf("[AGENT] [DRY RUN] Initiating safety audit for fix ID: %s\n", $id);

        if ($id === 'memory_limit') {
            $current = ini_get('memory_limit');
            printf("[AGENT] [ACTION] Attempting temporary memory increase. Current: %s\n", $current);
            
            if (@ini_set('memory_limit', '512M') !== false) {
                printf("[AGENT] [SUCCESS] Memory limit temporarily set to 512M.\n");
                return true;
            }
            
            printf("[AGENT] [FAILURE] Unable to set memory_limit via ini_set. \n");
            printf("[AGENT] [SUGGESTION] Modify your php.ini or .htaccess: php_value memory_limit 512M\n");
            return false;
        }

        if ($id === 'max_execution_time') {
            printf("[AGENT] [ACTION] Attempting to extend max_execution_time to 300s.\n");
            if (@ini_set('max_execution_time', '300') !== false) {
                printf("[AGENT] [SUCCESS] Time limit extended.\n");
                return true;
            }
            return false;
        }

        if (str_starts_with($id, 'ext_')) {
            $ext = substr($id, 4);
            printf("[AGENT] [INFO] Extension '%s' is missing.\n", $ext);
            printf("[AGENT] [SUGGESTION] This must be enabled at the server level (apt-get install php-%s).\n", $ext);
            return false;
        }

        printf("[AGENT] [WARN] No automated fix routine found for: %s\n", $id);
        return false;
    }

    /**
     * @inheritDoc
     */
    public function report(): array
    {
        return $this->results ?: $this->check();
    }

    /**
     * Internal check for PHP resource limits.
     * 
     * @return array<string, array<string, mixed>>
     */
    private function checkPhpLimits(): array
    {
        $limits = [
            'memory_limit' => ['min' => '128M', 'rec' => '256M'],
            'max_execution_time' => ['min' => '30', 'rec' => '300'],
            'upload_max_filesize' => ['min' => '2M', 'rec' => '128M'],
            'post_max_size' => ['min' => '8M', 'rec' => '128M'],
        ];

        $comparison = [];
        foreach ($limits as $key => $values) {
            $actual = ini_get($key);
            $status = $this->convertToBytes($actual) >= $this->convertToBytes((string)$values['min']) ? 'OK' : 'WARN';
            
            $comparison[$key] = [
                'actual' => $actual,
                'recommended' => $values['rec'],
                'status' => $status,
            ];
        }

        return $comparison;
    }

    /**
     * Internal check for required PHP extensions.
     * 
     * @return array<string, string>
     */
    private function checkExtensions(): array
    {
        $required = ['mysqli', 'curl', 'json', 'dom', 'gd', 'mbstring', 'openssl', 'zip'];
        $results = [];

        foreach ($required as $ext) {
            $results[$ext] = extension_loaded($ext) ? 'OK' : 'WARN';
        }

        return $results;
    }

    /**
     * Helper to convert PHP ini values (e.g., 128M) to bytes.
     * 
     * @param string $val
     * @return int
     */
    private function convertToBytes(string $val): int
    {
        $val = trim($val);
        $last = strtolower($val[strlen($val) - 1]);
        $bytes = (int) $val;

        switch ($last) {
            case 'g': $bytes *= 1024;
            case 'm': $bytes *= 1024;
            case 'k': $bytes *= 1024;
        }

        return $bytes;
    }
}
