<?php
declare(strict_types=1);

namespace WPDiagnose\Agents\BootstrapInspector;

use WPDiagnose\Core\DiagnosticInterface;

/**
 * Class BootstrapInspector
 * 
 * Specifically designed for emergency recovery when WordPress bootstrap (wp-load.php) fails.
 * Attempts to parse wp-config.php without execution to diagnose database issues.
 */
class BootstrapInspector implements DiagnosticInterface
{
    /** @var array<string, mixed> Audit results */
    private array $results = [];

    /** @var string|null Path to detected wp-config.php */
    private ?string $configPath = null;

    /** @var array<string, string> Extracted database credentials */
    private array $dbCreds = [];

    /**
     * @inheritDoc
     */
    public function getName(): string
    {
        return 'BootstrapInspector';
    }

    /**
     * @inheritDoc
     */
    public function check(): array
    {
        if (defined('ABSPATH')) {
            $this->results['core_boot'] = ['status' => 'OK', 'info' => 'WordPress core already loaded via standard ABSPATH.'];
            return $this->results;
        }

        $this->locateConfig();

        if ($this->configPath) {
            $this->extractDbConfig();
            $connectionStatus = $this->manualDbCheck();
            
            $this->results['config_file'] = [
                'status' => 'OK',
                'info' => 'Found: ' . $this->configPath,
            ];

            $this->results['db_connection'] = [
                'status' => $connectionStatus['success'] ? 'OK' : 'ERROR',
                'info' => $connectionStatus['success'] ? 'Manual connection to DB successful.' : 'Connection Error: ' . ($connectionStatus['error'] ?? 'Unknown'),
            ];
        } else {
            $this->results['config_file'] = [
                'status' => 'WARN',
                'info' => 'wp-config.php not found in standard root or parent directories.',
            ];
        }

        return $this->results;
    }

    /**
     * Attempts to find the wp-config.php file in standard locations.
     */
    private function locateConfig(): void
    {
        $locations = ['./wp-config.php', '../wp-config.php', './../wp-config.php'];
        foreach ($locations as $loc) {
            if (is_file($loc)) {
                $this->configPath = realpath($loc);
                return;
            }
        }
    }

    /**
     * Regex fallback to pull DB constants without including the file.
     * This avoids fatal errors if wp-config.php is corrupted or has syntax errors.
     */
    private function extractDbConfig(): void
    {
        $content = file_get_contents($this->configPath);
        
        // Match constants define('DB_NAME', 'value');
        $pattern = "/define\s*\(\s*['\"](.+?)['\"]\s*,\s*['\"](.*?)['\"]\s*\)\s*;/";
        if (preg_match_all($pattern, $content, $matches)) {
            $constants = array_combine($matches[1], $matches[2]);
            $this->dbCreds = [
                'host' => $constants['DB_HOST'] ?? 'localhost',
                'user' => $constants['DB_USER'] ?? '',
                'pass' => $constants['DB_PASSWORD'] ?? '',
                'name' => $constants['DB_NAME'] ?? '',
            ];
        }
    }

    /**
     * Performs a direct MySQLi connection check using extracted credentials.
     * 
     * @return array<string, mixed>
     */
    private function manualDbCheck(): array
    {
        if (empty($this->dbCreds['name'])) {
            return ['success' => false, 'error' => 'Could not extract DB_NAME from config file.'];
        }

        $mysqli = @new \mysqli(
            $this->dbCreds['host'],
            $this->dbCreds['user'],
            $this->dbCreds['pass'],
            $this->dbCreds['name']
        );

        if ($mysqli->connect_errno) {
            return [
                'success' => false,
                'error' => $mysqli->connect_error,
                'error_code' => $mysqli->connect_errno
            ];
        }

        $version = $mysqli->server_info;
        $mysqli->close();

        return [
            'success' => true,
            'info' => 'Manual database connection verified.',
            'db_version' => $version
        ];
    }

    /**
     * @inheritDoc
     */
    public function fix(string $id): bool
    {
        // Bootstrap-level fixes usually require manual path corrections or credentials update.
        return false;
    }

    /**
     * @inheritDoc
     */
    public function report(): array
    {
        return $this->results ?: $this->check();
    }
}
