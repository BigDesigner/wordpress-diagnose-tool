<?php
declare(strict_types=1);

namespace WPDiagnose\Agents\SecurityInspector;

use WPDiagnose\Core\DiagnosticInterface;

/**
 * Class SecurityInspector
 * 
 * Conducts security audits including file permissions, secret keys verification, and administrative user check.
 */
class SecurityInspector implements DiagnosticInterface
{
    /** @var array<string, mixed> Audit results */
    private array $results = [];

    /** @var string Absolute path to the WordPress root directory */
    private string $absPath = '';

    /**
     * SecurityInspector constructor.
     * 
     * @param string $absPath The absolute path to target for directory and file permission checks.
     */
    public function __construct(string $absPath = '')
    {
        $this->absPath = $absPath ?: (defined('ABSPATH') ? ABSPATH : '');
    }

    /**
     * @inheritDoc
     */
    public function getName(): string
    {
        return 'SecurityInspector';
    }

    /**
     * @inheritDoc
     */
    public function check(): array
    {
        $this->results = [];
        
        // Permissions
        $perms = $this->auditPermissions();
        $this->results['wp_config_perms'] = [
            'status' => $perms['wp_config']['status'],
            'info' => "Perms: " . $perms['wp_config']['actual'],
        ];
        $this->results['root_dir_perms'] = [
            'status' => $perms['root_directory']['status'],
            'info' => "Perms: " . $perms['root_directory']['actual'],
        ];

        // Salts
        $salts = $this->auditSalts();
        $this->results['security_keys'] = [
            'status' => $salts['status'],
            'info' => $salts['status'] === 'OK' ? 'All secure keys defined' : 'Keys missing: ' . implode(',', $salts['missing_keys']),
        ];

        // Exposed Files
        $exposed = $this->auditExposedFiles();
        $this->results['exposed_files'] = [
            'status' => $exposed['status'],
            'info' => $exposed['status'] === 'OK'
                ? 'No common exposed files'
                : ($exposed['status'] === 'ERROR'
                    ? 'Root path unavailable for exposed file audit.'
                    : 'Files found: ' . implode(',', $exposed['detected'])),
        ];

        return $this->results;
    }

    /**
     * @inheritDoc
     */
    public function fix(string $id): bool
    {
        // Fixing logic for security (like chmod files or cleaning exposed files) will be implemented here.
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
     * Audits file and directory permissions for common security risks.
     * 
     * @return array<string, mixed>
     */
    private function auditPermissions(): array
    {
        if (!$this->absPath || !is_dir($this->absPath)) {
            return [
                'wp_config' => ['actual' => 'N/A', 'status' => 'ERROR'],
                'root_directory' => ['actual' => 'N/A', 'status' => 'ERROR'],
            ];
        }

        $configPath = $this->absPath . 'wp-config.php';
        $configPermsStatus = 'OK';
        $configPerms = 'N/A';

        if (is_file($configPath)) {
            $configPerms = substr(sprintf('%o', fileperms($configPath)), -4);
            $configPermsStatus = ($configPerms === '0644' || $configPerms === '0600') ? 'OK' : 'WARN';
        }

        $dirPerms = substr(sprintf('%o', fileperms($this->absPath)), -4);
        $dirPermsStatus = (in_array($dirPerms, ['0755', '0750', '0700'])) ? 'OK' : 'WARN';

        return [
            'wp_config' => ['actual' => $configPerms, 'status' => $configPermsStatus],
            'root_directory' => ['actual' => $dirPerms, 'status' => $dirPermsStatus],
        ];
    }

    /**
     * Audits security keys (salts) in wp-config.php.
     * 
     * @return array<string, mixed>
     */
    private function auditSalts(): array
    {
        $salts = ['AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY', 'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT'];
        $missing = [];
        $configContent = $this->readConfigFile();

        foreach ($salts as $salt) {
            $hasDefinedConstant = defined($salt);
            $hasConfigEntry = $configContent !== null
                && preg_match("/define\s*\(\s*['\"]" . preg_quote($salt, '/') . "['\"]\s*,/i", $configContent) === 1;

            if (!$hasDefinedConstant && !$hasConfigEntry) {
                $missing[] = $salt;
            }
        }

        return [
            'missing_keys' => $missing,
            'status' => empty($missing) ? 'OK' : 'WARN',
        ];
    }

    /**
     * Checks for the presence of files that should be deleted for security (e.g., readme.html).
     * 
     * @return array<string, mixed>
     */
    private function auditExposedFiles(): array
    {
        if (!$this->absPath || !is_dir($this->absPath)) {
            return [
                'detected' => [],
                'status' => 'ERROR',
            ];
        }

        $targets = ['readme.html', 'license.txt', 'wp-config-sample.php'];
        $present = [];

        foreach ($targets as $file) {
            if (is_file($this->absPath . $file)) {
                $present[] = $file;
            }
        }

        return [
            'detected' => $present,
            'status' => empty($present) ? 'OK' : 'WARN',
        ];
    }

    private function readConfigFile(): ?string
    {
        if (!$this->absPath || !is_dir($this->absPath)) {
            return null;
        }

        $candidates = [
            $this->absPath . 'wp-config.php',
            dirname(rtrim($this->absPath, '/\\')) . '/wp-config.php',
        ];

        foreach ($candidates as $candidate) {
            if (is_file($candidate)) {
                $content = @file_get_contents($candidate);
                return $content === false ? null : $content;
            }
        }

        return null;
    }
}
