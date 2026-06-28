<?php
declare(strict_types=1);

namespace WPDiagnose\Agents\PHPInfoAgent;

use WPDiagnose\Core\DiagnosticInterface;

/**
 * Class PHPInfoAgent
 * 
 * Audits server's PHP configuration settings, extension modules, and security parameters.
 */
class PHPInfoAgent implements DiagnosticInterface
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
        return 'PHPInfoAgent';
    }

    public function check(): array
    {
        $this->results = [];

        // 1. Core Config
        $this->results['core_config'] = [
            'status' => 'OK',
            'info' => 'Core PHP configurations retrieved.',
            'data' => [
                'PHP Version' => PHP_VERSION,
                'PHP SAPI' => php_sapi_name(),
                'Memory Limit' => ini_get('memory_limit') ?: 'n/a',
                'Max Execution Time' => ini_get('max_execution_time') !== false ? ini_get('max_execution_time') . 's' : 'n/a',
                'Upload Max Filesize' => ini_get('upload_max_filesize') ?: 'n/a',
                'Post Max Size' => ini_get('post_max_size') ?: 'n/a',
                'Open Basedir' => ini_get('open_basedir') ?: 'None',
                'Disable Functions' => ini_get('disable_functions') ?: 'None',
                'OPcache Enabled' => function_exists('opcache_get_status') && @opcache_get_status(false) ? 'Yes' : 'No',
            ]
        ];

        // 2. Security Hardening Check
        $exposePhp = ini_get('expose_php');
        $sessionCookieHttponly = ini_get('session.cookie_httponly');
        $sessionCookieSecure = ini_get('session.cookie_secure');
        $allowUrlFopen = ini_get('allow_url_fopen');
        
        $securityScore = 'OK';
        $securityWarnings = [];
        if ($exposePhp && strtolower($exposePhp) !== 'off' && $exposePhp !== '0') {
            $securityWarnings[] = 'expose_php is ON (reveals PHP version in headers)';
            $securityScore = 'WARN';
        }
        if (!$sessionCookieHttponly || $sessionCookieHttponly === '0') {
            $securityWarnings[] = 'session.cookie_httponly is OFF (session cookies vulnerable to XSS)';
            $securityScore = 'WARN';
        }
        
        $this->results['security_hardening'] = [
            'status' => $securityScore,
            'info' => $securityScore === 'OK' ? 'PHP security hardening checks passed.' : implode(' | ', $securityWarnings),
            'data' => [
                'Expose PHP' => $exposePhp ? 'Yes' : 'No',
                'Allow URL Fopen' => $allowUrlFopen ? 'Yes' : 'No',
                'Allow URL Include' => ini_get('allow_url_include') ? 'Yes' : 'No',
                'Session Only Cookies' => ini_get('session.use_only_cookies') ? 'Yes' : 'No',
                'Session Cookie HTTPOnly' => $sessionCookieHttponly ? 'Yes' : 'No',
                'Session Cookie Secure' => $sessionCookieSecure ? 'Yes' : 'No',
            ]
        ];

        // 3. Extensions & Loaded Modules
        $criticalExtensions = ['mysqli', 'pdo_mysql', 'curl', 'gd', 'imagick', 'mbstring', 'openssl', 'zip', 'xml', 'json'];
        $extData = [];
        foreach ($criticalExtensions as $ext) {
            $extData[$ext] = extension_loaded($ext) ? 'Loaded' : 'Not Loaded';
        }

        $missing = [];
        foreach ($extData as $ext => $status) {
            if ($status === 'Not Loaded') {
                $missing[] = $ext;
            }
        }

        $this->results['extensions_status'] = [
            'status' => empty($missing) ? 'OK' : 'WARN',
            'info' => empty($missing) ? 'All critical PHP extensions are loaded.' : 'Missing: ' . implode(', ', $missing),
            'data' => $extData
        ];

        return $this->results;
    }

    public function report(): array
    {
        return $this->results ?: $this->check();
    }

    public function fix(string $id): bool
    {
        return false;
    }

    public function getLastActionResult(): ?array
    {
        return null;
    }
}
