<?php
declare(strict_types=1);

namespace WPDiagnose\Agents\IntegrityRepairAgent;

use WPDiagnose\Core\DiagnosticInterface;

/**
 * Class IntegrityRepairAgent
 * 
 * Rebuilds corrupted core entrypoints (.htaccess, index.php) using standard templates.
 */
class IntegrityRepairAgent implements DiagnosticInterface
{
    private array $results = [];
    private ?array $lastActionResult = null;

    public function getName(): string
    {
        return 'IntegrityRepairAgent';
    }

    public function check(): array
    {
        $this->results = [];
        $baseDir = defined('ABSPATH') ? ABSPATH : dirname(__DIR__, 4) . '/';

        // 1. Audit .htaccess
        $htaccessPath = $baseDir . '.htaccess';
        $hasBackup = false;
        $backupName = '';
        foreach (['.htaccess_old', '.htaccess.bak', '.htaccess.disabled', '.htaccess-disabled'] as $backupFile) {
            if (is_file($baseDir . $backupFile)) {
                $hasBackup = true;
                $backupName = $backupFile;
                break;
            }
        }

        if (is_file($htaccessPath)) {
            $content = (string)@file_get_contents($htaccessPath);
            $isStandard = str_contains($content, 'RewriteRule . /index.php [L]') || str_contains($content, 'RewriteRule ^index\.php$ - [L]');
            $isSuspicious = preg_match('/(eval|base64_decode|gzinflate|auto_prepend_file|auto_append_file)/i', $content);
            $hasPhpHandler = str_contains($content, 'PHP Handler') || preg_match('/SetHandler/i', $content);
            
            if ($isSuspicious) {
                $status = 'ERROR';
                $info = 'Suspicious PHP direct execution patterns detected in .htaccess.';
            } elseif ($hasPhpHandler) {
                $status = 'WARN';
                $info = 'PHP Version Handler block detected in .htaccess. If the site returned a 500 error after changing the PHP version, this handler might be invalid or unsupported by your host.';
            } else {
                $status = $isStandard ? 'OK' : 'WARN';
                $info = $isStandard ? '.htaccess file conforms to WordPress standards.' : '.htaccess exists but deviates from standard WordPress rewrite rules.';
            }
            
            $this->results['htaccess_integrity'] = [
                'status' => $status,
                'info' => $info
            ];
        } else {
            $this->results['htaccess_integrity'] = [
                'status' => 'WARN',
                'info' => $hasBackup 
                    ? "Active .htaccess is missing, but a backup was detected: '{$backupName}'. You can restore it (which will also automatically strip any problematic PHP handlers)."
                    : '.htaccess file is missing.'
            ];
        }

        // 2. Audit index.php
        $indexPath = $baseDir . 'index.php';
        if (is_file($indexPath)) {
            $content = (string)file_get_contents($indexPath);
            $isStandard = str_contains($content, "require __DIR__ . '/wp-blog-header.php';") || str_contains($content, "require( './wp-blog-header.php' );");
            $isSuspicious = preg_match('/(eval\b|base64_decode\b|gzuncompress\b|\$_POST|\$_GET)/i', $content) && !str_contains($content, 'wp-diagnose');
            
            $this->results['index_php_integrity'] = [
                'status' => ($isSuspicious ? 'ERROR' : ($isStandard ? 'OK' : 'WARN')),
                'info' => $isSuspicious 
                    ? 'Suspicious code signatures detected in index.php (potential compromise).' 
                    : ($isStandard ? 'index.php conforms to WordPress standards.' : 'index.php exists but does not contain standard WordPress bootstrap hooks.')
            ];
        } else {
            $this->results['index_php_integrity'] = [
                'status' => 'ERROR',
                'info' => 'index.php is missing. Sites cannot bootstrap without it.'
            ];
        }

        // 3. Configuration Files & PHP Version Switching
        $phpIniPath = $baseDir . 'php.ini';
        $userIniPath = $baseDir . '.user.ini';

        $this->results['config_files'] = [
            'status' => 'OK',
            'info' => 'Configuration files and PHP settings.',
            'data' => [
                'htaccess' => [
                    'path' => $this->relativePath($htaccessPath),
                    'exists' => is_file($htaccessPath),
                    'content' => is_file($htaccessPath) ? (string)@file_get_contents($htaccessPath) : '',
                ],
                'php_ini' => [
                    'path' => $this->relativePath($phpIniPath),
                    'exists' => is_file($phpIniPath),
                    'content' => is_file($phpIniPath) ? (string)@file_get_contents($phpIniPath) : '',
                ],
                'user_ini' => [
                    'path' => $this->relativePath($userIniPath),
                    'exists' => is_file($userIniPath),
                    'content' => is_file($userIniPath) ? (string)@file_get_contents($userIniPath) : '',
                ]
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

        if ($id === 'repair_htaccess') {
            return $this->repairHtaccess();
        }

        if ($id === 'remove_php_handler') {
            return $this->removePhpHandler();
        }

        if ($id === 'repair_index_php') {
            return $this->repairIndexPhp();
        }

        if (str_starts_with($id, 'save_file:')) {
            $filename = substr($id, 10);
            $content = $_POST['content'] ?? '';
            return $this->saveFile($filename, $content);
        }

        if (str_starts_with($id, 'read_arbitrary_file:')) {
            $pathEncoded = substr($id, 20);
            $relPath = base64_decode($pathEncoded);
            return $this->readArbitraryFile($relPath);
        }

        if (str_starts_with($id, 'save_arbitrary_file:')) {
            $pathEncoded = substr($id, 20);
            $relPath = base64_decode($pathEncoded);
            $content = $_POST['content'] ?? '';
            return $this->saveArbitraryFile($relPath, $content);
        }

        return false;
    }

    public function getLastActionResult(): ?array
    {
        return $this->lastActionResult;
    }

    private function repairHtaccess(): bool
    {
        $baseDir = defined('ABSPATH') ? ABSPATH : dirname(__DIR__, 4) . '/';
        $htaccessPath = $baseDir . '.htaccess';

        $standardHtaccess = "# BEGIN WordPress\n" .
                            "<IfModule mod_rewrite.c>\n" .
                            "RewriteEngine On\n" .
                            "RewriteBase /\n" .
                            "RewriteRule ^index\\.php$ - [L]\n" .
                            "RewriteCond %{REQUEST_FILENAME} !-f\n" .
                            "RewriteCond %{REQUEST_FILENAME} !-d\n" .
                            "RewriteRule . /index.php [L]\n" .
                            "</IfModule>\n" .
                            "# END WordPress\n";

        if (file_put_contents($htaccessPath, $standardHtaccess) !== false) {
            $this->lastActionResult = ['success' => true, 'message' => '.htaccess has been reset to standard WordPress configuration.'];
            return true;
        }

        $this->lastActionResult = ['success' => false, 'message' => 'Failed to write .htaccess. Check permissions.'];
        return false;
    }

    private function repairIndexPhp(): bool
    {
        $baseDir = defined('ABSPATH') ? ABSPATH : dirname(__DIR__, 4) . '/';
        $indexPath = $baseDir . 'index.php';

        $standardIndex = "<?php\n" .
                         "/**\n" .
                         " * Front to the WordPress application. This file doesn't do anything, but loads\n" .
                         " * wp-blog-header.php which does and tells WordPress to template the theme.\n" .
                         " *\n" .
                         " * @var bool\n" .
                         " */\n" .
                         "define( 'WP_USE_THEMES', true );\n\n" .
                         "/** Loads the WordPress Environment and Template */\n" .
                         "require __DIR__ . '/wp-blog-header.php';\n";

        if (file_put_contents($indexPath, $standardIndex) !== false) {
            $this->lastActionResult = ['success' => true, 'message' => 'index.php has been restored to standard WordPress template.'];
            return true;
        }

        $this->lastActionResult = ['success' => false, 'message' => 'Failed to restore index.php. Check permissions.'];
        return false;
    }

    private function saveFile(string $fileType, string $content): bool
    {
        $baseDir = defined('ABSPATH') ? ABSPATH : dirname(__DIR__, 4) . '/';
        
        if ($fileType === 'htaccess') {
            $filePath = $baseDir . '.htaccess';
        } elseif ($fileType === 'php_ini') {
            $filePath = $baseDir . 'php.ini';
        } elseif ($fileType === 'user_ini') {
            $filePath = $baseDir . '.user.ini';
        } else {
            $this->lastActionResult = ['success' => false, 'message' => 'Invalid file selection.'];
            return false;
        }

        if (file_put_contents($filePath, $content) !== false) {
            $this->lastActionResult = ['success' => true, 'message' => "File '$fileType' saved successfully."];
            return true;
        }

        $this->lastActionResult = ['success' => false, 'message' => "Failed to save file '$fileType'. Check write permissions."];
        return false;
    }

    private function relativePath(string $path): string
    {
        $baseDir = defined('ABSPATH') ? ABSPATH : dirname(__DIR__, 4) . '/';
        return str_replace('\\', '/', ltrim(str_replace($baseDir, '', $path), '/\\'));
    }

    private function validateAndResolvePath(string $relPath): ?string
    {
        $baseDir = defined('ABSPATH') ? ABSPATH : dirname(__DIR__, 4) . '/';
        $realBase = realpath($baseDir);
        if (!$realBase) {
            return null;
        }

        $targetPath = $baseDir . ltrim(str_replace('\\', '/', $relPath), '/');
        $realTarget = realpath($targetPath);
        
        if ($realTarget === false) {
            $parentDir = dirname($targetPath);
            $realParent = realpath($parentDir);
            if ($realParent === false) {
                return null;
            }
            if (strpos($realParent, $realBase) !== 0) {
                return null;
            }
            return $targetPath;
        }

        if (strpos($realTarget, $realBase) !== 0) {
            return null;
        }

        return $realTarget;
    }

    private function readArbitraryFile(string $relPath): bool
    {
        $resolved = $this->validateAndResolvePath($relPath);
        if (!$resolved || !is_file($resolved)) {
            $this->lastActionResult = ['success' => false, 'message' => 'Invalid file path or file not found.'];
            return false;
        }

        $content = @file_get_contents($resolved);
        if ($content === false) {
            $this->lastActionResult = ['success' => false, 'message' => 'Failed to read file. Check permissions.'];
            return false;
        }

        $this->lastActionResult = [
            'success' => true,
            'message' => 'File loaded successfully.',
            'data' => [
                'path' => $relPath,
                'content' => $content
            ]
        ];
        return true;
    }

    private function saveArbitraryFile(string $relPath, string $content): bool
    {
        $resolved = $this->validateAndResolvePath($relPath);
        if (!$resolved) {
            $this->lastActionResult = ['success' => false, 'message' => 'Access denied: Path is outside WordPress directory tree.'];
            return false;
        }

        if (@file_put_contents($resolved, $content) !== false) {
            $this->lastActionResult = ['success' => true, 'message' => "File '$relPath' saved successfully."];
            return true;
        }

        $this->lastActionResult = ['success' => false, 'message' => "Failed to save file. Check write permissions."];
        return false;
    }

    private function removePhpHandler(): bool
    {
        $baseDir = defined('ABSPATH') ? ABSPATH : dirname(__DIR__, 4) . '/';
        $htaccessPath = $baseDir . '.htaccess';
        
        // If .htaccess is missing, check if a backup exists and restore it first
        if (!is_file($htaccessPath)) {
            foreach (['.htaccess_old', '.htaccess.bak', '.htaccess.disabled', '.htaccess-disabled'] as $backupFile) {
                if (is_file($baseDir . $backupFile)) {
                    if (@copy($baseDir . $backupFile, $htaccessPath)) {
                        break;
                    }
                }
            }
        }
        
        if (is_file($htaccessPath)) {
            $content = (string)@file_get_contents($htaccessPath);
            $cleanContent = preg_replace('/# BEGIN PHP Handler.*?# END PHP Handler/s', '', $content);
            $cleanContent = preg_replace('/<FilesMatch.*?>\s*SetHandler.*?\s*<\/FilesMatch>/si', '', $cleanContent);
            
            if (@file_put_contents($htaccessPath, trim($cleanContent) . "\n") !== false) {
                $this->lastActionResult = ['success' => true, 'message' => 'PHP handler directives have been successfully removed from .htaccess.'];
                return true;
            }
        }
        
        $this->lastActionResult = ['success' => false, 'message' => 'Could not locate or modify .htaccess to strip PHP handlers.'];
        return false;
    }
}
