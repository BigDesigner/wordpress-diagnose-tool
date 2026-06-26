<?php
declare(strict_types=1);

namespace WPDiagnose\Agents\IntegrityRepairAgent {

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
            if (is_file($htaccessPath)) {
                $content = (string)file_get_contents($htaccessPath);
                $isStandard = str_contains($content, 'RewriteRule . /index.php [L]') || str_contains($content, 'RewriteRule ^index\.php$ - [L]');
                $isSuspicious = preg_match('/(eval|base64_decode|gzinflate|auto_prepend_file|auto_append_file)/i', $content);
                
                $this->results['htaccess_integrity'] = [
                    'status' => ($isSuspicious ? 'ERROR' : ($isStandard ? 'OK' : 'WARN')),
                    'info' => $isSuspicious 
                        ? 'Suspicious PHP direct execution patterns detected in .htaccess.' 
                        : ($isStandard ? '.htaccess file conforms to WordPress standards.' : '.htaccess exists but deviates from standard WordPress rewrite rules.')
                ];
            } else {
                $this->results['htaccess_integrity'] = [
                    'status' => 'WARN',
                    'info' => '.htaccess file is missing.'
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

            if ($id === 'repair_index_php') {
                return $this->repairIndexPhp();
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
    }
}
