<?php
declare(strict_types=1);

namespace WPDiagnose\Agents\AssetManagerAgent;

use WPDiagnose\Core\DiagnosticInterface;

/**
 * Class AssetManagerAgent (The Commander)
 * 
 * Manages Plugins and Themes. Operations work even in Independent Mode (no WP Core).
 */
class AssetManagerAgent implements DiagnosticInterface
{
    private array $results = [];
    private bool $isWpLoaded;
    private array $lastActionResult = ['success' => true, 'message' => '', 'data' => null];

    public function __construct(bool $isWpLoaded = false)
    {
        $this->isWpLoaded = $isWpLoaded;
    }

    public function getName(): string
    {
        return 'AssetManagerAgent';
    }

    public function check(): array
    {
        $this->results = [];
        
        $plugins = $this->getPluginsStatus();
        if (!empty($plugins)) {
            $this->results['manage_plugins'] = [
                'status' => 'OK',
                'info'   => count($plugins) . " total plugins detected.",
                'data'   => $plugins,
            ];
        } else {
            $this->results['manage_plugins'] = [
                'status' => 'WARN',
                'info'   => 'Cannot retrieve plugins. Check connection or file permissions.',
            ];
        }

        $themes = $this->getThemesStatus();
        if (!empty($themes)) {
            $this->results['manage_themes'] = [
                'status' => 'OK',
                'info'   => count($themes) . " themes available.",
                'data'   => $themes,
            ];
        }

        return $this->results;
    }

    public function fix(string $id): bool
    {
        $this->lastActionResult = ['success' => false, 'message' => 'Unknown asset action.', 'data' => null];

        if (strpos($id, 'toggle_plugin:') === 0) {
            $pluginFile = substr($id, 14);
            return $this->togglePlugin($pluginFile);
        }

        if (strpos($id, 'theme_activate:') === 0) {
            $themeSlug = substr($id, 15);
            return $this->activateTheme($themeSlug);
        }

        if (strpos($id, 'update_plugin:') === 0) {
            $pluginFile = substr($id, 14);
            return $this->updatePlugin($pluginFile);
        }

        return false;
    }

    public function report(): array
    {
        return $this->results ?: $this->check();
    }

    public function getLastActionResult(): array
    {
        return $this->lastActionResult;
    }

    private function getPluginsStatus(): array
    {
        $activePlugins = $this->normalizePluginList($this->getOption('active_plugins', []));

        // Get WordPress update plugins transient if available to check for updates
        $updateList = [];
        $updateState = $this->getOption('_site_transient_update_plugins');
        if ($updateState) {
            $response = is_object($updateState) ? ($updateState->response ?? []) : ($updateState['response'] ?? []);
            foreach ($response as $file => $data) {
                $newVer = is_object($data) ? ($data->new_version ?? '') : ($data['new_version'] ?? '');
                if ($newVer) {
                    $updateList[$this->normalizePluginPath($file)] = $newVer;
                }
            }
        }

        $plugins = [];
        // Scan wp-content/plugins directly to support independent mode
        $pluginDir = ABSPATH . 'wp-content/plugins/';
        if (!is_dir($pluginDir)) return [];

        $iterator = new \DirectoryIterator($pluginDir);
        foreach ($iterator as $fileinfo) {
            if ($fileinfo->isDot()) continue;
            
            if ($fileinfo->isDir()) {
                $subIterator = new \DirectoryIterator($fileinfo->getPathname());
                foreach ($subIterator as $subfile) {
                    if ($subfile->isFile() && $subfile->getExtension() === 'php') {
                        $content = file_get_contents($subfile->getPathname(), false, null, 0, 8192);
                        if (preg_match('/^[ \t\/*#@]*Plugin Name:(.*)$/mi', $content, $match)) {
                            $pluginName = trim($match[1]);
                            $pluginVersion = '0.0.0';
                            if (preg_match('/^[ \t\/*#@]*Version:(.*)$/mi', $content, $vMatch)) {
                                $pluginVersion = trim($vMatch[1]);
                            }
                            $relPath = $this->normalizePluginPath($fileinfo->getFilename() . '/' . $subfile->getFilename());
                            $plugins[$relPath] = [
                                'name'   => $pluginName,
                                'active' => in_array($relPath, $activePlugins, true),
                                'version' => $pluginVersion,
                                'update_version' => (isset($updateList[$relPath]) && version_compare($pluginVersion, $updateList[$relPath], '<')) ? $updateList[$relPath] : null,
                            ];
                        }
                    }
                }
            } elseif ($fileinfo->isFile() && $fileinfo->getExtension() === 'php') {
                $content = file_get_contents($fileinfo->getPathname(), false, null, 0, 8192);
                if (preg_match('/^[ \t\/*#@]*Plugin Name:(.*)$/mi', $content, $match)) {
                    $pluginName = trim($match[1]);
                    $pluginVersion = '0.0.0';
                    if (preg_match('/^[ \t\/*#@]*Version:(.*)$/mi', $content, $vMatch)) {
                        $pluginVersion = trim($vMatch[1]);
                    }
                    $relPath = $this->normalizePluginPath($fileinfo->getFilename());
                    $plugins[$relPath] = [
                        'name'   => $pluginName,
                        'active' => in_array($relPath, $activePlugins, true),
                        'version' => $pluginVersion,
                        'update_version' => $updateList[$relPath] ?? null,
                    ];
                }
            }
        }
        return $plugins;
    }

    private function getThemesStatus(): array
    {
        $currentStylesheet = $this->normalizeThemeSlug((string) $this->getOption('stylesheet', ''));
        $currentTemplate = $this->normalizeThemeSlug((string) $this->getOption('template', ''));

        // Get WordPress update themes transient if available
        $updateList = [];
        $updateState = $this->getOption('_site_transient_update_themes');
        if ($updateState) {
            $response = is_object($updateState) ? ($updateState->response ?? []) : ($updateState['response'] ?? []);
            foreach ($response as $slug => $data) {
                $newVer = is_object($data) ? ($data->new_version ?? '') : ($data['new_version'] ?? '');
                if ($newVer) {
                    $updateList[$this->normalizeThemeSlug($slug)] = $newVer;
                }
            }
        }

        $themes = [];
        $themeDir = ABSPATH . 'wp-content/themes/';
        if (!is_dir($themeDir)) return [];

        $iterator = new \DirectoryIterator($themeDir);
        foreach ($iterator as $fileinfo) {
            if ($fileinfo->isDot() || !$fileinfo->isDir()) continue;
            
            $slug = $fileinfo->getFilename();
            $styleCss = $fileinfo->getPathname() . '/style.css';
            if (is_file($styleCss)) {
                $content = file_get_contents($styleCss, false, null, 0, 8192);
                $themeName = preg_match('/^[ \t\/*#]*Theme Name:(.*)$/mi', $content, $match) ? trim($match[1]) : $slug;
                $themeVersion = '0.0.0';
                if (preg_match('/^[ \t\/*#]*Version:(.*)$/mi', $content, $vMatch)) {
                    $themeVersion = trim($vMatch[1]);
                }
                $themes[$slug] = [
                    'name'   => $themeName,
                    'active' => ($currentStylesheet === $slug || ($currentStylesheet === '' && $currentTemplate === $slug)),
                    'version' => $themeVersion,
                    'update_version' => (isset($updateList[$slug]) && version_compare($themeVersion, $updateList[$slug], '<')) ? $updateList[$slug] : null,
                ];
            }
        }
        return $themes;
    }

    private function togglePlugin(string $pluginRelPath): bool
    {
        $pluginRelPath = $this->normalizePluginPath($pluginRelPath);
        $activePlugins = $this->normalizePluginList($this->getOption('active_plugins', []));

        $index = array_search($pluginRelPath, $activePlugins, true);
        if ($index !== false) {
            unset($activePlugins[$index]);
            $activePlugins = array_values($activePlugins);
            $result = $this->updateOption('active_plugins', $activePlugins);
            $this->lastActionResult = [
                'success' => $result,
                'message' => $result ? "Plugin deactivated: {$pluginRelPath}" : "Failed to deactivate plugin: {$pluginRelPath}",
                'data' => ['plugin' => $pluginRelPath, 'active' => false],
            ];
            return $result;
        } else {
            $activePlugins[] = $pluginRelPath;
            $activePlugins = array_values(array_unique($activePlugins));
            $result = $this->updateOption('active_plugins', $activePlugins);
            $this->lastActionResult = [
                'success' => $result,
                'message' => $result ? "Plugin activated: {$pluginRelPath}" : "Failed to activate plugin: {$pluginRelPath}",
                'data' => ['plugin' => $pluginRelPath, 'active' => true],
            ];
            return $result;
        }
    }

    private function activateTheme(string $themeSlug): bool
    {
        $themeSlug = $this->normalizeThemeSlug($themeSlug);
        $themeDir = ABSPATH . 'wp-content/themes/' . $themeSlug;
        if (!is_dir($themeDir)) {
            $this->lastActionResult = [
                'success' => false,
                'message' => "Theme directory not found: {$themeSlug}",
                'data' => ['theme' => $themeSlug],
            ];
            return false;
        }

        $styleCss = $themeDir . '/style.css';
        if (is_file($styleCss)) {
            $content = file_get_contents($styleCss, false, null, 0, 8192);
            $template = preg_match('/^[ \t\/*#]*Template:(.*)$/mi', $content, $match) ? trim($match[1]) : $themeSlug;
            $themeName = preg_match('/^[ \t\/*#]*Theme Name:(.*)$/mi', $content, $nameMatch) ? trim($nameMatch[1]) : $themeSlug;

            $updated = $this->updateOption('template', $template)
                && $this->updateOption('stylesheet', $themeSlug)
                && $this->updateOption('current_theme', $themeName);

            $this->lastActionResult = [
                'success' => $updated,
                'message' => $updated ? "Theme activated: {$themeName}" : "Failed to activate theme: {$themeName}",
                'data' => ['theme' => $themeSlug, 'template' => $template],
            ];
            return $updated;
        }

        $this->lastActionResult = [
            'success' => false,
            'message' => "Theme stylesheet missing: {$themeSlug}",
            'data' => ['theme' => $themeSlug],
        ];
        return false;
    }

    private function getOption(string $name, $default = null)
    {
        if ($this->isWpLoaded && function_exists('get_option')) {
            return get_option($name, $default);
        }

        global $DB;
        if ($DB) {
            $val = $DB->get_option($name);
            if ($val !== null) {
                return $this->maybeUnserialize($val);
            }
        }
        return $default;
    }

    private function updateOption(string $name, $value): bool
    {
        if ($this->isWpLoaded && function_exists('update_option')) {
            return update_option($name, $value);
        }

        global $DB;
        if ($DB) {
            $serialized = $this->maybeSerialize($value);
            return $DB->update_option($name, $serialized);
        }
        return false;
    }

    /**
     * @param mixed $value
     * @return array<int, string>
     */
    private function normalizePluginList($value): array
    {
        if (!is_array($value)) {
            return [];
        }

        $normalized = [];
        foreach ($value as $pluginPath) {
            if (is_string($pluginPath) && $pluginPath !== '') {
                $normalized[] = $this->normalizePluginPath($pluginPath);
            }
        }

        return array_values(array_unique($normalized));
    }

    private function normalizePluginPath(string $path): string
    {
        return trim(str_replace('\\', '/', $path), '/');
    }

    private function normalizeThemeSlug(string $slug): string
    {
        return trim(str_replace('\\', '/', $slug), '/');
    }

    /**
     * @param mixed $value
     * @return mixed
     */
    private function maybeUnserialize($value)
    {
        if (!is_string($value) || !$this->isSerialized($value)) {
            return $value;
        }

        $result = @unserialize($value);
        return $result === false && $value !== 'b:0;' ? $value : $result;
    }

    /**
     * @param mixed $value
     * @return mixed
     */
    private function maybeSerialize($value)
    {
        return is_array($value) || is_object($value) ? serialize($value) : $value;
    }

    private function isSerialized(string $value): bool
    {
        $value = trim($value);
        if ($value === 'N;') {
            return true;
        }

        return preg_match('/^(?:a|O|s|b|i|d):/', $value) === 1;
    }

    private function updatePlugin(string $pluginRelPath): bool
    {
        $pluginRelPath = $this->normalizePluginPath($pluginRelPath);
        $slug = $pluginRelPath;
        if (strpos($pluginRelPath, '/') !== false) {
            $slug = explode('/', $pluginRelPath)[0];
        } else {
            $slug = pathinfo($pluginRelPath, PATHINFO_FILENAME);
        }

        $url = "https://downloads.wordpress.org/plugin/" . $slug . ".zip";
        
        $zipData = null;
        if (function_exists('curl_init')) {
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_TIMEOUT, 60);
            $zipData = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            
            if ($httpCode !== 200) {
                $zipData = null;
            }
        }
        
        if (!$zipData) {
            $zipData = @file_get_contents($url);
        }

        if (!$zipData) {
            $this->lastActionResult = [
                'success' => false,
                'message' => "Could not download update zip for plugin '{$slug}' from WordPress.org. Verify the plugin name or connection.",
                'data' => null
            ];
            return false;
        }

        $backupDir = ABSPATH . 'wp-content/uploads/wp-diagnose-backups';
        if (!is_dir($backupDir)) {
            @mkdir($backupDir, 0755, true);
        }
        $tempZip = $backupDir . '/temp-update-' . time() . '.zip';
        if (@file_put_contents($tempZip, $zipData) === false) {
            $this->lastActionResult = [
                'success' => false,
                'message' => "Could not write temporary zip file. Check folder permissions in wp-content/uploads/.",
                'data' => null
            ];
            return false;
        }

        if (!class_exists('ZipArchive')) {
            @unlink($tempZip);
            $this->lastActionResult = [
                'success' => false,
                'message' => "ZipArchive class not loaded. Cannot extract plugin update.",
                'data' => null
            ];
            return false;
        }

        $zip = new \ZipArchive();
        if ($zip->open($tempZip) === true) {
            $extractPath = ABSPATH . 'wp-content/plugins/';
            $extractSuccess = @$zip->extractTo($extractPath);
            $zip->close();
            @unlink($tempZip);

            if ($extractSuccess) {
                $this->lastActionResult = [
                    'success' => true,
                    'message' => "Plugin '{$slug}' was updated successfully to the latest version from WordPress.org.",
                    'data' => ['plugin' => $pluginRelPath]
                ];
                return true;
            }
        }

        @unlink($tempZip);
        $this->lastActionResult = [
            'success' => false,
            'message' => "Failed to extract update zip for '{$slug}'. Check directory permissions.",
            'data' => null
        ];
        return false;
    }
}
