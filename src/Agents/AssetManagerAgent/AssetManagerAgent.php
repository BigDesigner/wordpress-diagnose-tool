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

        // $id could be "toggle_plugin:akismet/akismet.php"
        // or "toggle_theme:twentytwentyfour" etc.
        if (strpos($id, 'toggle_plugin:') === 0) {
            $pluginFile = substr($id, 14);
            return $this->togglePlugin($pluginFile);
        }

        if (strpos($id, 'theme_activate:') === 0) {
            $themeSlug = substr($id, 15);
            return $this->activateTheme($themeSlug);
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
                            $relPath = $this->normalizePluginPath($fileinfo->getFilename() . '/' . $subfile->getFilename());
                            $plugins[$relPath] = [
                                'name'   => $pluginName,
                                'active' => in_array($relPath, $activePlugins, true),
                            ];
                        }
                    }
                }
            } elseif ($fileinfo->isFile() && $fileinfo->getExtension() === 'php') {
                $content = file_get_contents($fileinfo->getPathname(), false, null, 0, 8192);
                if (preg_match('/^[ \t\/*#@]*Plugin Name:(.*)$/mi', $content, $match)) {
                    $pluginName = trim($match[1]);
                    $relPath = $this->normalizePluginPath($fileinfo->getFilename());
                    $plugins[$relPath] = [
                        'name'   => $pluginName,
                        'active' => in_array($relPath, $activePlugins, true),
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
                $themes[$slug] = [
                    'name'   => $themeName,
                    'active' => ($currentStylesheet === $slug || ($currentStylesheet === '' && $currentTemplate === $slug)),
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
}
