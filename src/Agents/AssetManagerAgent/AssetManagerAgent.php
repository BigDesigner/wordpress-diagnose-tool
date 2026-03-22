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

    private function getPluginsStatus(): array
    {
        $activePlugins = $this->getOption('active_plugins', []);
        if (!is_array($activePlugins)) {
            $activePlugins = [];
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
                            $relPath = $fileinfo->getFilename() . '/' . $subfile->getFilename();
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
                    $relPath = $fileinfo->getFilename();
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
        $currentTheme = (string) $this->getOption('stylesheet', '');

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
                    'active' => ($currentTheme === $slug),
                ];
            }
        }
        return $themes;
    }

    private function togglePlugin(string $pluginRelPath): bool
    {
        $activePlugins = $this->getOption('active_plugins', []);
        if (!is_array($activePlugins)) $activePlugins = [];

        $index = array_search($pluginRelPath, $activePlugins, true);
        if ($index !== false) {
            unset($activePlugins[$index]);
            $activePlugins = array_values($activePlugins);
        } else {
            $activePlugins[] = $pluginRelPath;
        }

        return $this->updateOption('active_plugins', $activePlugins);
    }

    private function activateTheme(string $themeSlug): bool
    {
        $themeDir = ABSPATH . 'wp-content/themes/' . $themeSlug;
        if (!is_dir($themeDir)) return false;

        $styleCss = $themeDir . '/style.css';
        if (is_file($styleCss)) {
            $content = file_get_contents($styleCss, false, null, 0, 8192);
            $template = preg_match('/^[ \t\/*#]*Template:(.*)$/mi', $content, $match) ? trim($match[1]) : $themeSlug;
            
            $this->updateOption('template', $template);
            $this->updateOption('stylesheet', $themeSlug);
            $this->updateOption('current_theme', $themeSlug);
            return true;
        }
        return false;
    }

    private function getOption(string $name, $default = null)
    {
        global $DB;
        if ($DB) {
            $val = $DB->get_option($name);
            if ($val !== null) {
                $unserialized = @unserialize($val);
                return $unserialized !== false ? $unserialized : $val;
            }
        }
        return $default;
    }

    private function updateOption(string $name, $value): bool
    {
        global $DB;
        if ($DB) {
            $serialized = is_array($value) || is_object($value) ? serialize($value) : $value;
            $DB->update_option($name, $serialized);
            return true;
        }
        return false;
    }
}
