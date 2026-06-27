<?php
declare(strict_types=1);

namespace WPDiagnose\Agents\WPInspector;

use WPDiagnose\Core\DiagnosticInterface;

/**
 * Class WPInspector
 * 
 * Audits the WordPress core, installed plugins, and active themes.
 * Supports both Full Loading (active WordPress instance) and DB/FS mode.
 */
class WPInspector implements DiagnosticInterface
{
    /** @var array<string, mixed> Reports and findings from the audit */
    private array $results = [];

    /** @var bool Whether WordPress core functions are accessible */
    private bool $isWpLoaded = false;

    /**
     * WPInspector constructor.
     * 
     * @param bool $isWpLoaded Indicates if the full WordPress environment is bootstrapped.
     */
    public function __construct(bool $isWpLoaded = false)
    {
        $this->isWpLoaded = $isWpLoaded;
    }

    /**
     * @inheritDoc
     */
    public function getName(): string
    {
        return 'WPInspector';
    }

    /**
     * @inheritDoc
     */
    public function check(): array
    {
        $this->results = [];

        // Suppress notices/warnings during WP API calls to prevent JSON contamination.
        $prevReporting = error_reporting(E_ERROR);

        if ($this->isWpLoaded) {
            // WordPress Core Version
            $core = $this->getCoreStatus();
            $this->results['wp_version'] = [
                'status' => $core['status'],
                'info'   => "v" . $core['current'] . ($core['update_available'] ? " (Update to {$core['new_version']} available)" : " (Up to date)"),
            ];

            // Active Plugins Health
            $plugins     = $this->getPluginsStatus();
            $activeCount = count(array_filter($plugins, fn($p) => $p['active']));
            $updateCount = count(array_filter($plugins, fn($p) => $p['update_available']));

            $this->results['active_plugins'] = [
                'status' => $updateCount > 0 ? 'WARN' : 'OK',
                'info'   => "$activeCount Active | $updateCount Updates Pending",
                'data'   => $plugins,
            ];

            // Theme Health
            $themes      = $this->getThemesStatus();
            $activeTheme = array_values(array_filter($themes, fn($t) => $t['is_active']))[0] ?? null;

            $this->results['theme_health'] = [
                'status' => ($activeTheme && $activeTheme['update_available']) ? 'WARN' : 'OK',
                'info'   => ($activeTheme ? "Active: {$activeTheme['name']} v{$activeTheme['version']}" : "No Theme Active"),
                'data'   => $themes,
            ];
        } else {
            global $DB;
            if ($DB) {
                // Get WP version from wp-includes/version.php
                $wpVersion = null;
                $versionFile = ABSPATH . 'wp-includes/version.php';
                if (is_file($versionFile)) {
                    include $versionFile;
                    $wpVersion = $wp_version ?? null;
                }

                // Check updates if we can unserialize transients
                $pluginUpdates = [];
                $themeUpdates = [];
                $coreUpdateAvailable = false;
                $coreNewVersion = null;

                $val = $DB->get_option('_site_transient_update_plugins');
                $updatePlugins = $val ? @unserialize($val) : null;
                if ($updatePlugins && isset($updatePlugins->response) && is_array($updatePlugins->response)) {
                    $pluginUpdates = $updatePlugins->response;
                }

                $val = $DB->get_option('_site_transient_update_themes');
                $updateThemes = $val ? @unserialize($val) : null;
                if ($updateThemes && isset($updateThemes->response) && is_array($updateThemes->response)) {
                    $themeUpdates = $updateThemes->response;
                }

                $val = $DB->get_option('_site_transient_update_core');
                $updateCore = $val ? @unserialize($val) : null;
                if ($updateCore && isset($updateCore->updates) && is_array($updateCore->updates)) {
                    foreach ($updateCore->updates as $up) {
                        if ($up->response === 'upgrade') {
                            $coreUpdateAvailable = true;
                            $coreNewVersion = $up->current;
                            break;
                        }
                    }
                }

                $this->results['wp_version'] = [
                    'status' => $coreUpdateAvailable ? 'WARN' : 'OK',
                    'info'   => 'v' . ($wpVersion ?: 'Unknown') . ($coreUpdateAvailable ? " (Update to {$coreNewVersion} available)" : ' (Up to date)') . ' (Independent DB/FS Mode)',
                ];

                // Get active plugins from option
                $activePlugins = [];
                $serialized = $DB->get_option('active_plugins');
                if ($serialized) {
                    $unserialized = @unserialize($serialized);
                    if (is_array($unserialized)) {
                        $activePlugins = $unserialized;
                    }
                }

                // Scan plugins directory
                $plugins = [];
                $pluginsDir = ABSPATH . 'wp-content/plugins';
                if (is_dir($pluginsDir)) {
                    $items = @scandir($pluginsDir);
                    if ($items) {
                        foreach ($items as $item) {
                            if ($item === '.' || $item === '..') continue;
                            $itemPath = $pluginsDir . '/' . $item;
                            if (is_file($itemPath) && str_ends_with($item, '.php')) {
                                $this->parsePluginFile($itemPath, $item, $activePlugins, $pluginUpdates, $plugins);
                            } elseif (is_dir($itemPath)) {
                                $subFiles = @scandir($itemPath);
                                if ($subFiles) {
                                    foreach ($subFiles as $subFile) {
                                        if (str_ends_with($subFile, '.php')) {
                                            $subPath = $itemPath . '/' . $subFile;
                                            if ($this->parsePluginFile($subPath, $item . '/' . $subFile, $activePlugins, $pluginUpdates, $plugins)) {
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                $activeCount = count(array_filter($plugins, fn($p) => $p['active']));
                $updateCount = count(array_filter($plugins, fn($p) => $p['update_available']));
                $this->results['active_plugins'] = [
                    'status' => $updateCount > 0 ? 'WARN' : 'OK',
                    'info'   => "$activeCount Active | $updateCount Updates Pending (Independent DB/FS Mode)",
                    'data'   => $plugins,
                ];

                // Get active theme from option
                $activeStylesheet = $DB->get_option('stylesheet') ?: 'twentytwentyfour';
                $activeTemplate = $DB->get_option('template') ?: 'twentytwentyfour';

                // Scan themes directory
                $themes = [];
                $themesDir = ABSPATH . 'wp-content/themes';
                if (is_dir($themesDir)) {
                    $items = @scandir($themesDir);
                    if ($items) {
                        foreach ($items as $item) {
                            if ($item === '.' || $item === '..') continue;
                            $styleCss = $themesDir . '/' . $item . '/style.css';
                            if (is_file($styleCss)) {
                                $content = @file_get_contents($styleCss);
                                if ($content) {
                                    $themeName = preg_match('/Theme Name:\s*(.*)/i', $content, $m) ? trim($m[1]) : $item;
                                    $themeVersion = preg_match('/Version:\s*(.*)/i', $content, $m) ? trim($m[1]) : 'Unknown';
                                    $isActive = ($item === $activeStylesheet || $item === $activeTemplate);
                                    $updateAvailable = isset($themeUpdates[$item]);
                                    $newVersion = $updateAvailable ? ($themeUpdates[$item]['new_version'] ?? null) : null;
                                    $themes[$item] = [
                                        'name' => $themeName,
                                        'is_active' => $isActive,
                                        'version' => $themeVersion,
                                        'update_available' => $updateAvailable,
                                        'new_version' => $newVersion
                                    ];
                                }
                            }
                        }
                    }
                }

                $activeTheme = array_values(array_filter($themes, fn($t) => $t['is_active']))[0] ?? null;
                $this->results['theme_health'] = [
                    'status' => ($activeTheme && $activeTheme['update_available']) ? 'WARN' : 'OK',
                    'info'   => ($activeTheme ? "Active: {$activeTheme['name']} v{$activeTheme['version']}" : "No Theme Active") . " (Independent DB/FS Mode)",
                    'data'   => $themes,
                ];
            } else {
                global $WP_LOAD_ERROR;
                $this->results['wp_env'] = [
                    'status' => 'WARN',
                    'info'   => 'WordPress not loaded. Running in Independent Diagnostic Mode.' . ($WP_LOAD_ERROR ? ' (Reason: ' . $WP_LOAD_ERROR . ')' : ''),
                ];
            }
        }

        error_reporting($prevReporting); // Restore original error level
        return $this->results;
    }

    /**
     * @inheritDoc
     */
    public function fix(string $id): bool
    {
        // Fixing logic for WP (like updating core, plugins) will be implemented here.
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
     * Audits the current WordPress Core version and update status.
     * 
     * @return array<string, mixed>
     */
    private function getCoreStatus(): array
    {
        if (!$this->isWpLoaded) {
            return ['version' => 'N/A'];
        }

        if (is_file(ABSPATH . 'wp-admin/includes/update.php')) {
            require_once ABSPATH . 'wp-admin/includes/update.php';
        }

        $currentVersion = get_bloginfo('version');
        if (!function_exists('get_core_updates')) {
            return [
                'current' => $currentVersion,
                'update_available' => false,
                'new_version' => null,
                'status' => 'OK',
            ];
        }

        $offers = get_core_updates(['dismissed' => false]);
        
        return [
            'current' => $currentVersion,
            'update_available' => !empty($offers[0]),
            'new_version' => !empty($offers[0]) ? $offers[0]->current : null,
            'status' => empty($offers[0]) ? 'OK' : 'WARN',
        ];
    }

    /**
     * Audits installed plugins for activity and updates.
     * 
     * @return array<string, array<string, mixed>>
     */
    private function getPluginsStatus(): array
    {
        if (!$this->isWpLoaded) {
            return [];
        }

        if (!is_file(ABSPATH . 'wp-admin/includes/plugin.php')) {
            return [];
        }

        require_once ABSPATH . 'wp-admin/includes/plugin.php';
        $plugins = get_plugins();
        $active = (array) get_option('active_plugins', []);
        $updates = get_site_transient('update_plugins');
        $needUpdate = array_keys($updates->response ?? []);

        $list = [];
        foreach ($plugins as $file => $data) {
            $updateAvailable = in_array($file, $needUpdate, true);
            $list[$file] = [
                'name' => $data['Name'],
                'active' => in_array($file, $active, true),
                'version' => $data['Version'],
                'update_available' => $updateAvailable,
                'new_version' => $updateAvailable ? $updates->response[$file]->new_version : null,
            ];
        }

        return $list;
    }

    /**
     * Audits active and available themes.
     * 
     * @return array<string, array<string, mixed>>
     */
    private function getThemesStatus(): array
    {
        if (!$this->isWpLoaded) {
            return [];
        }

        $themes = wp_get_themes();
        $current = wp_get_theme();
        $updates = get_site_transient('update_themes');
        $needUpdate = array_keys($updates->response ?? []);

        $list = [];
        foreach ($themes as $slug => $theme) {
            $updateAvailable = in_array($slug, $needUpdate, true);
            $list[$slug] = [
                'name' => $theme->get('Name'),
                'is_active' => $current->get_stylesheet() === $theme->get_stylesheet(),
                'version' => $theme->get('Version'),
                'update_available' => $updateAvailable,
                'new_version' => $updateAvailable ? $updates->response[$slug]['new_version'] : null,
            ];
        }

        return $list;
    }

    private function parsePluginFile(string $path, string $slug, array $activePlugins, array $pluginUpdates, array &$plugins): bool
    {
        $content = @file_get_contents($path);
        if ($content && str_contains($content, 'Plugin Name:')) {
            $name = preg_match('/Plugin Name:\s*(.*)/i', $content, $m) ? trim($m[1]) : $slug;
            $version = preg_match('/Version:\s*(.*)/i', $content, $m) ? trim($m[1]) : 'Unknown';
            $updateAvailable = isset($pluginUpdates[$slug]);
            $newVersion = $updateAvailable ? ($pluginUpdates[$slug]->new_version ?? null) : null;
            $plugins[$slug] = [
                'name' => $name,
                'active' => in_array($slug, $activePlugins, true),
                'version' => $version,
                'update_available' => $updateAvailable,
                'new_version' => $newVersion
            ];
            return true;
        }
        return false;
    }
}
