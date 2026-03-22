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
            $this->results['wp_env'] = [
                'status' => 'WARN',
                'info'   => 'WordPress not loaded. Running in Independent Diagnostic Mode.',
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

        $currentVersion = get_bloginfo('version');
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
}
