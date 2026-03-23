<?php
declare(strict_types=1);

namespace WPDiagnose\Agents\ThreatIntelAgent;

use WPDiagnose\Core\DiagnosticInterface;

final class ThreatIntelAgent implements DiagnosticInterface
{
    private const DEFAULT_CACHE_TTL = 21600;
    private const OPTION_API_KEY = 'wpd_wordfence_api_key';
    private const DOCS_URL = 'https://www.wordfence.com/help/wordfence-intelligence/v3-accessing-and-consuming-the-vulnerability-data-feed/';

    private array $results = [];
    private bool $isWpLoaded;
    private array $lastActionResult = ['success' => true, 'message' => '', 'data' => null];

    public function __construct(bool $isWpLoaded = false)
    {
        $this->isWpLoaded = $isWpLoaded;
    }

    public function getName(): string
    {
        return 'ThreatIntelAgent';
    }

    public function check(): array
    {
        $this->results = [];

        $inventory = $this->buildInventory();
        $feed = $this->loadWordfenceFeed();

        $this->results['feed_status'] = [
            'status' => $feed['status'],
            'info' => $feed['message'],
        ];

        $this->results['inventory_summary'] = [
            'status' => 'OK',
            'info' => sprintf(
                'Inventory: core=%s | plugins=%d | themes=%d',
                $inventory['core']['version'] ?? 'unknown',
                count($inventory['plugins']),
                count($inventory['themes'])
            ),
        ];

        $this->results['intel_configuration'] = [
            'status' => $this->hasConfiguredApiKey() ? 'OK' : 'WARN',
            'info' => $this->hasConfiguredApiKey()
                ? 'Wordfence API key is configured. Live vulnerability matching is enabled when the feed is reachable.'
                : 'Wordfence API key is not configured yet. Add a free API key to enable live CVE matching.',
            'data' => [
                'provider' => 'Wordfence Intelligence V3',
                'api_key_status' => $this->hasConfiguredApiKey() ? 'configured' : 'missing',
                'api_key_source' => $this->getApiKeySource(),
                'api_key_hint' => $this->maskApiKey($this->getConfiguredApiKey()),
                'docs_url' => self::DOCS_URL,
            ],
        ];

        if (($feed['status'] ?? 'WARN') !== 'OK' || !isset($feed['data']) || !is_array($feed['data'])) {
            $this->results['vulnerability_overview'] = [
                'status' => 'WARN',
                'info' => 'Threat intelligence feed unavailable. Configure WPD_WORDFENCE_API_KEY to enable CVE matching.',
            ];
            return $this->results;
        }

        $findings = $this->matchVulnerabilities($inventory, $feed['data']);
        $critical = count(array_filter($findings, static fn(array $finding): bool => in_array($finding['severity'], ['Critical', 'High'], true)));

        $this->results['vulnerability_overview'] = [
            'status' => empty($findings) ? 'OK' : ($critical > 0 ? 'ERROR' : 'WARN'),
            'info' => empty($findings)
                ? 'No known WordPress core/plugin/theme vulnerabilities matched the current inventory.'
                : sprintf('%d known vulnerability match(es) detected. %d high or critical.', count($findings), $critical),
        ];

        if (!empty($findings)) {
            $this->results['known_vulnerabilities'] = [
                'status' => $critical > 0 ? 'ERROR' : 'WARN',
                'info' => 'Matched against Wordfence Intelligence V3 production feed.',
                'data' => array_map(static function (array $finding): string {
                    $patched = $finding['patched_versions'] !== [] ? implode(', ', $finding['patched_versions']) : 'unpatched';
                    return sprintf(
                        '[%s] %s %s | %s | %s | patched in %s',
                        strtoupper($finding['type']),
                        $finding['software_name'],
                        $finding['installed_version'],
                        $finding['title'],
                        $finding['cve'] ?? 'No CVE',
                        $patched
                    );
                }, array_slice($findings, 0, 25)),
            ];
        }

        return $this->results;
    }

    public function fix(string $id): bool
    {
        $this->lastActionResult = ['success' => false, 'message' => 'Unknown threat intelligence action.', 'data' => null];

        if ($id === 'save_wordfence_api_key') {
            return $this->saveWordfenceApiKey();
        }

        if ($id === 'clear_wordfence_api_key') {
            return $this->clearWordfenceApiKey();
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

    /**
     * @return array{core: array{name: string, slug: string, version: string}|array<string, string>, plugins: array<string, array{name: string, slug: string, version: string}>, themes: array<string, array{name: string, slug: string, version: string}>}
     */
    private function buildInventory(): array
    {
        return [
            'core' => $this->getCoreInventory(),
            'plugins' => $this->getPluginInventory(),
            'themes' => $this->getThemeInventory(),
        ];
    }

    /**
     * @return array{status: string, message: string, data?: array<string, mixed>}
     */
    private function loadWordfenceFeed(): array
    {
        $apiKey = $this->getConfiguredApiKey();
        if ($apiKey === '') {
            return [
                'status' => 'WARN',
                'message' => 'Wordfence V3 API key missing. Set WPD_WORDFENCE_API_KEY to enable live vulnerability intelligence.',
            ];
        }

        $cacheFile = rtrim(ABSPATH, '/\\') . '/wp-content/.wpd-threat-intel-cache.json';
        $cacheTtl = (int) (getenv('WPD_THREAT_FEED_TTL') ?: self::DEFAULT_CACHE_TTL);
        if ($cacheTtl < 60) {
            $cacheTtl = self::DEFAULT_CACHE_TTL;
        }

        if (is_file($cacheFile) && (time() - (int) filemtime($cacheFile)) < $cacheTtl) {
            $cached = json_decode((string) file_get_contents($cacheFile), true);
            if (is_array($cached)) {
                return [
                    'status' => 'OK',
                    'message' => 'Wordfence Intelligence feed loaded from cache.',
                    'data' => $cached,
                ];
            }
        }

        $feedUrl = getenv('WPD_WORDFENCE_FEED_URL') ?: 'https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production';
        $payload = $this->httpGetJson($feedUrl, [
            'Authorization: Bearer ' . $apiKey,
            'Accept: application/json',
        ]);

        if (!is_array($payload)) {
            return [
                'status' => 'WARN',
                'message' => 'Wordfence Intelligence feed request failed or returned invalid JSON.',
            ];
        }

        $cacheDir = dirname($cacheFile);
        if (!is_dir($cacheDir)) {
            @mkdir($cacheDir, 0755, true);
        }
        @file_put_contents($cacheFile, json_encode($payload, JSON_UNESCAPED_SLASHES));

        return [
            'status' => 'OK',
            'message' => 'Wordfence Intelligence V3 production feed loaded successfully.',
            'data' => $payload,
        ];
    }

    private function saveWordfenceApiKey(): bool
    {
        $apiKey = trim((string) ($_POST['wordfence_api_key'] ?? $_GET['wordfence_api_key'] ?? ''));
        if ($apiKey === '') {
            $this->lastActionResult = [
                'success' => false,
                'message' => 'Wordfence API key cannot be empty.',
                'data' => null,
            ];
            return false;
        }

        $saved = $this->setOption(self::OPTION_API_KEY, $apiKey);
        $this->lastActionResult = [
            'success' => $saved,
            'message' => $saved ? 'Wordfence API key saved successfully.' : 'Failed to save Wordfence API key.',
            'data' => $saved ? ['api_key_hint' => $this->maskApiKey($apiKey)] : null,
        ];
        return $saved;
    }

    private function clearWordfenceApiKey(): bool
    {
        $cleared = $this->setOption(self::OPTION_API_KEY, '');
        $this->lastActionResult = [
            'success' => $cleared,
            'message' => $cleared ? 'Wordfence API key cleared.' : 'Failed to clear Wordfence API key.',
            'data' => null,
        ];
        return $cleared;
    }

    private function hasConfiguredApiKey(): bool
    {
        return $this->getConfiguredApiKey() !== '';
    }

    private function getConfiguredApiKey(): string
    {
        $envValue = trim((string) (getenv('WPD_WORDFENCE_API_KEY') ?: ''));
        if ($envValue !== '') {
            return $envValue;
        }

        $storedValue = $this->getOption(self::OPTION_API_KEY, '');
        return is_string($storedValue) ? trim($storedValue) : '';
    }

    private function getApiKeySource(): string
    {
        if (trim((string) (getenv('WPD_WORDFENCE_API_KEY') ?: '')) !== '') {
            return 'environment';
        }

        return $this->getConfiguredApiKey() !== '' ? 'database' : 'unset';
    }

    private function maskApiKey(string $apiKey): string
    {
        if ($apiKey === '') {
            return 'not set';
        }

        if (strlen($apiKey) <= 8) {
            return str_repeat('*', strlen($apiKey));
        }

        return substr($apiKey, 0, 4) . str_repeat('*', max(4, strlen($apiKey) - 8)) . substr($apiKey, -4);
    }

    /**
     * @param mixed $default
     * @return mixed
     */
    private function getOption(string $name, $default = null)
    {
        if ($this->isWpLoaded && function_exists('get_option')) {
            return get_option($name, $default);
        }

        global $DB;
        if ($DB) {
            $value = $DB->get_option($name);
            if ($value !== null) {
                return $value;
            }
        }

        return $default;
    }

    /**
     * @param mixed $value
     */
    private function setOption(string $name, $value): bool
    {
        if ($this->isWpLoaded && function_exists('update_option')) {
            return update_option($name, $value);
        }

        global $DB;
        if ($DB) {
            return $DB->update_option($name, is_scalar($value) ? (string) $value : json_encode($value, JSON_UNESCAPED_SLASHES));
        }

        return false;
    }

    /**
     * @param array{core: array<string, string>, plugins: array<string, array{name: string, slug: string, version: string}>, themes: array<string, array{name: string, slug: string, version: string}>} $inventory
     * @param array<string, mixed> $feed
     * @return array<int, array<string, mixed>>
     */
    private function matchVulnerabilities(array $inventory, array $feed): array
    {
        $findings = [];

        foreach ($feed as $record) {
            if (!is_array($record) || !isset($record['software']) || !is_array($record['software'])) {
                continue;
            }

            foreach ($record['software'] as $software) {
                if (!is_array($software) || !isset($software['type'], $software['slug'], $software['affected_versions'])) {
                    continue;
                }

                $candidate = $this->resolveInventoryCandidate($inventory, (string) $software['type'], (string) $software['slug']);
                if ($candidate === null) {
                    continue;
                }

                if (!$this->isVersionAffected($candidate['version'], $software['affected_versions'])) {
                    continue;
                }

                $findings[] = [
                    'type' => (string) $software['type'],
                    'software_name' => $candidate['name'] ?: ((string) ($software['name'] ?? $software['slug'])),
                    'slug' => (string) $software['slug'],
                    'installed_version' => $candidate['version'],
                    'title' => (string) ($record['title'] ?? 'Unknown vulnerability'),
                    'cve' => isset($record['cve']) && is_string($record['cve']) && $record['cve'] !== '' ? $record['cve'] : null,
                    'severity' => (string) ($record['cvss']['rating'] ?? 'Unknown'),
                    'score' => $record['cvss']['score'] ?? null,
                    'patched_versions' => isset($software['patched_versions']) && is_array($software['patched_versions']) ? array_values($software['patched_versions']) : [],
                    'reference' => isset($record['references'][0]) ? (string) $record['references'][0] : null,
                    'published' => $record['published'] ?? null,
                ];
            }
        }

        usort($findings, function (array $left, array $right): int {
            $weight = ['Critical' => 5, 'High' => 4, 'Medium' => 3, 'Low' => 2, 'None' => 1, 'Unknown' => 0];
            return ($weight[$right['severity']] ?? 0) <=> ($weight[$left['severity']] ?? 0);
        });

        return $findings;
    }

    /**
     * @param array{core: array<string, string>, plugins: array<string, array{name: string, slug: string, version: string}>, themes: array<string, array{name: string, slug: string, version: string}>} $inventory
     * @return array{name: string, version: string}|null
     */
    private function resolveInventoryCandidate(array $inventory, string $type, string $slug): ?array
    {
        if ($type === 'core') {
            $version = $inventory['core']['version'] ?? '';
            if ($version === '') {
                return null;
            }

            return [
                'name' => 'WordPress Core',
                'version' => $version,
            ];
        }

        if ($type === 'plugin' && isset($inventory['plugins'][$slug])) {
            return [
                'name' => $inventory['plugins'][$slug]['name'],
                'version' => $inventory['plugins'][$slug]['version'],
            ];
        }

        if ($type === 'theme' && isset($inventory['themes'][$slug])) {
            return [
                'name' => $inventory['themes'][$slug]['name'],
                'version' => $inventory['themes'][$slug]['version'],
            ];
        }

        return null;
    }

    /**
     * @param mixed $affectedVersions
     */
    private function isVersionAffected(string $installedVersion, $affectedVersions): bool
    {
        if (!is_array($affectedVersions) || $installedVersion === '') {
            return false;
        }

        foreach ($affectedVersions as $range) {
            if (!is_array($range)) {
                continue;
            }

            $fromVersion = (string) ($range['from_version'] ?? '*');
            $toVersion = (string) ($range['to_version'] ?? '*');
            $fromInclusive = (bool) ($range['from_inclusive'] ?? true);
            $toInclusive = (bool) ($range['to_inclusive'] ?? true);

            $lowerOk = $fromVersion === '*' || $this->compareVersions($installedVersion, $fromVersion, $fromInclusive ? '>=' : '>');
            $upperOk = $toVersion === '*' || $this->compareVersions($installedVersion, $toVersion, $toInclusive ? '<=' : '<');

            if ($lowerOk && $upperOk) {
                return true;
            }
        }

        return false;
    }

    private function compareVersions(string $left, string $right, string $operator): bool
    {
        $normalize = static function (string $version): string {
            $version = trim($version);
            $version = preg_replace('/[^0-9A-Za-z\.\-\+_]/', '', $version);
            return $version === '' ? '0' : $version;
        };

        return version_compare($normalize($left), $normalize($right), $operator);
    }

    /**
     * @return array{name: string, slug: string, version: string}
     */
    private function getCoreInventory(): array
    {
        if ($this->isWpLoaded && function_exists('get_bloginfo')) {
            return [
                'name' => 'WordPress Core',
                'slug' => 'wordpress',
                'version' => (string) get_bloginfo('version'),
            ];
        }

        $versionFile = ABSPATH . 'wp-includes/version.php';
        if (is_file($versionFile)) {
            $wp_version = '';
            include $versionFile;
            return [
                'name' => 'WordPress Core',
                'slug' => 'wordpress',
                'version' => is_string($wp_version) ? $wp_version : '',
            ];
        }

        return [
            'name' => 'WordPress Core',
            'slug' => 'wordpress',
            'version' => '',
        ];
    }

    /**
     * @return array<string, array{name: string, slug: string, version: string}>
     */
    private function getPluginInventory(): array
    {
        $plugins = [];

        if ($this->isWpLoaded && is_file(ABSPATH . 'wp-admin/includes/plugin.php')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
            if (function_exists('get_plugins')) {
                foreach (get_plugins() as $file => $data) {
                    $slug = strtok($file, '/');
                    $plugins[$slug] = [
                        'name' => (string) ($data['Name'] ?? $slug),
                        'slug' => $slug,
                        'version' => (string) ($data['Version'] ?? ''),
                    ];
                }
                return $plugins;
            }
        }

        $pluginDir = ABSPATH . 'wp-content/plugins/';
        if (!is_dir($pluginDir)) {
            return [];
        }

        $iterator = new \DirectoryIterator($pluginDir);
        foreach ($iterator as $item) {
            if ($item->isDot()) {
                continue;
            }

            if ($item->isDir()) {
                $slug = $item->getFilename();
                $plugins[$slug] = $this->inspectPluginDirectory($item->getPathname(), $slug);
            } elseif ($item->isFile() && $item->getExtension() === 'php') {
                $slug = pathinfo($item->getFilename(), PATHINFO_FILENAME);
                $plugins[$slug] = $this->readPluginHeader($item->getPathname(), $slug);
            }
        }

        return array_filter($plugins, static fn(array $plugin): bool => $plugin['version'] !== '' || $plugin['name'] !== '');
    }

    /**
     * @return array<string, array{name: string, slug: string, version: string}>
     */
    private function getThemeInventory(): array
    {
        $themes = [];

        if ($this->isWpLoaded && function_exists('wp_get_themes')) {
            foreach (wp_get_themes() as $slug => $theme) {
                $themes[$slug] = [
                    'name' => (string) $theme->get('Name'),
                    'slug' => (string) $slug,
                    'version' => (string) $theme->get('Version'),
                ];
            }
            return $themes;
        }

        $themeDir = ABSPATH . 'wp-content/themes/';
        if (!is_dir($themeDir)) {
            return [];
        }

        $iterator = new \DirectoryIterator($themeDir);
        foreach ($iterator as $item) {
            if ($item->isDot() || !$item->isDir()) {
                continue;
            }

            $styleCss = $item->getPathname() . '/style.css';
            if (!is_file($styleCss)) {
                continue;
            }

            $header = $this->readStyleHeader($styleCss);
            $slug = $item->getFilename();
            $themes[$slug] = [
                'name' => $header['Theme Name'] ?: $slug,
                'slug' => $slug,
                'version' => $header['Version'] ?: '',
            ];
        }

        return $themes;
    }

    /**
     * @return array{name: string, slug: string, version: string}
     */
    private function inspectPluginDirectory(string $directory, string $slug): array
    {
        $iterator = new \DirectoryIterator($directory);
        foreach ($iterator as $item) {
            if ($item->isDot() || !$item->isFile() || $item->getExtension() !== 'php') {
                continue;
            }

            $header = $this->readPluginHeader($item->getPathname(), $slug);
            if ($header['name'] !== '' || $header['version'] !== '') {
                return $header;
            }
        }

        return ['name' => $slug, 'slug' => $slug, 'version' => ''];
    }

    /**
     * @return array{name: string, slug: string, version: string}
     */
    private function readPluginHeader(string $path, string $slug): array
    {
        $content = (string) file_get_contents($path, false, null, 0, 8192);
        $name = preg_match('/^[ \t\/*#@]*Plugin Name:(.*)$/mi', $content, $matchName) ? trim($matchName[1]) : $slug;
        $version = preg_match('/^[ \t\/*#@]*Version:(.*)$/mi', $content, $matchVersion) ? trim($matchVersion[1]) : '';

        return [
            'name' => $name,
            'slug' => $slug,
            'version' => $version,
        ];
    }

    /**
     * @return array<string, string>
     */
    private function readStyleHeader(string $path): array
    {
        $content = (string) file_get_contents($path, false, null, 0, 8192);
        $fields = ['Theme Name', 'Version'];
        $result = [];

        foreach ($fields as $field) {
            $result[$field] = preg_match('/^[ \t\/*#@]*' . preg_quote($field, '/') . ':(.*)$/mi', $content, $matches)
                ? trim($matches[1])
                : '';
        }

        return $result;
    }

    /**
     * @param array<int, string> $headers
     * @return array<string, mixed>|null
     */
    private function httpGetJson(string $url, array $headers): ?array
    {
        if (function_exists('curl_init')) {
            $ch = curl_init($url);
            if ($ch === false) {
                return null;
            }

            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => 20,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_HTTPHEADER => $headers,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
            ]);

            $body = curl_exec($ch);
            $status = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            curl_close($ch);

            if ($body === false || $status >= 400) {
                return null;
            }

            $decoded = json_decode((string) $body, true);
            return is_array($decoded) ? $decoded : null;
        }

        $context = stream_context_create([
            'http' => [
                'method' => 'GET',
                'timeout' => 20,
                'header' => implode("\r\n", $headers),
            ],
        ]);

        $body = @file_get_contents($url, false, $context);
        if ($body === false) {
            return null;
        }

        $decoded = json_decode($body, true);
        return is_array($decoded) ? $decoded : null;
    }
}
