<?php
declare(strict_types=1);

namespace WPDiagnose\Agents\ThreatIntelAgent;

use WPDiagnose\Core\DiagnosticInterface;

final class ThreatIntelAgent implements DiagnosticInterface
{
    private const OPTION_API_KEY = 'wpd_wordfence_api_key';
    private const DOCS_URL = 'https://www.wordfence.com/help/wordfence-intelligence/v3-accessing-and-consuming-the-vulnerability-data-feed/';
    private const RATE_LIMIT_COOLDOWN_SECONDS = 900;

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

        $cacheMeta = $this->getFeedCacheMeta();
        $stateMeta = $this->getFeedStateMeta();

        $this->results['intel_configuration'] = [
            'status' => !$this->hasConfiguredApiKey() ? 'WARN' : ($stateMeta['cooldown_active'] ? 'WARN' : 'OK'),
            'info' => $this->hasConfiguredApiKey()
                ? ($stateMeta['cooldown_active']
                    ? 'Wordfence API key is configured, but Sync Feed is cooling down after an upstream rate limit.'
                    : 'Wordfence API key is configured. Use Sync Feed to refresh the cached vulnerability intelligence dataset.')
                : 'Wordfence API key is not configured yet. Add a free API key to enable live CVE matching.',
            'data' => [
                'provider' => 'Wordfence Intelligence V3',
                'api_key_status' => $this->hasConfiguredApiKey() ? 'configured' : 'missing',
                'api_key_source' => $this->getApiKeySource(),
                'api_key_hint' => $this->maskApiKey($this->getConfiguredApiKey()),
                'docs_url' => self::DOCS_URL,
                'cache_status' => $cacheMeta['status'],
                'cache_updated_at' => $cacheMeta['updated_at'],
                'cache_feed_type' => $cacheMeta['feed_type'],
                'cooldown_active' => $stateMeta['cooldown_active'],
                'cooldown_until' => $stateMeta['cooldown_until'],
                'last_error' => $stateMeta['last_error'],
                'last_success_at' => $stateMeta['last_success_at'],
            ],
        ];

        if (($feed['status'] ?? 'WARN') !== 'OK' || !isset($feed['data']) || !is_array($feed['data'])) {
            $this->results['vulnerability_overview'] = [
                'status' => 'WARN',
                'info' => $this->hasConfiguredApiKey()
                    ? 'Threat intelligence cache unavailable. Save the API key and trigger Sync Feed to populate local CVE data.'
                    : 'Threat intelligence feed unavailable. Configure a Wordfence API key to enable CVE matching.',
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

        if ($id === 'refresh_threat_feed') {
            return $this->refreshThreatFeed();
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
        $cacheFile = $this->getCacheFilePath();
        if (!is_file($cacheFile)) {
            return [
                'status' => 'WARN',
                'message' => 'Threat intelligence cache is empty. Run Sync Feed after saving a Wordfence API key.',
            ];
        }

        $cached = json_decode((string) file_get_contents($cacheFile), true);
        if (!is_array($cached) || !isset($cached['records']) || !is_array($cached['records'])) {
            return [
                'status' => 'WARN',
                'message' => 'Threat intelligence cache file is invalid. Run Sync Feed to rebuild it.',
            ];
        }

        return [
            'status' => 'OK',
            'message' => 'Threat intelligence data loaded from local cache.',
            'data' => $cached['records'],
        ];
    }

    private function refreshThreatFeed(): bool
    {
        $apiKey = $this->getConfiguredApiKey();
        if ($apiKey === '') {
            $this->lastActionResult = [
                'success' => false,
                'message' => 'Wordfence API key is required before syncing the feed.',
                'data' => null,
            ];
            return false;
        }

        $state = $this->loadFeedState();
        if (($state['cooldown_until'] ?? 0) > time()) {
            $nextRetry = gmdate('c', (int) $state['cooldown_until']);
            $this->lastActionResult = [
                'success' => false,
                'message' => "Sync Feed is temporarily cooling down after a rate limit. Please retry after {$nextRetry}.",
                'data' => [
                    'cooldown_until' => $nextRetry,
                ],
            ];
            return false;
        }

        $headers = [
            'Authorization: Bearer ' . $apiKey,
            'Accept: application/json',
            'User-Agent: WP-Diagnose/' . (class_exists('\WPDiagnose\Core\Version') ? \WPDiagnose\Core\Version::current() : 'dev'),
        ];

        $candidates = [
            'production' => getenv('WPD_WORDFENCE_FEED_URL') ?: 'https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production',
            'scanner' => getenv('WPD_WORDFENCE_SCANNER_FEED_URL') ?: 'https://www.wordfence.com/api/intelligence/v3/vulnerabilities/scanner',
        ];

        $selectedFeed = 'production';
        $selectedPayload = null;
        $lastFailure = null;

        foreach ($candidates as $feedType => $feedUrl) {
            $response = $this->httpGetJson($feedUrl, $headers);
            if ($response['ok'] && is_array($response['decoded'])) {
                $selectedFeed = $feedType;
                $selectedPayload = $response['decoded'];
                break;
            }

            $lastFailure = $response;
            if (($response['status'] ?? 0) === 401 || ($response['status'] ?? 0) === 403) {
                break;
            }
        }

        if (!is_array($selectedPayload)) {
            $failureMessage = $this->buildFeedFailureMessage($lastFailure);
            $stateUpdate = [
                'last_error' => $failureMessage,
            ];
            if (($lastFailure['status'] ?? 0) === 429) {
                $stateUpdate['cooldown_until'] = time() + self::RATE_LIMIT_COOLDOWN_SECONDS;
            } else {
                $stateUpdate['cooldown_until'] = 0;
            }
            $this->saveFeedState($stateUpdate);

            $this->lastActionResult = [
                'success' => false,
                'message' => $failureMessage,
                'data' => $lastFailure ? [
                    'http_status' => $lastFailure['status'],
                    'content_type' => $lastFailure['content_type'],
                    'response_preview' => $lastFailure['preview'],
                    'cooldown_until' => isset($stateUpdate['cooldown_until']) && (int) $stateUpdate['cooldown_until'] > 0 ? gmdate('c', (int) $stateUpdate['cooldown_until']) : null,
                ] : null,
            ];
            return false;
        }

        $normalized = $this->normalizeFeed($selectedPayload);
        $cacheFile = $this->getCacheFilePath();
        $cacheDir = dirname($cacheFile);
        if (!is_dir($cacheDir)) {
            @mkdir($cacheDir, 0755, true);
        }

        $written = @file_put_contents($cacheFile, json_encode([
            'updated_at' => gmdate('c'),
            'feed_type' => $selectedFeed,
            'records' => $normalized,
        ], JSON_UNESCAPED_SLASHES));

        $success = $written !== false;
        $this->saveFeedState($success ? [
            'cooldown_until' => 0,
            'last_error' => '',
            'last_success_at' => time(),
        ] : [
            'last_error' => 'Threat intelligence feed was downloaded but could not be cached locally.',
        ]);
        $this->lastActionResult = [
            'success' => $success,
            'message' => $success
                ? sprintf('Threat intelligence feed synced successfully using the %s feed.', $selectedFeed)
                : 'Threat intelligence feed was downloaded but could not be cached locally.',
            'data' => $success ? ['records' => count($normalized), 'feed_type' => $selectedFeed] : null,
        ];
        return $success;
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
        if ($saved) {
            $this->saveFeedState([
                'cooldown_until' => 0,
                'last_error' => '',
            ]);
        }
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
        if ($cleared) {
            $this->saveFeedState([
                'cooldown_until' => 0,
                'last_error' => '',
            ]);
        }
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

    private function getCacheFilePath(): string
    {
        return rtrim(ABSPATH, '/\\') . '/wp-content/.wpd-threat-intel-cache.json';
    }

    private function getStateFilePath(): string
    {
        return rtrim(ABSPATH, '/\\') . '/wp-content/.wpd-threat-intel-state.json';
    }

    /**
     * @return array{status: string, updated_at: string, feed_type: string}
     */
    private function getFeedCacheMeta(): array
    {
        $cacheFile = $this->getCacheFilePath();
        if (!is_file($cacheFile)) {
            return [
                'status' => 'missing',
                'updated_at' => 'never',
                'feed_type' => 'none',
            ];
        }

        $cached = json_decode((string) file_get_contents($cacheFile), true);
        return [
            'status' => 'ready',
            'updated_at' => is_array($cached) && isset($cached['updated_at']) ? (string) $cached['updated_at'] : gmdate('c', (int) filemtime($cacheFile)),
            'feed_type' => is_array($cached) && isset($cached['feed_type']) ? (string) $cached['feed_type'] : 'unknown',
        ];
    }

    /**
     * @return array{cooldown_active: bool, cooldown_until: string, last_error: string, last_success_at: string}
     */
    private function getFeedStateMeta(): array
    {
        $state = $this->loadFeedState();
        $cooldownUntil = (int) ($state['cooldown_until'] ?? 0);
        $lastSuccessAt = (int) ($state['last_success_at'] ?? 0);

        return [
            'cooldown_active' => $cooldownUntil > time(),
            'cooldown_until' => $cooldownUntil > 0 ? gmdate('c', $cooldownUntil) : 'ready',
            'last_error' => (string) ($state['last_error'] ?? ''),
            'last_success_at' => $lastSuccessAt > 0 ? gmdate('c', $lastSuccessAt) : 'never',
        ];
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
     * @param array<string, mixed> $payload
     * @return array<string, mixed>
     */
    private function normalizeFeed(array $payload): array
    {
        $normalized = [];

        foreach ($payload as $id => $record) {
            if (!is_array($record) || !isset($record['software']) || !is_array($record['software'])) {
                continue;
            }

            $softwareRecords = [];
            foreach ($record['software'] as $software) {
                if (!is_array($software) || !isset($software['type'], $software['slug'], $software['affected_versions'])) {
                    continue;
                }

                $softwareRecords[] = [
                    'type' => $software['type'],
                    'name' => $software['name'] ?? $software['slug'],
                    'slug' => $software['slug'],
                    'affected_versions' => $software['affected_versions'],
                    'patched_versions' => $software['patched_versions'] ?? [],
                ];
            }

            if ($softwareRecords === []) {
                continue;
            }

            $normalized[$id] = [
                'title' => $record['title'] ?? 'Unknown vulnerability',
                'software' => $softwareRecords,
                'cve' => $record['cve'] ?? null,
                'cvss' => $record['cvss'] ?? [],
                'references' => $record['references'] ?? [],
                'published' => $record['published'] ?? null,
            ];
        }

        return $normalized;
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
            if (function_exists('get_option') && get_option($name, null) === $value) {
                return true;
            }

            return update_option($name, $value);
        }

        global $DB;
        if ($DB) {
            $currentValue = $DB->get_option($name);
            $serializedValue = is_scalar($value) ? (string) $value : json_encode($value, JSON_UNESCAPED_SLASHES);
            if ((string) $currentValue === (string) $serializedValue) {
                return true;
            }

            return $DB->update_option($name, $serializedValue);
        }

        return false;
    }

    /**
     * @return array<string, mixed>
     */
    private function loadFeedState(): array
    {
        $stateFile = $this->getStateFilePath();
        if (!is_file($stateFile)) {
            return [];
        }

        $decoded = json_decode((string) file_get_contents($stateFile), true);
        return is_array($decoded) ? $decoded : [];
    }

    /**
     * @param array<string, mixed> $updates
     */
    private function saveFeedState(array $updates): void
    {
        $stateFile = $this->getStateFilePath();
        $directory = dirname($stateFile);
        if (!is_dir($directory)) {
            @mkdir($directory, 0755, true);
        }

        $state = array_merge($this->loadFeedState(), $updates);
        @file_put_contents($stateFile, json_encode($state, JSON_UNESCAPED_SLASHES));
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
     * @return array{ok: bool, status: int, content_type: string, preview: string, error: string, decoded: ?array}
     */
    private function httpGetJson(string $url, array $headers): array
    {
        if (function_exists('curl_init')) {
            $ch = curl_init($url);
            if ($ch === false) {
                return [
                    'ok' => false,
                    'status' => 0,
                    'content_type' => '',
                    'preview' => '',
                    'error' => 'cURL initialization failed.',
                    'decoded' => null,
                ];
            }

            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => 20,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_ENCODING => '',
                CURLOPT_HTTPHEADER => $headers,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
            ]);

            $body = curl_exec($ch);
            $status = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            $contentType = (string) curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
            $error = curl_error($ch);
            curl_close($ch);

            return $this->normalizeHttpJsonResponse(
                $body === false ? '' : (string) $body,
                (int) $status,
                $contentType,
                $error
            );
        }

        $context = stream_context_create([
            'http' => [
                'method' => 'GET',
                'timeout' => 20,
                'header' => implode("\r\n", $headers),
                'ignore_errors' => true,
            ],
        ]);

        $body = @file_get_contents($url, false, $context);
        $status = 0;
        $contentType = '';
        if (isset($http_response_header) && is_array($http_response_header)) {
            foreach ($http_response_header as $headerLine) {
                if (preg_match('#^HTTP/\S+\s+(\d{3})#i', $headerLine, $match)) {
                    $status = (int) $match[1];
                } elseif (stripos($headerLine, 'Content-Type:') === 0) {
                    $contentType = trim(substr($headerLine, strlen('Content-Type:')));
                }
            }
        }

        return $this->normalizeHttpJsonResponse(
            $body === false ? '' : (string) $body,
            $status,
            $contentType,
            $body === false ? 'HTTP request failed.' : ''
        );
    }

    /**
     * @return array{ok: bool, status: int, content_type: string, preview: string, error: string, decoded: ?array}
     */
    private function normalizeHttpJsonResponse(string $body, int $status, string $contentType, string $error): array
    {
        $decoded = json_decode($body, true);
        $preview = trim(substr(preg_replace('/\s+/', ' ', $body) ?? '', 0, 220));

        return [
            'ok' => $body !== '' && $status < 400 && is_array($decoded),
            'status' => $status,
            'content_type' => $contentType,
            'preview' => $preview,
            'error' => $error,
            'decoded' => is_array($decoded) ? $decoded : null,
        ];
    }

    /**
     * @param array{ok: bool, status: int, content_type: string, preview: string, error: string, decoded: ?array}|null $failure
     */
    private function buildFeedFailureMessage(?array $failure): string
    {
        if ($failure === null) {
            return 'Wordfence Intelligence feed request failed before a response was received.';
        }

        if ($failure['status'] === 401 || $failure['status'] === 403) {
            return 'Wordfence rejected the API key. Please use a Wordfence Intelligence V3 API key from the Integrations page.';
        }

        if ($failure['status'] === 429) {
            return 'Wordfence rate-limited the feed request. Please wait a bit and try Sync Feed again.';
        }

        if ($failure['error'] !== '') {
            return 'Feed sync failed during the HTTPS request: ' . $failure['error'];
        }

        if ($failure['status'] >= 400) {
            return sprintf(
                'Feed sync failed with HTTP %d. Response preview: %s',
                $failure['status'],
                $failure['preview'] !== '' ? $failure['preview'] : 'empty response'
            );
        }

        if ($failure['preview'] !== '') {
            return 'Wordfence returned a non-JSON response. Preview: ' . $failure['preview'];
        }

        return 'Wordfence returned an empty response. This is usually an outbound HTTPS or host-level filtering issue.';
    }
}
