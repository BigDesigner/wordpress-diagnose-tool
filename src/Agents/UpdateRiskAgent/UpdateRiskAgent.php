<?php
declare(strict_types=1);

namespace WPDiagnose\Agents\UpdateRiskAgent {

    use WPDiagnose\Core\DiagnosticInterface;

    /**
     * Class UpdateRiskAgent
     * 
     * Performs compatibility checks and risk analysis on pending core, theme, and plugin updates.
     */
    class UpdateRiskAgent implements DiagnosticInterface
    {
        private array $results = [];
        private bool $wpLoaded = false;

        public function __construct(bool $wpLoaded = false)
        {
            $this->wpLoaded = $wpLoaded;
        }

        public function getName(): string
        {
            return 'UpdateRiskAgent';
        }

        public function check(): array
        {
            $this->results = [];

            if (!$this->wpLoaded) {
                $this->results['update_status'] = [
                    'status' => 'WARN',
                    'info' => 'WordPress is not loaded. Cannot fetch pending updates.'
                ];
                return $this->results;
            }

            // In loaded mode, check updates
            $updates = [
                'core' => 0,
                'plugins' => 0,
                'themes' => 0
            ];

            // 1. Core updates
            $updateCore = get_site_transient('update_core');
            if (isset($updateCore->updates) && is_array($updateCore->updates)) {
                foreach ($updateCore->updates as $up) {
                    if ($up->response === 'upgrade') {
                        $updates['core']++;
                    }
                }
            }

            // 2. Plugin updates
            $updatePlugins = get_site_transient('update_plugins');
            if (isset($updatePlugins->response) && is_array($updatePlugins->response)) {
                $updates['plugins'] = count($updatePlugins->response);
            }

            // 3. Theme updates
            $updateThemes = get_site_transient('update_themes');
            if (isset($updateThemes->response) && is_array($updateThemes->response)) {
                $updates['themes'] = count($updateThemes->response);
            }

            $total = $updates['core'] + $updates['plugins'] + $updates['themes'];
            
            $this->results['pending_updates'] = [
                'status' => $total > 10 ? 'WARN' : 'OK',
                'info' => sprintf('%d pending updates (Core: %d | Plugins: %d | Themes: %d).', $total, $updates['core'], $updates['plugins'], $updates['themes']),
                'data' => [
                    'risk_level' => $updates['core'] > 0 ? 'Medium' : ($total > 15 ? 'Medium' : 'Low'),
                    'recommendation' => 'Always take a full site backup before applying updates.'
                ]
            ];

            return $this->results;
        }

        public function fix(string $id): bool
        {
            // Update risk has no automatic fix; it is diagnostic only.
            return false;
        }
    }
}
