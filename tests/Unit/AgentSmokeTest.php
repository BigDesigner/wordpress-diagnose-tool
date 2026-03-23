<?php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use WPDiagnose\Agents\AssetManagerAgent\AssetManagerAgent;
use WPDiagnose\Agents\BootstrapInspector\BootstrapInspector;
use WPDiagnose\Agents\CoreIntegrityAgent\CoreIntegrityAgent;
use WPDiagnose\Agents\CoreOperationsAgent\CoreOperationsAgent;
use WPDiagnose\Agents\DBHealth\DBHealth;
use WPDiagnose\Agents\MalwareInspector\MalwareInspector;
use WPDiagnose\Agents\SecurityInspector\SecurityInspector;
use WPDiagnose\Agents\ServerInspector\ServerInspector;
use WPDiagnose\Agents\ThreatIntelAgent\ThreatIntelAgent;
use WPDiagnose\Agents\WPInspector\WPInspector;

final class AgentSmokeTest extends TestCase
{
    protected function setUp(): void
    {
        wpd_tests_reset_root();
        wpd_tests_write('wp-config.php', "<?php\n/* test config */\n");
    }

    public function testServerInspectorProducesPhpVersionFinding(): void
    {
        $report = (new ServerInspector())->check();

        self::assertArrayHasKey('php_version', $report);
    }

    public function testBootstrapInspectorWarnsWhenNoDatabaseConstantsExist(): void
    {
        $originalCwd = getcwd();
        chdir(WPD_TEST_ROOT);

        try {
            $report = (new BootstrapInspector())->check();
        } finally {
            chdir($originalCwd);
        }

        self::assertArrayHasKey('config_file', $report);
        self::assertArrayHasKey('db_connection', $report);
        self::assertSame('ERROR', $report['db_connection']['status']);
    }

    public function testSecurityInspectorAuditsConfiguredRoot(): void
    {
        $report = (new SecurityInspector(WPD_TEST_ROOT))->check();

        self::assertArrayHasKey('wp_config_perms', $report);
        self::assertArrayHasKey('security_keys', $report);
    }

    public function testWpInspectorReportsIndependentModeWhenWordPressIsNotLoaded(): void
    {
        $report = (new WPInspector(false))->check();

        self::assertSame('WARN', $report['wp_env']['status']);
    }

    public function testDbHealthReturnsWarningWithoutLoadedWordPress(): void
    {
        $report = (new DBHealth(false))->check();

        self::assertSame('WARN', $report['db_status']['status']);
    }

    public function testCoreIntegrityAgentReportsMissingVersionInformation(): void
    {
        $report = (new CoreIntegrityAgent(false))->check();

        self::assertSame('ERROR', $report['checksum_scan']['status']);
    }

    public function testAssetManagerAgentDiscoversPluginsAndThemesFromFilesystem(): void
    {
        wpd_tests_write('wp-content/plugins/sample-plugin/sample-plugin.php', "<?php\n/*\nPlugin Name: Sample Plugin\n*/\n");
        wpd_tests_write('wp-content/themes/sample-theme/style.css', "/*\nTheme Name: Sample Theme\n*/\n");

        $report = (new AssetManagerAgent(false))->check();

        self::assertArrayHasKey('manage_plugins', $report);
        self::assertArrayHasKey('manage_themes', $report);
        self::assertArrayHasKey('sample-plugin/sample-plugin.php', $report['manage_plugins']['data']);
        self::assertArrayHasKey('sample-theme', $report['manage_themes']['data']);
    }

    public function testCoreOperationsAgentTogglesDebugSuiteAndAddsCustomLogPath(): void
    {
        wpd_tests_write(
            'wp-config.php',
            "<?php\n" .
            "define('WP_DEBUG', false);\n" .
            "/* That's all, stop editing! Happy publishing. */\n"
        );

        $agent = new CoreOperationsAgent(false);
        $result = $agent->fix('toggle_wp_debug');

        self::assertTrue($result);

        $config = wpd_tests_read('wp-config.php');
        self::assertStringContainsString("define('WP_DEBUG', true);", $config);
        self::assertStringContainsString("define('WP_DEBUG_DISPLAY', false);", $config);
        self::assertStringContainsString("define('WP_DEBUG_LOG', '" . WPD_TEST_ROOT . "wp-content/wp-diagnose-tool.log');", $config);
    }

    public function testThreatIntelAgentWarnsWhenWordfenceApiKeyIsMissing(): void
    {
        putenv('WPD_WORDFENCE_API_KEY');
        wpd_tests_write('wp-includes/version.php', "<?php\n\$wp_version = '6.8.1';\n");
        wpd_tests_write('wp-content/plugins/sample-plugin/sample-plugin.php', "<?php\n/*\nPlugin Name: Sample Plugin\nVersion: 1.2.3\n*/\n");
        wpd_tests_write('wp-content/themes/sample-theme/style.css', "/*\nTheme Name: Sample Theme\nVersion: 2.0.0\n*/\n");

        $report = (new ThreatIntelAgent(false))->check();

        self::assertArrayHasKey('feed_status', $report);
        self::assertSame('WARN', $report['feed_status']['status']);
        self::assertArrayHasKey('inventory_summary', $report);
    }

    public function testThreatIntelAgentCanPersistApiKeyViaFallbackDatabase(): void
    {
        $fakeDb = new class {
            public array $options = [];

            public function get_option(string $name)
            {
                return $this->options[$name] ?? null;
            }

            public function update_option(string $name, string $value): bool
            {
                $this->options[$name] = $value;
                return true;
            }
        };

        $GLOBALS['DB'] = $fakeDb;
        $_POST['wordfence_api_key'] = 'wf_test_key_123456';

        try {
            $agent = new ThreatIntelAgent(false);
            $saved = $agent->fix('save_wordfence_api_key');

            self::assertTrue($saved);
            self::assertSame('wf_test_key_123456', $fakeDb->options['wpd_wordfence_api_key']);
            self::assertTrue(method_exists($agent, 'getLastActionResult'));
        } finally {
            unset($GLOBALS['DB'], $_POST['wordfence_api_key']);
        }
    }

    public function testThreatIntelAgentReadsNormalizedFindingsFromLocalCache(): void
    {
        wpd_tests_write('wp-includes/version.php', "<?php\n\$wp_version = '6.8.1';\n");
        wpd_tests_write('wp-content/.wpd-threat-intel-cache.json', json_encode([
            'updated_at' => '2026-03-23T10:00:00Z',
            'records' => [
                'wf-1' => [
                    'title' => 'Sample plugin vulnerability',
                    'software' => [
                        [
                            'type' => 'plugin',
                            'name' => 'Sample Plugin',
                            'slug' => 'sample-plugin',
                            'affected_versions' => [
                                [
                                    'from_version' => '*',
                                    'to_version' => '1.2.3',
                                    'from_inclusive' => true,
                                    'to_inclusive' => true,
                                ],
                            ],
                            'patched_versions' => ['1.2.4'],
                        ],
                    ],
                    'cve' => 'CVE-2026-0001',
                    'cvss' => ['rating' => 'High', 'score' => 8.8],
                    'references' => ['https://example.test/advisory'],
                    'published' => '2026-03-20T10:00:00Z',
                ],
            ],
        ], JSON_UNESCAPED_SLASHES));
        wpd_tests_write('wp-content/plugins/sample-plugin/sample-plugin.php', "<?php\n/*\nPlugin Name: Sample Plugin\nVersion: 1.2.3\n*/\n");

        $report = (new ThreatIntelAgent(false))->check();

        self::assertSame('OK', $report['feed_status']['status']);
        self::assertSame('ERROR', $report['vulnerability_overview']['status']);
        self::assertArrayHasKey('known_vulnerabilities', $report);
    }

    public function testMalwareInspectorFlagsUploadsPhpAndUnexpectedRootPhp(): void
    {
        wpd_tests_write('wp-content/uploads/2026/03/u5.php', "<?php echo 'shell';");
        wpd_tests_write('wp7.php', "<?php echo 'root shell';");

        $report = (new MalwareInspector())->check();

        self::assertSame('ERROR', $report['malware_summary']['status']);
        self::assertContains('wp-content/uploads/2026/03/u5.php', $report['php_in_uploads']['data']);
        self::assertContains('wp7.php', $report['unexpected_root_php']['data']);
    }
}
