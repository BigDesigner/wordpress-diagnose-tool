<?php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use WPDiagnose\Agents\AssetManagerAgent\AssetManagerAgent;
use WPDiagnose\Agents\BootstrapInspector\BootstrapInspector;
use WPDiagnose\Agents\CoreIntegrityAgent\CoreIntegrityAgent;
use WPDiagnose\Agents\CoreOperationsAgent\CoreOperationsAgent;
use WPDiagnose\Agents\DBHealth\DBHealth;
use WPDiagnose\Agents\SecurityInspector\SecurityInspector;
use WPDiagnose\Agents\ServerInspector\ServerInspector;
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
}
