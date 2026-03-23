<?php
declare(strict_types=1);

$projectRoot = dirname(__DIR__);

require_once $projectRoot . '/Core/Version.php';
require_once $projectRoot . '/Core/SecurityManager.php';
require_once $projectRoot . '/Core/DiagnosticInterface.php';
require_once $projectRoot . '/Core/Engine.php';
require_once $projectRoot . '/Core/Cleanup.php';
require_once $projectRoot . '/src/Agents/ServerInspector/ServerInspector.php';
require_once $projectRoot . '/src/Agents/WPInspector/WPInspector.php';
require_once $projectRoot . '/src/Agents/SecurityInspector/SecurityInspector.php';
require_once $projectRoot . '/src/Agents/BootstrapInspector/BootstrapInspector.php';
require_once $projectRoot . '/src/Agents/DBHealth/DBHealth.php';
require_once $projectRoot . '/src/Agents/CoreIntegrityAgent/CoreIntegrityAgent.php';
require_once $projectRoot . '/src/Agents/AssetManagerAgent/AssetManagerAgent.php';
require_once $projectRoot . '/src/Agents/CoreOperationsAgent/CoreOperationsAgent.php';

if (!defined('WPD_TEST_ROOT')) {
    define('WPD_TEST_ROOT', sys_get_temp_dir() . '/wp-diagnose-tests-root/');
}

if (!defined('ABSPATH')) {
    define('ABSPATH', WPD_TEST_ROOT);
}

function wpd_tests_reset_root(): void
{
    if (is_dir(WPD_TEST_ROOT)) {
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator(WPD_TEST_ROOT, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );

        foreach ($iterator as $item) {
            if ($item->isDir()) {
                @rmdir($item->getPathname());
            } else {
                @unlink($item->getPathname());
            }
        }

        @rmdir(WPD_TEST_ROOT);
    }

    mkdir(WPD_TEST_ROOT, 0777, true);
    mkdir(WPD_TEST_ROOT . 'wp-content/plugins', 0777, true);
    mkdir(WPD_TEST_ROOT . 'wp-content/themes', 0777, true);
    mkdir(WPD_TEST_ROOT . 'wp-includes', 0777, true);
}

function wpd_tests_write(string $relativePath, string $contents): void
{
    $fullPath = WPD_TEST_ROOT . str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $relativePath);
    $directory = dirname($fullPath);
    if (!is_dir($directory)) {
        mkdir($directory, 0777, true);
    }

    file_put_contents($fullPath, $contents);
}

function wpd_tests_read(string $relativePath): string
{
    return (string) file_get_contents(WPD_TEST_ROOT . str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $relativePath));
}

wpd_tests_reset_root();
