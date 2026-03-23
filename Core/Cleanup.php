<?php
declare(strict_types=1);

namespace WPDiagnose\Core;

/**
 * Class Cleanup
 * 
 * Handles recursive directory deletion and full system wipe for the self-destruct mechanism.
 */
class Cleanup
{
    /**
     * Performs a full recursive wipe of all project directories and files.
     * 
     * @return bool True if successful, false otherwise.
     */
    public static function fullWipe(): bool
    {
        $success = true;
        $roots = self::detectRoots();

        foreach (self::buildTargets($roots) as $target) {
            if (is_dir($target)) {
                $success = $success && self::recursiveRmdir($target);
            } elseif (is_file($target)) {
                $success = $success && @unlink($target);
            }
        }

        return $success;
    }

    /**
     * Detects likely project roots for both source and bundled deployments.
     *
     * @return array<int, string>
     */
    private static function detectRoots(): array
    {
        $roots = [basename(__DIR__) === 'Core' ? dirname(__DIR__) : __DIR__];
        $scriptFile = $_SERVER['SCRIPT_FILENAME'] ?? '';

        if (is_string($scriptFile) && $scriptFile !== '') {
            $scriptDir = dirname($scriptFile);
            $roots[] = $scriptDir;

            if (basename($scriptDir) === 'src') {
                $roots[] = dirname($scriptDir);
            }
        }

        return array_values(array_unique(array_filter($roots, 'is_dir')));
    }

    /**
     * Builds the list of files and directories that belong to this tool.
     *
     * @param array<int, string> $roots
     * @return array<int, string>
     */
    private static function buildTargets(array $roots): array
    {
        $targets = [];
        $scriptFile = $_SERVER['SCRIPT_FILENAME'] ?? '';
        $scriptDir = is_string($scriptFile) && $scriptFile !== '' ? dirname($scriptFile) : '';

        foreach ($roots as $root) {
            $targets[] = $root . '/Core';
            $targets[] = $root . '/src';
            $targets[] = $root . '/.ht-wp-diagnose.log';
            $targets[] = $root . '/wp-diagnose.php';
            $targets[] = $root . '/wp-diagnose-pro.php';

            // Only remove the redirect stub when the tool is running from its own subdirectory.
            if ($scriptDir !== '' && $root === $scriptDir && basename($root) === 'diagnose') {
                $targets[] = $root . '/index.php';
            }
        }

        if (is_string($scriptFile) && $scriptFile !== '') {
            $targets[] = $scriptFile;
        }

        return array_values(array_unique($targets));
    }

    /**
     * Recursively deletes a directory and its contents.
     * 
     * @param string $dir
     * @return bool
     */
    private static function recursiveRmdir(string $dir): bool
    {
        if (!is_dir($dir)) {
            return false;
        }

        $items = array_diff(scandir($dir), ['.', '..']);
        foreach ($items as $item) {
            $path = $dir . DIRECTORY_SEPARATOR . $item;
            is_dir($path) ? self::recursiveRmdir($path) : @unlink($path);
        }

        return @rmdir($dir);
    }
}
