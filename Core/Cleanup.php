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
        $baseDir = dirname(__DIR__); // Assumes calling from Core/Cleanup.php
        $targets = [
            $baseDir . '/Core',
            $baseDir . '/src',
            $baseDir . '/.ht-wp-diagnose.log'
        ];

        $success = true;

        foreach ($targets as $target) {
            if (is_dir($target)) {
                $success = $success && self::recursiveRmdir($target);
            } elseif (is_file($target)) {
                $success = $success && @unlink($target);
            }
        }

        // Self-delete the main entry file if it exists in the same root
        $mainFile = $baseDir . '/wp-diagnose.php';
        if (is_file($mainFile)) {
            $success = $success && @unlink($mainFile);
        }

        return $success;
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
