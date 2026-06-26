<?php
declare(strict_types=1);

namespace WPDiagnose\Agents\BackupAgent;

use WPDiagnose\Core\DiagnosticInterface;

/**
 * Class BackupAgent
 * 
 * Manages WordPress database and file backups.
 */
class BackupAgent implements DiagnosticInterface
{
    private array $results = [];
    private bool $wpLoaded = false;
    private string $backupDir;
    private ?array $lastActionResult = null;

    public function __construct(bool $wpLoaded = false)
    {
        $this->wpLoaded = $wpLoaded;
        // Define backup directory path
        $baseDir = defined('ABSPATH') ? ABSPATH : dirname(__DIR__, 4) . '/';
        $this->backupDir = rtrim($baseDir, '/\\') . '/wp-content/uploads/wp-diagnose-backups';
    }

    public function getName(): string
    {
        return 'BackupAgent';
    }

    public function check(): array
    {
        $this->results = [];

        // Ensure backup directory exists
        if (!is_dir($this->backupDir)) {
            @mkdir($this->backupDir, 0755, true);
            // Create .htaccess to block direct HTTP access
            @file_put_contents($this->backupDir . '/.htaccess', "Deny from all\n");
            @file_put_contents($this->backupDir . '/index.html', "");
        }

        $isWritable = is_writable($this->backupDir);
        
        // Scan backup directory
        $backups = [];
        if (is_dir($this->backupDir)) {
            $files = scandir($this->backupDir);
            foreach ($files as $file) {
                if ($file === '.' || $file === '..' || $file === '.htaccess' || $file === 'index.html') {
                    continue;
                }
                $filePath = $this->backupDir . '/' . $file;
                if (is_file($filePath)) {
                    $backups[] = [
                        'filename' => $file,
                        'size' => $this->formatSize(filesize($filePath)),
                        'created_at' => date('Y-m-d H:i:s', filemtime($filePath)),
                        'type' => str_ends_with($file, '.sql') ? 'Database' : 'Files'
                    ];
                }
            }
        }

        $this->results['backup_directory'] = [
            'status' => $isWritable ? 'OK' : 'WARN',
            'info' => $isWritable ? 'Backup folder is writable.' : 'Backup folder is not writable.',
            'data' => $backups
        ];

        // Disk space check
        $freeSpace = @disk_free_space(dirname($this->backupDir));
        $totalSpace = @disk_total_space(dirname($this->backupDir));
        
        if ($freeSpace !== false && $totalSpace !== false) {
            $percentFree = ($freeSpace / $totalSpace) * 100;
            $this->results['disk_space'] = [
                'status' => $percentFree > 10 ? 'OK' : 'WARN',
                'info' => sprintf('Free: %s / Total: %s (%.1f%% free)', $this->formatSize($freeSpace), $this->formatSize($totalSpace), $percentFree)
            ];
        } else {
            $this->results['disk_space'] = [
                'status' => 'OK',
                'info' => 'Unable to determine free disk space.'
            ];
        }

        return $this->results;
    }

    public function report(): array
    {
        return $this->results ?: $this->check();
    }

    public function fix(string $id): bool
    {
        $this->lastActionResult = null;

        if ($id === 'backup_db') {
            return $this->runDatabaseBackup();
        }

        if ($id === 'backup_wpcontent') {
            return $this->runWpContentBackup();
        }

        if ($id === 'backup_full') {
            return $this->runFullBackup();
        }

        if (str_starts_with($id, 'delete_backup:')) {
            $filename = substr($id, 14);
            return $this->deleteBackupFile($filename);
        }

        return false;
    }

    public function getLastActionResult(): ?array
    {
        return $this->lastActionResult;
    }

    private function runDatabaseBackup(): bool
    {
        if (!is_dir($this->backupDir) && !@mkdir($this->backupDir, 0755, true)) {
            $this->lastActionResult = ['success' => false, 'message' => 'Could not create backup directory.'];
            return false;
        }

        $dbConnection = $this->getDatabaseConnection();
        if (!$dbConnection) {
            $this->lastActionResult = ['success' => false, 'message' => 'No active database connection available.'];
            return false;
        }

        $tables = [];
        if ($this->wpLoaded) {
            global $wpdb;
            $tableList = $wpdb->get_col("SHOW TABLES");
            $tables = $tableList ?: [];
        } else {
            $result = $dbConnection->query("SHOW TABLES");
            if ($result) {
                while ($row = $result->fetch_row()) {
                    $tables[] = $row[0];
                }
            }
        }

        if (empty($tables)) {
            $this->lastActionResult = ['success' => false, 'message' => 'No tables found in database.'];
            return false;
        }

        $sqlDump = "-- WordPress Diagnose Tool - Database Backup\n";
        $sqlDump .= "-- Created at: " . date('Y-m-d H:i:s') . " UTC\n\n";
        $sqlDump .= "SET FOREIGN_KEY_CHECKS=0;\n\n";

        foreach ($tables as $table) {
            // Table structure
            if ($this->wpLoaded) {
                global $wpdb;
                $row = $wpdb->get_row("SHOW CREATE TABLE `{$table}`", ARRAY_N);
                $createTableSql = $row[1] ?? '';
            } else {
                $res = $dbConnection->query("SHOW CREATE TABLE `{$table}`");
                $row = $res ? $res->fetch_row() : null;
                $createTableSql = $row[1] ?? '';
            }

            if ($createTableSql) {
                $sqlDump .= "DROP TABLE IF EXISTS `{$table}`;\n";
                $sqlDump .= $createTableSql . ";\n\n";
            }

            // Table data
            if ($this->wpLoaded) {
                global $wpdb;
                $rows = $wpdb->get_results("SELECT * FROM `{$table}`", ARRAY_A);
            } else {
                $res = $dbConnection->query("SELECT * FROM `{$table}`");
                $rows = [];
                if ($res) {
                    while ($row = $res->fetch_assoc()) {
                        $rows[] = $row;
                    }
                }
            }

            if (!empty($rows)) {
                foreach ($rows as $row) {
                    $escapedValues = [];
                    foreach ($row as $val) {
                        if ($val === null) {
                            $escapedValues[] = 'NULL';
                        } else {
                            if ($this->wpLoaded) {
                                $escapedValues[] = "'" . esc_sql($val) . "'";
                            } else {
                                $escapedValues[] = "'" . $dbConnection->escape_string($val) . "'";
                            }
                        }
                    }
                    $sqlDump .= "INSERT INTO `{$table}` VALUES (" . implode(',', $escapedValues) . ");\n";
                }
                $sqlDump .= "\n";
            }
        }

        $sqlDump .= "SET FOREIGN_KEY_CHECKS=1;\n";

        $filename = 'wp-db-backup-' . time() . '-' . bin2hex(random_bytes(4)) . '.sql';
        $filePath = $this->backupDir . '/' . $filename;

        if (file_put_contents($filePath, $sqlDump) !== false) {
            $this->lastActionResult = ['success' => true, 'message' => "Database backup saved successfully as $filename."];
            return true;
        }

        $this->lastActionResult = ['success' => false, 'message' => 'Failed to write SQL backup file. Check permissions.'];
        return false;
    }

    private function runWpContentBackup(): bool
    {
        if (!class_exists('ZipArchive')) {
            $this->lastActionResult = ['success' => false, 'message' => 'ZipArchive PHP extension is not loaded on this server.'];
            return false;
        }

        $filename = 'wp-content-backup-' . time() . '-' . bin2hex(random_bytes(4)) . '.zip';
        $zipPath = $this->backupDir . '/' . $filename;

        $zip = new \ZipArchive();
        if ($zip->open($zipPath, \ZipArchive::CREATE) !== true) {
            $this->lastActionResult = ['success' => false, 'message' => 'Failed to create zip archive.'];
            return false;
        }

        $wpContentDir = dirname($this->backupDir);
        $realWpContent = realpath($wpContentDir);
        $realBackupDir = realpath($this->backupDir);

        if (!$realWpContent) {
            $this->lastActionResult = ['success' => false, 'message' => 'wp-content directory not found.'];
            return false;
        }

        $files = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($realWpContent),
            \RecursiveIteratorIterator::LEAVES_ONLY
        );

        $count = 0;
        foreach ($files as $file) {
            if (!$file->isFile()) {
                continue;
            }

            $filePath = $file->getRealPath();
            
            // Exclude backup directory itself to prevent infinite loop
            if (str_starts_with($filePath, $realBackupDir)) {
                continue;
            }

            // Relative path in ZIP
            $relativePath = substr($filePath, strlen($realWpContent) + 1);
            $zip->addFile($filePath, 'wp-content/' . $relativePath);
            $count++;
        }

        $zip->close();

        if ($count > 0 && is_file($zipPath)) {
            $this->lastActionResult = ['success' => true, 'message' => "wp-content files backed up successfully as $filename ($count files archived)."];
            return true;
        }

        @unlink($zipPath);
        $this->lastActionResult = ['success' => false, 'message' => 'No files were compressed. Archive was deleted.'];
        return false;
    }

    private function runFullBackup(): bool
    {
        if (!class_exists('ZipArchive')) {
            $this->lastActionResult = ['success' => false, 'message' => 'ZipArchive PHP extension is not loaded. Full backup aborted.'];
            return false;
        }

        // Step 1: Run database backup first so we can include it in the zip
        $dbSuccess = $this->runDatabaseBackup();
        $dbFilename = '';
        if ($dbSuccess && isset($this->lastActionResult['message']) && preg_match('/as (wp-db-backup-.*?\.sql)/', $this->lastActionResult['message'], $m)) {
            $dbFilename = $m[1];
        }

        // Step 2: Zip everything in WordPress root
        $filename = 'wp-full-backup-' . time() . '-' . bin2hex(random_bytes(4)) . '.zip';
        $zipPath = $this->backupDir . '/' . $filename;

        $zip = new \ZipArchive();
        if ($zip->open($zipPath, \ZipArchive::CREATE) !== true) {
            if ($dbFilename) {
                @unlink($this->backupDir . '/' . $dbFilename);
            }
            $this->lastActionResult = ['success' => false, 'message' => 'Failed to create zip archive for full backup.'];
            return false;
        }

        $baseDir = defined('ABSPATH') ? ABSPATH : dirname(__DIR__, 4) . '/';
        $realBaseDir = realpath($baseDir);
        $realBackupDir = realpath($this->backupDir);

        $files = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($realBaseDir),
            \RecursiveIteratorIterator::LEAVES_ONLY
        );

        $count = 0;
        foreach ($files as $file) {
            if (!$file->isFile()) {
                continue;
            }

            $filePath = $file->getRealPath();

            // Exclude other backups to avoid recursive sizes, except the db backup we just created
            if (str_starts_with($filePath, $realBackupDir)) {
                if ($dbFilename && $filePath === realpath($this->backupDir . '/' . $dbFilename)) {
                    // Include the DB backup
                } else {
                    continue;
                }
            }

            $relativePath = substr($filePath, strlen($realBaseDir) + 1);
            $zip->addFile($filePath, $relativePath);
            $count++;
        }

        $zip->close();

        // Clean up the DB backup sql file since it is now archived
        if ($dbFilename) {
            @unlink($this->backupDir . '/' . $dbFilename);
        }

        if ($count > 0 && is_file($zipPath)) {
            $this->lastActionResult = ['success' => true, 'message' => "Full WordPress backup completed as $filename ($count files archived)."];
            return true;
        }

        @unlink($zipPath);
        $this->lastActionResult = ['success' => false, 'message' => 'Full backup packaging failed.'];
        return false;
    }

    private function deleteBackupFile(string $filename): bool
    {
        // Sanitize filename to prevent directory traversal
        $filename = basename($filename);
        $filePath = $this->backupDir . '/' . $filename;
        
        if (is_file($filePath) && @unlink($filePath)) {
            $this->lastActionResult = ['success' => true, 'message' => "Backup file '$filename' deleted."];
            return true;
        }

        $this->lastActionResult = ['success' => false, 'message' => 'Failed to delete backup file or file not found.'];
        return false;
    }

    private function getDatabaseConnection()
    {
        if ($this->wpLoaded) {
            global $wpdb;
            return $wpdb;
        }

        global $DB;
        if ($DB instanceof \WPD_DB && $DB->mysqli) {
            return $DB->mysqli;
        }

        return null;
    }

    private function formatSize(float $bytes): string
    {
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];
        for ($i = 0; $bytes >= 1024 && $i < count($units) - 1; $i++) {
            $bytes /= 1024;
        }
        return round($bytes, 2) . ' ' . $units[$i];
    }
}
