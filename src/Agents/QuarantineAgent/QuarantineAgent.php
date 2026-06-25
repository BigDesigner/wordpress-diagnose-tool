<?php
declare(strict_types=1);

namespace WPDiagnose\Agents\QuarantineAgent {

    use WPDiagnose\Core\DiagnosticInterface;

    /**
     * Class QuarantineAgent
     * 
     * Isolates and restores suspicious files to prevent active malware executions.
     */
    class QuarantineAgent implements DiagnosticInterface
    {
        private array $results = [];
        private string $quarantineDir;
        private string $manifestPath;
        private ?array $lastActionResult = null;

        public function __construct()
        {
            $baseDir = defined('ABSPATH') ? ABSPATH : dirname(__DIR__, 4) . '/';
            $this->quarantineDir = rtrim($baseDir, '/\\') . '/wp-content/uploads/wp-diagnose-backups/.quarantine';
            $this->manifestPath = $this->quarantineDir . '/manifest.json';
        }

        public function getName(): string
        {
            return 'QuarantineAgent';
        }

        public function check(): array
        {
            $this->results = [];
            $manifest = $this->loadManifest();

            $this->results['quarantine_status'] = [
                'status' => 'OK',
                'info' => sprintf('%d file(s) currently in quarantine.', count($manifest)),
                'data' => $manifest
            ];

            return $this->results;
        }

        public function fix(string $id): bool
        {
            $this->lastActionResult = null;

            if (str_starts_with($id, 'quarantine_file:')) {
                $filePath = base64_decode(substr($id, 16));
                return $this->quarantineFile($filePath);
            }

            if (str_starts_with($id, 'restore_file:')) {
                $fileHash = substr($id, 13);
                return $this->restoreFile($fileHash);
            }

            if (str_starts_with($id, 'delete_quarantined:')) {
                $fileHash = substr($id, 19);
                return $this->deleteQuarantined($fileHash);
            }

            return false;
        }

        public function getLastActionResult(): ?array
        {
            return $this->lastActionResult;
        }

        private function quarantineFile(string $filePath): bool
        {
            // Resolve real path of ABSPATH to prevent outside manipulations
            $baseDir = realpath(defined('ABSPATH') ? ABSPATH : dirname(__DIR__, 4) . '/');
            $realPath = realpath($filePath);

            if (!$realPath || !is_file($realPath)) {
                $this->lastActionResult = ['success' => false, 'message' => "File '$filePath' not found or invalid."];
                return false;
            }

            // Prevent quarantining wp-config.php or this script itself
            $fileName = basename($realPath);
            if ($fileName === 'wp-config.php' || str_contains($fileName, 'wp-diagnose')) {
                $this->lastActionResult = ['success' => false, 'message' => 'Quarantining critical diagnostic or configuration files is blocked.'];
                return false;
            }

            if (!is_dir($this->quarantineDir)) {
                @mkdir($this->quarantineDir, 0755, true);
                @file_put_contents($this->quarantineDir . '/.htaccess', "Deny from all\n");
            }

            $fileHash = md5($realPath);
            $quarantinePath = $this->quarantineDir . '/' . $fileHash . '.bin';

            $manifest = $this->loadManifest();
            if (isset($manifest[$fileHash])) {
                $this->lastActionResult = ['success' => false, 'message' => 'File is already in quarantine.'];
                return false;
            }

            // Save permissions
            $perms = fileperms($realPath);

            // Move the file
            if (@rename($realPath, $quarantinePath)) {
                $manifest[$fileHash] = [
                    'hash' => $fileHash,
                    'original_path' => $filePath,
                    'filename' => $fileName,
                    'size' => filesize($quarantinePath),
                    'perms' => $perms,
                    'quarantined_at' => date('Y-m-d H:i:s')
                ];
                $this->saveManifest($manifest);
                $this->lastActionResult = ['success' => true, 'message' => "File '$fileName' quarantined successfully."];
                return true;
            }

            $this->lastActionResult = ['success' => false, 'message' => "Could not move file '$fileName' to quarantine. Check permissions."];
            return false;
        }

        private function restoreFile(string $fileHash): bool
        {
            $manifest = $this->loadManifest();
            if (!isset($manifest[$fileHash])) {
                $this->lastActionResult = ['success' => false, 'message' => 'File entry not found in quarantine manifest.'];
                return false;
            }

            $entry = $manifest[$fileHash];
            $quarantinePath = $this->quarantineDir . '/' . $fileHash . '.bin';
            $originalPath = $entry['original_path'];

            if (!is_file($quarantinePath)) {
                $this->lastActionResult = ['success' => false, 'message' => 'Quarantine storage file is missing.'];
                return false;
            }

            // Ensure destination directory exists
            $destDir = dirname($originalPath);
            if (!is_dir($destDir)) {
                @mkdir($destDir, 0755, true);
            }

            if (@rename($quarantinePath, $originalPath)) {
                @chmod($originalPath, $entry['perms'] & 0777);
                unset($manifest[$fileHash]);
                $this->saveManifest($manifest);
                $this->lastActionResult = ['success' => true, 'message' => "File '{$entry['filename']}' restored to original path."];
                return true;
            }

            $this->lastActionResult = ['success' => false, 'message' => "Failed to restore file to '{$originalPath}'."];
            return false;
        }

        private function deleteQuarantined(string $fileHash): bool
        {
            $manifest = $this->loadManifest();
            if (!isset($manifest[$fileHash])) {
                $this->lastActionResult = ['success' => false, 'message' => 'File entry not found in quarantine manifest.'];
                return false;
            }

            $entry = $manifest[$fileHash];
            $quarantinePath = $this->quarantineDir . '/' . $fileHash . '.bin';

            @unlink($quarantinePath);
            unset($manifest[$fileHash]);
            $this->saveManifest($manifest);

            $this->lastActionResult = ['success' => true, 'message' => "Quarantined file '{$entry['filename']}' permanently deleted."];
            return true;
        }

        private function loadManifest(): array
        {
            if (is_file($this->manifestPath)) {
                $data = json_decode((string)file_get_contents($this->manifestPath), true);
                return is_array($data) ? $data : [];
            }
            return [];
        }

        private function saveManifest(array $manifest): void
        {
            @file_put_contents($this->manifestPath, json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
        }
    }
}
