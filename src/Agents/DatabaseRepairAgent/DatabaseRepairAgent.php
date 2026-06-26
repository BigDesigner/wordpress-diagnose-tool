<?php
declare(strict_types=1);

namespace WPDiagnose\Agents\DatabaseRepairAgent;

use WPDiagnose\Core\DiagnosticInterface;

/**
 * Class DatabaseRepairAgent
 * 
 * Optimizes and repairs crashed database tables.
 */
class DatabaseRepairAgent implements DiagnosticInterface
{
    private array $results = [];
    private bool $wpLoaded = false;
    private ?array $lastActionResult = null;

    public function __construct(bool $wpLoaded = false)
    {
        $this->wpLoaded = $wpLoaded;
    }

    public function getName(): string
    {
        return 'DatabaseRepairAgent';
    }

    public function check(): array
    {
        $this->results = [];

        $dbConnection = $this->getDatabaseConnection();
        if (!$dbConnection) {
            $this->results['database_repair_status'] = [
                'status' => 'WARN',
                'info' => 'No active database connection. Repair routines unavailable.'
            ];
            return $this->results;
        }

        $prefix = $this->getTablePrefix();
        $tables = [];

        if ($this->wpLoaded) {
            global $wpdb;
            $tables = $wpdb->get_col("SHOW TABLES LIKE '{$prefix}%'");
        } else {
            $res = $dbConnection->query("SHOW TABLES LIKE '{$prefix}%'");
            if ($res) {
                while ($row = $res->fetch_row()) {
                    $tables[] = $row[0];
                }
            }
        }

        $crashedTables = [];
        foreach ($tables as $table) {
            $checkQuery = "CHECK TABLE `{$table}`";
            $status = 'OK';
            
            if ($this->wpLoaded) {
                global $wpdb;
                $rows = $wpdb->get_results($checkQuery, ARRAY_A);
            } else {
                $res = $dbConnection->query($checkQuery);
                $rows = [];
                if ($res) {
                    while ($row = $res->fetch_assoc()) {
                        $rows[] = $row;
                    }
                }
            }

            foreach ($rows as $row) {
                $msgType = strtolower($row['Msg_type'] ?? '');
                $msgText = strtolower($row['Msg_text'] ?? '');
                if (($msgType === 'status' && $msgText !== 'ok') || 
                    ($msgType === 'error') || 
                    str_contains($msgText, 'corrupt') || 
                    str_contains($msgText, 'crashed')) {
                    $status = 'ERROR';
                    $crashedTables[] = $table;
                    break;
                }
            }
        }

        $hasCrashed = count($crashedTables) > 0;
        $this->results['table_integrity'] = [
            'status' => $hasCrashed ? 'ERROR' : 'OK',
            'info' => $hasCrashed 
                ? sprintf('%d crashed database tables detected.', count($crashedTables))
                : 'All database tables passed health check.',
            'data' => $crashedTables
        ];

        return $this->results;
    }

    public function report(): array
    {
        return $this->results ?: $this->check();
    }

    public function fix(string $id): bool
    {
        $this->lastActionResult = null;

        if ($id === 'repair_database') {
            return $this->repairDatabase();
        }

        if ($id === 'search_replace') {
            $search = $_POST['search'] ?? $_GET['search'] ?? '';
            $replace = $_POST['replace'] ?? $_GET['replace'] ?? '';
            return $this->dbSearchReplace($search, $replace);
        }

        return false;
    }

    public function getLastActionResult(): ?array
    {
        return $this->lastActionResult;
    }

    private function repairDatabase(): bool
    {
        $dbConnection = $this->getDatabaseConnection();
        if (!$dbConnection) {
            $this->lastActionResult = ['success' => false, 'message' => 'No database connection.'];
            return false;
        }

        $prefix = $this->getTablePrefix();
        $tables = [];

        if ($this->wpLoaded) {
            global $wpdb;
            $tables = $wpdb->get_col("SHOW TABLES LIKE '{$prefix}%'");
        } else {
            $res = $dbConnection->query("SHOW TABLES LIKE '{$prefix}%'");
            if ($res) {
                while ($row = $res->fetch_row()) {
                    $tables[] = $row[0];
                }
            }
        }

        $repaired = [];
        foreach ($tables as $table) {
            $repairQuery = "REPAIR TABLE `{$table}`";
            $optimizeQuery = "OPTIMIZE TABLE `{$table}`";
            
            if ($this->wpLoaded) {
                global $wpdb;
                $wpdb->query($repairQuery);
                $wpdb->query($optimizeQuery);
            } else {
                $dbConnection->query($repairQuery);
                $dbConnection->query($optimizeQuery);
            }
            $repaired[] = $table;
        }

        $this->lastActionResult = [
            'success' => true, 
            'message' => sprintf('Repaired and optimized %d tables successfully.', count($repaired))
        ];
        return true;
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

    private function getTablePrefix(): string
    {
        if ($this->wpLoaded) {
            global $wpdb;
            return $wpdb->prefix;
        }

        global $DB;
        if ($DB instanceof \WPD_DB && $DB->prefix) {
            return $DB->prefix;
        }

        return 'wp_';
    }

    private function dbSearchReplace(string $search, string $replace): bool
    {
        if ($search === '') {
            $this->lastActionResult = ['success' => false, 'message' => 'Search term cannot be empty.'];
            return false;
        }

        $dbConnection = $this->getDatabaseConnection();
        if (!$dbConnection) {
            $this->lastActionResult = ['success' => false, 'message' => 'No database connection.'];
            return false;
        }

        $prefix = $this->getTablePrefix();
        $tables = [];

        if ($this->wpLoaded) {
            global $wpdb;
            $tables = $wpdb->get_col("SHOW TABLES LIKE '{$prefix}%'");
        } else {
            $res = $dbConnection->query("SHOW TABLES LIKE '{$prefix}%'");
            if ($res) {
                while ($row = $res->fetch_row()) {
                    $tables[] = $row[0];
                }
            }
        }

        $totalUpdatedRows = 0;
        $totalTablesScanned = 0;

        foreach ($tables as $table) {
            $columnsQuery = "SHOW COLUMNS FROM `{$table}`";
            $columns = [];
            $primaryKey = null;

            if ($this->wpLoaded) {
                global $wpdb;
                $colsData = $wpdb->get_results($columnsQuery, ARRAY_A);
            } else {
                $res = $dbConnection->query($columnsQuery);
                $colsData = [];
                if ($res) {
                    while ($row = $res->fetch_assoc()) {
                        $colsData[] = $row;
                    }
                }
            }

            foreach ($colsData as $col) {
                $type = strtolower($col['Type'] ?? '');
                $key = strtolower($col['Key'] ?? '');
                if ($key === 'pri') {
                    $primaryKey = $col['Field'];
                }
                if (str_contains($type, 'char') || str_contains($type, 'text') || str_contains($type, 'blob')) {
                    $columns[] = $col['Field'];
                }
            }

            if (empty($columns) || !$primaryKey) {
                continue;
            }

            $totalTablesScanned++;
            $selectQuery = "SELECT `" . implode("`, `", array_merge([$primaryKey], $columns)) . "` FROM `{$table}`";
            
            if ($this->wpLoaded) {
                global $wpdb;
                $rows = $wpdb->get_results($selectQuery, ARRAY_A);
            } else {
                $res = $dbConnection->query($selectQuery);
                $rows = [];
                if ($res) {
                    while ($row = $res->fetch_assoc()) {
                        $rows[] = $row;
                    }
                }
            }

            foreach ($rows as $row) {
                $pkValue = $row[$primaryKey];
                $updates = [];
                $params = [];

                foreach ($columns as $col) {
                    $originalVal = $row[$col];
                    if ($originalVal === null || $originalVal === '') {
                        continue;
                    }
                    if (str_contains($originalVal, $search)) {
                        $newVal = $this->processValue($originalVal, $search, $replace);
                        if ($newVal !== $originalVal) {
                            $updates[] = "`{$col}` = ?";
                            $params[] = $newVal;
                        }
                    }
                }

                if (!empty($updates)) {
                    $updateSql = "UPDATE `{$table}` SET " . implode(", ", $updates) . " WHERE `{$primaryKey}` = ?";
                    $params[] = $pkValue;

                    if ($this->wpLoaded) {
                        global $wpdb;
                        $wpdb->query($wpdb->prepare($updateSql, ...$params));
                    } else {
                        $stmt = $dbConnection->prepare($updateSql);
                        if ($stmt) {
                            $types = str_repeat('s', count($params));
                            $stmt->bind_param($types, ...$params);
                            $stmt->execute();
                            $stmt->close();
                        }
                    }
                    $totalUpdatedRows++;
                }
            }
        }

        $this->lastActionResult = [
            'success' => true,
            'message' => sprintf('Serialized-safe Search & Replace complete. Scanned %d tables. Updated %d rows.', $totalTablesScanned, $totalUpdatedRows)
        ];
        return true;
    }

    private function processValue(string $value, string $search, string $replace): string
    {
        if ($search === '') {
            return $value;
        }

        $isSerialized = false;
        $unserialized = null;

        if (preg_match('/^[aOisd]:/', $value)) {
            $unserialized = @unserialize($value);
            if ($unserialized !== false || $value === 'b:0;') {
                $isSerialized = true;
            }
        }

        if ($isSerialized) {
            $this->recursiveSearchReplace($unserialized, $search, $replace);
            return serialize($unserialized);
        }

        return str_replace($search, $replace, $value);
    }

    private function recursiveSearchReplace(&$data, string $search, string $replace): void
    {
        if (is_string($data)) {
            $data = str_replace($search, $replace, $data);
        } elseif (is_array($data)) {
            foreach ($data as $key => &$value) {
                $this->recursiveSearchReplace($value, $search, $replace);
            }
        } elseif (is_object($data)) {
            $properties = get_object_vars($data);
            foreach ($properties as $property => $value) {
                $this->recursiveSearchReplace($data->$property, $search, $replace);
            }
        }
    }
}
