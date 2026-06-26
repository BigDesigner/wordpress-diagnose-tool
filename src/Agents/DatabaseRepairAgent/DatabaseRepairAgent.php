<?php
declare(strict_types=1);

namespace WPDiagnose\Agents\DatabaseRepairAgent {

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
    }
}
