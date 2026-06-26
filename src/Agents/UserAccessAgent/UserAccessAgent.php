<?php
declare(strict_types=1);

namespace WPDiagnose\Agents\UserAccessAgent {

    use WPDiagnose\Core\DiagnosticInterface;

    /**
     * Class UserAccessAgent
     * 
     * Audits and manages administrator accounts and user privileges.
     */
    class UserAccessAgent implements DiagnosticInterface
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
            return 'UserAccessAgent';
        }

        public function check(): array
        {
            $this->results = [];
            $admins = [];

            $dbConnection = $this->getDatabaseConnection();
            if ($this->wpLoaded) {
                $userQuery = new \WP_User_Query([
                    'role' => 'administrator',
                    'orderby' => 'user_registered',
                    'order' => 'DESC'
                ]);
                $users = $userQuery->get_results();
                foreach ($users as $user) {
                    $admins[] = [
                        'id' => $user->ID,
                        'user_login' => $user->user_login,
                        'user_email' => $user->user_email,
                        'registered' => $user->user_registered,
                    ];
                }
            } elseif ($dbConnection) {
                // Independent mode DB query
                $prefix = $this->getTablePrefix();
                // Find users having 'administrator' in their capabilities usermeta
                $query = "
                    SELECT u.ID, u.user_login, u.user_email, u.user_registered 
                    FROM {$prefix}users u
                    INNER JOIN {$prefix}usermeta m ON u.ID = m.user_id
                    WHERE m.meta_key = '{$prefix}capabilities' 
                      AND m.meta_value LIKE '%administrator%'
                    ORDER BY u.user_registered DESC
                ";
                
                if ($this->wpLoaded) {
                    global $wpdb;
                    $rows = $wpdb->get_results($query, ARRAY_A);
                } else {
                    $res = $dbConnection->query($query);
                    $rows = [];
                    if ($res) {
                        while ($row = $res->fetch_assoc()) {
                            $rows[] = $row;
                        }
                    }
                }

                foreach ($rows as $row) {
                    $admins[] = [
                        'id' => (int)$row['ID'],
                        'user_login' => $row['user_login'],
                        'user_email' => $row['user_email'],
                        'registered' => $row['user_registered'],
                    ];
                }
            }

            // Flag suspicious domains or registration times
            $warnings = 0;
            $suspiciousDomains = ['tempmail', 'throwaway', 'mailinator', 'yopmail'];
            foreach ($admins as $admin) {
                $email = strtolower($admin['user_email']);
                foreach ($suspiciousDomains as $domain) {
                    if (str_contains($email, $domain)) {
                        $warnings++;
                    }
                }
            }

            $this->results['admin_accounts'] = [
                'status' => $warnings > 0 ? 'WARN' : 'OK',
                'info' => sprintf('%d Administrator account(s) registered.', count($admins)),
                'data' => $admins
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

            if (str_starts_with($id, 'demote_admin:')) {
                $userId = (int)substr($id, 13);
                return $this->demoteAdmin($userId);
            }

            if (str_starts_with($id, 'delete_user:')) {
                $userId = (int)substr($id, 12);
                return $this->deleteUser($userId);
            }

            return false;
        }

        public function getLastActionResult(): ?array
        {
            return $this->lastActionResult;
        }

        private function demoteAdmin(int $userId): bool
        {
            $dbConnection = $this->getDatabaseConnection();
            if ($this->wpLoaded) {
                $user = get_userdata($userId);
                if ($user) {
                    // Prevent self-demotion
                    if (function_exists('get_current_user_id') && get_current_user_id() === $userId) {
                        $this->lastActionResult = ['success' => false, 'message' => 'Demoting your own logged-in user is blocked.'];
                        return false;
                    }

                    $user->set_role('subscriber');
                    $this->lastActionResult = ['success' => true, 'message' => "User ID $userId has been demoted to subscriber."];
                    return true;
                }
            } elseif ($dbConnection) {
                $prefix = $this->getTablePrefix();
                // Update capabilities usermeta to subscriber
                $subMeta = serialize(['subscriber' => true]);
                $stmt = $dbConnection->prepare("UPDATE {$prefix}usermeta SET meta_value = ? WHERE user_id = ? AND meta_key = ?");
                if ($stmt) {
                    $key = $prefix . 'capabilities';
                    $stmt->bind_param("sis", $subMeta, $userId, $key);
                    $result = $stmt->execute();
                    $stmt->close();
                    if ($result) {
                        $this->lastActionResult = ['success' => true, 'message' => "User ID $userId demoted to subscriber via database."];
                        return true;
                    }
                }
            }

            $this->lastActionResult = ['success' => false, 'message' => 'Failed to demote administrator.'];
            return false;
        }

        private function deleteUser(int $userId): bool
        {
            $dbConnection = $this->getDatabaseConnection();
            if ($this->wpLoaded) {
                require_once ABSPATH . 'wp-admin/includes/user.php';
                // Prevent self-deletion
                if (function_exists('get_current_user_id') && get_current_user_id() === $userId) {
                    $this->lastActionResult = ['success' => false, 'message' => 'Deleting your own logged-in user is blocked.'];
                    return false;
                }
                
                if (wp_delete_user($userId)) {
                    $this->lastActionResult = ['success' => true, 'message' => "User ID $userId deleted successfully."];
                    return true;
                }
            } elseif ($dbConnection) {
                $prefix = $this->getTablePrefix();
                
                $dbConnection->begin_transaction();
                try {
                    $stmt1 = $dbConnection->prepare("DELETE FROM {$prefix}users WHERE ID = ?");
                    $stmt1->bind_param("i", $userId);
                    $stmt1->execute();
                    $stmt1->close();

                    $stmt2 = $dbConnection->prepare("DELETE FROM {$prefix}usermeta WHERE user_id = ?");
                    $stmt2->bind_param("i", $userId);
                    $stmt2->execute();
                    $stmt2->close();

                    $dbConnection->commit();
                    $this->lastActionResult = ['success' => true, 'message' => "User ID $userId deleted from database."];
                    return true;
                } catch (\Throwable $e) {
                    $dbConnection->rollback();
                }
            }

            $this->lastActionResult = ['success' => false, 'message' => 'Failed to delete user.'];
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
