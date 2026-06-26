<?php
declare(strict_types=1);

namespace WPDiagnose\Agents\MailAgent;

use WPDiagnose\Core\DiagnosticInterface;

/**
 * Class MailAgent
 * 
 * Diagnoses mail transmission systems and triggers test delivery actions.
 */
class MailAgent implements DiagnosticInterface
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
        return 'MailAgent';
    }

    public function check(): array
    {
        $this->results = [];

        $wpMailExists = function_exists('wp_mail');
        $smtpPlugin = 'None';
        
        if ($this->wpLoaded) {
            // Check common SMTP plugins
            $smtpPluginsList = [
                'wp-mail-smtp/wp_mail_smtp.php' => 'WP Mail SMTP',
                'easy-wp-smtp/easy-wp-smtp.php' => 'Easy WP SMTP',
                'post-smtp/postman-smtp.php' => 'Post SMTP',
                'smtp-mailer/smtp-mailer.php' => 'SMTP Mailer'
            ];
            
            $activePlugins = get_option('active_plugins', []);
            foreach ($smtpPluginsList as $file => $name) {
                if (in_array($file, $activePlugins)) {
                    $smtpPlugin = $name;
                    break;
                }
            }
        }

        $this->results['mail_system'] = [
            'status' => $wpMailExists ? 'OK' : 'WARN',
            'info' => $wpMailExists 
                ? "wp_mail function is loaded. SMTP provider: $smtpPlugin."
                : 'wp_mail is not loaded. Fallback PHP mail() will be used.',
            'data' => [
                'smtp_provider' => $smtpPlugin
            ]
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

        if (str_starts_with($id, 'send_test_mail:')) {
            $email = substr($id, 15);
            return $this->sendTestMail($email);
        }

        return false;
    }

    public function getLastActionResult(): ?array
    {
        return $this->lastActionResult;
    }

    private function sendTestMail(string $email): bool
    {
        // Basic validation
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $this->lastActionResult = ['success' => false, 'message' => "Invalid destination email address: '$email'."];
            return false;
        }

        $subject = 'WordPress Diagnose Tool - Mail System Test';
        $message = "This is a test email sent from the WordPress Diagnose Tool at " . date('Y-m-d H:i:s') . " UTC.\n" .
                   "If you received this message, the email transmission layer on your server is functioning.";
        
        // Set error handler to capture php mail warnings
        $phpMailError = '';
        set_error_handler(function($errno, $errstr) use (&$phpMailError) {
            $phpMailError = $errstr;
        });

        $success = false;
        try {
            if ($this->wpLoaded && function_exists('wp_mail')) {
                $success = wp_mail($email, $subject, $message);
            } else {
                $headers = 'From: no-reply@' . ($_SERVER['HTTP_HOST'] ?? 'localhost') . "\r\n";
                $success = mail($email, $subject, $message, $headers);
            }
        } catch (\Throwable $e) {
            $phpMailError = $e->getMessage();
        }

        restore_error_handler();

        if ($success) {
            $this->lastActionResult = ['success' => true, 'message' => "Test email successfully dispatched to $email."];
            return true;
        }

        $errMsg = !empty($phpMailError) ? $phpMailError : 'Unknown transmission failure.';
        $this->lastActionResult = ['success' => false, 'message' => "Failed to dispatch email: $errMsg"];
        return false;
    }
}
