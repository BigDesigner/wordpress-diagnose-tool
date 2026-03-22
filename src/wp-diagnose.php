<?php
/**
 * WP Diagnose v0.2.1-beta – Single File, EN/TR, Full & DB Mode
 * A drop-in diagnosis, maintenance, and plugin management tool for WordPress.
 * Upload to root directory as `wp-diagnose.php` – use it – then delete it.
 *
 * Author: https://github.com/BigDesigner
 *
 * v0.2.1-beta - Fresh start baseline.
 */

require_once __DIR__ . '/Core/DiagnosticInterface.php';
require_once __DIR__ . '/Core/Engine.php';
require_once __DIR__ . '/Core/Cleanup.php';
require_once __DIR__ . '/src/Agents/ServerInspector/ServerInspector.php';
require_once __DIR__ . '/src/Agents/WPInspector/WPInspector.php';
require_once __DIR__ . '/src/Agents/SecurityInspector/SecurityInspector.php';
require_once __DIR__ . '/src/Agents/BootstrapInspector/BootstrapInspector.php';
require_once __DIR__ . '/src/Agents/DBHealth/DBHealth.php';

// -------------------- WP-CLI INTEGRATION --------------------
if (defined('WP_CLI') && WP_CLI) {
    \WP_CLI::add_command('diagnose run', function($args, $assoc_args) {
        $engine = new \WPDiagnose\Core\Engine();
        $engine->registerAgent(new \WPDiagnose\Agents\ServerInspector\ServerInspector());
        $engine->registerAgent(new \WPDiagnose\Agents\WPInspector\WPInspector(true));
        $engine->registerAgent(new \WPDiagnose\Agents\SecurityInspector\SecurityInspector());
        $engine->registerAgent(new \WPDiagnose\Agents\BootstrapInspector\BootstrapInspector());
        $engine->registerAgent(new \WPDiagnose\Agents\DBHealth\DBHealth(true));

        if (isset($assoc_args['fix'])) {
            $agent = $assoc_args['agent'] ?? 'ServerInspector';
            $target = $assoc_args['fix'];
            \WP_CLI::log("Executing fix routine for '{$target}' via [{$agent}]...");
            $engine->performFix($agent, $target);
            return;
        }

        \WP_CLI::line(\WP_CLI::colorize('%BStarting WP Diagnose Agentic Engine...%n'));
        $reports = $engine->getReports();
        foreach ($reports as $agentName => $data) {
            \WP_CLI::success("Report: {$agentName}");
            print_r($data);
        }
    });
}

// In API/JSON mode suppress all notices so they never contaminate the JSON stream.
// In browser mode keep full error reporting for diagnostics.
$is_api_request = (isset($_GET['format']) && $_GET['format'] === 'json') || isset($_GET['action']);
if ($is_api_request) {
    error_reporting(0);
    ini_set('display_errors', '0');
} else {
    error_reporting(E_ALL);
    ini_set('display_errors', '1');
}

// Start output buffering immediately so any stray output can be discarded before JSON output.
ob_start();

// -------------------- 0.2.1-beta SECURITY CONFIGURATION --------------------
define('DIAG_TOKEN', 'SECURE_TOKEN_2026'); // Usage: wp-diagnose.php?token=SECURE_TOKEN_2026
define('ALLOWED_IPS', ['127.0.0.1', '::1', 'CHANGE_TO_YOUR_STATIC_IP']); // Strict IP Allowlist
define('LOG_FILE', __DIR__ . '/.ht-wp-diagnose.log');

// -------------------- SECURITY ENFORCER --------------------
$client_ip = $_SERVER['HTTP_CLIENT_IP'] ?? $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'];
if (!in_array($client_ip, ALLOWED_IPS, true) && ALLOWED_IPS[2] !== 'CHANGE_TO_YOUR_STATIC_IP') {
    http_response_code(403);
    die('403 Forbidden: IP Address not whitelisted.');
}

if (!isset($_GET['token']) || $_GET['token'] !== DIAG_TOKEN) {
    http_response_code(401);
    die('401 Unauthorized: Invalid or missing access token.');
}

// -------------------- Try load WordPress --------------------
$WP_LOADED = false;
$base = __DIR__;

// If API request, prepare for accidental exit/fatal in wp-load.php
if ($is_api_request) {
    register_shutdown_function(function() {
        if (!defined('ABSPATH') && !headers_sent()) {
            while (ob_get_level()) ob_end_clean();
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode([
                'status'  => 'error',
                'message' => 'WordPress Load Interrupted: Fatal Error or Exit detected during bootstrap.'
            ], JSON_UNESCAPED_UNICODE);
        }
    });
}

for ($i = 0; $i <= 5; $i++) {
    $cand = $base . '/wp-load.php';
    if (is_file($cand)) {
        try {
            require_once $cand;
            $WP_LOADED = true;
        } catch (\Throwable $e) {
            // Catch fatal errors/exceptions to prevent catastrophic failure
            $WP_LOADED = false;
        }
        break;
    }
    $base = dirname($base);
}

// -------------------- JSON API & Actions --------------------
$is_json = (isset($_GET['format']) && $_GET['format'] === 'json') || 
           (isset($_SERVER['HTTP_ACCEPT']) && strpos($_SERVER['HTTP_ACCEPT'], 'application/json') !== false);

if ($is_json || isset($_GET['action'])) {
    
    // Sanitize & Debug API for predictable JSON parsing
    error_reporting(E_ALL);
    ini_set('display_errors', '0');

    try {
        $engine = new \WPDiagnose\Core\Engine();
        $engine->registerAgent(new \WPDiagnose\Agents\ServerInspector\ServerInspector());
        $engine->registerAgent(new \WPDiagnose\Agents\WPInspector\WPInspector($WP_LOADED));
        $engine->registerAgent(new \WPDiagnose\Agents\SecurityInspector\SecurityInspector());
        $engine->registerAgent(new \WPDiagnose\Agents\BootstrapInspector\BootstrapInspector());
        $engine->registerAgent(new \WPDiagnose\Agents\DBHealth\DBHealth($WP_LOADED));

        $response = ['success' => true, 'data' => []];

        if (isset($_GET['action'])) {
            if ($_GET['action'] === 'fix') {
                $agent = $_GET['agent'] ?? '';
                $id    = $_GET['id'] ?? '';
                $response['success'] = $engine->performFix($agent, $id);
            } elseif ($_GET['action'] === 'self_destruct') {
                $response['success'] = \WPDiagnose\Core\Cleanup::fullWipe();
            } elseif ($_GET['action'] === 'fetch_report') {
                $reports = $engine->getReports();
                while (ob_get_level()) ob_end_clean(); // Guaranteed clean output
                header('Content-Type: application/json; charset=utf-8');
                echo json_encode($reports, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
                exit;
            }

            if ($is_json) {
                while (ob_get_level()) ob_end_clean(); // Purge all buffers completely
                header('Content-Type: application/json; charset=utf-8');
                echo json_encode($response, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
                exit;
            }
        }

        if ($is_json) {
            $reports = $engine->getReports();
            while (ob_get_level()) ob_end_clean(); // Fallback for format=json
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode($reports, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            exit;
        }
        
    } catch (\Throwable $e) {
        if ($is_json) {
            while (ob_get_level()) ob_end_clean();
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode([
                'status'  => 'error', 
                'message' => 'API Engine Crash: ' . $e->getMessage()
            ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            exit;
        }
    }
}

// -------------------- AUDIT LOGGER --------------------
function wpd_log_action($action, $details = '') {
    $timestamp = date('Y-m-d H:i:s');
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN';
    $message = "[$timestamp] [IP: $ip] ACTION: $action" . ($details ? " | DETAILS: $details" : "") . PHP_EOL;
    @file_put_contents(LOG_FILE, $message, FILE_APPEND | LOCK_EX);
}

// -------------------- Self-Destruct Mechanism (0.2.1-beta Enhanced) --------------------
$self_destruct_file = __FILE__;
$expiration_time = 3600; // 60 minutes in seconds
$file_age = time() - filemtime(__FILE__);

if ($file_age > $expiration_time) {
    wpd_log_action('AUTO_DESTRUCT', 'TTL exceeded 60 minutes. Initiating self-destruct.');
    if (\WPDiagnose\Core\Cleanup::fullWipe()) {
        header('Content-Type: text/html; charset=utf-8');
        exit('<div style="background:#000;color:#00b84f;padding:20px;text-align:center;">WP Diagnose dosyasÄ± ve tÃ¼m yardÄ±mcÄ± modÃ¼ller gÃ¼venlik iÃ§in silinmiÅŸtir.</div>');
    } else {
        header('Content-Type: text/html; charset=utf-8');
        exit('<div style="background:#000;color:#ef4444;padding:20px;text-align:center;">UYARI: Dosyalar otomatik olarak silinemedi. LÃ¼tfen gÃ¼venlik iÃ§in manuel olarak silin.</div>');
    }
}
// -------------------- End Self-Destruct --------------------

@header('Content-Type: text/html; charset=utf-8');
@date_default_timezone_set('UTC');

// -------------------- Session / Lang / Nonce --------------------
if (session_status() !== PHP_SESSION_ACTIVE) {
    @session_start();
}

// Language
if (!empty($_GET['lang']))
    $_SESSION['wpdiag_lang'] = $_GET['lang'];
$LANG = $_SESSION['wpdiag_lang'] ?? 'en';
if (!in_array($LANG, ['tr', 'en'], true))
    $LANG = 'en';

// Nonce
if (empty($_SESSION['wpdiag_nonce']))
    $_SESSION['wpdiag_nonce'] = bin2hex(random_bytes(16));
$NONCE = $_SESSION['wpdiag_nonce'];
function check_nonce()
{
    if (empty($_REQUEST['_nonce']) || $_REQUEST['_nonce'] !== ($_SESSION['wpdiag_nonce'] ?? ''))
        exit('Nonce error');
}

// i18n
function t($key)
{
    static $TR, $EN;
    global $LANG;
    if (!$TR) {
        $TR = [
            'title' => 'WP TeÅŸhis',
            'reload' => 'Yeniden Tara',
            'mode_full' => 'Tam Mod',
            'mode_db' => 'DB Modu',
            'general' => 'Genel BakÄ±ÅŸ',
            'integrity' => 'Ã‡ekirdek BÃ¼tÃ¼nlÃ¼ÄŸÃ¼',
            'security' => 'GÃ¼venlik HÄ±zlÄ± KazanÄ±mlarÄ±',
            'urls' => 'URL TutarlÄ±lÄ±ÄŸÄ± & HTTPS',
            'seo' => 'SEO & Sitemap',
            'plugins' => 'Eklentiler',
            'themes' => 'Temalar',
            'updates' => 'GÃ¼ncellemeler',
            'tools' => 'AraÃ§lar',
            'server' => 'Sunucu/PHP',
            'db_mode_form_title' => 'DB Modu â€“ WordPress yÃ¼klenemedi. VeritabanÄ± bilgilerini girin:',
            'db_host' => 'DB Sunucusu',
            'db_name' => 'DB AdÄ±',
            'db_user' => 'DB KullanÄ±cÄ±',
            'db_pass' => 'DB Parola',
            'db_prefix' => 'Tablo Ã–neki (table_prefix)',
            'save' => 'Kaydet',
            'full_only' => '(Tam Mod gerekli)',
            'activate' => 'AktifleÅŸtir',
            'deactivate' => 'Devre DÄ±ÅŸÄ± BÄ±rak',
            'update' => 'GÃ¼ncelle',
            'update_all_plugins' => 'TÃ¼m GÃ¼ncel Eklentileri GÃ¼ncelle',
            'update_all_themes' => 'TÃ¼m GÃ¼ncel TemalarÄ± GÃ¼ncelle',
            'update_core' => 'WordPress Ã‡ekirdeÄŸini GÃ¼ncelle',
            'flush_permalinks' => 'Permalinks Flush',
            'clear_transients' => 'Transients Temizle',
            'clear_error_logs' => 'Hata LoglarÄ±nÄ± Temizle',
            'files_cleared' => 'dosya temizlendi.',
            'delete_maintenance' => '.maintenance Sil',
            'sitemap_on' => 'Sitemap Force ON',
            'sitemap_off' => 'Sitemap Force OFF',
            'active' => 'Aktif',
            'inactive' => 'Pasif',
            'status' => 'Durum',
            'version' => 'Versiyon',
            'action' => 'Ä°ÅŸlem',
            'hint_delete_after' => 'Ã–NEMLÄ°!!! Bu araÃ§ geÃ§icidir. Ä°ÅŸiniz bitince dosyayÄ± silin.',
            'lang' => 'Dil',
            'rest_api' => 'REST API',
            'core_55' => 'WordPress >= 5.5',
            'blog_public' => 'Arama motorlarÄ±nÄ± engelle',
            'sitemaps_enabled' => 'wp_sitemaps_enabled',
            'endpoint' => 'UÃ§ nokta',
            'http' => 'HTTP',
            'site' => 'Site',
            'wp_version' => 'WP SÃ¼rÃ¼m',
            'php_version' => 'PHP SÃ¼rÃ¼m',
            'ok' => 'OK',
            'warn' => 'UYARI',
            'err' => 'HATA',
            'full_needed' => 'Bu iÅŸlem iÃ§in WordPress tam yÃ¼klenmeli.',
            'db_saved' => 'DB bilgileriniz kaydedildi (oturum).',
            'nonce_confirm' => 'Emin misiniz?',
            'core_file_count' => 'Ã‡ekirdek Dosya SayÄ±sÄ±',
            'checksums_api' => 'Checksum API EriÅŸimi',
            'modified_files' => 'DeÄŸiÅŸtirilmiÅŸ Dosyalar',
            'missing_files' => 'Eksik Dosyalar',
            'unknown_files' => 'Bilinmeyen Dosyalar',
            'file_permissions' => 'Dosya Ä°zinleri',
            'wp_config_perms' => 'wp-config.php',
            'dir_perms' => 'Dizinler',
            'secure_keys' => 'GÃ¼venlik AnahtarlarÄ±',
            'auth_keys' => 'AUTH_KEY vb.',
            'admin_user' => 'Admin KullanÄ±cÄ± AdÄ±',
            'directory_listing' => 'Dizin Listeleme',
            'readme_license' => 'Readme/License DosyalarÄ±',
            'home_url' => 'Ana URL (home_url)',
            'site_url' => 'Site URL (site_url)',
            'mixed_content' => 'KarÄ±ÅŸÄ±k Ä°Ã§erik',
            'https_redirect' => 'HTTPS YÃ¶nlendirme',
            'ext_loaded' => 'YÃ¼klÃ¼ UzantÄ±lar',
            'recommended' => 'Ã–nerilen',
            'actual' => 'Mevcut',
            'php_limits' => 'PHP Limitleri',
            'no_update' => 'GÃ¼ncelleme Gerekmiyor',
            'debug_log' => 'Hata GÃ¼nlÃ¼ÄŸÃ¼ (Debug Log)',
            'export_json' => 'Raporu DÄ±ÅŸa Aktar (JSON)',
            'checksum_api_error_1' => 'Checksum API\'den alÄ±namadÄ±.',
            'checksum_api_error_2' => 'Checksum verisi eksik.',
            'admin_user_exists' => 'Admin kullanÄ±cÄ±sÄ± mevcut.',
            'admin_user_not_found' => 'Admin kullanÄ±cÄ±sÄ± bulunamadÄ±.',
            'all_keys_ok' => 'TÃ¼m anahtarlar tanÄ±mlÄ±.',
            'some_keys_missing' => 'BazÄ± gÃ¼venlik anahtarlarÄ± eksik.',
            'files_removed' => 'KaldÄ±rÄ±lmÄ±ÅŸ.',
            'files_present_remove' => 'Mevcut. GÃ¼venlik iÃ§in kaldÄ±rÄ±n.',
            'url_consistency_ok' => 'URL\'ler tutarlÄ±.',
            'https_in_use' => 'HTTPS kullanÄ±lÄ±yor.',
            'https_not_in_use' => 'HTTPS kullanÄ±lmÄ±yor.',
            'redirect_check_failed' => 'YÃ¶nlendirme kontrol edilemedi:',
            'http_status_code' => 'HTTP Durumu:',
            'mixed_content_found' => 'Ayarlarda potansiyel karma iÃ§erik bulundu.',
            'mixed_content_ok' => 'Ayarlarda belirgin karma iÃ§erik sorunu bulunamadÄ±.',
            'debug_log_not_found' => 'Hata gÃ¼nlÃ¼ÄŸÃ¼ bulunamadÄ± ya da boÅŸ.',
            'clear_plugin_transient' => 'Eklenti GÃ¼ncelleme Ã–nbelleÄŸini Temizle',
            'clear_theme_transient' => 'Tema GÃ¼ncelleme Ã–nbelleÄŸini Temizle',
        ];
        $EN = [
            'title' => 'WP Diagnose',
            'reload' => 'Rescan',
            'mode_full' => 'Full Mode',
            'mode_db' => 'DB Mode',
            'general' => 'Overview',
            'integrity' => 'Core Integrity (Checksums)',
            'security' => 'Security Quick Wins',
            'urls' => 'URL Consistency & HTTPS',
            'seo' => 'SEO & Sitemap',
            'plugins' => 'Plugins',
            'themes' => 'Themes',
            'updates' => 'Updates',
            'tools' => 'Tools',
            'server' => 'Server/PHP',
            'db_mode_form_title' => 'DB Mode â€“ WordPress not loaded. Enter database credentials:',
            'db_host' => 'DB Host',
            'db_name' => 'DB Name',
            'db_user' => 'DB User',
            'db_pass' => 'DB Password',
            'db_prefix' => 'Table Prefix',
            'save' => 'Save',
            'full_only' => '(requires Full Mode)',
            'activate' => 'Activate',
            'deactivate' => 'Deactivate',
            'update' => 'Update',
            'update_all_plugins' => 'Update All Upgradable Plugins',
            'update_all_themes' => 'Update All Upgradable Themes',
            'update_core' => 'Update WordPress Core',
            'flush_permalinks' => 'Flush Permalinks',
            'clear_transients' => 'Clear Transients',
            'clear_error_logs' => 'Clear Error Logs',
            'files_cleared' => 'files cleared.',
            'delete_maintenance' => 'Delete .maintenance',
            'sitemap_on' => 'Sitemap Force ON',
            'sitemap_off' => 'Sitemap Force OFF',
            'active' => 'Active',
            'inactive' => 'Inactive',
            'status' => 'Status',
            'version' => 'Version',
            'action' => 'Action',
            'hint_delete_after' => 'IMPORTANT!!! Temporary tool. Delete this file after use.',
            'lang' => 'Language',
            'rest_api' => 'REST API',
            'core_55' => 'WordPress >= 5.5',
            'blog_public' => 'Discourage search engines',
            'sitemaps_enabled' => 'wp_sitemaps_enabled',
            'endpoint' => 'Endpoint',
            'http' => 'HTTP',
            'site' => 'Site',
            'wp_version' => 'WP Version',
            'php_version' => 'PHP Version',
            'ok' => 'OK',
            'warn' => 'WARN',
            'err' => 'ERROR',
            'full_needed' => 'This operation requires WordPress fully loaded.',
            'db_saved' => 'DB credentials stored in session.',
            'nonce_confirm' => 'Are you sure?',
            'core_file_count' => 'Core File Count',
            'checksums_api' => 'Checksum API Access',
            'modified_files' => 'Modified Files',
            'missing_files' => 'Missing Files',
            'unknown_files' => 'Unknown Files',
            'file_permissions' => 'File Permissions',
            'wp_config_perms' => 'wp-config.php',
            'dir_perms' => 'Directories',
            'secure_keys' => 'Secure Keys',
            'auth_keys' => 'AUTH_KEY etc.',
            'admin_user' => 'Admin Username',
            'directory_listing' => 'Directory Listing',
            'readme_license' => 'Readme/License Files',
            'home_url' => 'Home URL (home_url)',
            'site_url' => 'Site URL (site_url)',
            'mixed_content' => 'Mixed Content',
            'https_redirect' => 'HTTPS Redirect',
            'ext_loaded' => 'Loaded Extensions',
            'recommended' => 'Recommended',
            'actual' => 'Actual',
            'php_limits' => 'PHP Limits',
            'no_update' => 'No Update Needed',
            'debug_log' => 'Debug Log',
            'export_json' => 'Export Report (JSON)',
            'checksum_api_error_1' => 'Could not retrieve checksums from API.',
            'checksum_api_error_2' => 'Checksum data missing.',
            'admin_user_exists' => 'Admin user exists.',
            'admin_user_not_found' => 'No "admin" user found.',
            'all_keys_ok' => 'All keys are defined.',
            'some_keys_missing' => 'Some security keys are missing.',
            'files_removed' => 'Removed.',
            'files_present_remove' => 'Present. Remove them for security.',
            'url_consistency_ok' => 'URLs are consistent.',
            'https_in_use' => 'Using HTTPS.',
            'https_not_in_use' => 'Not using HTTPS.',
            'redirect_check_failed' => 'Could not check redirect:',
            'http_status_code' => 'HTTP Status:',
            'mixed_content_found' => 'Potentially mixed content found in options.',
            'mixed_content_ok' => 'No obvious mixed content issues found in options.',
            'debug_log_not_found' => 'Debug log not found or empty.',
            'clear_plugin_transient' => 'Clear Plugin Update Cache',
            'clear_theme_transient' => 'Clear Theme Update Cache',
        ];
    }
    return ($GLOBALS['LANG'] === 'tr' ? ($TR[$key] ?? $key) : ($EN[$key] ?? $key));
}
function h($s)
{
    return htmlspecialchars((string) $s, ENT_QUOTES, 'UTF-8');
}
function badge($type)
{
    $label = ['OK' => t('ok'), 'WARN' => t('warn'), 'ERROR' => t('err')][$type] ?? $type;
    $class = strtolower($type);
    return '<span class="badge badge-' . $class . '">' . $label . '</span>';
}

// WordPress load attempt moved up.

// -------------------- DB Mode Helper --------------------
class WPD_DB
{
    public $mysqli;
    public $prefix;
    function __construct($h, $u, $p, $d, $pref)
    {
        $this->mysqli = @new mysqli($h, $u, $p, $d);
        if ($this->mysqli->connect_errno)
            throw new Exception($this->mysqli->connect_error);
        $this->mysqli->set_charset('utf8mb4');
        $this->prefix = $pref;
    }
    function get_option($name)
    {
        $stmt = $this->mysqli->prepare("SELECT option_value FROM {$this->prefix}options WHERE option_name=? LIMIT 1");
        $stmt->bind_param("s", $name);
        $stmt->execute();
        $stmt->bind_result($val);
        if ($stmt->fetch()) {
            $stmt->close();
            return $val;
        }
        $stmt->close();
        return null;
    }
    function update_option($name, $value)
    {
        $stmt = $this->mysqli->prepare("SELECT option_id FROM {$this->prefix}options WHERE option_name=? LIMIT 1");
        $stmt->bind_param("s", $name);
        $stmt->execute();
        $stmt->store_result();
        $exists = $stmt->fetch();
        $stmt->close();
        if ($exists) {
            $stmt = $this->mysqli->prepare("UPDATE {$this->prefix}options SET option_value=? WHERE option_name=?");
            $stmt->bind_param("ss", $value, $name);
            $stmt->execute();
            $stmt->close();
        } else {
            $autoload = 'no';
            $stmt = $this->mysqli->prepare("INSERT INTO {$this->prefix}options (option_name, option_value, autoload) VALUES (?,?,?)");
            $stmt->bind_param("sss", $name, $value, $autoload);
            $stmt->execute();
            $stmt->close();
        }
    }
    function get_user($login)
    {
        $stmt = $this->mysqli->prepare("SELECT ID FROM {$this->prefix}users WHERE user_login=?");
        $stmt->bind_param("s", $login);
        $stmt->execute();
        $stmt->store_result();
        $count = $stmt->num_rows;
        $stmt->close();
        return $count;
    }
}

// Helper to get all options for mixed content check
function wpd_get_all_options()
{
    global $wpdb;
    return $wpdb->get_results("SELECT option_name, option_value FROM {$wpdb->options}");
}

// Store DB creds in session if posted
if (isset($_POST['dbsave']) && !empty($_POST['_nonce'])) {
    check_nonce();
    $_SESSION['db_host'] = trim($_POST['db_host'] ?? '');
    $_SESSION['db_name'] = trim($_POST['db_name'] ?? '');
    $_SESSION['db_user'] = trim($_POST['db_user'] ?? '');
    $_SESSION['db_pass'] = (string) ($_POST['db_pass'] ?? '');
    $_SESSION['db_prefix'] = trim($_POST['db_prefix'] ?? 'wp_');
    $_SESSION['db_msg'] = t('db_saved');
    wpd_log_action('DB_CREDENTIALS_SAVED', 'DB Host: ' . $_SESSION['db_host']);
    header("Location: " . $_SERVER['PHP_SELF'] . "?token=" . DIAG_TOKEN . "#general");
    exit;
}

// Try construct DB object in DB Mode
$DB = null;
$DB_ERR = '';
if (!$WP_LOADED && !empty($_SESSION['db_host'])) {
    try {
        $DB = new WPD_DB($_SESSION['db_host'], $_SESSION['db_user'], $_SESSION['db_pass'], $_SESSION['db_name'], $_SESSION['db_prefix'] ?: 'wp_');
    } catch (Throwable $e) {
        $DB_ERR = $e->getMessage();
    }
}

// -------------------- Modern SPA Dashboard (v0.2.1-beta) --------------------
?><!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WP Diagnose PRO v0.2.1-beta</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>
    <style>
        [x-cloak] { display: none !important; }
        body { background-color: #0f172a; color: #e2e8f0; }
        ::-webkit-scrollbar { width: 8px; }
        ::-webkit-scrollbar-track { background: #1e293b; }
        ::-webkit-scrollbar-thumb { background: #334155; border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: #475569; }
    </style>
</head>
<body class="antialiased">
    <div x-data="diagnoseApp()" x-init="init()" class="min-h-screen p-4 md:p-8" x-cloak>
        <!-- Header -->
        <header class="max-w-6xl mx-auto flex flex-col md:flex-row justify-between items-center mb-10 border-b border-slate-700 pb-6 gap-4">
            <div>
                <h1 class="text-3xl font-black text-emerald-500 flex items-center gap-3">
                    <svg class="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
                    WP DIAGNOSE <span class="text-sm font-mono bg-slate-800 text-slate-400 px-3 py-1 rounded-full">v0.2.1-beta</span>
                </h1>
                <p class="text-slate-500 text-xs mt-1 font-mono uppercase tracking-widest">Advanced Diagnostic Agents Swarm</p>
            </div>
            
            <div class="flex gap-4 items-center">
                <button @click="fetchReport()" :disabled="loading" class="bg-slate-700 hover:bg-slate-600 disabled:opacity-50 text-white px-4 py-2 rounded text-sm font-semibold transition flex items-center gap-2">
                    <svg class="w-4 h-4" :class="loading ? 'animate-spin' : ''" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>
                    Refresh
                </button>
                <button @click="selfDestruct()" class="bg-red-600/20 hover:bg-red-600 text-red-500 hover:text-white border border-red-600/50 px-4 py-2 rounded text-sm font-bold transition">Self-Destruct</button>
            </div>
        </header>

        <!-- Main Content -->
        <main class="max-w-6xl mx-auto space-y-8">
            
            <!-- Quick Stats -->
            <div class="grid grid-cols-1 md:grid-cols-4 gap-4" x-show="!loading">
                <div class="bg-slate-800/50 p-4 rounded-lg border border-slate-700">
                    <span class="text-slate-500 text-xs font-bold uppercase block mb-1">Environment</span>
                    <span class="text-emerald-400 font-mono text-lg" x-text="'<?php echo $WP_LOADED ? 'WordPress Core' : 'Independent Mode'; ?>'"></span>
                </div>
                <div class="bg-slate-800/50 p-4 rounded-lg border border-slate-700">
                    <span class="text-slate-500 text-xs font-bold uppercase block mb-1">Active Agents</span>
                    <span class="text-slate-200 font-mono text-lg" x-text="Object.keys(reports).length"></span>
                </div>
                <div class="bg-slate-800/50 p-4 rounded-lg border border-slate-700">
                    <span class="text-slate-500 text-xs font-bold uppercase block mb-1">Stability</span>
                    <span class="text-blue-500 font-mono text-lg">PRO ACTIVE</span>
                </div>
                <div class="bg-slate-800/50 p-4 rounded-lg border border-slate-700">
                    <span class="text-slate-500 text-xs font-bold uppercase block mb-1">Audit Mode</span>
                    <span class="text-slate-400 font-mono text-sm block truncate">v0.2.1-beta Agentic Collective</span>
                </div>
            </div>

            <!-- Tab Navigation -->
            <div x-show="!loading" class="flex flex-wrap border-b border-slate-700/50 gap-2 mb-6">
                <button @click="activeTab = 'all'" :class="activeTab === 'all' ? 'border-emerald-500 text-emerald-400' : 'border-transparent text-slate-500 hover:text-slate-300'" class="px-6 py-3 border-b-2 font-bold text-xs uppercase tracking-widest transition">All Agents</button>
                <template x-for="(report, agent) in reports" :key="agent">
                    <button @click="activeTab = agent" :class="activeTab === agent ? 'border-emerald-500 text-emerald-400' : 'border-transparent text-slate-500 hover:text-slate-300'" class="px-6 py-3 border-b-2 font-bold text-xs uppercase tracking-widest transition" x-text="agent"></button>
                </template>
            </div>

            <!-- Loading Spinner -->
            <div x-show="loading" class="flex flex-col items-center justify-center py-32 space-y-4">
                <div class="w-16 h-16 border-4 border-emerald-500/20 border-t-emerald-500 rounded-full animate-spin"></div>
                <p class="text-slate-400 font-mono animate-pulse">Interrogating Diagnostic Swarm...</p>
            </div>

            <!-- Agent Grid -->
            <div x-show="!loading" class="grid grid-cols-1 lg:grid-cols-2 gap-8">
                <template x-for="(report, agent) in reports" :key="agent">
                    <div x-show="activeTab === 'all' || activeTab === agent" class="bg-slate-800 border border-slate-700/50 rounded-xl shadow-2xl overflow-hidden flex flex-col hover:border-slate-600 transition">
                        <div class="bg-slate-900/50 px-6 py-4 flex justify-between items-center border-b border-slate-700">
                            <div class="flex items-center gap-3">
                                <div class="w-2 h-2 rounded-full bg-emerald-500"></div>
                                <h2 class="text-lg font-bold text-slate-100 uppercase tracking-tight" x-text="agent"></h2>
                            </div>
                        </div>
                        
                        <div class="p-0 divide-y divide-slate-700/50">
                            <template x-for="(finding, id) in report" :key="id">
                                <div class="p-6 hover:bg-slate-700/10 transition group">
                                    <div class="flex justify-between items-center mb-3">
                                        <span class="font-mono text-xs text-sky-400 flex items-center gap-2">
                                            <span class="w-1 h-1 bg-sky-900 rounded-full"></span>
                                            <span x-text="id"></span>
                                        </span>
                                        <span :class="{
                                            'text-emerald-400 bg-emerald-400/10 border-emerald-400/20': finding.status === 'OK' || finding.status === 'SUCCESS' || finding.status === 'SKIP',
                                            'text-amber-400 bg-amber-400/10 border-amber-400/20': finding.status === 'WARN',
                                            'text-red-400 bg-red-400/10 border-red-400/20': finding.status === 'ERROR'
                                        }" class="text-[9px] font-black px-2 py-0.5 rounded border uppercase" x-text="finding.status"></span>
                                    </div>
                                    
                                    <p class="text-sm text-slate-400 leading-relaxed mb-4" x-text="formatFound(finding)"></p>
                                    
                                    <!-- Action Buttons -->
                                    <template x-if="finding.status !== 'OK' && (agent === 'ServerInspector' || agent === 'BootstrapInspector' || agent === 'DBHealth')">
                                        <div class="flex gap-2">
                                            <button @click="attemptFix(agent, id)" class="text-[10px] font-bold uppercase tracking-wider bg-emerald-600/20 hover:bg-emerald-600 text-emerald-400 hover:text-white border border-emerald-600/50 px-4 py-2 rounded transition">
                                                Execute Recovery Routine
                                            </button>
                                        </div>
                                    </template>
                                </div>
                            </template>
                        </div>
                    </div>
                </template>
            </div>
        </main>

        <!-- Footer -->
        <footer class="max-w-6xl mx-auto mt-20 pt-10 border-t border-slate-700/50 text-center mb-10">
            <p class="text-slate-600 text-[10px] font-mono uppercase tracking-[0.2em]">WP Diagnose Agentic Swarm v0.2.1-beta &copy; 2026</p>
        </footer>
    </div>

    <script>
        function diagnoseApp() {
            return {
                loading: true,
                reports: {},
                activeTab: 'all',
                token: '<?php echo DIAG_TOKEN; ?>',
                init() {
                    this.fetchReport();
                },
                async fetchReport() {
                    this.loading = true;
                    try {
                        const response = await fetch(`?token=${this.token}&action=fetch_report`);
                        const contentType = response.headers.get('Content-Type') || '';
                        if (!contentType.includes('application/json')) {
                            const raw = await response.text();
                            console.error('[WP Diagnose] Non-JSON response from API:', raw.substring(0, 500));
                            alert('API Bağlantı Hatası: Sunucu JSON formatında yanıt vermedi (Kalıntı veya PHP Hataları olabilir).');
                            this.reports = {}; // Active agents will drop to 0
                        } else {
                            try {
                                this.reports = await response.json();
                                // Check if the backend reported a graceful crash
                                if (this.reports.status === 'error') {
                                    alert('API Bağlantı Hatası: ' + this.reports.message);
                                    this.reports = {};
                                }
                            } catch (parseErr) {
                                console.error('[WP Diagnose] JSON Parse failed:', parseErr);
                                alert('API Bağlantı Hatası: Gelen JSON verisi ayrıştırılamadı. Format bozuk.');
                                this.reports = {};
                            }
                        }
                    } catch (e) {
                        console.error('[WP Diagnose] Network error:', e);
                        alert('API Bağlantı Hatası: Sunucuya ulaşılamıyor veya bağlantı koptu.');
                        this.reports = {};
                    }
                    setTimeout(() => { this.loading = false; }, 600);
                },
                formatFound(finding) {
                    if (typeof finding === 'string') return finding;
                    if (finding.info) return finding.info;
                    if (finding.message) return finding.message;
                    if (finding.status === 'OK' && !finding.info) {
                        const keys = Object.keys(finding).filter(k => k !== 'status');
                        return keys.length > 0 ? keys.map(k => `${k}: ${finding[k]}`).join(' | ') : 'Compliance check passed.';
                    }
                    return JSON.stringify(finding);
                },
                async attemptFix(agent, id) {
                    if (!confirm(`Trigger Agentic Fix for [${id}]?`)) return;
                    
                    try {
                        const response = await fetch(`?token=${this.token}&action=fix&agent=${agent}&id=${id}&format=json`);
                        const result = await response.json();
                        if (result.success) {
                            alert('Agent recovered successfully. Updating audit...');
                            this.fetchReport();
                        } else {
                            alert('Recovery failed. Manual intervention advised.');
                        }
                    } catch (e) {
                        alert('API Communication Timeout.');
                    }
                },
                async selfDestruct() {
                    if (!confirm('ULTIMATUM: Permanent recursive wipe of ALL diagnostic components. Proceed?')) return;
                    
                    try {
                        const response = await fetch(`?token=${this.token}&action=self_destruct&format=json`);
                        const result = await response.json();
                        if (result.success) {
                            document.body.innerHTML = '<div class="min-h-screen flex flex-col items-center justify-center bg-slate-950 text-emerald-500 font-mono uppercase tracking-[0.5em] text-center p-10"><div>System Cleansed</div><div class="text-[10px] text-slate-700 mt-6 tracking-normal lowercase">All modular components purged from file system.</div></div>';
                        } else {
                            alert('Recursion partially blocked. Manual directory removal required.');
                        }
                    } catch (e) {
                        alert('Wipe sequence initiated. Verify server state.');
                    }
                }
            }
        }
    </script>
</body>
</html>
<?php exit; ?>
