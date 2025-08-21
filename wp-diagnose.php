<?php
/**
 * WP Diagnose – Single File, EN/TR, Full & DB Mode
 * A drop-in diagnosis, maintenance, and plugin management tool for WordPress.
 * Upload to root directory as `wp-diagnose.php` → use it → then delete it.
 *
 * Author: https://github.com/BigDesigner
 *
 * v1.0
 */

// Your existing WP Diagnose code starts here

// -------------------- Self-Destruct Mechanism --------------------
$self_destruct_file = __FILE__;
$expiration_time = 3600; // 60 minutes in seconds

// Check if the file creation time is stored in session
if (empty($_SESSION['wpdiag_created_at'])) {
    $_SESSION['wpdiag_created_at'] = time();
}

// Check if the expiration time has passed
if ((time() - $_SESSION['wpdiag_created_at']) > $expiration_time) {
    if (@unlink($self_destruct_file)) {
        header('Content-Type: text/html; charset=utf-8');
        exit('<div style="background:#000;color:#00b84f;padding:20px;text-align:center;">WP Diagnose dosyası, güvenlik nedeniyle otomatik olarak silinmiştir.</div>');
    } else {
        header('Content-Type: text/html; charset=utf-8');
        exit('<div style="background:#000;color:#ef4444;padding:20px;text-align:center;">UYARI: WP Diagnose dosyası otomatik olarak silinemedi. Lütfen güvenlik için sunucunuzdan manuel olarak silin.</div>');
    }
}
// -------------------- End Self-Destruct --------------------

@header('Content-Type: text/html; charset=utf-8');
@date_default_timezone_set('UTC');

// -------------------- Session / Lang / Nonce --------------------
if (session_status() !== PHP_SESSION_ACTIVE) { @session_start(); }

// Language
if (!empty($_GET['lang'])) $_SESSION['wpdiag_lang'] = $_GET['lang'];
$LANG = $_SESSION['wpdiag_lang'] ?? 'en';
if (!in_array($LANG, ['tr','en'], true)) $LANG = 'en';

// Nonce
if (empty($_SESSION['wpdiag_nonce'])) $_SESSION['wpdiag_nonce'] = bin2hex(random_bytes(16));
$NONCE = $_SESSION['wpdiag_nonce'];
function check_nonce(){
    if (empty($_REQUEST['_nonce']) || $_REQUEST['_nonce'] !== ($_SESSION['wpdiag_nonce'] ?? '')) exit('Nonce error');
}

// i18n
function t($key){
    static $TR, $EN;
    global $LANG;
    if (!$TR){
        $TR = [
            'title'=>'WP Teşhis',
            'reload'=>'Yeniden Tara',
            'mode_full'=>'Tam Mod',
            'mode_db'=>'DB Modu',
            'general'=>'Genel Bakış',
            'integrity'=>'Çekirdek Bütünlüğü',
            'security'=>'Güvenlik Hızlı Kazanımları',
            'urls'=>'URL Tutarlılığı & HTTPS',
            'seo'=>'SEO & Sitemap',
            'plugins'=>'Eklentiler',
            'themes'=>'Temalar',
            'updates'=>'Güncellemeler',
            'tools'=>'Araçlar',
            'server'=>'Sunucu/PHP',
            'db_mode_form_title'=>'DB Modu – WordPress yüklenemedi. Veritabanı bilgilerini girin:',
            'db_host'=>'DB Sunucusu',
            'db_name'=>'DB Adı',
            'db_user'=>'DB Kullanıcı',
            'db_pass'=>'DB Parola',
            'db_prefix'=>'Tablo Öneki (table_prefix)',
            'save'=>'Kaydet',
            'full_only'=>'(Tam Mod gerekli)',
            'activate'=>'Aktifleştir',
            'deactivate'=>'Devre Dışı Bırak',
            'update'=>'Güncelle',
            'update_all_plugins'=>'Tüm Güncel Eklentileri Güncelle',
            'update_all_themes'=>'Tüm Güncel Temaları Güncelle',
            'update_core'=>'WordPress Çekirdeğini Güncelle',
            'flush_permalinks'=>'Permalinks Flush',
            'clear_transients'=>'Transients Temizle',
            'clear_error_logs'=>'Hata Loglarını Temizle',
            'files_cleared'=>'dosya temizlendi.',
            'delete_maintenance'=>'.maintenance Sil',
            'sitemap_on'=>'Sitemap Force ON',
            'sitemap_off'=>'Sitemap Force OFF',
            'active'=>'Aktif',
            'inactive'=>'Pasif',
            'status'=>'Durum',
            'version'=>'Versiyon',
            'action'=>'İşlem',
            'hint_delete_after'=>'ÖNEMLİ!!! Bu araç geçicidir. İşiniz bitince dosyayı silin.',
            'lang'=>'Dil',
            'rest_api'=>'REST API',
            'core_55'=>'WordPress >= 5.5',
            'blog_public'=>'Arama motorlarını engelle',
            'sitemaps_enabled'=>'wp_sitemaps_enabled',
            'endpoint'=>'Uç nokta',
            'http'=>'HTTP',
            'site'=>'Site',
            'wp_version'=>'WP Sürüm',
            'php_version'=>'PHP Sürüm',
            'ok'=>'OK',
            'warn'=>'UYARI',
            'err'=>'HATA',
            'full_needed'=>'Bu işlem için WordPress tam yüklenmeli.',
            'db_saved'=>'DB bilgileriniz kaydedildi (oturum).',
            'nonce_confirm'=>'Emin misiniz?',
            'core_file_count'=>'Çekirdek Dosya Sayısı',
            'checksums_api'=>'Checksum API Erişimi',
            'modified_files'=>'Değiştirilmiş Dosyalar',
            'missing_files'=>'Eksik Dosyalar',
            'unknown_files'=>'Bilinmeyen Dosyalar',
            'file_permissions'=>'Dosya İzinleri',
            'wp_config_perms'=>'wp-config.php',
            'dir_perms'=>'Dizinler',
            'secure_keys'=>'Güvenlik Anahtarları',
            'auth_keys'=>'AUTH_KEY vb.',
            'admin_user'=>'Admin Kullanıcı Adı',
            'directory_listing'=>'Dizin Listeleme',
            'readme_license'=>'Readme/License Dosyaları',
            'home_url'=>'Ana URL (home_url)',
            'site_url'=>'Site URL (site_url)',
            'mixed_content'=>'Karışık İçerik',
            'https_redirect'=>'HTTPS Yönlendirme',
            'ext_loaded'=>'Yüklü Uzantılar',
            'recommended'=>'Önerilen',
            'actual'=>'Mevcut',
            'php_limits'=>'PHP Limitleri',
            'no_update'=>'Güncelleme Gerekmiyor',
            'debug_log'=>'Hata Günlüğü (Debug Log)',
            'export_json'=>'Raporu Dışa Aktar (JSON)',
            'checksum_api_error_1'=>'Checksum API\'den alınamadı.',
            'checksum_api_error_2'=>'Checksum verisi eksik.',
            'admin_user_exists'=>'Admin kullanıcısı mevcut.',
            'admin_user_not_found'=>'Admin kullanıcısı bulunamadı.',
            'all_keys_ok'=>'Tüm anahtarlar tanımlı.',
            'some_keys_missing'=>'Bazı güvenlik anahtarları eksik.',
            'files_removed'=>'Kaldırılmış.',
            'files_present_remove'=>'Mevcut. Güvenlik için kaldırın.',
            'url_consistency_ok'=>'URL\'ler tutarlı.',
            'https_in_use'=>'HTTPS kullanılıyor.',
            'https_not_in_use'=>'HTTPS kullanılmıyor.',
            'redirect_check_failed'=>'Yönlendirme kontrol edilemedi:',
            'http_status_code'=>'HTTP Durumu:',
            'mixed_content_found'=>'Ayarlarda potansiyel karma içerik bulundu.',
            'mixed_content_ok'=>'Ayarlarda belirgin karma içerik sorunu bulunamadı.',
            'debug_log_not_found'=>'Hata günlüğü bulunamadı ya da boş.',
            'clear_plugin_transient'=>'Eklenti Güncelleme Önbelleğini Temizle',
            'clear_theme_transient'=>'Tema Güncelleme Önbelleğini Temizle',
        ];
        $EN = [
            'title'=>'WP Diagnose',
            'reload'=>'Rescan',
            'mode_full'=>'Full Mode',
            'mode_db'=>'DB Mode',
            'general'=>'Overview',
            'integrity'=>'Core Integrity (Checksums)',
            'security'=>'Security Quick Wins',
            'urls'=>'URL Consistency & HTTPS',
            'seo'=>'SEO & Sitemap',
            'plugins'=>'Plugins',
            'themes'=>'Themes',
            'updates'=>'Updates',
            'tools'=>'Tools',
            'server'=>'Server/PHP',
            'db_mode_form_title'=>'DB Mode – WordPress not loaded. Enter database credentials:',
            'db_host'=>'DB Host',
            'db_name'=>'DB Name',
            'db_user'=>'DB User',
            'db_pass'=>'DB Password',
            'db_prefix'=>'Table Prefix',
            'save'=>'Save',
            'full_only'=>'(requires Full Mode)',
            'activate'=>'Activate',
            'deactivate'=>'Deactivate',
            'update'=>'Update',
            'update_all_plugins'=>'Update All Upgradable Plugins',
            'update_all_themes'=>'Update All Upgradable Themes',
            'update_core'=>'Update WordPress Core',
            'flush_permalinks'=>'Flush Permalinks',
            'clear_transients'=>'Clear Transients',
            'clear_error_logs'=>'Clear Error Logs',
            'files_cleared'=>'files cleared.',
            'delete_maintenance'=>'Delete .maintenance',
            'sitemap_on'=>'Sitemap Force ON',
            'sitemap_off'=>'Sitemap Force OFF',
            'active'=>'Active',
            'inactive'=>'Inactive',
            'status'=>'Status',
            'version'=>'Version',
            'action'=>'Action',
            'hint_delete_after'=>'IMPORTANT!!! Temporary tool. Delete this file after use.',
            'lang'=>'Language',
            'rest_api'=>'REST API',
            'core_55'=>'WordPress >= 5.5',
            'blog_public'=>'Discourage search engines',
            'sitemaps_enabled'=>'wp_sitemaps_enabled',
            'endpoint'=>'Endpoint',
            'http'=>'HTTP',
            'site'=>'Site',
            'wp_version'=>'WP Version',
            'php_version'=>'PHP Version',
            'ok'=>'OK',
            'warn'=>'WARN',
            'err'=>'ERROR',
            'full_needed'=>'This operation requires WordPress fully loaded.',
            'db_saved'=>'DB credentials stored in session.',
            'nonce_confirm'=>'Are you sure?',
            'core_file_count'=>'Core File Count',
            'checksums_api'=>'Checksum API Access',
            'modified_files'=>'Modified Files',
            'missing_files'=>'Missing Files',
            'unknown_files'=>'Unknown Files',
            'file_permissions'=>'File Permissions',
            'wp_config_perms'=>'wp-config.php',
            'dir_perms'=>'Directories',
            'secure_keys'=>'Secure Keys',
            'auth_keys'=>'AUTH_KEY etc.',
            'admin_user'=>'Admin Username',
            'directory_listing'=>'Directory Listing',
            'readme_license'=>'Readme/License Files',
            'home_url'=>'Home URL (home_url)',
            'site_url'=>'Site URL (site_url)',
            'mixed_content'=>'Mixed Content',
            'https_redirect'=>'HTTPS Redirect',
            'ext_loaded'=>'Loaded Extensions',
            'recommended'=>'Recommended',
            'actual'=>'Actual',
            'php_limits'=>'PHP Limits',
            'no_update'=>'No Update Needed',
            'debug_log'=>'Debug Log',
            'export_json'=>'Export Report (JSON)',
            'checksum_api_error_1'=>'Could not retrieve checksums from API.',
            'checksum_api_error_2'=>'Checksum data missing.',
            'admin_user_exists'=>'Admin user exists.',
            'admin_user_not_found'=>'No "admin" user found.',
            'all_keys_ok'=>'All keys are defined.',
            'some_keys_missing'=>'Some security keys are missing.',
            'files_removed'=>'Removed.',
            'files_present_remove'=>'Present. Remove them for security.',
            'url_consistency_ok'=>'URLs are consistent.',
            'https_in_use'=>'Using HTTPS.',
            'https_not_in_use'=>'Not using HTTPS.',
            'redirect_check_failed'=>'Could not check redirect:',
            'http_status_code'=>'HTTP Status:',
            'mixed_content_found'=>'Potentially mixed content found in options.',
            'mixed_content_ok'=>'No obvious mixed content issues found in options.',
            'debug_log_not_found'=>'Debug log not found or empty.',
            'clear_plugin_transient'=>'Clear Plugin Update Cache',
            'clear_theme_transient'=>'Clear Theme Update Cache',
        ];
    }
    return ($GLOBALS['LANG']==='tr' ? ($TR[$key] ?? $key) : ($EN[$key] ?? $key));
}
function h($s){ return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }
function badge($type){
    $label = ['OK'=>t('ok'),'WARN'=>t('warn'),'ERROR'=>t('err')][$type] ?? $type;
    $class = strtolower($type);
    return '<span class="badge badge-'.$class.'">'.$label.'</span>';
}

// -------------------- Try load WordPress --------------------
$WP_LOADED = false;
$base = __DIR__;
for ($i=0; $i<=5; $i++){
    $cand = $base . '/wp-load.php';
    if (is_file($cand)) { require_once $cand; $WP_LOADED = true; break; }
    $base = dirname($base);
}

// -------------------- DB Mode Helper --------------------
class WPD_DB {
    public $mysqli;
    public $prefix;
    function __construct($h,$u,$p,$d,$pref){
        $this->mysqli = @new mysqli($h,$u,$p,$d);
        if ($this->mysqli->connect_errno) throw new Exception($this->mysqli->connect_error);
        $this->mysqli->set_charset('utf8mb4');
        $this->prefix = $pref;
    }
    function get_option($name){
        $stmt = $this->mysqli->prepare("SELECT option_value FROM {$this->prefix}options WHERE option_name=? LIMIT 1");
        $stmt->bind_param("s",$name); $stmt->execute(); $stmt->bind_result($val);
        if ($stmt->fetch()){ $stmt->close(); return $val; }
        $stmt->close(); return null;
    }
    function update_option($name,$value){
        $stmt = $this->mysqli->prepare("SELECT option_id FROM {$this->prefix}options WHERE option_name=? LIMIT 1");
        $stmt->bind_param("s",$name); $stmt->execute(); $stmt->store_result();
        $exists = $stmt->fetch(); $stmt->close();
        if ($exists){
            $stmt = $this->mysqli->prepare("UPDATE {$this->prefix}options SET option_value=? WHERE option_name=?");
            $stmt->bind_param("ss",$value,$name); $stmt->execute(); $stmt->close();
        } else {
            $autoload='no';
            $stmt = $this->mysqli->prepare("INSERT INTO {$this->prefix}options (option_name, option_value, autoload) VALUES (?,?,?)");
            $stmt->bind_param("sss",$name,$value,$autoload); $stmt->execute(); $stmt->close();
        }
    }
    function get_user($login){
        $stmt = $this->mysqli->prepare("SELECT ID FROM {$this->prefix}users WHERE user_login=?");
        $stmt->bind_param("s",$login); $stmt->execute(); $stmt->store_result();
        $count = $stmt->num_rows; $stmt->close(); return $count;
    }
}

// Helper to get all options for mixed content check
function wpd_get_all_options() {
    global $wpdb;
    return $wpdb->get_results("SELECT option_name, option_value FROM {$wpdb->options}");
}

// Store DB creds in session if posted
if (isset($_POST['dbsave']) && !empty($_POST['_nonce'])) {
    check_nonce();
    $_SESSION['db_host'] = trim($_POST['db_host'] ?? '');
    $_SESSION['db_name'] = trim($_POST['db_name'] ?? '');
    $_SESSION['db_user'] = trim($_POST['db_user'] ?? '');
    $_SESSION['db_pass'] = (string)($_POST['db_pass'] ?? '');
    $_SESSION['db_prefix'] = trim($_POST['db_prefix'] ?? 'wp_');
    $_SESSION['db_msg'] = t('db_saved');
    header("Location: ".$_SERVER['PHP_SELF']."#general");
    exit;
}

// Try construct DB object in DB Mode
$DB = null; $DB_ERR = '';
if (!$WP_LOADED && !empty($_SESSION['db_host'])) {
    try {
        $DB = new WPD_DB($_SESSION['db_host'], $_SESSION['db_user'], $_SESSION['db_pass'], $_SESSION['db_name'], $_SESSION['db_prefix'] ?: 'wp_');
    } catch (Throwable $e) { $DB_ERR = $e->getMessage(); }
}

// -------------------- HTML Head --------------------
?><!doctype html>
<html lang="<?php echo $LANG==='tr'?'tr':'en'; ?>">
<head>
<meta charset="utf-8">
<meta name="robots" content="noindex,nofollow">
<title><?php echo t('title'); ?></title>
<style>
/* WordPress Admin Theme v1.9.4 */
body{margin:0;padding:0;background:#f0f0f1;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen-Sans,Ubuntu,Cantarell,"Helvetica Neue",sans-serif;font-size:14px;color:#1d2327}
.wp-wrap{max-width:1200px;margin:20px auto;background:#fff;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.13);overflow:hidden}
.wp-header{display:flex;justify-content:space-between;align-items:center;padding:15px 20px;border-bottom:1px solid #c3c4c7;background:#fff;flex-wrap:wrap}
.wp-header h1{margin:0;padding:0;font-size:24px;color:#1d2327}
.wp-header .actions a{display:inline-block;padding:5px 10px;text-decoration:none;border-radius:3px;margin-left:5px;transition:all .2s;background:#f3f3f5;color:#333;border:1px solid #ccc;font-size:13px;line-height:1.5}
.wp-header .actions a:hover{background:#e3e3e5;border-color:#aaa}
.wp-header .actions a:active{background:#d3d3d5;border-color:#999;transform:translateY(1px)}
.wp-content{display:flex}
.wp-nav{width:220px;flex-shrink:0;padding:20px 0;background:#fff;border-right:1px solid #c3c4c7}
.wp-nav a{display:block;padding:10px 20px;color:#1d2327;text-decoration:none;transition:background-color .2s}
.wp-nav a:hover{background-color:#f3f3f5}
.wp-main{flex-grow:1;padding:20px;overflow-x:auto}
.section{margin-bottom:20px;background:#fff;border:1px solid #c3c4c7;border-radius:5px}
.section h2{margin:0;padding:10px 15px;background:#f6f7f7;border-bottom:1px solid #c3c4c7;font-size:18px;font-weight:600;color:#1d2327}
.section .pad{padding:15px}
table{width:100%;border-collapse:collapse;margin:0 0 15px}
th,td{padding:10px;border-bottom:1px solid #ddd;text-align:left}
th{background:#f0f0f1;color:#555}
tr:nth-child(even) td{background:#fcfcfc}
.badge{padding:3px 8px;border-radius:12px;font-weight:600;font-size:12px;line-height:1;display:inline-block}
.badge-ok{background:#dcf5e7;color:#169455}
.badge-warn{background:#fdf2e3;color:#c18006}
.badge-error,.badge-bad{background:#ffebe9;color:#c9261a}
.notice{padding:12px;margin:10px 0;border-radius:4px;border:1px solid;font-size:13px}
.notice.notice-success{background-color:#eaf2e3;border-color:#d4e2c8;color:#5b841b}
.notice.notice-warning{background-color:#fdf2e3;border-color:#f0b849;color:#79550b}
.notice.notice-error{background-color:#fbe6e6;border-color:#c82124;color:#c82124}
.notice.notice-info{background-color:#e5f5fa;border-color:#0073aa;color:#0073aa}

.button-primary,.button{
    background:#0071a1;
    border-color:#0071a1;
    color:#fff;
    text-decoration:none;
    text-shadow:none;
    border-radius:5px;
    cursor:pointer;
    display:inline-block;
    padding:6px 6px;
    font-size:12px;
    line-height:20px;
    font-weight:600;
    height:22px;
}

.button{
    background:#e0e0e0;
    border-color:#ccc;
    color:#555;
}
.button-primary:hover{background:#0085ba}
.button-primary:active{background:#006799;transform:translateY(1px)}
.button:hover{background:#d0d0d0}
.button:active{background:#c0c0c0;transform:translateY(1px)}
.kit a{margin-right:10px;margin-bottom:10px}
.kit{margin-top:15px;display:flex;flex-wrap:wrap}
</style>
<script>
function confirmAct(msg, url){
  if(confirm(msg)){ location.href = url; }
  return false;
}
function exportJson(){
    var data = document.querySelector('pre#json-data').innerText;
    var blob = new Blob([data], {type: 'application/json'});
    var a = document.createElement('a');
    a.download = 'wp-diagnose-report.json';
    a.href = URL.createObjectURL(blob);
    a.click();
}
</script>
</head>
<body>
<div class="wp-wrap">
<div class="wp-header">
  <h1 class="title"><?php echo t('title'); ?></h1>
  <div class="actions">
    <a href="?lang=<?php echo $LANG==='tr'?'en':'tr'; ?>">
      <?php echo t('lang'); ?>: <?php echo $LANG==='tr'?'EN':'TR'; ?>
    </a>
    <a href="?reload=1#general"><?php echo t('reload'); ?></a>
    <a href="javascript:void(0)" onclick="exportJson()"><?php echo t('export_json'); ?></a>
  </div>
</div>
<div class="pad" style="padding:20px; text-align:center;">
  <p class="notice notice-warning" style="font-weight:bold;"><?php echo t('hint_delete_after'); ?></p>
</div>
<div class="wp-content">
  <div class="wp-nav">
    <a href="#general"><?php echo t('general'); ?></a>
    <a href="#integrity"><?php echo t('integrity'); ?></a>
    <a href="#security"><?php echo t('security'); ?></a>
    <a href="#urls"><?php echo t('urls'); ?></a>
    <a href="#seo"><?php echo t('seo'); ?></a>
    <a href="#plugins"><?php echo t('plugins'); ?></a>
    <a href="#themes"><?php echo t('themes'); ?></a>
    <a href="#updates"><?php echo t('updates'); ?></a>
    <a href="#tools"><?php echo t('tools'); ?></a>
    <a href="#server"><?php echo t('server'); ?></a>
    <a href="#debug"><?php echo t('debug_log'); ?></a>
  </div>
  <div class="wp-main">

<?php
// -------------------- Actions (Full Mode) --------------------
$MSG = '';
$REPORT_DATA = [];
if ($WP_LOADED && isset($_GET['action'])) {
    check_nonce();
    require_once ABSPATH.'wp-admin/includes/plugin.php';
    require_once ABSPATH.'wp-admin/includes/theme.php';
    require_once ABSPATH.'wp-admin/includes/file.php';
    require_once ABSPATH.'wp-admin/includes/update.php';
    require_once ABSPATH.'wp-admin/includes/class-wp-upgrader.php';
    if (!defined('WP_ADMIN')) define('WP_ADMIN', true);

    $a = $_GET['action'];
    if ($a==='deactivate_plugin' && !empty($_GET['plugin'])) { deactivate_plugins($_GET['plugin'], true); $MSG='<div class="notice notice-success">'.t('plugins').': '.t('deactivate').' OK</div>'; }
    if ($a==='activate_plugin' && !empty($_GET['plugin'])) {
        $r = activate_plugin($_GET['plugin'], '', false, false);
        $MSG = is_wp_error($r) ? '<div class="notice notice-error">'.h($r->get_error_message()).'</div>' : '<div class="notice notice-success">'.t('plugins').': '.t('activate').' OK</div>';
    }
    if ($a==='update_plugin' && !empty($_GET['plugin'])) { $up=new Plugin_Upgrader(new Automatic_Upgrader_Skin()); $up->upgrade($_GET['plugin']); $MSG='<div class="notice notice-success">'.t('plugins').': '.t('update').' OK</div>'; }
    if ($a==='update_all_plugins') {
        $upd = get_site_transient('update_plugins'); $list = array_keys($upd->response ?? []);
        if ($list){ $up=new Plugin_Upgrader(new Automatic_Upgrader_Skin()); foreach($list as $p){ $up->upgrade($p);} $MSG='<div class="notice notice-success">'.t('update_all_plugins').' OK</div>'; }
        else $MSG='<div class="notice notice-info">'.t('update_all_plugins').': 0</div>';
    }
    if ($a==='update_theme' && !empty($_GET['theme'])) { $up=new Theme_Upgrader(new Automatic_Upgrader_Skin()); $up->upgrade($_GET['theme']); $MSG='<div class="notice notice-success">'.t('themes').': '.t('update').' OK</div>'; }
    if ($a==='update_all_themes') {
        $upd=get_site_transient('update_themes'); $list=array_keys($upd->response ?? []);
        if ($list){ $up=new Theme_Upgrader(new Automatic_Upgrader_Skin()); foreach($list as $t){ $up->upgrade($t);} $MSG='<div class="notice notice-success">'.t('update_all_themes').' OK</div>'; }
        else $MSG='<div class="notice notice-info">'.t('update_all_themes').': 0</div>';
    }
    if ($a==='update_core') {
        require_once ABSPATH.'wp-admin/includes/class-core-upgrader.php';
        $up=new Core_Upgrader(new Automatic_Upgrader_Skin()); $offers=get_core_updates(['dismissed'=>false]);
        if (!empty($offers[0])){ $res=$up->upgrade($offers[0]); $MSG=is_wp_error($res)?'<div class="notice notice-error">'.h($res->get_error_message()).'</div>':'<div class="notice notice-success">'.t('update_core').' OK</div>'; }
        else $MSG='<div class="notice notice-info">'.t('update_core').': 0</div>';
    }
    if ($a==='flush_permalinks') { flush_rewrite_rules(true); $MSG='<div class="notice notice-success">'.t('flush_permalinks').' OK</div>'; }
    if ($a==='clear_transients') { global $wpdb; $c=$wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '\_transient\_%' OR option_name LIKE '\_site\_transient\_%'"); $MSG='<div class="notice notice-success">'.t('clear_transients').': '.intval($c).'</div>'; }
    if ($a==='clear_error_logs') {
        $cleared = 0;
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(ABSPATH, FilesystemIterator::SKIP_DOTS));
        foreach ($iterator as $file) {
            if ($file->getFilename() === 'error_log' && $file->isWritable()) {
                if (file_put_contents($file->getPathname(), '') !== false) {
                    $cleared++;
                }
            }
        }
        $MSG = '<div class="notice notice-success">'.$cleared.' '.t('files_cleared').'</div>';
    }
    if ($a==='clear_plugin_transient') {
        delete_site_transient('update_plugins');
        wp_update_plugins(); // Force check for updates
        $MSG = '<div class="notice notice-success">'.t('clear_plugin_transient').' OK</div>';
    }
    if ($a==='clear_theme_transient') {
        delete_site_transient('update_themes');
        wp_update_themes(); // Force check for updates
        $MSG = '<div class="notice notice-success">'.t('clear_theme_transient').' OK</div>';
    }
    if ($a==='delete_maintenance') { $f=ABSPATH.'.maintenance'; if (is_file($f)) @unlink($f); $MSG='<div class="notice notice-success">'.t('delete_maintenance').' OK</div>'; }
    if ($a==='force_sitemap_on') { $dir=WP_CONTENT_DIR.'/mu-plugins'; if(!is_dir($dir)) @mkdir($dir,0755,true); @file_put_contents($dir.'/force-sitemaps.php',"<?php\n/* Plugin Name: Force Enable WP Sitemaps */\nadd_filter('wp_sitemaps_enabled','__return_true');\n"); $MSG='<div class="notice notice-success">'.t('sitemap_on').' OK</div>'; }
    if ($a==='force_sitemap_off') { $f=WP_CONTENT_DIR.'/mu-plugins/force-sitemaps.php'; if(is_file($f)) @unlink($f); $MSG='<div class="notice notice-success">'.t('sitemap_off').' OK</div>'; }
}

// -------------------- Actions (DB Mode) --------------------
if (!$WP_LOADED && $DB) {
    if (isset($_GET['db_action'])) {
        check_nonce();
        $a = $_GET['db_action'];
        if ($a==='db_deactivate' && !empty($_GET['plugin'])) {
            $ser = $DB->get_option('active_plugins');
            $arr = @unserialize($ser, ['allowed_classes'=>false]); if (!is_array($arr)) $arr=[];
            $file = (string)$_GET['plugin'];
            $arr = array_values(array_filter($arr, fn($x)=>$x!==$file));
            $DB->update_option('active_plugins', serialize($arr));
            echo '<div class="notice notice-success">'.t('plugins').': '.t('deactivate').' OK</div>';
        }
        if ($a==='db_activate' && !empty($_GET['plugin'])) {
            $ser = $DB->get_option('active_plugins');
            $arr = @unserialize($ser, ['allowed_classes'=>false]); if (!is_array($arr)) $arr=[];
            $file = (string)$_GET['plugin'];
            if (!in_array($file,$arr,true)){ $arr[]=$file; $DB->update_option('active_plugins', serialize($arr)); }
            echo '<div class="notice notice-success">'.t('plugins').': '.t('activate').' OK</div>';
        }
        if ($a==='delete_maintenance') { $f=__DIR__.'/.maintenance'; if(is_file($f)) @unlink($f); echo '<div class="notice notice-success">'.t('delete_maintenance').' OK</div>'; }
        if ($a==='force_sitemap_on') { $dir=__DIR__.'/wp-content/mu-plugins'; if(!is_dir($dir)) @mkdir($dir,0755,true); @file_put_contents($dir.'/force-sitemaps.php',"<?php\n/* Plugin Name: Force Enable WP Sitemaps */\nadd_filter('wp_sitemaps_enabled','__return_true');\n"); echo '<div class="notice notice-success">'.t('sitemap_on').' OK</div>'; }
        if ($a==='force_sitemap_off') { $f=__DIR__.'/wp-content/mu-plugins/force-sitemaps.php'; if(is_file($f)) @unlink($f); echo '<div class="notice notice-success">'.t('sitemap_off').' OK</div>'; }
        if ($a === 'clear_error_logs') {
            $cleared = 0;
            $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(ABSPATH, FilesystemIterator::SKIP_DOTS));
            foreach ($iterator as $file) {
                if ($file->getFilename() === 'error_log' && $file->isWritable()) {
                    if (file_put_contents($file->getPathname(), '') !== false) {
                        $cleared++;
                    }
                }
            }
            echo '<div class="notice notice-success">'.$cleared.' '.t('files_cleared').'</div>';
        }
    }
}

// -------------------- General --------------------
echo '<a id="general"></a>';
echo '<div class="section"><h2>'.t('general').' — '.($WP_LOADED?t('mode_full'):($DB?'DB':'Lite').' '.t('mode_db')).'</h2><div class="pad">';
if ($MSG) echo $MSG;

if (!$WP_LOADED) {
    if (!empty($_SESSION['db_msg'])){ echo '<div class="notice notice-success">'.h($_SESSION['db_msg']).'</div>'; unset($_SESSION['db_msg']); }
    echo '<div class="notice notice-info">'.t('db_mode_form_title').'</div>';
    echo '<form method="post" class="form-table">';
    echo '<input type="hidden" name="_nonce" value="'.$NONCE.'">';
    echo '<tr><th><label for="db_host">'.t('db_host').'</label></th><td><input type="text" name="db_host" id="db_host" value="'.h($_SESSION['db_host'] ?? 'localhost').'"></td></tr>';
    echo '<tr><th><label for="db_name">'.t('db_name').'</label></th><td><input type="text" name="db_name" id="db_name" value="'.h($_SESSION['db_name'] ?? '').'"></td></tr>';
    echo '<tr><th><label for="db_user">'.t('db_user').'</label></th><td><input type="text" name="db_user" id="db_user" value="'.h($_SESSION['db_user'] ?? '').'"></td></tr>';
    echo '<tr><th><label for="db_pass">'.t('db_pass').'</label></th><td><input type="password" name="db_pass" id="db_pass" value="'.h($_SESSION['db_pass'] ?? '').'"></td></tr>';
    echo '<tr><th><label for="db_prefix">'.t('db_prefix').'</label></th><td><input type="text" name="db_prefix" id="db_prefix" value="'.h($_SESSION['db_prefix'] ?? 'wp_').'"></td></tr>';
    echo '<tr><td colspan="2"><button class="button-primary" name="dbsave" value="1">'.t('save').'</button></td></tr>';
    echo '</form>';
    if ($DB_ERR) echo '<div class="notice notice-error">'.h($DB_ERR).'</div>';
}

if ($WP_LOADED) {
    echo '<table>';
    echo '<tr><th>'.t('site').'</th><td>'.h(home_url('/')).'</td></tr>';
    echo '<tr><th>'.t('wp_version').'</th><td>'.h(get_bloginfo('version')).'</td></tr>';
    echo '<tr><th>'.t('php_version').'</th><td>'.h(PHP_VERSION).'</td></tr>';
    echo '</table>';
    $REPORT_DATA['general'] = [
        'mode' => 'Full Mode',
        'site_url' => home_url('/'),
        'wp_version' => get_bloginfo('version'),
        'php_version' => PHP_VERSION,
    ];
} else {
    echo '<table>';
    echo '<tr><th>'.t('php_version').'</th><td>'.h(PHP_VERSION).'</td></tr>';
    echo '</table>';
    $REPORT_DATA['general'] = [
        'mode' => 'DB Mode',
        'php_version' => PHP_VERSION,
    ];
}
echo '</div></div>';

// -------------------- Core Integrity (Checksums) --------------------
echo '<a id="integrity"></a>';
echo '<div class="section"><h2>'.t('integrity').'</h2><div class="pad">';
if ($WP_LOADED) {
    global $wp_version;
    $checksums_api_url = "https://api.wordpress.org/core/checksums/1.0/?version={$wp_version}&locale=en_US";
    $api_response = wp_remote_get($checksums_api_url);

    echo '<table><tr><th>'.t('check').'</th><th>'.t('status').'</th><th>Info</th></tr>';
    $rows = [];
    $rows[] = [t('wp_version'), 'OK', 'v'.$wp_version];
    $REPORT_DATA['integrity'] = ['wp_version' => $wp_version];
    if (is_wp_error($api_response) || wp_remote_retrieve_response_code($api_response) !== 200) {
        $rows[] = [t('checksums_api'), 'ERROR', t('checksum_api_error_1')];
        $REPORT_DATA['integrity']['checksums_api'] = 'ERROR';
    } else {
        $checksums = json_decode(wp_remote_retrieve_body($api_response), true);
        if (empty($checksums['checksums'])) {
            $rows[] = [t('checksums_api'), 'ERROR', t('checksum_api_error_2')];
            $REPORT_DATA['integrity']['checksums_api'] = 'ERROR';
        } else {
            // New logic: Filter the official checksum list.
            $known_files = [];
            foreach ($checksums['checksums'] as $file_path => $hash) {
                // Exclude themes, plugins, and other non-core files
                if (strpos($file_path, 'wp-content/themes/') === 0 || strpos($file_path, 'wp-content/plugins/') === 0) {
                    continue;
                }
                if ($file_path === 'readme.html' || $file_path === 'license.txt') {
                    continue;
                }
                $known_files[$file_path] = $hash;
            }

            $modified_files = [];
            $missing_files = [];
            $unknown_files = [];

            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator(ABSPATH, FilesystemIterator::SKIP_DOTS),
                RecursiveIteratorIterator::SELF_FIRST
            );
            $local_files = [];
            foreach ($iterator as $file) {
                if ($file->isFile()) {
                    $path = str_replace(ABSPATH, '', $file->getPathname());
                    $path = str_replace('\\', '/', $path);
                    $local_files[$path] = hash_file('md5', $file->getPathname());
                }
            }

            foreach ($known_files as $file_path => $hash) {
                if (!isset($local_files[$file_path])) {
                    $missing_files[] = $file_path;
                } elseif ($local_files[$file_path] !== $hash) {
                    $modified_files[] = $file_path;
                }
            }
            
            // NEW LOGIC: Filter unknown files for common/harmless ones
            foreach ($local_files as $file_path => $hash) {
                // Skip files in directories we know about
                if (strpos($file_path, 'wp-content/uploads/') === 0 ||
                    strpos($file_path, 'wp-content/languages/') === 0 ||
                    strpos($file_path, 'wp-content/plugins/') === 0 ||
                    strpos($file_path, 'wp-content/themes/') === 0) {
                    continue;
                }
                // Skip common non-core files
                if (in_array($file_path, ['.htaccess', 'robots.txt', 'wp-config.php', 'wp-diagnose.php'])) {
                    continue;
                }

                if (!isset($known_files[$file_path])) {
                    $unknown_files[] = $file_path;
                }
            }

            $rows[] = [t('core_file_count'), 'OK', count($known_files)];
            $rows[] = [t('modified_files'), empty($modified_files) ? 'OK' : 'ERROR', count($modified_files)];
            $rows[] = [t('missing_files'), empty($missing_files) ? 'OK' : 'WARN', count($missing_files)];
            $rows[] = [t('unknown_files'), empty($unknown_files) ? 'OK' : 'WARN', count($unknown_files)];
            
            $REPORT_DATA['integrity']['modified_files'] = $modified_files;
            $REPORT_DATA['integrity']['missing_files'] = $missing_files;
            $REPORT_DATA['integrity']['unknown_files'] = $unknown_files;
        }
    }
    foreach ($rows as $r) {
        $info_text = h($r[2]);
        // Display modified files in a textarea
        if ($r[0] === t('modified_files') && !empty($modified_files)) {
            $info_text = '<textarea readonly style="height:200px; width: -moz-available;">' . implode("\n", $modified_files) . '</textarea>';
        }
        if ($r[0] === t('missing_files') && !empty($missing_files)) {
            $info_text = '<textarea readonly style="height:200px; width: -moz-available;">' . implode("\n", $missing_files) . '</textarea>';
        }
        if ($r[0] === t('unknown_files') && !empty($unknown_files)) {
             $info_text = '<textarea readonly style="height:200px; width: -moz-available;">' . implode("\n", $unknown_files) . '</textarea>';
        }
        echo '<tr><td>'.h($r[0]).'</td><td>'.badge($r[1]).'</td><td>'.$info_text.'</td></tr>';
    }
    echo '</table>';
} else {
    echo '<div class="notice notice-info">'.t('full_needed').'</div>';
}
echo '</div></div>';

// -------------------- Security Quick Wins --------------------
echo '<a id="security"></a>';
echo '<div class="section"><h2>'.t('security').'</h2><div class="pad">';
if ($WP_LOADED || $DB) {
    echo '<table><tr><th>'.t('check').'</th><th>'.t('status').'</th><th>Info</th></tr>';
    $rows = [];

    $admin_user_exists = false;
    if ($WP_LOADED) {
        global $wpdb;
        $admin_user_exists = $wpdb->get_var("SELECT user_login FROM {$wpdb->users} WHERE user_login = 'admin'");
    } elseif ($DB) {
        $admin_user_exists = $DB->get_user('admin');
    }
    $admin_status = $admin_user_exists ? 'WARN' : 'OK';
    $admin_info = $admin_user_exists ? t('admin_user_exists') : t('admin_user_not_found');
    $rows[] = [t('admin_user'), $admin_status, $admin_info];
    $REPORT_DATA['security']['admin_user'] = $admin_status;

    $wp_config_path = ABSPATH . 'wp-config.php';
    if(is_file($wp_config_path)){
        $perms = substr(sprintf('%o', fileperms($wp_config_path)), -4);
        $perms_status = ($perms === '0644' || $perms === '0600') ? 'OK' : 'WARN';
        $rows[] = [t('wp_config_perms'), $perms_status, $perms];
        $REPORT_DATA['security']['wp_config_perms'] = $perms_status;
    }
    $dir_perms_ok = is_dir(ABSPATH) && (substr(sprintf('%o', fileperms(ABSPATH)), -4) === '0755' || substr(sprintf('%o', fileperms(ABSPATH)), -4) === '0750' || substr(sprintf('%o', fileperms(ABSPATH)), -4) === '0700');
    $dir_perms_status = $dir_perms_ok ? 'OK' : 'WARN';
    $rows[] = [t('dir_perms'), $dir_perms_status, substr(sprintf('%o', fileperms(ABSPATH)), -4)];
    $REPORT_DATA['security']['dir_perms'] = $dir_perms_status;

    $salts_ok = true;
    $wp_config_content = @file_get_contents($wp_config_path);
    $salts = ['AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY', 'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT'];
    foreach ($salts as $salt) {
        if (!defined($salt) && strpos($wp_config_content, $salt) === false) {
            $salts_ok = false;
            break;
        }
    }
    $salts_status = $salts_ok ? 'OK' : 'WARN';
    $salts_info = $salts_ok ? t('all_keys_ok') : t('some_keys_missing');
    $rows[] = [t('auth_keys'), $salts_status, $salts_info];
    $REPORT_DATA['security']['secure_keys'] = $salts_status;

    $readme_ok = !is_file(ABSPATH . 'readme.html') && !is_file(ABSPATH . 'license.txt');
    $readme_status = $readme_ok ? 'OK' : 'WARN';
    $readme_info = $readme_ok ? t('files_removed') : t('files_present_remove');
    $rows[] = [t('readme_license'), $readme_status, $readme_info];
    $REPORT_DATA['security']['readme_license'] = $readme_status;

    foreach ($rows as $r) { echo '<tr><td>'.h($r[0]).'</td><td>'.badge($r[1]).'</td><td>'.h($r[2]).'</td></tr>'; }
    echo '</table>';
} else {
    echo '<div class="notice notice-info">'.t('full_needed').'</div>';
}
echo '</div></div>';

// -------------------- URL Consistency & HTTPS --------------------
echo '<a id="urls"></a>';
echo '<div class="section"><h2>'.t('urls').'</h2><div class="pad">';
if ($WP_LOADED) {
    global $wpdb;
    
    // Get values directly from the database to avoid filter issues
    $db_home_url = $wpdb->get_var("SELECT option_value FROM {$wpdb->options} WHERE option_name = 'home'");
    $db_site_url = $wpdb->get_var("SELECT option_value FROM {$wpdb->options} WHERE option_name = 'siteurl'");

    echo '<table><tr><th>'.t('check').'</th><th>'.t('status').'</th><th>Info</th></tr>';
    $rows = [];

    $home_url = $db_home_url;
    $site_url = $db_site_url;
    $rows[] = [t('home_url'), '', h($home_url)];
    $rows[] = [t('site_url'), '', h($site_url)];
    $consistency_status = $home_url === $site_url ? 'OK' : 'WARN';
    $consistency_info = $home_url === $site_url ? t('url_consistency_ok') : '';
    $rows[] = ['URL Consistency', $consistency_status, $consistency_info];

    $is_https = strpos($home_url, 'https://') === 0;
    $https_status = $is_https ? 'OK' : 'WARN';
    $https_info = $is_https ? t('https_in_use') : t('https_not_in_use');
    $rows[] = ['HTTPS', $https_status, $https_info];

    $http_url = str_replace('https://', 'http://', $home_url);
    $redirect_test = wp_remote_get($http_url, ['redirection' => 0]);
    if (is_wp_error($redirect_test)) {
        $redirect_status = 'ERROR';
        $redirect_info = t('redirect_check_failed') . ' ' . h($redirect_test->get_error_message());
    } else {
        $response_code = wp_remote_retrieve_response_code($redirect_test);
        $redirect_ok = ($response_code === 301 || $response_code === 302) && strpos(wp_remote_retrieve_header($redirect_test, 'location'), 'https://') === 0;
        $redirect_status = $redirect_ok ? 'OK' : 'WARN';
        $redirect_info = t('http_status_code') . ' ' . $response_code;
    }
    $rows[] = [t('https_redirect'), $redirect_status, $redirect_info];

    $mixed_content_warn = false;
    $options = wpd_get_all_options();
    foreach ($options as $option) {
        if (is_string($option->option_value) && strpos($option->option_value, 'http://') !== false && strpos($option->option_value, 'https://') !== false) {
             $mixed_content_warn = true;
             break;
        }
    }
    $mixed_content_status = $mixed_content_warn ? 'WARN' : 'OK';
    $mixed_content_info = $mixed_content_warn ? t('mixed_content_found') : t('mixed_content_ok');
    $rows[] = [t('mixed_content'), $mixed_content_status, $mixed_content_info];

    $REPORT_DATA['urls'] = [
        'home_url' => $home_url,
        'site_url' => $site_url,
        'consistency_status' => $consistency_status,
        'https_status' => $https_status,
        'https_redirect_status' => $redirect_status,
        'mixed_content_status' => $mixed_content_status,
    ];

    foreach ($rows as $r) { echo '<tr><td>'.h($r[0]).'</td><td>'.badge($r[1]).'</td><td>'.h($r[2]).'</td></tr>'; }
    echo '</table>';
} else {
    echo '<div class="notice notice-info">'.t('full_needed').'</div>';
}
echo '</div></div>';


// -------------------- SEO & Sitemap --------------------
echo '<a id="seo"></a>';
echo '<div class="section"><h2>'.t('seo').'</h2><div class="pad">';

if ($WP_LOADED) {
    $rows=[];
    global $wp_version;
    $core55_status = version_compare($wp_version,'5.5','>=')?'OK':'ERROR';
    $rows[]=[t('core_55'), $core55_status, 'v '.$wp_version];
    $blog_public=get_option('blog_public');
    $blog_public_status = $blog_public?'OK':'WARN';
    $rows[]=[t('blog_public'), $blog_public_status, 'blog_public='.intval($blog_public)];
    $enabled = apply_filters('wp_sitemaps_enabled', true);
    $sitemaps_status = $enabled?'OK':'ERROR';
    $rows[]=[t('sitemaps_enabled'), $sitemaps_status, $enabled?'true':'false'];
    $r1 = wp_remote_get(home_url('/wp-sitemap.xml')); $c1=is_wp_error($r1)?0:wp_remote_retrieve_response_code($r1);
    $r2 = wp_remote_get(home_url('/sitemap_index.xml')); $c2=is_wp_error($r2)?0:wp_remote_retrieve_response_code($r2);
    $sitemap_status1 = ($c1>=200 && $c1<400)?'OK':'ERROR';
    $sitemap_status2 = ($c2>=200 && $c2<400)?'OK':'WARN';
    $rows[]=['/wp-sitemap.xml', $sitemap_status1, t('http').' '.$c1];
    $rows[]=['/sitemap_index.xml', $sitemap_status2, t('http').' '.$c2];

    $REPORT_DATA['seo'] = [
        'core_version_status' => $core55_status,
        'blog_public_status' => $blog_public_status,
        'sitemaps_enabled_status' => $sitemaps_status,
        'wp_sitemap_xml_status' => $sitemap_status1,
        'sitemap_index_xml_status' => $sitemap_status2,
    ];

    echo '<table><tr><th>'.t('check').'</th><th>'.t('status').'</th><th>Info</th></tr>';
    foreach($rows as $r){ echo '<tr><td>'.h($r[0]).'</td><td>'.badge($r[1]).'</td><td>'.h($r[2]).'</td></tr>'; }
    echo '</table>';
} else {
    echo '<div class="notice notice-info">'.t('full_needed').'</div>';
}
echo '</div></div>';

// -------------------- Plugins --------------------
echo '<a id="plugins"></a>';
echo '<div class="section"><h2>'.t('plugins').'</h2><div class="pad">';
$nonce='&_nonce='.$NONCE;
$plugins_data = [];

if ($WP_LOADED) {
    require_once ABSPATH.'wp-admin/includes/plugin.php';
    $plugins=get_plugins(); $active=(array)get_option('active_plugins',[]);
    $updates=get_site_transient('update_plugins'); $needUpd=array_keys($updates->response ?? []);
    echo '<p class="kit"><a class="button-primary" href="?action=update_all_plugins'.$nonce.'#plugins" onclick="return confirmAct(\''.t('nonce_confirm').'\', this.href);">'.t('update_all_plugins').'</a></p>';
    echo '<table><tr><th>'.t('plugins').'</th><th>'.t('status').'</th><th>'.t('version').'</th><th>'.t('action').'</th></tr>';
    foreach($plugins as $file=>$data){
        $isActive=in_array($file,$active,true);
        $isUpdateNeeded = in_array($file,$needUpd,true);
        $vers=$isUpdateNeeded? '<span class="badge badge-warn">'.t('update').'</span> → '.h($updates->response[$file]->new_version ?? '') : '<span class="badge badge-ok">'.h($data['Version']).'</span>';
        $acts=[];
        if ($isActive) $acts[]='<a class="button" href="?action=deactivate_plugin&plugin='.rawurlencode($file).$nonce.'#plugins" onclick="return confirmAct(\''.t('nonce_confirm').'\', this.href);">'.t('deactivate').'</a>';
        else $acts[]='<a class="button-primary" href="?action=activate_plugin&plugin='.rawurlencode($file).$nonce.'#plugins" onclick="return confirmAct(\''.t('nonce_confirm').'\', this.href);">'.t('activate').'</a>';
        if ($isUpdateNeeded) $acts[]='<a class="button-primary" href="?action=update_plugin&plugin='.rawurlencode($file).$nonce.'#plugins" onclick="return confirmAct(\''.t('nonce_confirm').'\', this.href);">'.t('update').'</a>';
        echo '<tr><td><b>'.h($data['Name']).'</b><br><small>'.h($file).'</small></td><td>'.($isActive?badge('OK'):badge('WARN')).'</td><td>'.$vers.'</td><td>'.implode(' ',$acts).'</td></tr>';
        $plugins_data[$file] = [
            'name' => $data['Name'],
            'status' => $isActive ? 'active' : 'inactive',
            'version' => $data['Version'],
            'update_available' => $isUpdateNeeded,
            'new_version' => $isUpdateNeeded ? $updates->response[$file]->new_version : null,
        ];
    }
    echo '</table>';
    $REPORT_DATA['plugins'] = $plugins_data;
} else {
    if ($DB) {
        $ser = $DB->get_option('active_plugins'); $active = @unserialize($ser,['allowed_classes'=>false]); if (!is_array($active)) $active=[];
        $plugdir = __DIR__.'/wp-content/plugins';
        $rows=[];
        if (is_dir($plugdir)){
            foreach (glob($plugdir.'/*', GLOB_ONLYDIR) as $dir){
                $files = glob($dir.'/*.php');
                $headerName=''; $headerFile='';
                foreach ($files as $f){
                    $src = @file_get_contents($f, false, null, 0, 8192);
                    if ($src && preg_match('/^\s*\/\*\s*.*?Plugin\s*Name:\s*(.+?)\r?\n/si',$src,$m)){
                        $headerName=trim($m[1]); $headerFile=basename($f); break;
                    }
                }
                if ($headerName){
                    $file = basename($dir).'/'.$headerFile;
                    $isActive = in_array($file,$active,true);
                    $rows[] = [$headerName,$file,$isActive];
                    $plugins_data[$file] = ['name' => $headerName, 'status' => $isActive ? 'active' : 'inactive'];
                }
            }
        }
        echo '<table><tr><th>'.t('plugins').'</th><th>'.t('status').'</th><th>'.t('action').'</th></tr>';
        foreach($rows as $r){
            $acts = $r[2]
                ? '<a class="button" href="?db_action=db_deactivate&plugin='.rawurlencode($r[1]).$nonce.'#plugins" onclick="return confirmAct(\''.t('nonce_confirm').'\', this.href);">'.t('deactivate').'</a>'
                : '<a class="button-primary" href="?db_action=db_activate&plugin='.rawurlencode($r[1]).$nonce.'#plugins" onclick="return confirmAct(\''.t('nonce_confirm').'\', this.href);">'.t('activate').'</a>';
            echo '<tr><td><b>'.h($r[0]).'</b><br><small>'.h($r[1]).'</small></td><td>'.($r[2]?'<span class="badge badge-ok">'.t('active').'</span>':'<span class="badge badge-warn">'.t('inactive').'</span>').'</td><td>'.implode(' ',$acts).'</td></tr>';
        }
        $REPORT_DATA['plugins'] = $plugins_data;
        if (!$rows) echo '<div class="notice notice-info">'.t('debug_log_not_found').'</div>';
    } else {
        echo '<div class="notice notice-info">'.t('db_mode_form_title').'</div>';
    }
}
echo '</div></div>';

// -------------------- Themes --------------------
echo '<a id="themes"></a>';
echo '<div class="section"><h2>'.t('themes').'</h2><div class="pad">';
if ($WP_LOADED) {
    $themes=wp_get_themes(); $current=wp_get_theme(); $upd=get_site_transient('update_themes'); $need=array_keys($upd->response ?? []);
    echo '<p class="kit"><a class="button-primary" href="?action=update_all_themes'.$nonce.'#themes" onclick="return confirmAct(\''.t('nonce_confirm').'\', this.href);">'.t('update_all_themes').'</a></p>';
    echo '<table><tr><th>'.t('themes').'</th><th>'.t('status').'</th><th>'.t('version').'</th><th>'.t('action').'</th></tr>';
    $themes_data = [];
    foreach($themes as $slug=>$th){
        $isCurrent = ($current->get_stylesheet() === $th->get_stylesheet());
        $isUpdateNeeded = in_array($slug,$need,true);
        $verBadge = $isUpdateNeeded? '<span class="badge badge-warn">'.t('update').'</span> → '.h($upd->response[$slug]['new_version']):'<span class="badge badge-ok">'.h($th->get('Version')).'</span>';
        $act = '<a class="button-primary" href="?action=update_theme&theme='.rawurlencode($slug).$nonce.'#themes" onclick="return confirmAct(\''.t('nonce_confirm').'\', this.href);">'.t('update').'</a>';
        echo '<tr><td><b>'.h($th->get('Name')).'</b><br><small>'.h($slug).'</small></td><td>'.($isCurrent?badge('OK'):'—').'</td><td>'.$verBadge.'</td><td>'.(in_array($slug, $need, true) ? $act : t('no_update')).'</td></tr>';
        $themes_data[$slug] = [
            'name' => $th->get('Name'),
            'status' => $isCurrent ? 'active' : 'inactive',
            'version' => $th->get('Version'),
            'update_available' => $isUpdateNeeded,
            'new_version' => $isUpdateNeeded ? $upd->response[$slug]['new_version'] : null,
        ];
    }
    echo '</table>';
    $REPORT_DATA['themes'] = $themes_data;
} else {
    echo '<div class="notice notice-info">'.t('full_needed').'</div>';
}
echo '</div></div>';

// -------------------- Updates --------------------
echo '<a id="updates"></a>';
echo '<div class="section"><h2>'.t('updates').'</h2><div class="pad">';
if ($WP_LOADED) {
    require_once ABSPATH.'wp-admin/includes/update.php';
    $offers=get_core_updates(['dismissed'=>false]);
    $core_update_data = [];
    if (!empty($offers[0])) {
        $o=$offers[0];
        echo '<div class="notice notice-warning">Current: '.h(get_bloginfo('version')).' → <b>'.h($o->current).'</b> ('.h($o->response).')</div>';
        echo '<a class="button-primary" href="?action=update_core'.$nonce.'#updates" onclick="return confirmAct(\''.t('nonce_confirm').'\', this.href);">'.t('update_core').'</a>';
        $core_update_data = ['status' => 'Update Available', 'current' => $o->current, 'new_version' => $o->response];
    } else {
        echo '<div class="notice notice-success">'.t('no_update').'</div>';
        $core_update_data = ['status' => 'No Update Needed'];
    }
    $REPORT_DATA['updates']['core'] = $core_update_data;
} else {
    echo '<div class="notice notice-info">'.t('full_needed').'</div>';
}
echo '</div></div>';

// -------------------- Tools --------------------
echo '<a id="tools"></a>';
echo '<div class="section"><h2>'.t('tools').'</h2><div class="pad">';
if ($WP_LOADED || $DB) {
    echo '<div class="kit">';
    if($WP_LOADED){
        echo '<a class="button-primary" href="?action=flush_permalinks'.$nonce.'#tools" onclick="return confirmAct(\''.t('nonce_confirm').'\', this.href);">'.t('flush_permalinks').'</a>';
        echo '<a class="button-primary" href="?action=clear_transients'.$nonce.'#tools" onclick="return confirmAct(\''.t('nonce_confirm').'\', this.href);">'.t('clear_transients').'</a>';
        echo '<a class="button-primary" href="?action=clear_plugin_transient'.$nonce.'#tools" onclick="return confirmAct(\''.t('nonce_confirm').'\', this.href);">'.t('clear_plugin_transient').'</a>';
        echo '<a class="button-primary" href="?action=clear_theme_transient'.$nonce.'#tools" onclick="return confirmAct(\''.t('nonce_confirm').'\', this.href);">'.t('clear_theme_transient').'</a>';
    }
    echo '<a class="button-primary" href="?action=clear_error_logs'.$nonce.'#tools" onclick="return confirmAct(\''.t('nonce_confirm').'\', this.href);">'.t('clear_error_logs').'</a>';
    echo '<a class="button-primary" href="?action=delete_maintenance'.$nonce.'#tools" onclick="return confirmAct(\''.t('nonce_confirm').'\', this.href);">'.t('delete_maintenance').'</a>';
    echo '<a class="button-primary" href="?action=force_sitemap_on'.$nonce.'#tools" onclick="return confirmAct(\''.t('nonce_confirm').'\', this.href);">'.t('sitemap_on').'</a>';
    echo '<a class="button-primary" href="?action=force_sitemap_off'.$nonce.'#tools" onclick="return confirmAct(\''.t('nonce_confirm').'\', this.href);">'.t('sitemap_off').'</a>';
    echo '</div>';
    $REPORT_DATA['tools'] = ['status' => 'Buttons available'];
} else {
    echo '<div class="notice notice-info">'.t('db_mode_form_title').'</div>';
}
echo '</div></div>';

// -------------------- Server/PHP --------------------
echo '<a id="server"></a>';
echo '<div class="section"><h2>'.t('server').'</h2><div class="pad">';
echo '<table><tr><th>Key</th><th>'.t('actual').'</th><th>'.t('recommended').'</th><th>'.t('status').'</th></tr>';
$php_limits = [
    'memory_limit' => ['128M','256M'],
    'max_execution_time' => [30, 300],
    'upload_max_filesize' => ['2M', '128M'],
    'post_max_size' => ['8M', '128M']
];

function convert_to_bytes($val) {
    $val = trim($val);
    $last = strtolower($val[strlen($val)-1]);
    $val = (int)$val;
    switch($last) {
        case 'g': $val *= 1024;
        case 'm': $val *= 1024;
        case 'k': $val *= 1024;
    }
    return $val;
}

$server_data = [];
foreach ($php_limits as $key => $recs) {
    $actual = ini_get($key);
    $rec_val = $recs[1];
    $status = convert_to_bytes($actual) >= convert_to_bytes($recs[0]) ? 'OK' : 'WARN';
    echo '<tr><td>'.h($key).'</td><td>'.h($actual).'</td><td>'.h($rec_val).'</td><td>'.badge($status).'</td></tr>';
    $server_data[$key] = ['actual' => $actual, 'recommended' => $rec_val, 'status' => $status];
}

echo '</table>';
echo '<hr>';
echo '<h3>'.t('ext_loaded').'</h3>';
echo '<table><tr><th>Extension</th><th>'.t('status').'</th></tr>';
$extensions = ['mysqli', 'curl', 'json', 'dom', 'gd', 'mbstring', 'openssl', 'zip'];
$extensions_data = [];
foreach ($extensions as $ext) {
    $status = extension_loaded($ext) ? 'OK' : 'WARN';
    echo '<tr><td>'.h($ext).'</td><td>'.badge($status).'</td></tr>';
    $extensions_data[$ext] = $status;
}
echo '</table>';
$REPORT_DATA['server']['extensions'] = $extensions_data;

if ($WP_LOADED) {
    $rest = wp_remote_get(home_url('/wp-json/')); $code = is_wp_error($rest)?0:wp_remote_retrieve_response_code($rest);
    echo '<hr>';
    echo '<p>'.t('rest_api').': HTTP '.$code.'</p>';
    $REPORT_DATA['server']['rest_api'] = $code;
}
echo '</div></div>';

// -------------------- Debug Log --------------------
echo '<a id="debug"></a>';
echo '<div class="section"><h2>'.t('debug_log').'</h2><div class="pad">';
$debug_log_path = ABSPATH . 'wp-content/debug.log';
if (is_file($debug_log_path) && is_readable($debug_log_path) && filesize($debug_log_path) > 0) {
    echo '<textarea readonly style="width:100%;min-height:400px;">'.h(file_get_contents($debug_log_path)).'</textarea>';
    $REPORT_DATA['debug'] = ['status' => 'OK', 'content' => file_get_contents($debug_log_path)];
} else {
    echo '<div class="notice notice-info">'.t('debug_log_not_found').'</div>';
    $REPORT_DATA['debug'] = ['status' => 'Not found or empty'];
}
echo '</div></div>';

?>
  </div>
</div>

<div style="display:none;">
    <pre id="json-data"><?php echo json_encode($REPORT_DATA, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE); ?></pre>
</div>

</body>
</html>