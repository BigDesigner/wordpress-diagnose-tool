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
require_once __DIR__ . '/src/Agents/CoreIntegrityAgent/CoreIntegrityAgent.php';
require_once __DIR__ . '/src/Agents/AssetManagerAgent/AssetManagerAgent.php';
require_once __DIR__ . '/src/Agents/CoreOperationsAgent/CoreOperationsAgent.php';

// -------------------- WP-CLI INTEGRATION --------------------
if (defined('WP_CLI') && WP_CLI) {
    \WP_CLI::add_command('diagnose run', function($args, $assoc_args) {
        $engine = new \WPDiagnose\Core\Engine();
        $engine->registerAgent(new \WPDiagnose\Agents\ServerInspector\ServerInspector());
        $engine->registerAgent(new \WPDiagnose\Agents\WPInspector\WPInspector(true));
        $engine->registerAgent(new \WPDiagnose\Agents\SecurityInspector\SecurityInspector());
        $engine->registerAgent(new \WPDiagnose\Agents\BootstrapInspector\BootstrapInspector());
        $engine->registerAgent(new \WPDiagnose\Agents\DBHealth\DBHealth(true));
        $engine->registerAgent(new \WPDiagnose\Agents\CoreIntegrityAgent\CoreIntegrityAgent(true));
        $engine->registerAgent(new \WPDiagnose\Agents\AssetManagerAgent\AssetManagerAgent(true));
        $engine->registerAgent(new \WPDiagnose\Agents\CoreOperationsAgent\CoreOperationsAgent(true));

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

// -------------------- 0.2.4-beta SECURITY CONFIGURATION --------------------
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

// Fallback for Independent Mode (Agents rely on ABSPATH)
if (!defined('ABSPATH')) {
    define('ABSPATH', rtrim($base, '/\\') . '/');
}

// -------------------- DB Mode Helper --------------------
class WPD_DB
{
    public $mysqli;
    public $prefix;
    function __construct($h, $u, $p, $d, $pref)
    {
        $this->mysqli = @new mysqli($h, $u, $p, $d);
        if ($this->mysqli->connect_errno)
            throw new \Exception($this->mysqli->connect_error);
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
}

// -------------------- Emergency Independent DB Connection --------------------
$DB = null;
$DB_ERR = '';

// ALWAYS parse wp-config.php for direct SQL access (bypassing high-level WP ops)
$config_path = ABSPATH . 'wp-config.php';
if (is_file($config_path)) {
    $cfg = file_get_contents($config_path);
    
    $db_host = preg_match("/define\(\s*['\"]DB_HOST['\"]\s*,\s*['\"](.*?)['\"]\s*\)/i", $cfg, $m) ? $m[1] : 'localhost';
    $db_name = preg_match("/define\(\s*['\"]DB_NAME['\"]\s*,\s*['\"](.*?)['\"]\s*\)/i", $cfg, $m) ? $m[1] : '';
    $db_user = preg_match("/define\(\s*['\"]DB_USER['\"]\s*,\s*['\"](.*?)['\"]\s*\)/i", $cfg, $m) ? $m[1] : '';
    $db_pass = preg_match("/define\(\s*['\"]DB_PASSWORD['\"]\s*,\s*['\"](.*?)['\"]\s*\)/i", $cfg, $m) ? $m[1] : '';
    $table_prefix = preg_match("/\\\$table_prefix\s*=\s*['\"](.*?)['\"]/i", $cfg, $m) ? $m[1] : 'wp_';
    
    if ($db_name && $db_user) {
        try {
            $DB = new \WPD_DB($db_host, $db_user, $db_pass, $db_name, $table_prefix);
        } catch (\Throwable $e) {
            $DB_ERR = $e->getMessage();
        }
    }
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
        $engine->registerAgent(new \WPDiagnose\Agents\CoreIntegrityAgent\CoreIntegrityAgent($WP_LOADED));
        $engine->registerAgent(new \WPDiagnose\Agents\AssetManagerAgent\AssetManagerAgent($WP_LOADED));
        $engine->registerAgent(new \WPDiagnose\Agents\CoreOperationsAgent\CoreOperationsAgent($WP_LOADED));

        $response = ['success' => true, 'data' => []];

        if (isset($_GET['action'])) {
            if ($_GET['action'] === 'fix') {
                $agent = $_POST['agent'] ?? $_GET['agent'] ?? '';
                $id    = $_POST['id'] ?? $_GET['id'] ?? '';
                
                wpd_log_action('API_FIX_POST', "Agent: $agent | FixID: $id | WP_LOADED: " . ($WP_LOADED ? 'YES' : 'NO'));
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

// -------------------- Self-Destruct Mechanism (0.2.4-beta Enhanced) --------------------
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

// WPD_DB and Independent Mode Connection Moved Up

// -------------------- Modern SPA Dashboard (v0.2.4-beta) --------------------
?><!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WP Diagnose PRO v0.2.4-beta</title>
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
                    <span class="text-slate-400 font-mono text-sm block truncate">v0.2.4-beta Agentic Collective</span>
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
                        <div class="px-6 py-4 bg-slate-800/80 border-t border-slate-700/60 flex justify-between items-center text-xs text-slate-400">
                            <span class="font-mono">WP Diagnose PRO v0.2.4-beta</span>
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
                                    
                                    <!-- Re-install Core Button for Watchdog -->
                                    <template x-if="(agent === 'CoreIntegrityAgent' && (id === 'mismatch_files' || id === 'missing_files')) && finding.status !== 'OK'">
                                        <div class="flex gap-2 mb-4">
                                            <button @click="attemptFix('CoreOperationsAgent', 'reinstall_core')" class="text-[10px] font-bold uppercase tracking-wider bg-rose-600/20 hover:bg-rose-600 text-rose-400 hover:text-white border border-rose-600/50 px-4 py-2 rounded transition">
                                                Force Re-install WP Core
                                            </button>
                                        </div>
                                    </template>

                                    <!-- Dynamic Data Table UI (The Scannable Layout) -->
                                    <template x-if="finding.data && typeof finding.data === 'object'">
                                        <div class="mb-4 overflow-hidden rounded-lg border border-slate-700/60 shadow-inner bg-slate-900/30">
                                            <!-- Simple List Array -->
                                            <template x-if="Array.isArray(finding.data) && typeof finding.data[0] === 'string'">
                                                <ul class="list-none divide-y divide-slate-800 text-sm text-slate-300 font-mono">
                                                    <template x-for="item in finding.data" :key="item">
                                                        <li class="px-4 py-2 hover:bg-slate-800/50 flex items-center gap-2">
                                                            <span class="w-1.5 h-1.5 bg-rose-500 rounded-full"></span>
                                                            <span x-text="item" class="break-all"></span>
                                                        </li>
                                                    </template>
                                                </ul>
                                            </template>
                                            
                                            <!-- Scannable Object Array Table -->
                                            <template x-if="!Array.isArray(finding.data) && typeof Object.values(finding.data)[0] === 'object'">
                                                <div class="overflow-x-auto">
                                                    <table class="w-full text-left text-sm text-slate-300">
                                                        <thead class="text-[10px] uppercase bg-slate-800 text-slate-400 border-b border-slate-700/60 sticky top-0">
                                                            <tr>
                                                                <th class="px-4 py-3 font-semibold tracking-wider">Asset Details</th>
                                                                <th class="px-4 py-3 font-semibold tracking-wider w-28 text-center">Status</th>
                                                                <th class="px-4 py-3 font-semibold tracking-wider w-36 text-right">Action (Independent)</th>
                                                            </tr>
                                                        </thead>
                                                        <tbody class="divide-y divide-slate-800 text-xs">
                                                            <template x-for="(props, key) in finding.data" :key="key">
                                                                <tr class="hover:bg-slate-800/50 transition">
                                                                    <td class="px-4 py-3">
                                                                        <div class="font-bold text-sky-400 mb-0.5" x-text="props.name || key"></div>
                                                                        <div class="text-[10px] font-mono text-slate-500 truncate max-w-[200px]" x-text="'Path: ' + key"></div>
                                                                    </td>
                                                                    <td class="px-4 py-3 text-center">
                                                                        <span :class="props.active ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' : 'bg-slate-700/50 text-slate-400 border-slate-600'" class="px-2 py-0.5 text-[9px] uppercase font-bold border rounded-full tracking-wide" x-text="props.active ? 'ACTIVE' : 'INACTIVE'"></span>
                                                                    </td>
                                                                    <td class="px-4 py-3 text-right">
                                                                        <!-- Togglers -->
                                                                        <button x-show="id === 'manage_plugins'" @click="attemptFix(agent, 'toggle_plugin:' + key)" class="text-[10px] px-3 py-1.5 rounded bg-slate-800 border disabled:opacity-30 border-slate-700 hover:border-amber-500 hover:text-amber-400 transition ml-auto" x-text="props.active ? 'Deactivate' : 'Activate'"></button>
                                                                        <button x-show="id === 'manage_themes' && !props.active" @click="attemptFix(agent, 'theme_activate:' + key)" class="text-[10px] px-3 py-1.5 rounded bg-slate-800 border disabled:opacity-30 border-slate-700 hover:border-sky-500 hover:text-sky-400 transition ml-auto">Activate Theme</button>
                                                                    </td>
                                                                </tr>
                                                            </template>
                                                        </tbody>
                                                    </table>
                                                </div>
                                            </template>
                                            
                                            <!-- Simple Key-Value Config / Toggles -->
                                            <template x-if="!Array.isArray(finding.data) && typeof Object.values(finding.data)[0] === 'string'">
                                                <div class="grid grid-cols-1 md:grid-cols-2 gap-2 p-3 bg-slate-900">
                                                    <template x-for="(v, k) in finding.data" :key="k">
                                                        <div class="flex items-center justify-between py-2 border-b border-slate-700/50 last:border-0 hover:bg-slate-800/30 transition px-2 -mx-2 rounded">
                                                            <dt class="font-bold text-slate-300 uppercase tracking-widest text-[10px]" x-text="k.replace(/_/g, ' ')"></dt>
                                                            
                                                            <!-- Simple value rendering -->
                                                            <template x-if="typeof v !== 'object'">
                                                                <div class="flex items-center gap-3">
                                                                    <span class="text-slate-300 font-mono text-xs whitespace-pre-wrap break-words" x-text="v === '' ? 'Empty' : (k === 'status' ? v.toUpperCase() : v)"></span>
                                                                    
                                                                    <!-- God Mode Controls -->
                                                                    <template x-if="agent === 'CoreOperationsAgent'">
                                                                        <div class="flex items-center gap-2">
                                                                            <button x-show="k === 'WP_DEBUG'" @click="attemptFix(agent, 'toggle_wp_debug')" class="px-2 py-1 bg-amber-600/20 text-amber-400 border border-amber-600/50 rounded text-[9px] uppercase font-bold hover:bg-amber-600 hover:text-white transition">Toggle</button>
                                                                            <button x-show="k === 'SAVEQUERIES'" @click="attemptFix(agent, 'toggle_savequeries')" class="px-2 py-1 bg-amber-600/20 text-amber-400 border border-amber-600/50 rounded text-[9px] uppercase font-bold hover:bg-amber-600 hover:text-white transition">Toggle</button>
                                                                            <button x-show="k === 'maintenance_mode'" @click="attemptFix(agent, 'toggle_maintenance')" class="px-2 py-1 bg-amber-600/20 text-amber-400 border border-amber-600/50 rounded text-[9px] uppercase font-bold hover:bg-amber-600 hover:text-white transition">Toggle</button>
                                                                            <button x-show="k === 'cache_clear'" @click="attemptFix(agent, 'clear_cache')" class="px-2 py-1 bg-sky-600/20 text-sky-400 border border-sky-600/50 rounded text-[9px] uppercase font-bold hover:bg-sky-600 hover:text-white transition" x-text="'Flush Cache'"></button>
                                                                            <button x-show="k === 'password_reset'" @click="attemptFix(agent, 'reset_admin:admin')" class="px-2 py-1 bg-rose-600/20 text-rose-400 border border-rose-600/50 rounded text-[9px] uppercase font-bold hover:bg-rose-600 hover:text-white transition" x-text="'Reset admin'"></button>
                                                                            <button x-show="k === 'core_update' && v !== 'unavailable'" @click="attemptFix(agent, 'core_update')" class="px-2 py-1 bg-emerald-600/20 text-emerald-400 border border-emerald-600/50 rounded text-[9px] uppercase font-bold hover:bg-emerald-600 hover:text-white transition" x-text="'Force Update'"></button>
                                                                        </div>
                                                                    </template>
                                                                </div>
                                                            </template>
                                                        </div>
                                                    </template>
                                                    
                                                    <!-- Error Log explicitly added to operations -->
                                                    <div x-show="id==='god_mode_tools'" class="flex items-center justify-between p-2 rounded bg-slate-800/80 border border-slate-700 group hover:border-rose-500/50 transition">
                                                        <div class="text-xs font-mono font-bold text-rose-300">EMERGENCY_LOG</div>
                                                        <button @click="showErrorLog(agent)" class="text-rose-400 hover:text-white px-2 py-0.5 rounded border border-rose-400/30 hover:bg-rose-500/20 text-[10px] uppercase font-bold text-center">View .log</button>
                                                    </div>
                                                </div>
                                            </template>
                                        </div>
                                    </template>
                                    
                                    <!-- Generic Action Buttons -->
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
            <p class="text-slate-600 text-[10px] font-mono uppercase tracking-[0.2em]">WP Diagnose Agentic Swarm v0.2.4-beta &copy; 2026</p>
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
                async showErrorLog(agent) {
                    try {
                        const response = await fetch(`?token=${this.token}&action=fix&agent=${agent}&id=view_error_log&format=json`);
                        const result = await response.json();
                        if (result.success && result.data) {
                            // Create modal manually parsing it
                            document.body.insertAdjacentHTML('beforeend', `
                                <div id="errorModal" class="fixed inset-0 bg-slate-900/90 z-50 flex items-center justify-center p-4">
                                    <div class="bg-black border border-slate-700 w-full max-w-4xl max-h-[85vh] flex flex-col rounded-lg shadow-2xl">
                                        <div class="flex justify-between items-center p-4 border-b border-slate-800">
                                            <h3 class="text-rose-500 font-mono font-bold text-sm">Emergency Output: wp-content/debug.log (Last 100 Lines)</h3>
                                            <button onclick="document.getElementById('errorModal').remove()" class="text-slate-400 hover:text-white font-bold">&times;</button>
                                        </div>
                                        <div class="p-4 overflow-y-auto font-mono text-xs text-slate-300 bg-[#0c0c0c] whitespace-pre-wrap leading-relaxed">${result.data.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</div>
                                    </div>
                                </div>
                            `);
                        } else {
                            alert(result.message || 'Log empty or unavailable.');
                        }
                    } catch (e) {
                        alert('Could not fetch log over API.');
                    }
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
                    
                    this.loading = true;
                    
                    try {
                        const fd = new FormData();
                        fd.append('agent', agent);
                        fd.append('id', id);

                        // Optimistic UI updates mapping BEFORE network completion
                        if (id.startsWith('toggle_plugin:')) {
                            const slug = id.split(':')[1];
                            if (this.reports[agent] && this.reports[agent].manage_plugins && this.reports[agent].manage_plugins.data[slug]) {
                                this.reports[agent].manage_plugins.data[slug].active = !this.reports[agent].manage_plugins.data[slug].active;
                            }
                        } else if (id.startsWith('theme_activate:')) {
                            const slug = id.split(':')[1];
                            if (this.reports[agent] && this.reports[agent].manage_themes && this.reports[agent].manage_themes.data) {
                                for (let t in this.reports[agent].manage_themes.data) {
                                    this.reports[agent].manage_themes.data[t].active = (t === slug);
                                }
                            }
                        }

                        const response = await fetch(`?token=${this.token}&action=fix&format=json`, {
                            method: 'POST',
                            body: fd
                        });
                        const result = await response.json();
                        if (result.success) {
                            alert('Action executed successfully! Scanning...');
                            this.fetchReport();
                        } else {
                            alert('Recovery failed or blocked. Manual intervention advised.');
                            this.fetchReport(); // Revert optimistic UI
                        }
                    } catch (e) {
                        alert('API Communication Timeout or Error: ' + e.message);
                        this.loading = false;
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
