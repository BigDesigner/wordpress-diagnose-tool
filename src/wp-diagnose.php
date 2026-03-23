<?php
/**
 * WP Diagnose - Single File, EN/TR, Full & DB Mode
 * A drop-in diagnosis, maintenance, and plugin management tool for WordPress.
 * Upload to root directory as `wp-diagnose.php` - use it - then delete it.
 *
 * Author: https://github.com/BigDesigner
 */

require_once dirname(__DIR__) . '/Core/Version.php';
require_once dirname(__DIR__) . '/Core/SecurityManager.php';
require_once dirname(__DIR__) . '/Core/DiagnosticInterface.php';
require_once dirname(__DIR__) . '/Core/Engine.php';
require_once dirname(__DIR__) . '/Core/Cleanup.php';
require_once __DIR__ . '/Agents/ServerInspector/ServerInspector.php';
require_once __DIR__ . '/Agents/WPInspector/WPInspector.php';
require_once __DIR__ . '/Agents/SecurityInspector/SecurityInspector.php';
require_once __DIR__ . '/Agents/BootstrapInspector/BootstrapInspector.php';
require_once __DIR__ . '/Agents/DBHealth/DBHealth.php';
require_once __DIR__ . '/Agents/CoreIntegrityAgent/CoreIntegrityAgent.php';
require_once __DIR__ . '/Agents/AssetManagerAgent/AssetManagerAgent.php';
require_once __DIR__ . '/Agents/CoreOperationsAgent/CoreOperationsAgent.php';
require_once __DIR__ . '/Agents/ThreatIntelAgent/ThreatIntelAgent.php';
require_once __DIR__ . '/Agents/MalwareInspector/MalwareInspector.php';

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
        $engine->registerAgent(new \WPDiagnose\Agents\ThreatIntelAgent\ThreatIntelAgent(true));
        $engine->registerAgent(new \WPDiagnose\Agents\MalwareInspector\MalwareInspector());

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

define('ACTION_LOG_FILE', __DIR__ . '/.ht-wp-diagnose.log');

$securityManager = new \WPDiagnose\Core\SecurityManager(storageDir: __DIR__);
$securityDecision = $securityManager->authorize($_GET['action'] ?? 'dashboard');
if (!$securityDecision['allowed']) {
    $securityManager->emitDeniedResponse($securityDecision);
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
        if (!$stmt) {
            return null;
        }
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
    function update_option($name, $value): bool
    {
        $stmt = $this->mysqli->prepare("SELECT option_id FROM {$this->prefix}options WHERE option_name=? LIMIT 1");
        if (!$stmt) {
            return false;
        }
        $stmt->bind_param("s", $name);
        $stmt->execute();
        $stmt->store_result();
        $exists = $stmt->num_rows > 0;
        $stmt->close();
        if ($exists) {
            $stmt = $this->mysqli->prepare("UPDATE {$this->prefix}options SET option_value=? WHERE option_name=?");
            if (!$stmt) {
                return false;
            }
            $stmt->bind_param("ss", $value, $name);
            $result = $stmt->execute();
            $stmt->close();
            return $result;
        } else {
            $autoload = 'no';
            $stmt = $this->mysqli->prepare("INSERT INTO {$this->prefix}options (option_name, option_value, autoload) VALUES (?,?,?)");
            if (!$stmt) {
                return false;
            }
            $stmt->bind_param("sss", $name, $value, $autoload);
            $result = $stmt->execute();
            $stmt->close();
            return $result;
        }
    }
}

function wpd_find_config_path(): ?string
{
    $candidates = [
        ABSPATH . 'wp-config.php',
        dirname(rtrim(ABSPATH, '/\\')) . '/wp-config.php',
    ];

    foreach ($candidates as $candidate) {
        if (is_file($candidate)) {
            return $candidate;
        }
    }

    return null;
}

// -------------------- Emergency Independent DB Connection --------------------
$DB = null;
$DB_ERR = '';

// ALWAYS parse wp-config.php for direct SQL access (bypassing high-level WP ops)
$config_path = wpd_find_config_path();
if ($config_path && is_file($config_path)) {
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
        $engine->registerAgent(new \WPDiagnose\Agents\ThreatIntelAgent\ThreatIntelAgent($WP_LOADED));
        $engine->registerAgent(new \WPDiagnose\Agents\MalwareInspector\MalwareInspector());

        $response = ['success' => true, 'message' => '', 'data' => []];

        if (isset($_GET['action'])) {
            if ($_GET['action'] === 'fix') {
                $agent = $_POST['agent'] ?? $_GET['agent'] ?? '';
                $id    = $_POST['id'] ?? $_GET['id'] ?? '';
                
                wpd_log_action('API_FIX_POST', "Agent: $agent | FixID: $id | WP_LOADED: " . ($WP_LOADED ? 'YES' : 'NO'));
                $response = $engine->performFix($agent, $id);
            } elseif ($_GET['action'] === 'self_destruct') {
                $success = \WPDiagnose\Core\Cleanup::fullWipe();
                $response = [
                    'success' => $success,
                    'message' => $success ? 'Self-destruct completed.' : 'Self-destruct was blocked or incomplete.',
                    'data' => null,
                ];
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
                'success' => false,
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
    @file_put_contents(ACTION_LOG_FILE, $message, FILE_APPEND | LOCK_EX);
}

// -------------------- Self-Destruct Mechanism --------------------
$self_destruct_file = __FILE__;
$expiration_time = 3600; // 60 minutes in seconds
$file_age = time() - filemtime(__FILE__);

if ($file_age > $expiration_time) {
    wpd_log_action('AUTO_DESTRUCT', 'TTL exceeded 60 minutes. Initiating self-destruct.');
    if (\WPDiagnose\Core\Cleanup::fullWipe()) {
        header('Content-Type: text/html; charset=utf-8');
        exit('<div style="background:#000;color:#00b84f;padding:20px;text-align:center;">WP Diagnose and all helper modules were removed for security.</div>');
    } else {
        header('Content-Type: text/html; charset=utf-8');
        exit('<div style="background:#000;color:#ef4444;padding:20px;text-align:center;">Warning: Files could not be removed automatically. Please delete them manually for security.</div>');
    }
}
// -------------------- End Self-Destruct --------------------

@header('Content-Type: text/html; charset=utf-8');
@date_default_timezone_set('UTC');

// WPD_DB and Independent Mode Connection Moved Up

// -------------------- Modern SPA Dashboard --------------------
?><!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WP Diagnose PRO <?php echo \WPDiagnose\Core\Version::label(); ?></title>
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
        <div class="fixed top-4 right-4 z-50 w-full max-w-md space-y-3 pointer-events-none">
            <template x-for="notice in notifications" :key="notice.id">
                <div
                    x-transition.opacity.duration.200ms
                    class="pointer-events-auto rounded-lg border px-4 py-3 shadow-2xl backdrop-blur"
                    :class="{
                        'bg-emerald-950/90 border-emerald-500/40 text-emerald-100': notice.type === 'success',
                        'bg-rose-950/90 border-rose-500/40 text-rose-100': notice.type === 'error',
                        'bg-sky-950/90 border-sky-500/40 text-sky-100': notice.type === 'info'
                    }"
                >
                    <div class="flex items-start gap-3">
                        <div class="flex-1 text-sm leading-relaxed" x-text="notice.message"></div>
                        <button
                            type="button"
                            @click="dismissNotification(notice.id)"
                            class="text-current/70 hover:text-current transition"
                        >&times;</button>
                    </div>
                </div>
            </template>
        </div>

        <div
            x-show="confirmState.open"
            x-transition.opacity.duration.200ms
            class="fixed inset-0 z-40 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4"
        >
            <div
                @click.outside="resolveConfirmation(false)"
                class="w-full max-w-lg rounded-2xl border border-slate-700 bg-slate-900 shadow-2xl overflow-hidden"
            >
                <div class="px-6 py-5 border-b border-slate-800">
                    <h3 class="text-lg font-bold text-slate-100" x-text="confirmState.title"></h3>
                    <p class="mt-2 text-sm text-slate-400 leading-relaxed" x-text="confirmState.body"></p>
                </div>
                <div class="px-6 py-4 flex items-center justify-end gap-3 bg-slate-950/60">
                    <button
                        type="button"
                        @click="resolveConfirmation(false)"
                        class="px-4 py-2 rounded-lg border border-slate-700 text-slate-300 hover:border-slate-500 hover:text-white transition"
                    >Cancel</button>
                    <button
                        type="button"
                        @click="resolveConfirmation(true)"
                        class="px-4 py-2 rounded-lg font-semibold transition"
                        :class="confirmState.danger
                            ? 'bg-rose-600 text-white hover:bg-rose-500'
                            : 'bg-emerald-600 text-white hover:bg-emerald-500'"
                        x-text="confirmState.confirmLabel"
                    ></button>
                </div>
            </div>
        </div>

        <!-- Header -->
        <header class="max-w-6xl mx-auto flex flex-col md:flex-row justify-between items-center mb-10 border-b border-slate-700 pb-6 gap-4">
            <div>
                <h1 class="text-3xl font-black text-emerald-500 flex items-center gap-3">
                    <svg class="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
                    WP DIAGNOSE <span class="text-sm font-mono bg-slate-800 text-slate-400 px-3 py-1 rounded-full"><?php echo \WPDiagnose\Core\Version::label(); ?></span>
                </h1>
                <p class="text-slate-500 text-xs mt-1 font-mono uppercase tracking-widest">Advanced Diagnostic Agents Swarm</p>
            </div>
            
            <div class="flex gap-4 items-center">
                <button type="button" @click="fetchReport()" :disabled="loading" class="bg-slate-700 hover:bg-slate-600 disabled:opacity-50 text-white px-4 py-2 rounded text-sm font-semibold transition flex items-center gap-2">
                    <svg class="w-4 h-4" :class="loading ? 'animate-spin' : ''" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>
                    Refresh
                </button>
                <button type="button" @click="selfDestruct()" class="bg-red-600/20 hover:bg-red-600 text-red-500 hover:text-white border border-red-600/50 px-4 py-2 rounded text-sm font-bold transition">Self-Destruct</button>
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
                    <span class="text-slate-400 font-mono text-sm block truncate"><?php echo \WPDiagnose\Core\Version::label(); ?> Agentic Collective</span>
                </div>
            </div>

            <!-- Agent Navigation -->
            <div x-show="!loading" class="mb-6 rounded-2xl border border-slate-700/60 bg-slate-900/60 p-4 shadow-lg">
                <div class="grid gap-4 lg:grid-cols-[auto_minmax(0,1fr)_280px] lg:items-end">
                    <div class="space-y-2">
                        <div class="text-[10px] font-bold uppercase tracking-[0.3em] text-slate-500">Agent Navigation</div>
                        <div class="inline-flex rounded-xl border border-slate-700 bg-slate-950/80 p-1">
                            <button
                                type="button"
                                @click="setViewMode('all')"
                                class="rounded-lg px-4 py-2 text-[11px] font-bold uppercase tracking-[0.2em] transition"
                                :class="viewMode === 'all' ? 'bg-emerald-500/15 text-emerald-300' : 'text-slate-400 hover:text-slate-200'"
                            >All Agents</button>
                            <button
                                type="button"
                                @click="setViewMode('single')"
                                class="rounded-lg px-4 py-2 text-[11px] font-bold uppercase tracking-[0.2em] transition"
                                :class="viewMode === 'single' ? 'bg-emerald-500/15 text-emerald-300' : 'text-slate-400 hover:text-slate-200'"
                            >Single Agent</button>
                        </div>
                    </div>

                    <div class="space-y-2">
                        <label class="text-[10px] font-bold uppercase tracking-[0.3em] text-slate-500">Search Agents</label>
                        <input
                            type="text"
                            x-model="agentSearch"
                            @input="syncAgentSearch()"
                            placeholder="Filter by label or class name"
                            class="w-full rounded-xl border border-slate-700 bg-slate-950/80 px-4 py-3 text-sm text-slate-100 outline-none transition focus:border-emerald-500"
                        >
                    </div>

                    <div class="space-y-2" x-show="viewMode === 'single'">
                        <label class="text-[10px] font-bold uppercase tracking-[0.3em] text-slate-500">Select Agent</label>
                        <select
                            x-model="activeTab"
                            class="w-full rounded-xl border border-slate-700 bg-slate-950/80 px-4 py-3 text-sm text-slate-100 outline-none transition focus:border-emerald-500"
                        >
                            <template x-for="agent in visibleAgents()" :key="agent">
                                <option :value="agent" x-text="displayAgentLabel(agent)"></option>
                            </template>
                        </select>
                    </div>
                </div>

                <div class="mt-4 flex flex-wrap items-center gap-3 text-[11px] text-slate-500">
                    <span x-text="`${visibleAgents().length} visible agent panel(s)`"></span>
                    <span class="rounded-full border border-slate-700 px-3 py-1 text-slate-300" x-text="viewMode === 'all' ? 'All Agents Mode' : 'Single Agent Mode'"></span>
                    <template x-if="viewMode === 'single' && activeTab !== 'all'">
                        <span class="rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3 py-1 text-emerald-300" x-text="displayAgentLabel(activeTab)"></span>
                    </template>
                </div>
            </div>

            <!-- Loading Spinner -->
            <div x-show="loading" class="flex flex-col items-center justify-center py-32 space-y-4">
                <div class="w-16 h-16 border-4 border-emerald-500/20 border-t-emerald-500 rounded-full animate-spin"></div>
                <p class="text-slate-400 font-mono animate-pulse">Interrogating Diagnostic Swarm...</p>
            </div>

            <!-- Agent Grid -->
            <div x-show="!loading" class="grid grid-cols-1 gap-8">
                <template x-for="(report, agent) in reports" :key="agent">
                    <div x-show="isAgentVisible(agent)" class="bg-slate-800 border border-slate-700/50 rounded-xl shadow-2xl overflow-hidden flex flex-col hover:border-slate-600 transition">
                        <div class="px-6 py-4 bg-slate-800/80 border-t border-slate-700/60 flex justify-between items-center text-xs text-slate-400">
                            <span class="font-mono">WP Diagnose PRO <?php echo \WPDiagnose\Core\Version::label(); ?></span>
                            <div class="flex items-center gap-3">
                                <div class="w-2 h-2 rounded-full bg-emerald-500"></div>
                                <div class="text-right">
                                    <h2 class="text-lg font-bold text-slate-100 tracking-tight" x-text="displayAgentLabel(agent)"></h2>
                                    <div class="text-[10px] font-mono text-slate-500" x-text="agent"></div>
                                </div>
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

                                    <template x-if="agent === 'ThreatIntelAgent' && id === 'intel_configuration'">
                                        <div class="mb-4 rounded-lg border border-slate-700 bg-slate-900/60 p-4 space-y-4">
                                            <div class="flex flex-col gap-2 lg:flex-row lg:items-center lg:justify-between">
                                                <div>
                                                    <div class="text-xs font-bold uppercase tracking-[0.25em] text-emerald-400">Wordfence Intelligence</div>
                                                    <div class="mt-1 text-xs text-slate-400">
                                                        Add a free API key to enable the live WordPress CVE feed. Without a key, this section stays passive.
                                                    </div>
                                                </div>
                                                <a
                                                    :href="finding.data.docs_url"
                                                    target="_blank"
                                                    rel="noopener noreferrer"
                                                    class="inline-flex items-center justify-center rounded border border-sky-500/40 px-3 py-2 text-[10px] font-bold uppercase tracking-[0.2em] text-sky-300 hover:bg-sky-500/10"
                                                >Get API Key</a>
                                            </div>

                                            <div class="grid gap-3 lg:grid-cols-[1fr_auto_auto]">
                                                <input
                                                    type="password"
                                                    x-model="threatIntelApiKeyDraft"
                                                    placeholder="Paste your Wordfence Intelligence API key"
                                                    class="w-full rounded border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none transition focus:border-emerald-500"
                                                >
                                                <button
                                                    type="button"
                                                    @click.prevent.stop="saveThreatIntelApiKey()"
                                                    class="rounded border border-emerald-500/40 bg-emerald-500/10 px-4 py-2 text-[10px] font-bold uppercase tracking-[0.2em] text-emerald-300 hover:bg-emerald-500/20"
                                                >Save Key</button>
                                                <button
                                                    type="button"
                                                    @click.prevent.stop="clearThreatIntelApiKey()"
                                                    class="rounded border border-rose-500/40 bg-rose-500/10 px-4 py-2 text-[10px] font-bold uppercase tracking-[0.2em] text-rose-300 hover:bg-rose-500/20"
                                                >Clear</button>
                                            </div>

                                            <div class="flex flex-wrap items-center gap-3">
                                                <button
                                                    type="button"
                                                    @click.prevent.stop="syncThreatIntelFeed()"
                                                    :disabled="finding.data.api_key_status !== 'configured' || finding.data.cooldown_active"
                                                    class="rounded border px-4 py-2 text-[10px] font-bold uppercase tracking-[0.2em] transition"
                                                    :class="finding.data.api_key_status === 'configured' && !finding.data.cooldown_active
                                                        ? 'border-sky-500/40 bg-sky-500/10 text-sky-300 hover:bg-sky-500/20'
                                                        : 'border-slate-700 bg-slate-800 text-slate-500 cursor-not-allowed'"
                                                >Sync Feed</button>
                                                <div class="text-[11px] text-slate-500">
                                                    Feed cache: <span class="text-slate-200" x-text="finding.data.cache_status"></span>
                                                </div>
                                                <div class="text-[11px] text-slate-500">
                                                    Feed source: <span class="text-slate-200" x-text="finding.data.cache_feed_type"></span>
                                                </div>
                                                <div class="text-[11px] text-slate-500">
                                                    Last sync: <span class="text-slate-200" x-text="finding.data.cache_updated_at"></span>
                                                </div>
                                            </div>

                                            <template x-if="finding.data.cooldown_active">
                                                <div class="rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-[11px] text-amber-200">
                                                    Sync Feed is cooling down after an upstream rate limit. Next retry window: <span class="font-mono" x-text="finding.data.cooldown_until"></span>
                                                </div>
                                            </template>

                                            <template x-if="finding.data.last_error">
                                                <div class="rounded-lg border border-slate-700 bg-slate-950/80 px-3 py-2 text-[11px] text-slate-400">
                                                    Last feed error: <span class="text-slate-200" x-text="finding.data.last_error"></span>
                                                </div>
                                            </template>

                                            <div class="grid gap-2 text-[11px] text-slate-400 md:grid-cols-2">
                                                <div>Provider: <span class="text-slate-200" x-text="finding.data.provider"></span></div>
                                                <div>Key status: <span class="text-slate-200" x-text="finding.data.api_key_status"></span></div>
                                                <div>Key source: <span class="text-slate-200" x-text="finding.data.api_key_source"></span></div>
                                                <div>Saved key: <span class="text-slate-200" x-text="finding.data.api_key_hint"></span></div>
                                                <div>Last successful sync: <span class="text-slate-200" x-text="finding.data.last_success_at"></span></div>
                                            </div>
                                        </div>
                                    </template>
                                    
                                    <!-- Re-install Core Button for Watchdog -->
                                    <template x-if="(agent === 'CoreIntegrityAgent' && (id === 'mismatch_files' || id === 'missing_files')) && finding.status !== 'OK'">
                                        <div class="flex gap-2 mb-4">
                                            <button type="button" @click="attemptFix('CoreOperationsAgent', 'reinstall_core')" class="text-[10px] font-bold uppercase tracking-wider bg-rose-600/20 hover:bg-rose-600 text-rose-400 hover:text-white border border-rose-600/50 px-4 py-2 rounded transition">
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
                                                                        <template x-if="id === 'manage_plugins'">
                                                                            <button type="button" @click.prevent.stop="triggerPluginToggle(agent, key)" class="relative z-10 ml-auto cursor-pointer text-[10px] px-3 py-1.5 rounded bg-slate-800 border border-slate-700 hover:border-amber-500 hover:text-amber-400 transition" x-text="props.active ? 'Deactivate' : 'Activate'"></button>
                                                                        </template>
                                                                        <template x-if="id === 'manage_themes' && !props.active">
                                                                            <button type="button" @click.prevent.stop="triggerThemeActivate(agent, key)" class="relative z-10 ml-auto cursor-pointer text-[10px] px-3 py-1.5 rounded bg-slate-800 border border-slate-700 hover:border-sky-500 hover:text-sky-400 transition">Activate Theme</button>
                                                                        </template>
                                                                    </td>
                                                                </tr>
                                                            </template>
                                                        </tbody>
                                                    </table>
                                                </div>
                                            </template>
                                            
                                            <!-- Simple Key-Value Config / Toggles -->
                                            <template x-if="!Array.isArray(finding.data) && typeof Object.values(finding.data)[0] === 'string' && !(agent === 'ThreatIntelAgent' && id === 'intel_configuration')">
                                                <div class="grid grid-cols-1 md:grid-cols-2 gap-2 p-3 bg-slate-900">
                                                    <template x-for="(v, k) in finding.data" :key="k">
                                                        <div class="flex items-center justify-between py-2 border-b border-slate-700/50 last:border-0 hover:bg-slate-800/30 transition px-2 -mx-2 rounded">
                                                            <div class="font-bold text-slate-300 uppercase tracking-widest text-[10px]" x-text="k.replace(/_/g, ' ')"></div>
                                                            
                                                            <!-- Simple value rendering -->
                                                            <template x-if="typeof v !== 'object'">
                                                                <div class="flex items-center gap-3">
                                                                    <span class="text-slate-300 font-mono text-xs whitespace-pre-wrap break-words" x-text="v === '' ? 'Empty' : (k === 'status' ? v.toUpperCase() : v)"></span>
                                                                    
                                                                    <!-- God Mode Controls -->
                                                                    <template x-if="agent === 'CoreOperationsAgent'">
                                                                        <div class="flex items-center gap-2">
                                                                            <template x-if="k === 'WP_DEBUG'">
                                                                                <button type="button" @click.prevent.stop="triggerCoreAction(agent, 'toggle_wp_debug')" class="relative z-10 cursor-pointer px-2 py-1 bg-amber-600/20 text-amber-400 border border-amber-600/50 rounded text-[9px] uppercase font-bold hover:bg-amber-600 hover:text-white transition">Toggle</button>
                                                                            </template>
                                                                            <template x-if="k === 'SAVEQUERIES'">
                                                                                <button type="button" @click.prevent.stop="triggerCoreAction(agent, 'toggle_savequeries')" class="relative z-10 cursor-pointer px-2 py-1 bg-amber-600/20 text-amber-400 border border-amber-600/50 rounded text-[9px] uppercase font-bold hover:bg-amber-600 hover:text-white transition">Toggle</button>
                                                                            </template>
                                                                            <template x-if="k === 'maintenance_mode'">
                                                                                <button type="button" @click.prevent.stop="triggerCoreAction(agent, 'toggle_maintenance')" class="relative z-10 cursor-pointer px-2 py-1 bg-amber-600/20 text-amber-400 border border-amber-600/50 rounded text-[9px] uppercase font-bold hover:bg-amber-600 hover:text-white transition">Toggle</button>
                                                                            </template>
                                                                            <template x-if="k === 'cache_clear'">
                                                                                <button type="button" @click.prevent.stop="triggerCoreAction(agent, 'clear_cache')" class="relative z-10 cursor-pointer px-2 py-1 bg-sky-600/20 text-sky-400 border border-sky-600/50 rounded text-[9px] uppercase font-bold hover:bg-sky-600 hover:text-white transition">Flush Cache</button>
                                                                            </template>
                                                                            <template x-if="k === 'password_reset'">
                                                                                <button type="button" @click.prevent.stop="triggerCoreAction(agent, 'reset_admin:admin')" class="relative z-10 cursor-pointer px-2 py-1 bg-rose-600/20 text-rose-400 border border-rose-600/50 rounded text-[9px] uppercase font-bold hover:bg-rose-600 hover:text-white transition">Reset admin</button>
                                                                            </template>
                                                                            <template x-if="k === 'core_update' && v !== 'unavailable'">
                                                                                <button type="button" @click.prevent.stop="triggerCoreAction(agent, 'core_update')" class="relative z-10 cursor-pointer px-2 py-1 bg-emerald-600/20 text-emerald-400 border border-emerald-600/50 rounded text-[9px] uppercase font-bold hover:bg-emerald-600 hover:text-white transition">Force Update</button>
                                                                            </template>
                                                                        </div>
                                                                    </template>
                                                                </div>
                                                            </template>
                                                        </div>
                                                    </template>
                                                    
                                                    <!-- Error Log explicitly added to operations -->
                                                    <div x-show="id==='god_mode_tools'" class="flex items-center justify-between p-2 rounded bg-slate-800/80 border border-slate-700 group hover:border-rose-500/50 transition">
                                                        <div class="text-xs font-mono font-bold text-rose-300">EMERGENCY_LOG</div>
                                                        <button type="button" @click.prevent.stop="showErrorLog(agent)" class="relative z-10 cursor-pointer text-rose-400 hover:text-white px-2 py-0.5 rounded border border-rose-400/30 hover:bg-rose-500/20 text-[10px] uppercase font-bold text-center">View .log</button>
                                                    </div>
                                                </div>
                                            </template>
                                        </div>
                                    </template>
                                    
                                    <!-- Generic Action Buttons -->
                                    <template x-if="finding.status !== 'OK' && (agent === 'ServerInspector' || agent === 'BootstrapInspector' || agent === 'DBHealth')">
                                        <div class="flex gap-2">
                                            <button type="button" @click="attemptFix(agent, id)" class="text-[10px] font-bold uppercase tracking-wider bg-emerald-600/20 hover:bg-emerald-600 text-emerald-400 hover:text-white border border-emerald-600/50 px-4 py-2 rounded transition">
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
            <p class="text-slate-600 text-[10px] font-mono uppercase tracking-[0.2em]">WP Diagnose Agentic Swarm <?php echo \WPDiagnose\Core\Version::label(); ?> &copy; 2026. Built by BigDesigner for GNNcyber.</p>
            <div class="mt-4 flex justify-center">
                <a
                    href="https://github.com/BigDesigner/wordpress-diagnose-tool"
                    target="_blank"
                    rel="noopener noreferrer"
                    class="inline-flex items-center gap-3 rounded-full border border-slate-700 bg-slate-900/80 px-4 py-2 text-slate-300 transition hover:border-emerald-500/40 hover:text-white"
                >
                    <svg class="h-5 w-5" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
                        <path d="M12 .5C5.65.5.5 5.66.5 12.02c0 5.1 3.3 9.43 7.88 10.96.58.1.79-.25.79-.56 0-.27-.01-1.02-.02-2-3.2.7-3.88-1.54-3.88-1.54-.52-1.33-1.28-1.69-1.28-1.69-1.05-.72.08-.71.08-.71 1.16.08 1.77 1.2 1.77 1.2 1.03 1.78 2.7 1.26 3.36.97.1-.75.4-1.26.73-1.54-2.55-.29-5.24-1.28-5.24-5.68 0-1.25.45-2.27 1.18-3.07-.12-.29-.51-1.46.11-3.05 0 0 .97-.31 3.17 1.17a11.08 11.08 0 0 1 5.78 0c2.2-1.48 3.16-1.17 3.16-1.17.63 1.59.24 2.76.12 3.05.73.8 1.17 1.82 1.17 3.07 0 4.41-2.69 5.38-5.26 5.67.42.36.79 1.07.79 2.16 0 1.57-.01 2.83-.01 3.22 0 .31.2.67.8.56A11.53 11.53 0 0 0 23.5 12C23.5 5.66 18.34.5 12 .5Z"/>
                    </svg>
                    <span class="text-[11px] font-bold uppercase tracking-[0.2em]">GitHub Repository</span>
                </a>
            </div>
        </footer>
    </div>

    <script>
        function diagnoseApp() {
            return {
                loading: true,
                reports: {},
                activeTab: 'all',
                viewMode: 'all',
                agentSearch: '',
                token: new URLSearchParams(window.location.search).get('token') || '',
                threatIntelApiKeyDraft: '',
                notifications: [],
                notificationSeed: 0,
                confirmState: {
                    open: false,
                    title: '',
                    body: '',
                    confirmLabel: 'Confirm',
                    danger: false,
                    resolver: null
                },
                init() {
                    this.fetchReport();
                },
                displayAgentLabel(agent) {
                    const labels = {
                        ServerInspector: 'Server Inspector',
                        WPInspector: 'WordPress Inspector',
                        SecurityInspector: 'Security Inspector',
                        BootstrapInspector: 'Bootstrap Inspector',
                        DBHealth: 'Database Health',
                        CoreIntegrityAgent: 'Core Integrity',
                        AssetManagerAgent: 'Asset Manager',
                        CoreOperationsAgent: 'Core Operations',
                        ThreatIntelAgent: 'Threat Intel',
                        MalwareInspector: 'Malware Inspector'
                    };
                    if (labels[agent]) {
                        return labels[agent];
                    }

                    return agent
                        .replace(/Agent$/, '')
                        .replace(/([a-z])([A-Z])/g, '$1 $2')
                        .replace(/^WP\b/, 'WordPress')
                        .replace(/\bDB\b/g, 'Database');
                },
                orderedAgents() {
                    return Object.keys(this.reports).sort((left, right) => this.displayAgentLabel(left).localeCompare(this.displayAgentLabel(right)));
                },
                matchesAgentFilter(agent) {
                    const query = this.agentSearch.trim().toLowerCase();
                    if (!query) {
                        return true;
                    }

                    return agent.toLowerCase().includes(query) || this.displayAgentLabel(agent).toLowerCase().includes(query);
                },
                visibleAgents() {
                    return this.orderedAgents().filter((agent) => this.matchesAgentFilter(agent));
                },
                ensureAgentSelection() {
                    const visible = this.visibleAgents();
                    if (this.viewMode === 'single') {
                        if (this.activeTab === 'all' || !visible.includes(this.activeTab)) {
                            this.activeTab = visible[0] || 'all';
                        }
                    } else {
                        this.activeTab = 'all';
                    }
                },
                setViewMode(mode) {
                    this.viewMode = mode;
                    this.ensureAgentSelection();
                },
                syncAgentSearch() {
                    this.ensureAgentSelection();
                },
                isAgentVisible(agent) {
                    if (!this.matchesAgentFilter(agent)) {
                        return false;
                    }

                    return this.viewMode === 'all' ? true : this.activeTab === agent;
                },
                hydrateThreatIntelState() {
                    const config = this.reports?.ThreatIntelAgent?.intel_configuration?.data;
                    if (!config || config.api_key_status !== 'configured') {
                        this.threatIntelApiKeyDraft = '';
                    }
                },
                notify(message, type = 'info', timeout = 4500) {
                    const id = ++this.notificationSeed;
                    this.notifications.push({ id, message, type });

                    if (timeout > 0) {
                        window.setTimeout(() => this.dismissNotification(id), timeout);
                    }
                },
                dismissNotification(id) {
                    this.notifications = this.notifications.filter((notice) => notice.id !== id);
                },
                askConfirmation(options = {}) {
                    return new Promise((resolve) => {
                        this.confirmState = {
                            open: true,
                            title: options.title || 'Confirm action',
                            body: options.body || 'Do you want to continue?',
                            confirmLabel: options.confirmLabel || 'Continue',
                            danger: !!options.danger,
                            resolver: resolve
                        };
                    });
                },
                resolveConfirmation(confirmed) {
                    const resolver = this.confirmState.resolver;
                    this.confirmState = {
                        open: false,
                        title: '',
                        body: '',
                        confirmLabel: 'Confirm',
                        danger: false,
                        resolver: null
                    };

                    if (resolver) {
                        resolver(confirmed);
                    }
                },
                async fetchReport() {
                    this.loading = true;
                    try {
                        const response = await fetch(`?token=${this.token}&action=fetch_report`);
                        const contentType = response.headers.get('Content-Type') || '';
                        if (!contentType.includes('application/json')) {
                            const raw = await response.text();
                            console.error('[WP Diagnose] Non-JSON response from API:', raw.substring(0, 500));
                            this.notify('API connection error: server did not return JSON.', 'error');
                            this.reports = {};
                        } else {
                            try {
                                this.reports = await response.json();
                                this.hydrateThreatIntelState();
                                this.ensureAgentSelection();
                                if (this.reports.status === 'error' || (this.reports.success === false && this.reports.message)) {
                                    this.notify('API connection error: ' + this.reports.message, 'error');
                                    this.reports = {};
                                }
                            } catch (parseErr) {
                                console.error('[WP Diagnose] JSON Parse failed:', parseErr);
                                this.notify('API connection error: response JSON could not be parsed.', 'error');
                                this.reports = {};
                            }
                        }
                    } catch (e) {
                        console.error('[WP Diagnose] Network error:', e);
                        this.notify('API connection error: server is unreachable or the connection was interrupted.', 'error');
                        this.reports = {};
                    }
                    setTimeout(() => { this.loading = false; }, 600);
                },
                async showErrorLog(agent) {
                    try {
                        const response = await fetch(`?token=${this.token}&action=fix&agent=${agent}&id=view_error_log&format=json`);
                        const result = await response.json();
                        if (result.success && result.data) {
                            const logPayload = typeof result.data === 'string'
                                ? { path: 'wp-content/wp-diagnose-tool.log', contents: result.data }
                                : result.data;
                            document.body.insertAdjacentHTML('beforeend', `
                                <div id="errorModal" class="fixed inset-0 bg-slate-900/90 z-50 flex items-center justify-center p-4">
                                    <div class="bg-black border border-slate-700 w-full max-w-4xl max-h-[85vh] flex flex-col rounded-lg shadow-2xl">
                                        <div class="flex justify-between items-center p-4 border-b border-slate-800">
                                            <h3 class="text-rose-500 font-mono font-bold text-sm">Emergency Output: ${logPayload.path} (Last 100 Lines)</h3>
                                            <button onclick="document.getElementById('errorModal').remove()" class="text-slate-400 hover:text-white font-bold">&times;</button>
                                        </div>
                                        <div class="p-4 overflow-y-auto font-mono text-xs text-slate-300 bg-[#0c0c0c] whitespace-pre-wrap leading-relaxed">${(logPayload.contents || '').replace(/</g, '&lt;').replace(/>/g, '&gt;')}</div>
                                    </div>
                                </div>
                            `);
                        } else {
                            this.notify(result.message || 'Log empty or unavailable.', 'error');
                        }
                    } catch (e) {
                        this.notify('Could not fetch log over API.', 'error');
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
                triggerPluginToggle(agent, key) {
                    return this.attemptFix(agent, 'toggle_plugin:' + key);
                },
                triggerThemeActivate(agent, key) {
                    return this.attemptFix(agent, 'theme_activate:' + key);
                },
                triggerCoreAction(agent, actionId) {
                    return this.attemptFix(agent, actionId);
                },
                async saveThreatIntelApiKey() {
                    const success = await this.attemptFix('ThreatIntelAgent', 'save_wordfence_api_key', {
                        wordfence_api_key: this.threatIntelApiKeyDraft
                    }, {
                        skipConfirm: true
                    });
                    if (success) {
                        this.threatIntelApiKeyDraft = '';
                    }
                    return success;
                },
                async clearThreatIntelApiKey() {
                    const success = await this.attemptFix('ThreatIntelAgent', 'clear_wordfence_api_key', {}, {
                        skipConfirm: true
                    });
                    if (success) {
                        this.threatIntelApiKeyDraft = '';
                    }
                    return success;
                },
                async syncThreatIntelFeed() {
                    return this.attemptFix('ThreatIntelAgent', 'refresh_threat_feed', {}, {
                        skipConfirm: true
                    });
                },
                async attemptFix(agent, id, params = {}, options = {}) {
                    const skipConfirm = options.skipConfirm === true;
                    const confirmed = skipConfirm ? true : await this.askConfirmation({
                        title: 'Trigger Agentic Fix',
                        body: `Apply recovery action [${id}] now?`,
                        confirmLabel: 'Run Fix',
                        danger: id === 'reinstall_core' || id.startsWith('reset_admin:')
                    });

                    if (!confirmed) {
                        return false;
                    }

                    this.loading = true;

                    try {
                        const fd = new FormData();
                        fd.append('agent', agent);
                        fd.append('id', id);
                        Object.entries(params).forEach(([key, value]) => {
                            fd.append(key, value ?? '');
                        });

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
                        const raw = await response.text();
                        if (!raw.trim()) {
                            this.notify('Action API returned an empty response.', 'error');
                            await this.fetchReport();
                            return false;
                        }

                        let result;
                        try {
                            result = JSON.parse(raw);
                        } catch (parseError) {
                            console.error('[WP Diagnose] Non-JSON action response:', raw.substring(0, 500));
                            this.notify('Action API did not return valid JSON.', 'error');
                            await this.fetchReport();
                            return false;
                        }

                        if (result.success) {
                            this.notify(result.message || 'Action executed successfully.', 'success');
                            await this.fetchReport();
                            return true;
                        } else {
                            this.notify(result.message || 'Recovery failed or blocked. Manual intervention advised.', 'error');
                            await this.fetchReport();
                            return false;
                        }
                    } catch (e) {
                        this.notify('API communication timeout or error: ' + e.message, 'error');
                        this.loading = false;
                        return false;
                    }
                },
                async selfDestruct() {
                    const confirmed = await this.askConfirmation({
                        title: 'Self-Destruct',
                        body: 'Permanent recursive wipe of all diagnostic components. Proceed?',
                        confirmLabel: 'Destroy',
                        danger: true
                    });

                    if (!confirmed) {
                        return;
                    }

                    try {
                        const response = await fetch(`?token=${this.token}&action=self_destruct&format=json`);
                        const result = await response.json();
                        if (result.success) {
                            document.body.innerHTML = '<div class="min-h-screen flex flex-col items-center justify-center bg-slate-950 text-emerald-500 font-mono uppercase tracking-[0.5em] text-center p-10"><div>System Cleansed</div><div class="text-[10px] text-slate-700 mt-6 tracking-normal lowercase">All modular components purged from file system.</div></div>';
                        } else {
                            this.notify('Recursion partially blocked. Manual directory removal required.', 'error');
                        }
                    } catch (e) {
                        this.notify('Wipe sequence initiated. Verify server state.', 'info');
                    }
                }
            }
        }
    </script>
</body>
</html>
<?php exit; ?>
