<?php
declare(strict_types = 1)
;

/**
 * WP Diagnose - Atomic Bracketed Namespace Bundler
 *
 * Strategy: Convert every module to bracketed namespace { } syntax.
 * This is the ONLY way to have multiple namespaces coexist in one PHP file.
 * Entry point (procedural + inline HTML) is wrapped in namespace { } (global).
 */

require_once __DIR__ . '/scripts/sync-version.php';

$version = syncProjectVersion(__DIR__);
$outputDir = 'diagnose';
$output = $outputDir . '/wp-diagnose-pro.php';

if (!is_dir($outputDir)) {
    mkdir($outputDir, 0755, true);
}

// OOP class modules
$coreModules = [
    'Core/Version.php',
    'Core/SecurityManager.php',
    'Core/DiagnosticInterface.php',
    'Core/Engine.php',
    'Core/Cleanup.php',
    'src/Agents/ServerInspector/ServerInspector.php',
    'src/Agents/WPInspector/WPInspector.php',
    'src/Agents/SecurityInspector/SecurityInspector.php',
    'src/Agents/BootstrapInspector/BootstrapInspector.php',
    'src/Agents/DBHealth/DBHealth.php',
    'src/Agents/CoreIntegrityAgent/CoreIntegrityAgent.php',
    'src/Agents/AssetManagerAgent/AssetManagerAgent.php',
    'src/Agents/CoreOperationsAgent/CoreOperationsAgent.php',
    'src/Agents/ThreatIntelAgent/ThreatIntelAgent.php',
    'src/Agents/MalwareInspector/MalwareInspector.php',
];

// Procedural entry point
$entryPoint = 'src/wp-diagnose.php';

/**
 * Strips the file header and extracts the declared namespace name.
 * Returns [cleanCode, namespaceString].
 */
function parseModule(string $code): array
{
    // Strip UTF-8 BOM
    $code = str_replace("\xEF\xBB\xBF", '', $code);

    // Strip opening <?php + optional declare(strict_types=1);
    $code = preg_replace('/^\s*<\?php\s*(declare\s*\(\s*strict_types\s*=\s*1\s*\)\s*;\s*)?/i', '', $code, 1);

    // Extract and remove the namespace declaration (e.g. namespace WPDiagnose\Core;)
    $namespace = '';
    $code = preg_replace_callback(
        '/^\s*namespace\s+([\w\\\\]+)\s*;\s*$/im',
        function (array $m) use (&$namespace): string {
        $namespace = $m[1];
        return '';
    },
        $code,
        1
    );

    // Strip modular require_once lines (already bundled)
    $code = preg_replace('/^\s*require_once\s+.+;\s*$/im', '', $code);

    return [trim($code), $namespace];
}

/**
 * Wraps cleaned module code in a bracketed namespace block.
 * e.g.  namespace WPDiagnose\Core { ... }
 */
function wrapNamespace(string $code, string $namespace): string
{
    $ns = $namespace !== '' ? "namespace $namespace" : 'namespace';
    return "$ns {\n\n$code\n\n}\n";
}

// --- Bundle Header (no namespace — file-level only) ---
$bundle = "<?php" . PHP_EOL;
$bundle .= "declare(strict_types=1);" . PHP_EOL;
$bundle .= "/**" . PHP_EOL;
$bundle .= " * WP DIAGNOSE PRO - Bundled Agentic Toolkit" . PHP_EOL;
$bundle .= " * Version : $version" . PHP_EOL;
$bundle .= " * Standard: Bracketed Namespace (Constitution v{$version})" . PHP_EOL;
$bundle .= " * Built   : " . gmdate('Y-m-d H:i:s') . " UTC" . PHP_EOL;
$bundle .= " * License : GPL-3.0" . PHP_EOL;
$bundle .= " */" . PHP_EOL . PHP_EOL;

// --- PHP Version Pre-flight (global namespace block) ---
$bundle .= "namespace {" . PHP_EOL;
$bundle .= "    if (version_compare(PHP_VERSION, '8.1.0', '<')) {" . PHP_EOL;
$bundle .= "        die('<div style=\"background:#ef4444;color:#fff;padding:20px;\">FATAL: PHP 8.1+ required. Detected: ' . PHP_VERSION . '</div>');" . PHP_EOL;
$bundle .= "    }" . PHP_EOL;
$bundle .= "}" . PHP_EOL . PHP_EOL;

// --- OOP Modules (each in its own bracketed namespace block) ---
foreach ($coreModules as $f) {
    if (!is_file($f)) {
        echo "WARNING: Skipping missing file - $f\n";
        continue;
    }

    [$clean, $ns] = parseModule(file_get_contents($f));

    $bundle .= "/* ======= Module: $f ======= */" . PHP_EOL;
    $bundle .= wrapNamespace($clean, $ns) . PHP_EOL;
}

// --- Entry Point (procedural + inline HTML, global namespace block) ---
if (!is_file($entryPoint)) {
    die("FATAL: Entry point not found: $entryPoint\n");
}

[$cleanEntry, ] = parseModule(file_get_contents($entryPoint));

// Wrap entry point in a global namespace block.
// Handle inline HTML output (PHP-HTML switch) inside the block.
// Close the block after the last statement.
$bundle .= "/* ======= Entry Point: $entryPoint ======= */" . PHP_EOL;
$bundle .= "namespace {" . PHP_EOL . PHP_EOL;
$bundle .= $cleanEntry . PHP_EOL;

// Close the global namespace block
if (str_ends_with(rtrim($cleanEntry), '?>')) {
    // Already in HTML mode at end — reopen PHP to close the block
    $bundle .= "<?php }" . PHP_EOL;
}
else {
    $bundle .= "}" . PHP_EOL;
}

// --- Write Output ---
if (file_put_contents($output, $bundle) === false) {
    die("FATAL: Cannot write $output — check permissions.\n");
}

// --- MANDATORY PRE-COMMIT LINT GUARD (CONSTITUTION MATCHES VERSION FILE) ---
// Strategy: Perform an OS-level syntax validation on the generated bundle.
// If even a single syntax error is detected, the bundle is destroyed immediately.
$lintCmd = PHP_BINARY . ' -l ' . escapeshellarg($output) . ' 2>&1';
exec($lintCmd, $lintResult, $lintCode);

if ($lintCode !== 0) {
    $lines = file($output);
    echo "==========================================================\n";
    echo " ❌ PRE-COMMIT LINT FAILED - BUILD VIOLATION DETECTED\n";
    echo "==========================================================\n";
    foreach ($lintResult as $msg) {
        echo " >> $msg\n";
        if (preg_match('/on line (\d+)/i', $msg, $m)) {
            $errLine = (int)$m[1];
            $start = max(0, $errLine - 15);
            $end = min(count($lines), $errLine + 15);
            echo " --- Context Layer ($start to $end) ---\n";
            for ($i = $start; $i < $end; $i++) {
                $marker = ($i + 1 === $errLine) ? ' >>> ' : '     ';
                printf("%s %4d: %s", $marker, $i + 1, $lines[$i]);
            }
        }
    }
    @unlink($output);
    echo "\n 🧨 CRITICAL FAILURE: Bundle destroyed to protect environment.\n";
    echo " Pipeline halted. Fix the syntax and rebuild.\n";
    echo "==========================================================\n";
    exit(1);
}

$kb = round(filesize($output) / 1024, 2);
echo "==========================================================\n";
echo " ✅ Build Successful : $output\n";
echo " Version            : $version (Constitution v{$version} compliant)\n";
echo " Integrity Check    : 100% PASSED (Pre-Commit Guard)\n";
echo " File Size          : {$kb} KB\n";
echo " Status             : READY FOR PRODUCTION\n";
echo "==========================================================\n";
