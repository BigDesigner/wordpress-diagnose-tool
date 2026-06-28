# WordPress Diagnose Tool (v1.2.0)

**WordPress Diagnose Tool** is an emergency-ready, zero-dependency diagnostics and recovery toolkit built for real-world outage, compromise, and maintenance scenarios. It ships as a modular PHP codebase for development and compiles into a **single-file production bundle** (`wp-diagnose-pro.php`) for fast drop-in deployment on live sites.

Unlike standard plugins, this tool runs completely independently of the WordPress core when needed. It acts as an emergency operating system for broken WordPress installations.

---

## 🚀 Key Use Cases (When to Use)

- **White Screen of Death (WSOD) & Fatal PHP Crashes**: If a broken plugin or theme throws a fatal PHP error and crashes the site (including `wp-admin`), upload this tool to deactivate the culprit, switch to a default theme, or rollback to a stable state.
- **Database Connection Failure ("Error Establishing a Database Connection")**: Bypasses WordPress bootstrap to directly read `wp-config.php`, test database credentials, identify the cause (offline DB, incorrect pass), and run physical table repairs (`REPAIR TABLE`).
- **Administrative Lockout**: If you lost your password, the admin email was hacked, or a 2FA plugin locks you out, use the dashboard to reset credentials, demote suspicious admins, or deactivate security/2FA plugins.
- **Security Compromise & Malware Infiltration**: Scan files using heuristic checks for PHP shells, verify core integrity checksums, quarantine suspicious scripts, and restore corrupted entrypoints (`.htaccess`, `index.php`).
- **Domain Migration & Search/Replace**: Safely perform search-and-replace queries across all text columns and prefix-matching tables. It recursively handles **PHP serialized options** without breaking them.
- **Emergency Backups**: Create standalone SQL dumps or full `/wp-content` zip archives directly to your server before running risky database repairs or core reinstalls.

---

## 🏆 Architectural Pillars & Secret Weapons

### 1. Zero-Dependency Independent Mode
If WordPress cannot bootstrap, the tool parses `wp-config.php` locally and uses raw `mysqli` connections. You can still manage plugins, execute SQL repairs, reset passwords, and edit configuration files when the site is 100% dead.

### 2. Interactive Stack Trace Code Editor Link
When viewing the PHP error logs in our Emergency Output modal, filenames and lines in stack traces (e.g., `in wp-content/plugins/plugin.php on line 123`) are converted into clickable links. Clicking one opens the file directly in the built-in code editor at that exact line for instant recovery.

### 3. AI-Ready Diagnosis Export (JSON)
Download a comprehensive `wp-diagnose-report-[timestamp].json` containing server metrics, critical directory permissions/ownership (root, `wp-config.php`, `.htaccess`, uploads), and active agent outputs. This report is structured for immediate ingestion by ChatGPT, Claude, Gemini, or custom AI agents to produce step-by-step resolution playbooks.

### 4. Fast Mode (Bypass Confirmation)
Enable "Fast Mode" via the header toggle to skip confirmation modals on repetitive recovery tasks (e.g., activating/deactivating multiple plugins in sequence). State is persisted in local storage.

---

## 🛠️ The 24 Diagnostic Agents

The tool orchestrates checks and actions across specialized modular agents:
- **ServerInspector**: Audits PHP versions, loaded extensions, memory limits, and execution timers.
- **BootstrapInspector**: Resolves `wp-config.php` location and tests MySQL connection credentials.
- **WPInspector**: Collects WordPress core specifications, active plugins, and stylesheets.
- **SecurityInspector**: Audits directory/file permission octals, checks for security keys (salts), and flags exposed readmes.
- **DBHealth**: Monitors autoload option sizes and storage pressure parameters.
- **CoreIntegrityAgent**: Verifies WordPress core file checksums against the official repository API.
- **AssetManagerAgent**: Manages plugins/themes activation states and triggers updates.
- **CoreOperationsAgent**: Manages WordPress debug modes, flushes cache, views error logs, and runs core repairs.
- **ThreatIntelAgent**: Syncs local vulnerability databases with Wordfence V3 and maps CVE alerts.
- **MalwareInspector**: Inspects entrypoints and directories for suspicious PHP signatures and common shells.
- **BackupAgent**: Creates and restores database zips and full site archives.
- **QuarantineAgent**: Safely encrypts and isolates infected files.
- **IncidentSnapshotAgent**: Captures recent code changes and saves JSON system integrity snapshots.
- **UserAccessAgent**: Scans administrative users, demotes suspicious admins, and resets credentials.
- **SecurityHeadersAgent**: Simulates loopbacks to verify security headers (HSTS, CSP) and injects rules into `.htaccess`.
- **CronInspector**: Audits scheduled tasks, flags stuck jobs, and clears overdue WP-Crons.
- **PerformanceAgent**: Profiles performance issues and flushes database transients.
- **PluginConflictAgent**: Sequential plugin deactivation framework (Safe Mode) to isolate active conflicts.
- **HTTPAgent**: Verifies internal loopback capabilities and REST API endpoints.
- **MailAgent**: Tests PHP `mail()` and WordPress SMTP functions.
- **IntegrityRepairAgent**: Restores standard `.htaccess`/`index.php` configurations and provides the custom File Editor.
- **DatabaseRepairAgent**: Performs physical SQL table repairs and runs the **Serialized Search & Replace** engine.
- **UpdateRiskAgent**: Assesses compatibility risks of pending plugin, theme, and core updates.
- **PHPInfoAgent**: Audits PHP configuration settings, extension modules, and security parameters.

---

## 🔒 Security Model (Why it is Safe to Use)

Because standalone emergency tools can be abused as backdoors, we built defense-in-depth directly into the core:
- **Token-Authorized Actions**: All REST API actions and pages are protected by signed token gates. No token, no access.
- **Automatic Self-Destruct (TTL)**: The script checks its own creation/modification time. If it has been on the server for more than **60 minutes**, it automatically triggers `Cleanup::fullWipe()`, deleting itself and all backup/quarantine data folders to prevent abuse.
- **Directory Traversal Protection**: The emergency file editor validates all target paths against the physical WordPress root using strict `realpath` boundaries. It is impossible to load or modify files outside the WordPress install directory tree.
- **Rate Limiting**:Centralized IP rate-limiting guards against brute-force attempts on the tokens.

---

## ⚡ Quick Start

### A. Deploy Pre-compiled File
1. Download the latest `wp-diagnose-pro.php` from GitHub Releases.
2. Upload the file to your WordPress root directory (same folder as `wp-config.php`).
3. Access the dashboard via `https://example.com/wp-diagnose-pro.php?token=YOUR_TOKEN` (the token is configured during compile or generated on first access).
4. Run diagnostics, fix the issue, and hit **Self-Destruct** in the header to clean up.

### B. Compile Locally
1. Clone the repository and run:
   ```bash
   php build.php
   ```
2. The compiler compiles all agents and wraps them in bracketed namespaces into a single file under the [`diagnose`](diagnose) folder.
3. Deploy the compiled `wp-diagnose-pro.php` to your host.

---

## 📄 License
Licensed under the GNU General Public License v3.0 (GPL-3.0). See [`docs/LICENSE`](docs/LICENSE).
