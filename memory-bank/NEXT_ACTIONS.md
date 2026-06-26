# Next Actions - WordPress Diagnose Tool

## Completed

- [x] **[Single-File Bundler]**: Compilation/build flow exists and produces a single-file emergency bundle via `build.php`. [Critical]
- [x] **[Security Cleanup]**: `Self-Destruct` cleanup flow now targets bundled diagnostic components and recursive cleanup logic is in place. [Critical]
- [x] **[Security Manager]**: Authentication, signed token validation, role-based access control, request rate limiting, and security audit logging are now centralized in `Core/SecurityManager.php`. [High]
- [x] **[Bootstrap Recovery Agent]**: `BootstrapInspector` exists and diagnoses broken bootstrap / missing `wp-load.php` scenarios by locating `wp-config.php` and validating DB access independently. [High]
- [x] **[Web-UI Agent]**: JSON/API wrapper and Alpine.js dashboard are already implemented in the current UI flow. [Medium]
- [x] **[Unit Tests]**: PHPUnit configuration, bootstrap scaffolding, and core regression tests for `Engine`, `SecurityManager`, and main agents now exist in `tests/`. [Low]
- [x] **[WP_DEBUG_LOG Deduplication]**: `CoreOperationsAgent` now normalizes repeated `WP_DEBUG_LOG` definitions, preserves a single canonical log target, and bootstraps the custom log file for the viewer. [Medium]
- [x] **[Debug Log Reliability]**: Debug log diagnostics now report writable paths and fallback files, and enabling debug proactively creates the custom log marker file for immediate viewer access. [High]
- [x] **[Threat Intel Rate-Limit Handling]**: `Sync Feed` now persists rate-limit cooldown state, exposes the next retry window in the UI, and preserves the last successful local cache while upstream calls are cooling down. [Medium]
- [x] **[MalwareInspector False Positive Reduction]**: `MalwareInspector` now separates high-confidence findings from low-confidence trusted-core review hits so WordPress core files do not raise `ERROR` from generic signatures alone. [High]
- [x] **[Agent Navigation UX Refresh]**: The crowded horizontal agent tab strip has been replaced with a cleaner Alpine.js navigation model featuring all/single agent modes, readable labels, and agent search/filter support. [Medium]
- [x] **[Footer Branding Refresh]**: The footer is now fully English and ready for GitHub-linked branding with repository attribution. [Low]

## Not Completed

- No active incomplete items in this planning file at the moment.

## Roadmap

### Priority 1 - Backup & Recovery [Completed]

- [x] **[BackupAgent Foundation]**: Introduce a dedicated `BackupAgent` with a clear backup catalog, job metadata, artifact listing, retention rules, and restore safety checks. [Critical]
- [x] **[Database Backup]**: Add database-only backup support that can export the active WordPress database in Independent Mode or loaded WordPress mode. [Critical]
- [x] **[wp-content Backup]**: Add targeted `wp-content` backup support so uploads and themes can be archived. [High]
- [x] **[Plugin & Theme Backup]**: Add selective backup options for plugins and themes. [High]
- [x] **[Full WordPress Backup]**: Add `wp-full` backup support that combines database + `wp-content` + critical root files. [Critical]
- [x] **[Backup Restore Flows]**: Add controlled restore routines for database-only and full-site recovery. [Critical]
- [x] **[Restore Safety Rails]**: Add pre-restore checks such as writable paths and integrity hash verification. [Critical]
- [x] **[Backup Storage Strategy]**: Define where backup artifacts live on disk and how they are named. [High]
- [x] **[Backup UI Experience]**: Build a dedicated dashboard section for creating, downloading, and deleting backups. [High]

### Priority 2 - Security & Malware [Completed]

- [x] **[QuarantineAgent]**: Add a quarantine workflow for high-confidence suspicious files. [High]
- [x] **[IncidentSnapshotAgent]**: Add an incident snapshot tool that records active plugins/themes, recent file changes, and config state. [High]
- [x] **[UserAccessAgent]**: Add user/role auditing for suspicious admin accounts and privilege assignments. [Medium]
- [x] **[SecurityHeadersAgent]**: Add live response checks for HSTS, CSP, and related headers. [Medium]

### Priority 3 - Stability & Diagnostics [Completed]

- [x] **[CronInspector]**: Add WP-Cron and scheduled task health reporting and clearing of overdue crons. [High]
- [x] **[PerformanceAgent]**: Add performance profiling signals for autoload bloat and large transients. [High]
- [x] **[PluginConflictAgent]**: Add guided plugin/theme isolation flows to help troubleshoot active plugin conflicts. [High]
- [x] **[HTTPAgent]**: Add loopback, homepage, and REST API health checks. [Medium]
- [x] **[MailAgent]**: Add `wp_mail()` and SMTP diagnostics. [Medium]

### Priority 4 - Recovery Automation [Completed]

- [x] **[IntegrityRepairAgent]**: Rebuild or restore critical files like `.htaccess`, `index.php` from trusted templates, edit `php.ini` / `.user.ini`, and configure PHP version presets. [High]
- [x] **[DatabaseRepairAgent]**: Add table repair and transient optimization routines. [Medium]
- [x] **[UpdateRiskAgent]**: Add an update risk planning tool that summarizes pending core/plugin/theme updates. [Medium]

## Later / Backlog

- No active backlog items remain from the current release checklist.
