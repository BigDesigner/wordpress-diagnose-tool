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

- [ ] No active incomplete items in this planning file at the moment.

## Roadmap

### Priority 1 - Backup & Recovery

- [ ] **[BackupAgent Foundation]**: Introduce a dedicated `BackupAgent` with a clear backup catalog, job metadata, artifact listing, retention rules, and restore safety checks. The agent should expose operator-friendly backup names, timestamps, sizes, and restore readiness in the UI. [Critical]
- [ ] **[Database Backup]**: Add database-only backup support that can export the active WordPress database in Independent Mode or loaded WordPress mode, verify the resulting SQL artifact, and record the exact source database, table prefix, and export timestamp. [Critical]
- [ ] **[wp-content Backup]**: Add targeted `wp-content` backup support so uploads, mu-plugins, and other mutable content can be archived without touching core files. The backup should preserve directory structure and file timestamps where possible. [High]
- [ ] **[Plugin & Theme Backup]**: Add selective backup options for plugins and themes, including one-click backup of all plugins, all themes, or a chosen slug before risky maintenance actions like toggles, updates, or malware cleanup. [High]
- [ ] **[Full WordPress Backup]**: Add `wp-full` backup support that combines database + `wp-content` + critical root files (`wp-config.php`, `.htaccess`, key entrypoints) into a single recovery package with a manifest. [Critical]
- [ ] **[Backup Restore Flows]**: Add controlled restore routines for database-only, plugin/theme-only, `wp-content`, and full-site recovery. Restores should validate the artifact type, show a confirmation summary, support dry-run validation, and avoid destructive overwrite without explicit operator confirmation. [Critical]
- [ ] **[Restore Safety Rails]**: Add pre-restore checks such as writable paths, backup integrity hash verification, disk space estimation, maintenance mode suggestion, and rollback snapshot creation before applying a restore. [Critical]
- [ ] **[Backup Storage Strategy]**: Define where backup artifacts live on disk, how long they are retained, how they are named, and how expired artifacts are purged safely. Include support for pruning old backups without deleting the newest good restore point. [High]
- [ ] **[Backup UI Experience]**: Build a dedicated dashboard section for creating, downloading, validating, and restoring backups. It should show backup type, size, age, manifest details, and restore warnings in plain English. [High]

### Priority 2 - Security & Malware

- [ ] **[QuarantineAgent]**: Add a quarantine workflow for high-confidence suspicious files so operators can isolate them without immediate deletion. The agent should track original path, quarantine path, checksum, and restore option. [High]
- [ ] **[IncidentSnapshotAgent]**: Add an incident snapshot tool that records active plugins/themes, recent PHP file changes, security-relevant config state, and suspicious file inventory before cleanup or restore operations. [High]
- [ ] **[UserAccessAgent]**: Add user/role auditing for suspicious admin accounts, anomalous privilege assignments, stale high-privilege users, and recently created administrator accounts. [Medium]
- [ ] **[SecurityHeadersAgent]**: Add live response checks for HSTS, CSP, X-Frame-Options, X-Content-Type-Options, and related headers so the tool can report missing browser hardening signals. [Medium]

### Priority 3 - Stability & Diagnostics

- [ ] **[CronInspector]**: Add WP-Cron and scheduled task health reporting for stuck events, overdue jobs, failing schedules, and disabled cron execution. [High]
- [ ] **[PerformanceAgent]**: Add performance profiling signals for autoload bloat, large transients, option table hotspots, object cache status, and heavy plugin suspects. [High]
- [ ] **[PluginConflictAgent]**: Add guided plugin/theme isolation flows to help identify which component is breaking the site, while keeping reversible state snapshots before each toggle wave. [High]
- [ ] **[HTTPAgent]**: Add loopback, homepage, admin, REST API, and redirect-chain health checks to surface upstream HTTP failures and broken internal requests. [Medium]
- [ ] **[MailAgent]**: Add `wp_mail()` and SMTP diagnostics so the tool can verify whether WordPress email delivery is functioning and where it is failing. [Medium]

### Priority 4 - Recovery Automation

- [ ] **[IntegrityRepairAgent]**: Extend repair capabilities beyond core reinstall so critical files like `.htaccess`, `index.php`, and selected bootstrap files can be rebuilt or restored from trusted templates/backups. [High]
- [ ] **[DatabaseRepairAgent]**: Add table repair, orphan cleanup, transient cleanup, and optional optimization routines with preview mode before applying changes. [Medium]
- [ ] **[UpdateRiskAgent]**: Add an update planning tool that can summarize pending core/plugin/theme updates, likely blast radius, and recommended pre-update backup scope. [Medium]

## Later / Backlog

- [ ] No active backlog items remain from the current release checklist.
