# WordPress Diagnose Tool (v0.3.1-beta)

**WordPress Diagnose Tool** is an emergency-ready WordPress diagnostics and recovery toolkit built for real-world outage, compromise, and maintenance scenarios. It ships as a modular PHP codebase for development and as a production bundle for fast drop-in deployment on live sites.

## Key Features (v0.3.1-beta)
- **Agent-driven diagnostics** for server health, bootstrap recovery, WordPress state, database health, core integrity, asset management, threat intelligence, malware signals, and emergency operations.
- **Independent Mode support** that can inspect and repair WordPress state even when normal bootstrap paths are degraded.
- **One-click recovery actions** for plugin/theme activation, WordPress debug toggles, cache cleanup, password reset, and forced core reinstallation.
- **Threat intelligence integration** with optional Wordfence Intelligence V3 feed support and local cache-based CVE matching.
- **Malware heuristics** for suspicious entrypoints, executable uploads, and high-risk shell signatures.
- **Single-file production build** for rapid deployment during incidents.
- **Centralized security controls** with token validation, signed access support, role-based permissions, allowlists, rate limiting, and self-destruct cleanup.

## Quick Start

### Option A: Use the Latest Release
1. Download the latest release artifact from GitHub Releases.
2. Extract the `diagnose/` package or upload `wp-diagnose-pro.php` directly to the WordPress root.
3. Open `https://your-site.example/wp-diagnose-pro.php?token=YOUR_TOKEN` or `https://your-site.example/diagnose/`.
4. Run diagnostics, apply fixes, and remove the tool when the job is complete.

### Option B: Build Locally
1. Use PHP 8.1 or newer.
2. Run `php build.php` from the repository root.
3. Collect the generated production bundle from [`diagnose`](diagnose).
4. Deploy as described in [`docs/DEPLOY.md`](docs/DEPLOY.md).

## Main Agents
- **ServerInspector**: PHP/runtime extensions, limits, and environment checks.
- **BootstrapInspector**: `wp-config.php` discovery, database bootstrap, and independent mode diagnostics.
- **WPInspector**: WordPress version, plugins, themes, and environment information.
- **SecurityInspector**: permissions, exposed files, salts, and defensive checks.
- **DBHealth**: autoload size, table-level database health indicators, and storage pressure signals.
- **CoreIntegrityAgent**: WordPress core checksum and unexpected/missing file analysis.
- **AssetManagerAgent**: plugin/theme state discovery and database-backed activation workflows.
- **CoreOperationsAgent**: debug toggles, log viewer, cache cleanup, maintenance mode, password reset, and core repair actions.
- **ThreatIntelAgent**: external vulnerability feed cache, version matching, and risk visibility.
- **MalwareInspector**: suspicious PHP locations, shell-like patterns, and high-confidence malware indicators.

## Security Model
- Access is enforced through the centralized `SecurityManager`.
- The tool supports legacy token mode and signed token mode.
- Sensitive operations are protected by role-aware action gates and rate limiting.
- The tool is designed for short-lived incident response usage, not for permanent installation.
- Self-destruct is available, but successful cleanup still depends on filesystem permissions on the target host.

## Runtime Notes
- Production build and CI target **PHP 8.1+**.
- Threat intel works without an API key in passive mode, but live feed syncing requires a valid Wordfence Intelligence V3 key.
- Debug log viewing depends on the target host honoring the configured `WP_DEBUG_LOG` path.
- Some host-level logging, network, or permission restrictions can still affect runtime behavior on production servers.

## Documentation
- [Deployment Guide](docs/DEPLOY.md)
- [Audit Report](docs/AUDIT_REPORT.md)
- [Architecture Constitution](specs/CONSTITUTION.md)
- [Verified Worklog](memory-bank/VERIFIED_WORKLOG.md)
- [Roadmap / Next Actions](memory-bank/NEXT_ACTIONS.md)
- [Production Bundle Notes](diagnose/README.md)

## License
This project is licensed under the GNU General Public License v3.0 (GPL-3.0). See [`docs/LICENSE`](docs/LICENSE).
