# Deployment Guide - WP Diagnose PRO

## Overview
WP Diagnose PRO is developed as a modular PHP application and deployed as a production-ready bundle. The source tree is intended for development, while the generated distribution is intended for emergency upload to a live WordPress installation.

## Source Layout
- `Core/`: orchestration, security, versioning, and cleanup primitives.
- `src/Agents/`: diagnostic and recovery agents.
- `src/wp-diagnose.php`: primary source entry point and dashboard/API implementation.
- `diagnose/`: generated production distribution assets.

## Supported Deployment Paths

### Option A: Deploy from GitHub Release
1. Download the latest release package.
2. Extract the `diagnose/` directory.
3. Upload either:
   - the entire `diagnose/` directory to the WordPress root, or
   - only `wp-diagnose-pro.php` to the WordPress root.
4. Open the tool in a browser.

### Option B: Build the Bundle Locally
1. Use PHP 8.1 or newer.
2. Run:
   ```bash
   php build.php
   ```
3. The build writes the production bundle to `diagnose/wp-diagnose-pro.php`.
4. Upload the generated file or the entire `diagnose/` directory to the WordPress root.

## Access URLs
- Single file: `https://your-site.example/wp-diagnose-pro.php?token=YOUR_TOKEN`
- Folder deployment: `https://your-site.example/diagnose/`

`diagnose/index.php` redirects to `wp-diagnose-pro.php`, so either path can be used when the distribution folder is uploaded intact.

## Recommended Deployment Procedure
1. Upload the bundle to the WordPress root.
2. Open the tool with a valid token.
3. Run a report first before attempting repair actions.
4. Apply only the fixes needed for the incident.
5. Verify the site is healthy again.
6. Use self-destruct or manually remove the bundle after the incident.

## Operational Notes
- The tool is built for short-lived incident response and recovery, not for permanent installation.
- Independent Mode allows database-backed diagnostics even when normal WordPress bootstrap is degraded.
- Some actions depend on remote connectivity, writable filesystem paths, or host-specific PHP behavior.
- Threat intelligence syncing requires a valid Wordfence Intelligence V3 API key.
- The debug log viewer depends on the host honoring the configured `WP_DEBUG_LOG` destination.

## Troubleshooting
- If the visible version in the UI does not match the tag you deployed, verify that the latest bundle artifact was uploaded rather than an older local copy.
- If self-destruct cannot remove files, check ownership and filesystem permissions on the target host.
- If feed sync fails, confirm outbound HTTPS access, the API key type, and current rate-limit status.
- If a log file cannot be viewed, confirm that WordPress or PHP actually wrote to the configured path.

## Security Reminder
Never leave the tool on a production server longer than necessary. Token protection, allowlists, and rate limiting reduce exposure, but removal after use remains the safest operating model.
