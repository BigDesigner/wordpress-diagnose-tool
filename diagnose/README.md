# WordPress Diagnose Tool - Distribution Quick Start

This directory contains the production-ready distribution assets.

## What Is Inside
- `wp-diagnose-pro.php`: the bundled single-file production build
- `index.php`: a small redirect helper for folder-based deployment
- `README.md`: this quick-start guide

## Deployment Options

### Option A: Upload the Entire `diagnose/` Folder
1. Upload the full `diagnose/` directory to the WordPress root.
2. Open `https://your-site.example/diagnose/`.

### Option B: Upload Only the Bundle
1. Upload `wp-diagnose-pro.php` to the WordPress root.
2. Open `https://your-site.example/wp-diagnose-pro.php?token=YOUR_TOKEN`.

## Recommended Usage Flow
1. Open the dashboard with a valid token.
2. Run diagnostics before applying fixes.
3. Apply only the actions required for the incident.
4. Confirm the site is healthy again.
5. Remove the tool after use.

## Security Notes
- This package is meant for short-lived operational use.
- Use the dashboard self-destruct flow when the job is complete.
- Cleanup still depends on the target host allowing file deletion.
- If you generated a custom build, verify your token and security settings before deployment.

For source-level build and release details, see the main repository documentation.
