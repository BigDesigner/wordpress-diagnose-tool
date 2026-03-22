# Deployment Guide - WP Diagnose Pro

## Overview
This toolkit is designed as an agentic, modular diagnostic system. For ease of deployment on crashed or emergency WordPress sites, it supports a **Single-File Bundle** strategy.

## Development Workflow
All core logic and specialized agents are maintained in separate directories for high maintainability and agentic interaction:
- `/Core`: Orchestration engine and base interfaces.
- `/src/Agents`: Specialized diagnostic logic (Server, WP, Security, Bootstrap).
- `wp-diagnose.php`: Main entry point and SPA Dashboard source.

## Production Deployment (The Bundle)
To deploy this tool to a live site, you must generate the professional bundle:

1. **Build the Bundle**:
   Run the following command in your development environment:
   ```bash
   php build.php
   ```
   This will generate a file named `wp-diagnose-pro.php`.

2. **Upload**:
   Upload **ONLY** the generated `wp-diagnose-pro.php` file to the root directory of your WordPress installation.

3. **Access**:
   Navigate to `https://your-site.com/wp-diagnose-pro.php?token=YOUR_TOKEN`.

4. **Self-Destruct**:
   Once diagnostics and fixes are complete, use the **Self-Destruct** button in the dashboard to securely remove the script and all its components from the server.

---
**SECURITY WARNING**: Never leave this script on a production server for extended periods. The built-in token and IP whitelisting provide security, but the best practice is to remove the file immediately after use.
