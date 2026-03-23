# WP Diagnose PRO (v0.2.5-beta)

**WP Diagnose PRO** is an agentic, modular, and highly secured diagnostic toolkit for WordPress. It is designed for emergency intervention when a site is inaccessible, returning fatal errors, or experiencing database connectivity issues.

## Key Features (v0.2.5-beta)
- **Agentic Orchestration:** Specialized agents for Server, WordPress, Security, and Bootstrap diagnostics.
- **Modern SPA Dashboard:** A premium, dark-themed interface built with Alpine.js and Tailwind CSS.
- **Emergency Bootstrap:** Locate and diagnose `wp-config.php` issues without executing corrupted files.
- **One-Click Fixes:** Automated correction routines for common server and configuration bottlenecks.
- **Professional Bundler:** Single-file deployment strategy via a secure build process.
- **Hardened Security:** IP Whitelisting, Token Auth, and Recursive Self-Destruct.

## Installation & Deployment

### 1. Development (Source)
Development happens in the `/src` and `/Core` directories. This modularity allows for high maintainability and specialized AI-agent interactions.
- **Specifications**: See [/specs](/specs) (Standard, Agentic Patterns).
- **Documentation**: See [/docs](/docs) (Audit Reports, Detailed Deployment).
- **Internal Logs**: See [/memory-bank](/memory-bank) (Worklog, Next Actions).

### 2. Production (The Bundle)
To deploy the tool, you must generate the professional single-file bundle in the distribution directory:

1. **Build**: Run `php build.php` in the root.
2. **Distribute**: Check the **[/diagnose](/diagnose)** directory.
3. **Deploy**: Upload **ONLY** the generated `wp-diagnose-pro.php` (or the entire `/diagnose` folder) to your WordPress root.
4. **Run**: Access `https://your-site.com/wp-diagnose-pro.php?token=YOUR_TOKEN`.

Refer to [docs/DEPLOY.md](/docs/DEPLOY.md) for detailed instructions.

## Security Warning
This tool is powerful and runs with high privileges. **Always use the "Self-Destruct" button immediately after use** to purge the script and its modular components from the server.

## License
This project is licensed under the GNU General Public License v3.0 (GPL-3.0). See the `LICENSE` file for details.
