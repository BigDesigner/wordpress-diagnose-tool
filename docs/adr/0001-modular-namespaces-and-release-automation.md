# ADR 1: Modular Namespacing for Bundler Compatibility and Automated Release Pipeline

## Status
Accepted

## Context
1. **Namespace Nesting Conflict**: 
   The single-file bundler `build.php` compiles all PSR-4 modular source files into a single, standalone distribution file (`wp-diagnose-pro.php`). To allow multiple independent modules to coexist, the compiler wraps each module's clean code inside bracketed namespace blocks (`namespace X { ... }`). 
   When the 13 new agents were written using bracketed namespaces in their source files directly, the regex matching in `build.php` failed to identify and strip the declaration, causing the bundler to nest these namespaces inside another global namespace wrapper. This resulted in `PHP Fatal error: Namespace declarations cannot be nested` in the compiled distribution.
   
2. **Release Execution Ambiguity**:
   The release pipeline (`make-release.yml`) was configured to execute release steps only when triggered by Git tag push events. This prevented manual runs (`workflow_dispatch`) from successfully tagging the codebase and publishing releases, forcing developers to manually tag and push version tags from their local command lines.

3. **Emergency Configuration Needs**:
   Wordpress emergency recovery frequently involves dealing with White Screen of Death (WSOD) states caused by PHP version mismatches or misconfigured files. The diagnostic tool needed direct configurations capability (editing `php.ini`, `.user.ini`, `.htaccess`, and switching PHP versions) from the dashboard.

## Decision
1. **File-Scoped Namespaces in Source Files**:
   All modular source files (`src/Agents/**/*.php` and `Core/**/*.php`) must declare file-scoped namespaces (e.g. `namespace WPDiagnose\Agents\BackupAgent;`) rather than bracketed namespaces. The compiler `build.php` will continue to parse these file-scoped declarations, extract the namespace, strip the declaration, and wrap the code in bracketed namespaces for the final bundle.
   
2. **Automated Pipeline Tagging**:
   Enhance the GitHub Actions release workflow to:
   - Read the version dynamically from the project `VERSION` file.
   - Verify if a corresponding Git version tag (e.g., `v0.3.4-beta`) exists on the remote repository.
   - Automatically create and push the Git tag from within the runner if it does not exist.
   - Build and release the compiled artifacts on both tag pushes and manual triggers (`workflow_dispatch`).

3. **Built-in Configuration Editors**:
   Add direct editing actions for `.htaccess`, `php.ini`, and `.user.ini` inside `IntegrityRepairAgent` alongside easy PHP version switching presets.

## Consequences
- **Code Cleanliness**: Individual source files remain PSR-4 compliant, standard, and fully parseable by IDEs and test suites.
- **Hands-off Releases**: Releasing a new version is completely automated. Developers only need to bump the `VERSION` file and run the workflow on GitHub, which takes care of tagging, building, and publishing the release.
- **WSOD Mitigation**: Operators can repair host PHP environment discrepancies and plugin-level issues directly from the web dashboard.
