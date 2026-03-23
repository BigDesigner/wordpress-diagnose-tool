# Security Audit Playbook - WordPress Diagnose Tool
_Last updated: 2026-03-23_

This document defines the repo-specific security review standard for WordPress Diagnose Tool. It is intended for auditing:
- AI-generated code
- hand-written patches
- pasted snippets
- release diffs
- production hardening changes

It is deliberately tuned to this repository's real attack surface rather than trying to be a universal security checklist.

---

## 1. Purpose

Use this playbook when reviewing changes that can affect:
- authentication or access control
- direct database reads/writes
- `wp-config.php` parsing or mutation
- file creation, deletion, or self-destruct cleanup
- production bundle generation
- outbound HTTP calls
- malware or threat intelligence logic
- admin or recovery actions exposed through the dashboard/API

This file is for security review only. It is not a general coding standard and it does not replace functional testing.

---

## 2. Reviewer Operating Mode

Act as a Senior Application Security Engineer with a WordPress incident-response mindset.

Rules:
- Assume a capable attacker.
- Treat the tool as high privilege because it can modify WordPress state directly.
- Do not assume the target host is well configured.
- Do not assume WordPress bootstrap is available or trustworthy.
- Prefer concrete evidence over generic warning language.
- If a claim cannot be proven from the diff or file, label it `Likely` and state what must be verified.

---

## 3. Review Output Format

When performing a formal security review, use this structure:

### SECURITY AUDIT: <short summary>
**Risk Assessment:** `Critical | High | Medium | Low | Secure`

#### Findings
- One item per finding
- Include:
  - vulnerability name
  - severity
  - confidence
  - category
  - exact file/line or changed function
  - exploit path
  - impact
  - evidence
  - smallest safe fix
  - regression tests

#### Observations
- Specific hardening notes only

#### No-Change Safety Notes
- If something is safe, explain why

---

## 4. Highest-Priority Risk Areas In This Repo

These are the areas that deserve the most scrutiny in this project.

### A. SecurityManager and Access Control
Files:
- `Core/SecurityManager.php`
- `src/wp-diagnose.php`

Audit for:
- token bypass
- signed token verification flaws
- audience, expiry, and clock-skew mistakes
- role escalation
- IP allowlist bypass
- proxy-header trust issues
- rate-limit bypass or collision
- accidental exposure of privileged actions to `viewer`

Critical questions:
- Can an attacker trigger `fix` or `self_destruct` without the intended role?
- Can a crafted header spoof client IP?
- Can an expired or malformed signed token still pass?
- Are denied responses consistent for JSON and HTML modes?

### B. Direct Database Writes in Independent Mode
Files:
- `src/wp-diagnose.php`
- `src/Agents/AssetManagerAgent/AssetManagerAgent.php`
- any agent touching `WPD_DB`

Audit for:
- SQL injection through option names, identifiers, or raw values
- incorrect dynamic table prefix usage
- unsafe serialize/unserialize handling
- writes to wrong option keys
- state changes that bypass expected authorization

Critical questions:
- Is every DB write tied to a privileged action?
- Are values written to `<prefix>options` deterministic and escaped correctly?
- Can attacker-controlled data reach SQL structure rather than only parameters?

### C. wp-config.php Parsing and Mutation
Files:
- `src/Agents/CoreOperationsAgent/CoreOperationsAgent.php`
- `src/Agents/BootstrapInspector/BootstrapInspector.php`
- `src/wp-diagnose.php`

Audit for:
- broken regex replacement that corrupts `wp-config.php`
- duplicate `define(...)` insertion
- unsafe path resolution
- privilege-sensitive constants being overwritten incorrectly
- recovery logic that silently changes unrelated config lines

Critical questions:
- Can this patch corrupt the site even when the action "succeeds"?
- Does it preserve existing config structure where possible?
- Does it behave safely when constants are missing, duplicated, or non-literal?

### D. File Operations and Self-Destruct
Files:
- `Core/Cleanup.php`
- `src/wp-diagnose.php`
- any backup/restore or log-management code

Audit for:
- arbitrary file deletion
- path traversal
- deleting files outside the intended deployment footprint
- failure to constrain cleanup targets
- writable-log abuse or unsafe file creation

Critical questions:
- Can cleanup remove core WordPress files by mistake?
- Are file paths derived from trusted roots only?
- Does this action behave differently in source mode vs bundled deployment?

### E. Outbound Requests and Threat Intelligence
Files:
- `src/Agents/ThreatIntelAgent/ThreatIntelAgent.php`

Audit for:
- SSRF through configurable feed URLs
- insecure TLS handling
- missing timeouts
- excessive retries
- API key leakage into responses or logs
- broken cooldown/rate-limit handling
- unsafe cache file writes

Critical questions:
- Are remote URLs fixed, allowlisted, or environment-controlled in a safe way?
- Could secrets be exposed in the UI, logs, or API output?
- Can malformed remote responses poison the cache or crash the report flow?

### F. Malware and Integrity Analysis
Files:
- `src/Agents/MalwareInspector/MalwareInspector.php`
- `src/Agents/CoreIntegrityAgent/CoreIntegrityAgent.php`

Audit for:
- dangerous false negatives on suspicious PHP locations
- false positives that could mislead operators into destructive action
- unsafe file scanning logic on large directories
- missing size/time bounds

Critical questions:
- Does the scanner distinguish trusted core files from rogue entrypoints?
- Can scanning become a denial-of-service vector on large installs?
- Are results precise enough to support operator decisions?

### G. Bundle Build and Release Pipeline
Files:
- `build.php`
- `scripts/sync-version.php`
- `.github/workflows/make-release.yml`

Audit for:
- unsafe release packaging
- build-time code injection
- version-sync corruption
- CI token overexposure
- shipping wrong files into production artifacts

Critical questions:
- Does the build output only the intended bundle assets?
- Could untrusted content get merged into the bundle header or runtime?
- Does CI run tests before publishing release artifacts?

---

## 5. Mandatory Coverage Checklist

For each non-trivial change, explicitly inspect these dimensions:

### Authentication and Authorization
- action-to-role mapping
- token extraction and validation
- JSON vs HTML denial behavior
- privilege boundaries around `fix` and `self_destruct`

### Injection and Unsafe Input Flow
- SQL structure vs SQL parameters
- regex replacement safety
- shell/command execution risk
- path handling and file roots

### Secrets and Sensitive Data
- no API keys, tokens, or passwords in logs
- no secrets echoed back except where intentionally required
- temporary passwords only exposed when explicitly designed

### Browser and API Safety
- no untrusted HTML injection into the dashboard
- JSON responses stay valid even on errors
- state-changing actions remain guarded

### Resource and Abuse Controls
- rate limits for sensitive routes
- bounded scans
- bounded network requests
- cooldown/backoff for external feeds

### Operational Safety
- no destructive action without explicit scope
- no silent corruption of `wp-config.php`
- no cleanup outside intended deployment paths

---

## 6. Repo-Specific Failure Modes To Always Check

These are common regression patterns in this project:

- `attemptFix(...)` UI wiring no longer reaches `Engine::performFix(...)`
- direct DB plugin/theme status drifts from UI status
- `WP_DEBUG_LOG` changes create duplicate `define(...)` lines
- self-destruct works in one deployment mode but deletes the wrong target in another
- API endpoints return empty output or non-JSON on fatal paths
- threat intel sync turns report fetch into a blocking network dependency
- malware heuristics mark trusted core files as hard errors
- new UI text or behavior reintroduces inconsistent product naming

---

## 7. Severity Guidance For This Repo

### Critical
- auth bypass to privileged actions
- arbitrary file deletion or overwrite
- unsafe direct DB mutation enabling takeover or destructive site state changes
- API key, token, or credential leakage
- SSRF to sensitive internal targets through feed or remote-fetch logic

### High
- role escalation
- `wp-config.php` corruption risk
- state-changing action reachable without intended protection
- dangerous cleanup targeting mistakes
- bundle/release pipeline issue that can ship compromised artifacts

### Medium
- denial-of-service through scans, remote sync, or unbounded operations
- significant false-positive or false-negative behavior in security agents
- host-sensitive logging or operational behavior that weakens incident response

### Low
- naming inconsistencies
- weak operator messaging
- defense-in-depth gaps with limited exploitability

---

## 8. Minimum Regression Tests For Security-Sensitive Changes

When a patch touches sensitive behavior, require focused tests for the affected area.

Examples:
- unauthorized token cannot execute `fix`
- `viewer` cannot trigger `self_destruct`
- `toggle_wp_debug` updates config without duplicating `WP_DEBUG_LOG`
- plugin/theme DB updates reflect correctly in a fresh report
- threat intel feed failure does not break `fetch_report`
- cleanup logic never targets WordPress root `index.php`

---

## 9. Review Gate

Before approving a security-sensitive patch, confirm:
- the changed trust boundary is identified
- exploitability is explained, not guessed
- the fix is the smallest safe change
- regression tests cover the failure mode
- secrets are not leaked
- destructive actions remain tightly scoped

If no meaningful issue is found, explicitly say:
- `Risk Assessment: Secure`
- why the relevant controls are sufficient
