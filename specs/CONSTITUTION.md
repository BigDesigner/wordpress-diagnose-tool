# WP Diagnose PRO - Standard Constitution (v0.2.6-beta)

## The Law of Namespacing
As of version 0.2.6-beta-PRO, the **Bracketed Namespace** structure is the absolute standard for all code within this project.

### 1. Mandatory Bracketed Syntax
All modules must be encapsulated within bracketed namespace blocks:
```php
namespace WPDiagnose\Core {
    class Engine { ... }
}
```
Unbracketed namespace declarations (`namespace X;`) are strictly forbidden in the final bundle.

### 2. Global Namespace Strategy
All procedural code, entry points, and inline HTML must be wrapped in a global namespace block:
```php
namespace {
    // Procedural logic
    echo "Hello World";
}
```

### 3. Purpose of this Standard
This architecture is non-negotiable because:
- It allows multiple independent modules to coexist safely within a single deployment file (`wp-diagnose-pro.php`).
- It prevents symbol collisions between agents (Server, Security, WordPress).
- It ensures a clear boundary between PSR-4 compliant OOP logic and the procedural entry point.

### 4. Build Integrity Guard (Pre-Commit/Pre-Build)
The `build.php` script implements an immutable integrity check:
- Every build MUST pass `php -l` syntax validation.
- If validation fails, the build artifact is immediately destroyed (`unlink`).
- No non-passing build shall ever reach the distribution directory.

---
*Signed by the Architect.*
