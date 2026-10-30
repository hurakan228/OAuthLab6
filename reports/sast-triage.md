# SAST Finding Review — OAuthLab6

## Scan configuration
Tool: Semgrep 1.182.1
Ruleset: p/default
Rules executed: 203

## Findings and disposition

1. CSRF middleware detection
Severity: INFO
Disposition: Reviewed — scanner detection limitation.
Evidence: csrf-sync middleware is enabled.
POST without token returned HTTP 403.
POST with valid token returned HTTP 200.

2. Cookie Domain
Severity: WARNING
Disposition: Intentional configuration.
Domain is omitted to keep the session cookie host-only.

3. Cookie Expires
Severity: WARNING
Disposition: Intentional configuration.
The express-session maxAge option defines the cookie lifetime.

4. Cookie Secure
Severity: WARNING
Disposition: Environment-dependent configuration.
Secure is enabled in production and disabled for local HTTP development.

## SCA
Initial result: 1 High vulnerability.
Affected package: body-parser 2.3.0.
Fixed version: 2.4.0.
Final npm audit: 0 vulnerabilities.

## Runtime security tests
CSRF without token: HTTP 403.
CSRF with valid token: HTTP 200.
