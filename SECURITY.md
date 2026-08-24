# Security Policy — DRACXX

## Authorized Use Only

DRACXX is a **non-exploitative** reconnaissance and vulnerability
intelligence framework. It performs information gathering, detection,
and correlation only.

**DRACXX permanently does not implement:** exploits, payloads, reverse
shells, RCE, credential attacks, brute force, privilege escalation,
persistence, malware, data exfiltration, or denial of service.

You must have **explicit written authorization** to scan any target.
Unauthorized scanning may violate the Computer Fraud and Abuse Act (US),
Computer Misuse Act (UK), or equivalent laws in your jurisdiction.

## Scope Enforcement

DRACXX enforces scope allowlists and requires confirmation before
active scanning. Do not bypass, patch, or disable scope-control logic.

## Reporting a Vulnerability in DRACXX Itself

If you find a security issue in the DRACXX codebase (not a target you
scanned with it), please open a private security advisory on GitHub or
contact the maintainer directly rather than filing a public issue.

## Responsible Data Handling

DRACXX may surface secrets/tokens found during recon (e.g. in exposed
JS files). These are reported and redacted only — DRACXX never uses
discovered credentials to authenticate anywhere.
