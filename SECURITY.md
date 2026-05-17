# Security Policy

## Status

GPG Meister is actively developed and security-sensitive by design.

The project handles GPG workflows, encrypted vault export and import, local metadata, and security-sensitive user interactions. Security reports are treated as high priority.

## Supported versions

Security fixes are focused on the latest public release branch and the current development branch.

At the moment, treat the newest published release and the active development branch as the supported targets.

## Reporting a vulnerability

Please do not open a public GitHub issue for a suspected security vulnerability.

Use one of these private contact paths instead:

- Email: `arn-c0de@protonmail.com`
- GitHub profile contact path: `https://github.com/arn-c0de`

## What to include

Please include as much of the following as possible:

- a short summary of the issue
- affected version or branch
- impacted platform such as Linux, macOS, or Windows
- reproduction steps
- proof of concept if available
- expected impact
- whether the issue can expose private key material, passphrases, decrypted content, metadata, or filesystem paths

If you are unsure whether something is security-relevant, report it privately.

## Preferred disclosure process

The preferred process is:

1. Report the issue privately.
2. Allow time to reproduce and assess it.
3. Allow time for a fix and release preparation.
4. Coordinate public disclosure after a fix is available or after the risk is clearly understood.

## Scope

Examples of issues that are in scope:

- passphrase exposure
- private key leakage
- decrypted plaintext leakage
- unsafe temporary file handling
- unsafe audit logging of secrets
- vault format weaknesses
- path trust or GPG binary trust bypasses
- signature verification failures with incorrect success states
- local privilege or file-permission mistakes that expose sensitive data

Examples that are usually lower priority unless they create a security impact:

- cosmetic UI issues
- documentation mistakes
- generic crashes without data exposure or trust boundary impact

## Hardening notes

GPG Meister includes several defensive measures:

- local-first operation
- dedicated GPG home usage
- safer GPG binary detection and trust pinning
- audit logging separated from diagnostic logging
- encrypted vaults with authenticated encryption
- atomic writes for sensitive artifacts
- short-lived in-memory handling for sensitive bytes

These controls reduce risk, but they do not replace careful review and responsible disclosure.
