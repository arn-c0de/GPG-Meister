# Startup Checks and GPG Detection

The startup code lives in `src/gpg_meister/startup`.

It validates the runtime environment before normal work begins.

## `gpg_detector.py`

This module decides which GPG binary may be executed.

It uses a trust model with:

- platform-specific whitelists
- canonical path checks
- writable-file checks
- optional SHA-256 pinning for user overrides

Important behavior:

- a binary outside the whitelist is not trusted automatically
- a hash mismatch is treated as a real event, not as a small warning
- symlink behavior is checked carefully so a whitelisted path cannot silently point somewhere unsafe

This gives the application an explicit trust boundary for the GPG executable.

## `environment_check.py`

This module runs preflight checks on every startup.

Checks include:

- GPG version
- directory permissions
- config file permissions
- required Python packages
- `mlock` availability
- swap encryption hints

The result is split into:

- hard failures that stop startup
- warnings that are shown in the UI

## Why this matters

These checks are part of the security posture.

They reduce the chance that the app runs in a weak or broken environment, such as:

- outdated GPG
- unsafe file permissions
- missing dependencies
- unencrypted swap on Linux

## Platform Notes

The code is conservative without treating every platform limitation as fatal.

Example:

- `mlock` absence does not stop startup
- a missing trusted GPG path can stop startup
- some platform checks return warnings instead of pretending to know too much
