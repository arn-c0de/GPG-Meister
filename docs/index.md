---
title: GPG Meister — Documentation
---

# GPG Meister Documentation

Local-first GPG desktop app built with Qt 6 and an MVVM architecture. All
cryptography runs on your machine via GnuPG; nothing is sent to a server.

> Looking for the code, installers, or changelog?
> See the [project repository](https://github.com/arn-c0de/GPG-Meister).

## Guides

- [Overview](overview.md) — what the app does and how the pieces fit together
- [Application startup](app-startup.md) — the launch sequence
- [Startup internals](startup.md) — deeper startup detail
- [Services](services.md) — the service layer
- [Models](models.md) — data models
- [UI](ui.md) — the view / view-model layer
- [Storage](storage.md) — how data is persisted
- [Security](security.md) — trust model and security boundaries
- [Smartcards and YubiKeys](smartcard.md) — card-held keys, PIN handling, token-unlockable vaults

## Development

- [Plan vs. code](plan-vs-code.md)
- [Codebase quality audit](dev/codebase-quality-audit-2026-05-14.md)
- [Security audit](dev/audit-2026-05-29.md)
- [1.0.2 security fixes](dev/1.0.2-sec-fixes.md)
