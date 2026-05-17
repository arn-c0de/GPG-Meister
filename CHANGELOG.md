# Changelog

All notable changes to this project will be documented in this file.

## [1.0.3] - 2026-05-15

### Added
- Per-key passphrase unlock UI for vault export.
- Two-key vault backup integration tests (create/decrypt/import).

### Fixed
- Smartcard export error handling in vault backup with improved error UI.
- Whitelisted zram swap devices.
- Added decryption help instructions.
- Clear inherited VIRTUAL_ENV in start script.

### Maintenance
- Updated dependencies and stabilized tests.

## [1.0.2] - 2026-05-14

### Security
- Fixed multiple vulnerabilities identified in the 2026-05-15 and 2026-05-14 audits.
- Enforced root ownership for whitelisted GPG binaries.
- Improved mlock detection and swap encryption checks.
- Added timeouts to all GPG operations.
- Restricted SecureBytes leakage in AEAD and KDF paths.
- Implemented atomic deletion for secret and public keys.
- Added device/inode tracking for GPG binary trust verification.
- Scoped trust settings and reduced passphrase lifetime.

### Added
- Key favorites: star toggle, delete guard, and grouped sorting.
- GPG trust-pinning dialog for non-whitelisted binaries.
- Share Key tab for exporting public keys.
- GnuPG module and home directory access to Flatpak packaging.

### Changed
- Moved blocking GPG and SQLite calls off the UI thread for better responsiveness.
- Simplified key deletion by removing redundant passphrase prompts.
- Increased maximum vault armor length to 8 MB.
- Switched project license to MIT.

### Fixed
- Duplicate backup banner and improved WarningBanner actions.
- Theme settings persistence.
- Stuck "New Key" action.
- Signal delivery in GUI workers.

### Documentation
- Added Security Policy and Code of Conduct.
- Added contribution guidelines.
- Updated README with screenshots and project status.

## [1.0.1] - 2026-05-12

### Added
- Initial release with core PGP management features.
- Support for encryption, decryption, signing, and verification.
- Vault management with export and import wizards.
- Audit logging for security-sensitive operations.
- Multi-language support (English and German).
- Automated GPG binary detection and hardening.

### Technical Foundation
- Phase 1: Foundation, crypto primitives, and core models.
- Phase 2: GPG integration and binary-path hardening.
- Phase 3: Storage primitives and service completion.
- Phase 4: UI shell and navigation.
- Phase 5: Key management views.
- Phase 6: Message operations (Encrypt/Decrypt/Sign/Verify).
- Phase 7: Vault views and backup reminders.
- Phase 8: Help system, settings, and end-to-end security tests.
- Phase 9: Packaging and release tooling.
