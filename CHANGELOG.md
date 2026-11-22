# Changelog

All notable changes to **Checkwash Lens** are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-11-22

### Added
- **Checkwash `v0.13.1` Static Engine**: Upgraded bundled engine pin from `v0.12.0` to official `v0.13.1` (`checkwash.pyz`, `1,079,499` bytes, SHA-256 `0a987325c6f738129f5dbdc1e0287cfeab40517342b46df80707cccff8dd2839`), adding detection for `TEST_PATCHES_SUBJECT` local function replacements and `GUARDRAIL_ADDITIVE` escalators.
- **Transparent Build Pipeline**: Removed precompiled binaries from Git tracking and added `bundled/upstream.json`, `scripts/build_bundled.js` (`npm run build:bundled`), and `scripts/sync_checkwash.js` (`npm run sync:checkwash`) to compile native C brokers from source and verify upstream `checkwash.pyz` digests fail-closed.
- **GitHub Actions CI & Release Workflows**: Added cross-platform CI (`windows-latest` + `ubuntu-latest`) and automated tag/dispatch Release workflows generating `SHA256SUMS.txt` and supporting optional VS Code Marketplace & Open VSX publishing.
- **Unified Test Entrypoints**: Added `npm test` (cross-platform headless core + red-team suites), `npm run test:prove`, and `npm run test:e2e` via `scripts/run_tests.js`.
- **Storefront & Public Documentation**: Rewrote `README.md` with showcase screenshots (`media/screenshots/`), added `CHANGELOG.md`, `galleryBanner`, `docs/SECURITY.md`, and `docs/PUBLISHING.md`.

### Changed
- `scripts/package_vsix.js` now validates `bundled/manifest.json` against `bundled/upstream.json`, stamps target-specific `bundled/manifest.json`, includes `CHANGELOG.md` and Marketplace VSX manifest properties/assets, and excludes `bundled/upstream.json` from distributable VSIX archives.
- Updated `docs/SUPPORT-MATRIX-AND-LIMITATIONS.md` and `docs/RUNTIME-LIFECYCLE-DESIGN.md` to align with `v0.2.0` and Checkwash `v0.13.1`.

### Security
- Preserved strict compile-time + runtime SHA-256 verification of `bundled/checkwash.pyz` and platform-native `CWBROKER1` brokers alongside zero-developer-path binary auditing during build and VSIX packaging.

## [0.1.0] - 2026-11-15

### Added
- Initial architecture and implementation of **Checkwash Lens** for Windows x64 (`win32-x64`) and Linux x64 (`linux-x64`, including WSL2 and Docker Dev Containers).
- Two-pass Checkwash (`v0.12.0`) JSON v2 + SARIF 2.1.0 static analysis with strict 5-state verdict model (`Not Run`, `Pass`, `Partial / Review`, `Block`, `Error`) and immutable `checkwash-rev:` read-only snapshots.
- Native `CWBROKER1` process-tree lifecycle brokers for Windows NT Job Objects (`native/checkwash_broker.c`) and Linux `PR_SET_CHILD_SUBREAPER` + process groups (`native/checkwash_broker_posix.c`).
- Dedicated Activity Bar cockpit, 1-click Source Control (`scm/title`) uncommitted snapshot Pre-Check (`Staged` / `Worktree`, zero `.git` mutation), side-by-side `Base ↔ Head` diff, 1-click editable file jump, and zero-process smart Git range presets.
- Environment Doctor with guided User/Machine settings setup, orthogonal Fast Guard non-verdict diff hints, Context Diet diff copy with omission disclosure & secret redaction, opt-in `checkwash-prove v0.1.0` satellite with single-use modal confirmation, and Restricted Mode read-only offline report viewer.
- Red-team security hardening (`RT-01`–`RT-10`): `.git` symlink/UNC/alternates safety validation, `GIT_CONFIG_COUNT=5` hook/fsmonitor neutralization, `0700` controlled empty CWD, Windows PE `MZ` & Linux `WSLInterop` blocking, `O_NOFOLLOW` offline report reads, and Unicode BiDi sanitization.
