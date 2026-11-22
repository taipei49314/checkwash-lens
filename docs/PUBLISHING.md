# Building from Source & Publishing Guide

This guide covers local transparent builds, first-time public open-source setup, registering publisher namespaces on **VS Code Marketplace** and **Open VSX**, configuring GitHub Actions secrets, and publishing a release (`v0.2.0` and beyond).

---

## 1. Building & Testing Locally from Source

No precompiled binaries are checked into Git. To build and verify locally on Windows x64 or Linux x64:

```bash
# 1. Install TypeScript build dependencies
npm ci

# 2. Compile the native CWBROKER1 broker from native/*.c and download + SHA-256-verify checkwash.pyz
npm run build:bundled

# 3. Compile TypeScript and run cross-platform headless unit, contract, and red-team suites
npm test

# 4. Package the current platform VSIX (with zero-leak & integrity audit)
npm run package:vsix:win32   # on Windows x64
npm run package:vsix:linux   # on Linux x64
```

Optional local test tiers:
- `npm run test:prove` — runs opt-in `checkwash-prove v0.1.0` integration suites (set `CW_TEST_PROVE_EXE` if not in default path).
- `npm run test:e2e` — runs real VS Code Desktop Extension Host suites (set `CW_TEST_VSCODE_EXE` if needed).

---

## 2. First-Time Public Open-Source Checklist

Before making `taipei49314/checkwash-lens` public:

- [ ] Verify `main` contains zero precompiled binaries (`git ls-files '*.exe' '*.pyz' 'bundled/checkwash-broker-*' 'bundled/manifest.json'` is empty).
- [ ] Verify zero personal filesystem paths, machine hostnames, or secrets appear in tracked files or packaged `.vsix` archives.
- [ ] Confirm `package.json` version (`0.2.0`), `CHANGELOG.md`, `LICENSE` (`Apache-2.0`), `README.md`, `media/icon.png`, and `media/screenshots/*.png` are up to date.
- [ ] Switch repository visibility to **Public** under GitHub **Settings → General → Danger Zone → Change repository visibility**.
- [ ] Enable branch protection on `main` requiring the `Build, Test & Package (win32-x64)` and `Build, Test & Package (linux-x64)` CI checks from [`.github/workflows/ci.yml`](../.github/workflows/ci.yml).

---

## 3. Registering VS Code Marketplace Publisher (`taipei49314`)

1. Sign in to [Azure DevOps](https://dev.azure.com/) with the Microsoft / GitHub account you want to own the publisher (create a free organization if prompted).
2. Create a Personal Access Token (PAT) in Azure DevOps (**User Settings → Personal access tokens → New Token**):
   - **Organization**: **All accessible organizations** (required by VS Code Marketplace).
   - **Scopes**: Custom defined → **Marketplace → Manage**.
   - **Expiration**: Set a reasonable rotation window (e.g. 90 days) and store the token safely.
3. Visit the [Visual Studio Marketplace Management Portal](https://marketplace.visualstudio.com/manage) and create the publisher with ID **`taipei49314`** (matching `"publisher": "taipei49314"` in `package.json`).
4. Verify your PAT locally before adding it to GitHub Secrets:
   ```bash
   npx --yes @vscode/vsce verify-pat taipei49314
   ```

---

## 4. Registering Open VSX Namespace (`taipei49314`)

1. Sign in to [Open VSX Registry](https://open-vsx.org/) with your GitHub account.
2. Link an Eclipse Foundation account and sign the **Eclipse Open VSX Publisher Agreement** under **Settings → Publisher Agreement**.
3. Create an Access Token under **Settings → Access Tokens → Generate New Token**.
4. Create the `taipei49314` namespace (one-time setup):
   ```bash
   OVSX_PAT="<your-open-vsx-token>" npx --yes ovsx create-namespace taipei49314
   ```

---

## 5. Configuring GitHub Actions Secrets

In `taipei49314/checkwash-lens` → **Settings → Secrets and variables → Actions → New repository secret**:

| Secret | Required? | Purpose |
| --- | --- | --- |
| `VSCE_PAT` | Optional | Azure DevOps PAT (`Marketplace: Manage`) for publishing both platform VSIX files to VS Code Marketplace. |
| `OVSX_PAT` | Optional | Open VSX access token for publishing both platform VSIX files to Open VSX Registry. |

> If either secret is unset or empty, [`.github/workflows/release.yml`](../.github/workflows/release.yml) cleanly skips that registry step without failing the GitHub Release job.

---

## 6. Publishing `v0.2.0`

1. Ensure `main` has the `v0.2.0` commit and CI is green on both `win32-x64` and `linux-x64`.
2. Create and push the annotated release tag matching `package.json`:
   ```bash
   git checkout main
   git pull --ff-only
   git tag -a v0.2.0 -m "Release Checkwash Lens v0.2.0"
   git push origin v0.2.0
   ```
3. Monitor the **Release** workflow ([`.github/workflows/release.yml`](../.github/workflows/release.yml)):
   - Builds `checkwash-lens-0.2.0-win32-x64.vsix` on `windows-latest` and `checkwash-lens-0.2.0-linux-x64.vsix` on `ubuntu-latest` from source.
   - Runs `npm test` on both runners before packaging.
   - Generates and verifies `SHA256SUMS.txt`.
   - Creates the GitHub Release `v0.2.0` with both `.vsix` files and `SHA256SUMS.txt`.
   - Publishes to VS Code Marketplace and Open VSX if `VSCE_PAT` / `OVSX_PAT` are configured.
4. Post-release verification:
   - Download both `.vsix` files and `SHA256SUMS.txt` from GitHub Releases and verify `sha256sum -c SHA256SUMS.txt`.
   - Verify the Marketplace and Open VSX listings display the icon, dark banner, screenshots, README, and Changelog tab cleanly.

### Manual Fallback Publish (Using GitHub Release Assets)
If you ever prefer to publish the CI-built `.vsix` files manually after verifying `SHA256SUMS.txt`:

```bash
# VS Code Marketplace
VSCE_PAT="<pat>" npx --yes @vscode/vsce publish --packagePath checkwash-lens-0.2.0-win32-x64.vsix
VSCE_PAT="<pat>" npx --yes @vscode/vsce publish --packagePath checkwash-lens-0.2.0-linux-x64.vsix

# Open VSX
OVSX_PAT="<pat>" npx --yes ovsx publish checkwash-lens-0.2.0-win32-x64.vsix
OVSX_PAT="<pat>" npx --yes ovsx publish checkwash-lens-0.2.0-linux-x64.vsix
```

---

## 7. Upgrading the Bundled Checkwash Engine in Future Releases

When a new stable release of `taipei49314/checkwash` is published:

1. Run `npm run sync:checkwash -- --tag vX.Y.Z` to fetch the official release metadata, independently verify `checkwash.pyz` bytes & SHA-256, and update `bundled/upstream.json`.
2. Update the compile-time defense-in-depth pins reported by `sync_checkwash.js` (`src/core/reportJoiner.ts`, `src/runtime/admission.ts`, `src/ui/diagnostics.ts`).
3. Regenerate Phase 0 fixtures (`node scripts/generate_phase0_fixtures.js`) and run `npm run build:bundled && npm test`.
