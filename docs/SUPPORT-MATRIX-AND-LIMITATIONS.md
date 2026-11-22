# Support Matrix & Limitations (`v0.2.0`)

## 1. Platform & Environment Support Matrix

| Target / Environment | `v0.2.0` Support Status | Verification & Admission Behavior |
| --- | --- | --- |
| **Windows 11 x64 (`win32-x64`)** | **Supported** (`checkwash-lens-0.2.0-win32-x64.vsix`) | Verified across unit, contract, counterexample, red-team, Extension Host, and installed-VSIX desktop suites on Windows 11 x64 + VS Code Desktop (`^1.96.0`) and GitHub Actions `windows-latest`. |
| **Linux x64 Desktop (`linux-x64`)** | **Supported** (`checkwash-lens-0.2.0-linux-x64.vsix`) | Verified across unit, contract, counterexample, red-team, and Linux container / GitHub Actions `ubuntu-latest` suites (`x86_64`). |
| **WSL2 (`remoteName: "wsl"`, `linux-x64`)** | **Supported** (`"extensionKind": ["workspace"]` + `checkwash-lens-0.2.0-linux-x64.vsix`) | Supported with VS Code Desktop connected to `vscode-server-linux-x64` across Restricted Mode (`0` spawns), native `ext4`, `/mnt/<drive>` `9p` DrvFS, `(st_dev, st_ino)` case-alias containment, `WSLInterop` Windows PE (`MZ` / `.exe`) rejection, cross-OS settings isolation, and remote Extension Host crash reaping. |
| **Docker Dev Containers (`remoteName: "dev-container" \| "attached-container"`, `linux-x64`)** | **Supported** (`"extensionKind": ["workspace"]` + `checkwash-lens-0.2.0-linux-x64.vsix`) | Supported with VS Code Desktop connected to Linux container `vscode-server-linux-x64` across committed scans, pre-commit snapshots, Environment Doctor, and opt-in `checkwash-prove v0.1.0`. |
| **Windows 10 x64 (`win32-x64`)** | **Unverified (`NOT_RUN`)** | Uses standard Win32 Job Object APIs (`win32-x64`), but standalone Windows 10 host verification has not been executed separately in `v0.2.0`. |
| **macOS (`darwin-x64`, `darwin-arm64`)** | **Planned for `v0.3.0`** (Unsupported in `v0.2.0`) | Deterministically rejected at `verifyLaunchAdmission` without fallback (`0` external process spawns) until native macOS broker & verification land in `v0.3.0`. |
| **Windows ARM64 / Linux ARM64** | **Unsupported in `v0.2.0`** | Deterministically rejected at `verifyLaunchAdmission` without fallback (`0` external process spawns). |
| **Web / Remote SSH (`ssh-remote`) / Dev Tunnels (`tunnel`) / Codespaces (`codespaces`) / Virtual Workspaces (`vscode-vfs`)** | **Unsupported for Execution** | Deterministically rejected at `verifyWorkspaceHostEnvironment` / `verifyLaunchAdmission` (`0` external process spawns); bounded read-only offline report viewing remains available where local file descriptors are supported. |
| **Third-Party VS Code Forks (`VSCodium` / `Cursor` / `Windsurf` / etc.)** | **Best-Effort / Unverified (`NOT_RUN`)** | Published to Open VSX for compatible editors; no separate fork-specific verification is claimed in `v0.2.0`. |
| **Bundled Checkwash Static Engine** | **Pinned `v0.13.1`** (`1,079,499` bytes, SHA-256 `0a987325c6f738129f5dbdc1e0287cfeab40517342b46df80707cccff8dd2839`, Release-Merge `5e2a89ef0d447ae6e08c289f4a3357325b7286e9`, Tag Commit `62656df812372c085b4d32c7864fcdfaccd0318a`) | Downloaded and verified fail-closed at build time (`scripts/build_bundled.js`) and re-verified by SHA-256 before every launch; never falls back to workspace `.venv` or `PATH`. |
| **Native Lifecycle Brokers** | **Built from Source (`CWBROKER1`)** (`native/checkwash_broker.c`, `native/checkwash_broker_posix.c`) | Compiled transparently at build/CI time and hashed into `bundled/manifest.json`; verified by exact byte size and SHA-256 before every launch. |
| **Opt-In Prove Satellite** | **Pinned `checkwash-prove v0.1.0`** (`582f1339ea48f4db48b4414648ca21316aeb0713`, Catalogue `v0.5-m2`, Generator SHA-256 `67096f7340a281585aaeaf801ae0ac29c4eb1a777c358ee973f02058cc7f4e14`) | Unrecognized versions or catalogue generator hashes fail closed before execution. |

---

## 2. Operational Semantics & User-Facing Limitations

1. **Committed Range Verdict (`A..B` / `A...B`) vs. Uncommitted Snapshot Pre-Check (`Staged` / `Worktree`)**
   - **Authoritative Committed Verdict (`Scan Committed Range`)** evaluates immutable committed Git revisions only.
   - **Pre-Commit Snapshot Pre-Check (`Pre-Check Uncommitted Changes`)** inspects either the Staged Index (`HEAD -> Index`) or the on-disk Working Tree (`HEAD -> Worktree`, including non-ignored untracked files) inside an isolated temporary Git object/index overlay without mutating `.git/index`, `.git/objects`, or `HEAD`.
   - Snapshot results are explicitly badged `[Staged Pre-Check]` or `[Worktree Pre-Check]` and do not include unsaved editor buffers. If any open working-tree editor becomes dirty after a `[Worktree Pre-Check]` completes, the status bar and sidebar immediately mark the pre-check verdict `(Stale)` (`$(warning)`) and withhold live inline diagnostics on diverged buffers.

2. **`Pass` vs. `Partial / Review` vs. `Error`**
   - **`Pass`**: Static Checkwash rules passed for the analyzed diff (including active exemptions) with zero unread/skipped files, config errors, SARIF notifications, or `stderr` warnings. `Pass` does not imply absence of logic bugs or full test adequacy.
   - **`Partial / Review`**: Engine reported `pass`, but one or more analysis gaps exist (`unread` files, `skipped_files`, `config_errors`, SARIF tool notifications, or non-empty `stderr` such as ignored exemptions).
   - **`Error`**: Schema mismatch, unsupported version, contradictory exit code (e.g. `exit 2`), timeout, `> 16 MiB` output overflow, or unconfirmed process-tree cleanup.

3. **Restricted Mode (Untrusted Workspaces)**
   - When Workspace Trust is not granted (`workspace.isTrusted === false`), Checkwash Lens spawns **zero** external processes (no Git, Python, Checkwash, or Prove) and performs zero `.git` directory probes. Only descriptor-verified (`O_NOFOLLOW`) read-only inspection of offline report files (`<= 16 MiB`) is enabled.

4. **`checkwash-prove` Execution Risk Notice**
   - Prove (`--list`, Full Prove, and single-mutant `Replay`) executes repository code and test suites **without a sandbox**, which may access credentials, network resources, or files outside temporary directories. Every run requires explicit single-use modal confirmation.
   - Raw `loss.replay` strings inside JSON reports are display-only and are never executed; `Replay` always reconstructs `argv` from pinned in-memory session records, and imported external Prove reports (`[Imported Read-Only]`) cannot trigger `Replay`.
