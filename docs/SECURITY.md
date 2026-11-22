# Security Architecture & Execution Guarantees

Checkwash Lens is designed to inspect untrusted or freshly modified Git repositories without allowing repository files, Git configuration, workspace settings, or stray child processes to escape containment.

For low-level broker internals and lifecycle invariants, see [`docs/RUNTIME-LIFECYCLE-DESIGN.md`](RUNTIME-LIFECYCLE-DESIGN.md).

---

## 1. Zero Auto-Execution & Restricted Mode

- **Zero Auto-Execution**: Extension activation (`onView` / `onCommand` only — no eager `*` or `onStartupFinished` events), opening files, editing buffers, saving files, modifying settings, and granting Workspace Trust never spawn external processes.
- **Strict Restricted Mode (`workspace.isTrusted === false`)**:
  - When Workspace Trust is not granted, the unified admission gate (`src/runtime/admission.ts`), Environment Doctor (`src/runtime/environmentDoctor.ts`), and smart Git range preset collector (`src/ui/commands.ts`) block **all** external process launches (Git, Python, Checkwash, Snapshot Pre-Check, Prove, Replay) and perform **zero** `.git` filesystem probes.
  - Only bounded (`<= 16 MiB`), `O_NOFOLLOW` file-descriptor-verified read-only viewing of offline JSON reports (`View Offline Report`) remains available.

---

## 2. Transparent Build & Runtime Artifact Pinning

- **No Precompiled Binaries in Git**: The Git repository contains only source code and the plain-text lockfile [`bundled/upstream.json`](../bundled/upstream.json).
- **Verifiable Build-Time Assembly (`npm run build:bundled`)**:
  - Downloads `checkwash.pyz` over HTTPS from allowlisted GitHub Release hosts and enforces exact byte-length and SHA-256 verification fail-closed before writing `bundled/checkwash.pyz`.
  - Compiles the platform-native `CWBROKER1` broker directly from [`native/checkwash_broker.c`](../native/checkwash_broker.c) (Windows x64) or [`native/checkwash_broker_posix.c`](../native/checkwash_broker_posix.c) (Linux x64), probes capabilities (`--probe`), scans for leaked local paths, and emits `bundled/manifest.json`.
- **Defense-in-Depth Runtime Verification**:
  - Before every external execution, `verifyBundledArtifacts()` re-hashes `bundled/checkwash.pyz` against **compile-time constants** in `src/runtime/admission.ts` and `src/core/reportJoiner.ts` as well as `bundled/manifest.json`, and verifies the active platform broker's exact byte size, SHA-256, and (on Linux) executable mode (`+x`).
  - Never falls back to workspace `.venv`, repository scripts, or arbitrary `PATH` installations of `checkwash`.

---

## 3. Repository `.git` Safety & Hook Neutralization

Before invoking Git, Checkwash, or Prove against any repository:

1. **Zero-Process `.git` Metadata Validation (`verifyRepositoryGitMetadataSafety`)**:
   - Rejects symlinked `.git`, `.git/index`, `.git/config`, and `.git/HEAD`.
   - Rejects UNC / Windows device-path or escaping `gitdir:` pointer files and non-Git directory structures.
   - Rejects `objects/info/http-alternates` and any `objects/info/alternates` entry that points to a symlink or escapes safe repository boundaries.
2. **Hardened Git Execution Environment (`GIT_CONFIG_COUNT=5`)**:
   - Every static scan injects `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=<null>`, `GIT_TERMINAL_PROMPT=0`, and `GIT_CONFIG_COUNT=5`:
     - `core.fsmonitor=false`
     - `core.hooksPath=<controlledEmptyCwd>`
     - `core.pager=cat`
     - `protocol.allow=never`
     - `core.sshCommand=false`
   - Committed diff reads always pass `--no-textconv` so repository `diff.<driver>.textconv` commands never run.
3. **Zero-Mutation Uncommitted Snapshot Pre-Check**:
   - Builds an ephemeral commit inside an isolated temporary directory using `GIT_OBJECT_DIRECTORY`, `GIT_ALTERNATE_OBJECT_DIRECTORIES`, and `GIT_INDEX_FILE` with filter-free plumbing (`hash-object -w --no-filters`, `update-index`, `write-tree`, `commit-tree`).
   - Never mutates `<repo>/.git/index`, `<repo>/.git/objects`, or `HEAD`, and never executes `.gitattributes` `filter.*.clean` commands.

---

## 4. Machine-Scoped Settings & Native Binary Verification

- **Workspace Settings Ignored**: Executable paths (`checkwashLens.pythonPath`, `checkwashLens.gitPath`, `checkwashLens.provePath`, `checkwashLens.proveTestPythonPath`) are declared `"scope": "machine"` and read exclusively from `globalRemoteValue` / `globalValue`. Any workspace `.vscode/settings.json` override is ignored and flagged by Environment Doctor.
- **Cross-OS Setting Isolation**: When running in WSL2 or Linux Dev Containers, synced Windows paths (`C:\...`) are automatically ignored in favor of trusted Linux paths.
- **Outside-Repository Native Binaries Only**:
  - Canonical paths (`fs.realpathSync.native`) must resolve to regular files strictly outside the target repository.
  - **Windows**: Requires `.exe` extension and valid PE `MZ` (`0x4d5a`) magic header, rejecting `.bat`/`.cmd` shims and scripts.
  - **Linux / WSL2**: Rejects `/mnt/<drive>` paths, `.exe`/`.bat`/`.cmd`/`.com`/`.ps1` extensions, and Windows PE (`MZ`) headers to block `binfmt_misc/WSLInterop` escape from Linux process-tree containment. Uses POSIX `(st_dev, st_ino)` ancestor containment checks to defeat case-insensitive DrvFS / bind-mount aliases.
- **Isolated Python & Controlled CWD**:
  - Invokes CPython 3.11+ with `-I -S -B -X utf8` (disabling `PYTHONPATH`, `PYTHONSTARTUP`, `usercustomize`, and `sitecustomize`) from an empty controlled working directory outside the repository (`0700` UID-verified on POSIX with automatic `mkdtempSync` fallback against local symlink squatting).
- **Bare `git` Identity Verification**:
  - Before every process launch, `verifyBareGitResolutionForProcessLaunch()` verifies that bare `git` invoked internally by `checkwash.pyz` or `checkwash-prove` resolves (via Windows `CreateProcessW` search order or POSIX `execvp` `PATH`) to the exact same canonical path and SHA-256 as the verified Git binary.

---

## 5. Native Process-Tree Lifecycle Brokers (`CWBROKER1`)

All external processes pass through a single spawn boundary (`src/runtime/windowsBroker.ts`, never using `shell: true`) backed by platform-native C brokers:

- **Windows (`native/checkwash_broker.c`)**:
  - Creates a non-inheritable NT Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` and no breakaway flags.
  - Spawns child processes with `CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP` and explicit `lpApplicationName`, assigns to the Job Object before `ResumeThread`, and kills the suspended child if assignment fails.
  - Runs a rolling-window `stdin` watchdog thread (`CANCEL` or Extension Host disconnect EOF) and verifies `ActiveProcesses == 0` via `QueryInformationJobObject` before reporting `cleanupConfirmed: true`.
- **Linux (`native/checkwash_broker_posix.c`)**:
  - Sets `prctl(PR_SET_CHILD_SUBREAPER, 1)` so double-forked or `setsid()` grandchildren reparent to the broker instead of PID 1.
  - Places children in a dedicated process group (`setpgid`), arms `PR_SET_PDEATHSIG(SIGKILL)` with parent-PID race verification, closes all FDs `>= 3`, monitors `stdin` EOF/`CANCEL` + `16 MiB` stream caps + monotonic timeout via `poll()`, and sweeps `-pgid` + `/proc` descendants until `activeProcessesRemaining === 0`.
- **Cleanup-First Classification**: If `cleanupConfirmed !== true`, Checkwash Lens refuses to claim a run stopped cleanly, surfaces `Error`, and blocks subsequent launches.

---

## 6. Opt-In `checkwash-prove` Execution Contract

> **Warning**: Unlike Checkwash static scans, `checkwash-prove` executes repository code and test suites **without a sandbox**. Running Prove on untrusted code can access local files, environment variables, credentials, or network endpoints.

To keep this boundary explicit:
- Prove commands (`--list`, Full Prove, and single-mutant `Replay`) are strictly manual and opt-in.
- Every run prepares an immutable execution plan (pinned repository root, exact Base/Head commit OIDs, verified binary SHA-256s, exact `argv`, timeouts, and mutant caps) sanitized against Unicode BiDi (`U+202A..U+202E`, `U+2066..U+2069`) and C0/C1 control characters, and requires a **single-use modal confirmation** bound to that exact plan.
- Raw `loss.replay` strings inside JSON reports are display-only and are **never executed**. `Replay` always reconstructs `argv` from extension-owned in-memory session records, and imported `[Imported Read-Only]` reports cannot trigger `Replay`.

---

## 7. Context Diet Secret Guard & Offline Report Safety

- **Context Diet Redaction**: Scans diffs (including C-quoted Git paths, deleted `.env` files, and hunk headers) for `.env` / YAML / INI assignments, cloud/provider tokens (AWS, GitHub, Anthropic, OpenAI, Stripe, Slack, JWT), and private keys. Defaults to redacted clipboard output unless the user explicitly confirms unredacted copy.
- **Offline Report Viewing**: Uses `O_NOFOLLOW` descriptor-verified reads capped at `16 MiB` with JSON nesting depth (`32`) and item count (`50,000`) bounds, and clears active offline previews automatically when switching repositories.

---

## Reporting a Vulnerability

Please report security issues privately through GitHub Security Advisories on [`taipei49314/checkwash-lens`](https://github.com/taipei49314/checkwash-lens/security/advisories) rather than opening a public issue.
