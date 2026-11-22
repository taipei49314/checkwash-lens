# Runtime 與程序生命週期設計紀錄（Checkwash Lens — `v0.2.0`）

## 1. 設計目標與不變量（Invariants）

1. **單一執行入口與互斥可取消排程（No Bypass & Exclusive Cancelable Lifecycle）**：
   * 產品程式碼（`src/`，不含測試輔助套件 `src/test/`）中只有 [`src/runtime/windowsBroker.ts`](../src/runtime/windowsBroker.ts) 允許呼叫 Node `child_process.spawn`（且永遠不設定 `shell: true`）。
   * 所有上層操作（Git commit 驗證、Python 版本探測、Environment Doctor 診斷探測、未提交 Staged／Worktree 隔離快照建立、Checkwash JSON/SARIF 雙次分析、Prove List/Full/Replay 之預檢計畫準備與授權後執行）一律經由 [`src/runtime/processRunner.ts`](../src/runtime/processRunner.ts) 的 `UnifiedProcessRunner`（`runExclusiveCancelableOperation` + `executeGatedProcess`）並先通過 [`src/runtime/admission.ts`](../src/runtime/admission.ts) 之 `verifyLaunchAdmission()`。
2. **Restricted Mode 零子程序與零 `.git` 探測保證（`B01`, `RT-01`）**：
   * 當 `isWorkspaceTrusted === false` 時，`verifyLaunchAdmission()`、[`src/runtime/environmentDoctor.ts`](../src/runtime/environmentDoctor.ts) 與 `collectSmartGitRangePresetsZeroProcess()` 在共同邊界立即拒絕／略過所有外部程序探測與 `.git` 元資料檔案讀取（僅執行擴充自身雜湊檢查與設定覆寫提示）。
   * 已分別於 Node 准入層（`B01`）與隔離 profile 安裝成品 `.vsix` 的真實 VS Code Desktop（Windows 11 `win32-x64` 與 Linux `linux-x64`，`vscode.workspace.isTrusted === false`）驗證：於擴充套件尚未啟用前（`ext.isActive === false`）即對 Extension Host PID 掛載核心層子程序建立監測器（Windows 為 Win32 NT Kernel Job Object + IOCP `JOB_OBJECT_MSG_NEW_PROCESS`；Linux 為 `ptrace(PTRACE_SEIZE)` `PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC`，並皆由可信工作區 Session 2 陽性對照驗證）及程序內 `child_process` 同步攔截，確認在「Extension Host 程序樹自擴充啟用前至完成 Activation、所有掃描／預檢／Environment Doctor／Prove 命令觸發、檔案開啟／編輯／儲存、設定變更、版本探測、Git 讀取、Prove／Replay 預檢與離線報告唯讀檢視」觀測範圍內為 **0 子程序建立**。
3. **Repository `.git` 元資料預檢與零污染快照設計（`RT-01`, `RT-02`, [`src/engine/snapshotBuilder.ts`](../src/engine/snapshotBuilder.ts)）**：
   * `verifyRepositoryGitMetadataSafety()` 於啟動任何 Git／Python／Prove 前先以零子程序檢查 `<repo>/.git`：拒絕符號連結 `.git`／`.git/index`／`.git/config`／`.git/HEAD`、拒絕 UNC／Device 路徑或非 Git 結構之 `gitdir:` 指標、拒絕 `objects/info/http-alternates` 及越界或指向符號連結的 `objects/info/alternates`。
   * 所有受控靜態子程序環境強制注入 `GIT_CONFIG_COUNT=5`（`core.fsmonitor=false`、`core.hooksPath=<controlledEmptyCwd>`、`core.pager=cat`、`protocol.allow=never`、`core.sshCommand=false`），使惡意 `<repo>/.git/config` 內建指令無法透過 `checkwash.pyz` 內部 `git` 呼叫執行。
   * 未提交快照預檢於系統暫存區建立獨立物件與索引目錄，透過 `GIT_OBJECT_DIRECTORY`、`GIT_ALTERNATE_OBJECT_DIRECTORIES` 與 `GIT_INDEX_FILE` 建立暫時 commit 供固定版 `checkwash.pyz` 與 `checkwash-rev:` 讀取，絕不修改 `<repo>/.git/index`、`<repo>/.git/objects` 或 `HEAD`，僅使用底層 plumbing（`ls-tree -r -z`、`ls-files --stage -z`、`ls-files --others --exclude-standard -z`、`hash-object -w --no-filters`、`update-index --cacheinfo`、`write-tree`、`commit-tree`）。
4. **靜態與 Prove 路徑之原生二進位驗證、受控 `cwd` 與 bare `git` 一致性（`B03`, `B04`, `RT-03`, `RT-04`）**：
   * 強制核對使用者設定之 CPython 3.11+、Git 與 `checkwash-prove` 為目標 repository 外部的真實檔案（`fs.realpathSync.native` 不落在目標 repo 內）；在 Windows 強制驗證 `.exe` 副檔名與 PE `MZ`（`0x4d5a`）標頭以拒絕 `.bat`/`.cmd` 批次跳板。
   * Python 一律加上 `-I -S -B -X utf8` 旗標啟動，隔離 `PYTHONPATH`、`PYTHONSTARTUP`、`usercustomize` 與 `sitecustomize`，並固定 UTF-8 I/O。
   * 靜態掃描執行工作目錄（`cwd`）固定為目標 repo 外的受控空白目錄（在 POSIX 上採用 UID 專屬 `0700` 權限與 `lstatSync` 擁有者驗證，若遭本機其他帳號預佔名稱則自動切換至 `mkdtempSync` `0700` 隔離目錄）。
   * `executeGatedProcess()` 在每次啟動前均呼叫 `verifyBareGitResolutionForProcessLaunch()`，於 Windows 依 `CreateProcessW` 搜尋順序、於 Linux 依 POSIX `execvp` `PATH`（拒絕空白或相對段）與同目錄 `git` 遮蔽檢查，重新驗證 bare `git` 必定解析為已核對之 canonical Git（同路徑且同 SHA-256）。
5. **WSL2 與 Docker Dev Containers 跨作業系統邊界防護**：
   * 擴充套件宣告 `"extensionKind": ["workspace"]`，在 WSL2（`remoteName === "wsl"`）與容器工作區（`remoteName === "dev-container" | "attached-container"`）固定執行於 Linux `x64` `vscode-server` Remote Extension Host；`ssh-remote`、`tunnel`、`codespaces` 與虛擬工作區（`vscode-vfs:`）一律在 `verifyWorkspaceHostEnvironment()` 拒絕且不啟動任何子程序。
   * **POSIX `(st_dev, st_ino)` 掛載別名包含檢查**：`areSameRepositoryPath()`、`isPathInsideOrEqualPlatform()` 與 `tryRelativeInsidePosixInodeRoot()` 結合 `fs.statSync(..., { bigint: true })` 祖先鏈 `(dev, ino)` 比對，防止透過 `/mnt/c` DrvFS 或 bind-mount 大小寫別名繞過 repo 邊界。
   * **`WSLInterop` 與 Windows PE（`MZ` `0x4d5a`）執行攔截**：在 Linux 宿主機拒絕 `/mnt/<drive>`、`.exe`/`.bat`/`.cmd`/`.com`/`.ps1` 後綴或帶有 `0x4d5a` (`MZ`) 標頭的二進位檔，杜絕經由 `binfmt_misc/WSLInterop` 脫離 Linux `pgid`、`PR_SET_PDEATHSIG` 與 `/proc` 監管。
   * **跨 OS Machine 設定自動隔離**：`readTrustedMachineStringSetting()` 自動識別並忽略跨 OS 本機路徑（如 Windows `C:\...` 合成進 Linux `globalValue`），改走安全的 Linux `PATH` 探測並在 Environment Doctor 報告中透明揭露。
6. **使用者體驗操作台、命令參數邊界與防欺騙顯示（`RT-05`, `RT-07`, `RT-08`, `RT-09`）**：
   * 專屬 Activity Bar 容器（`viewsContainers.activitybar` `checkwash-lens`）與 Git Source Control 標題列一鍵預檢按鈕（`menus["scm/title"]`）完全由 VS Code 宿主宣告式渲染，維持 `activationEvents` 僅含 `onCommand:checkwashLens.*`（15 個命令）與 `onView:checkwashLens.findingsView`。
   * `checkwashLens.runEnvironmentDoctor` 僅於使用者在互動對話框親手點擊確認時才寫入 `ConfigurationTarget.Global`，忽略任何外部自動化參數；`checkwashLens.openImmutableRevision` 強制驗證 `checkwash-rev:` URI 結構與 scheme，拒絕開啟任意 `file:`／UNC URI。
   * 離線報告檢視（`viewOfflineReportFileReadOnly`）以 `O_NOFOLLOW` 檔案描述元驗證一般檔案身分與 `16 MiB` 上限，切換 repository 時自動清除殘留預覽；所有 TreeView 與 Prove 確認對話框文字皆經過 Unicode BiDi 控制字元（`U+202A..U+202E`, `U+2066..U+2069`）與 C0/C1 控制字元中和處理。

---

## 2. 原生程序樹生命週期 Broker（`CWBROKER1`）

### 2.1 Windows Native Job Object Broker（`bundled/checkwash-broker.exe`，[`native/checkwash_broker.c`](../native/checkwash_broker.c)）

1. **不可繼承之 Job Object**：
   * `CreateJobObjectW(NULL, NULL)` 建立不可繼承 Handle（透過 `GetHandleInformation` 驗證 `(flags & HANDLE_FLAG_INHERIT) == 0`）。
   * 設定 `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION`，且**不啟用** `JOB_OBJECT_LIMIT_BREAKAWAY_OK` 或 `JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK`。
2. **Suspended 建立、原子化 PID 寫入與加入 Job（`B07`, `RT-10`）**：
   * 使用 `CreateProcessW` 搭配 `CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP` 與明確的 `lpApplicationName`；`pidFile` 透過 UTF-16 `CreateFileW` + `FlushFileBuffers` + `MoveFileExW(..., MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)` 原子替換寫入。
   * 先執行 `AssignProcessToJobObject(hJob, pi.hProcess)`，成功後才呼叫 `ResumeThread(pi.hThread)`。
   * 若 `AssignProcessToJobObject` 失敗，立即對該 suspended child 呼叫 `TerminateProcess`、`WaitForSingleObject`，並查驗 `ActiveProcesses == 0` 後回傳 `status: "assign_failed", suspendedChildTerminated: true, cleanupConfirmed: true`。
3. **Host IPC 通道斷線與跨區塊 `"CANCEL"` 監測（`B08`, `RT-10`）**：
   * `stdin_watchdog_thread` 以滑動視窗緩衝持續讀取 `stdin` 管線，即使 `"CANCEL"` 被管線拆分為多次 `ReadFile` 區塊亦能即時偵測；當收到 `"CANCEL"` 或上層斷線導致 `stdin` EOF 時，立即觸發 `hAbortEvent`、執行 `TerminateJobObject(hJob, 1)` 並輪詢 `ActiveProcesses == 0`。

### 2.2 Linux Native POSIX Process-Tree Broker（`bundled/checkwash-broker-linux-x64`，[`native/checkwash_broker_posix.c`](../native/checkwash_broker_posix.c)）

1. **核心 Parent-Death 防護、原子化 `O_NOFOLLOW` PID 寫入與獨立 Process Group（`B07`, `B08`, `RT-10`）**：
   * Broker 自身與受控子程序均設定 `prctl(PR_SET_PDEATHSIG, SIGKILL)` 並檢查 `getppid()` 防止競態孤兒化；`pidFile` 以 `open(..., O_NOFOLLOW | O_CLOEXEC, 0600)` + `fsync` + `rename` 原子發布。
   * 子程序於 `execve()` 前先呼叫 `setpgid(0, 0)` 建立獨立程序群組（`pgid == childPid`），並透過 `CLOEXEC` 同步管線確認群組隔離成功後才執行目標映像檔。
2. **`poll()` 多工監測與 `/proc` 程序樹完整清空確認（`B06`, `B08`, `B10`）**：
   * 使用單執行緒非阻塞 `poll()` 同時監控上層 `stdin`（`"CANCEL"` 或 `POLLHUP`／EOF）、子程序 `stdout`／`stderr`（`16 MiB` 上限）與單調時鐘逾時。
   * 終止時對 `-pgid` 發送 `SIGKILL`（`killpg`）並遞迴掃描 `/proc/<pid>/stat`（含跨 `setsid` 脫離群組之子孫程序）反覆發送 `SIGKILL` 直至確認存活數為 `0`（`activeProcessesRemaining === 0` -> `cleanupConfirmed: true`）。

### 2.3 跨平台共同限額與清理確認優先原則（`B06`, `B10`）

1. 預設限額：Checkwash 單次 format `30s`、整組靜態掃描 `90s`、`stdout`/`stderr`/報告各 `16 MiB`。
2. 只有當平台原生 broker 確認整棵受控子孫程序樹剩餘存活數為 `0` 時，才回報 `cleanupConfirmed: true`；取消 API `cancelActiveRunAndConfirmStop()` 亦僅於 `cleanupConfirmed === true` 時回傳 `stopped: true`。
3. 所有階段（probe、Git range 解析、分析、後處理、逾時與取消競賽）之最終狀態分類一律優先檢查 `cleanupConfirmed`：只要 `cleanupConfirmed === false`，即保留 `Error` 狀態、禁止宣稱 `confirmed stopped`，並阻擋後續靜態掃描與 Prove 啟動。
