/**
 * runtime/windowsBroker.ts
 *
 * Node bridge to bundled/checkwash-broker.exe (Windows Job Object) and
 * bundled/checkwash-broker-linux-x64 (Linux PR_SET_CHILD_SUBREAPER + PGID + /proc)
 * speaking the shared CWBROKER1 protocol.
 * This is the ONLY module in the codebase permitted to call child_process.spawn.
 * Never uses shell: true.
 *
 * Enforces Rev 3 §7.3 & §7.4 (B05, B06, B07, B08, B09, B10):
 * - Keeps broker stdin open as the Extension Host life-support channel; if the
 *   Extension Host crashes or reloads, stdin EOF triggers immediate Job Object teardown.
 * - Sends "CANCEL\n" over stdin when cancellation is requested.
 * - Receives raw stdout/stderr bytes via base64 and validates strict UTF-8.
 * - Reports cleanupConfirmed only when the broker confirms ActiveProcesses === 0.
 */

import { spawn } from "child_process";
import { ValidationResult } from "../core/checkwashSchema";
import { decodeStrictUtf8 } from "../core/sourceIdentity";

export interface BrokerProbeResponse {
  ok: boolean;
  protocol?: string;
  nonInheritableJobHandle?: boolean;
  killOnJobClose?: boolean;
  breakawayAllowed?: boolean;
  error?: string;
}

export interface BrokerLaunchRequest {
  brokerExecutablePath: string;
  executable: string;
  args: string[];
  cwd: string;
  env: Record<string, string>;
  timeoutMs: number;
  maxStdoutBytes: number;
  maxStderrBytes: number;
  simulateAssignFailure?: boolean;
  pidTrackFilePath?: string;
}

export type BrokerRunStatus =
  | "completed"
  | "cancelled"
  | "timed_out"
  | "stdout_overflow"
  | "stderr_overflow"
  | "assign_failed"
  | "spawn_failed"
  | "broker_error";

export interface BrokerLaunchOutcome {
  status: BrokerRunStatus;
  exitCode: number | null;
  childPid: number | null;
  stdoutRaw: Buffer;
  stderrRaw: Buffer;
  stdoutUtf8Valid: boolean;
  stderrUtf8Valid: boolean;
  stdoutText: string;
  stderrText: string;
  cleanupConfirmed: boolean;
  activeProcessesRemaining: number;
  suspendedChildTerminated?: boolean;
  win32Error?: number;
  brokerErrorDetail?: string;
}

let totalBrokerSpawnCount = 0;

export function getTotalBrokerSpawnCount(): number {
  return totalBrokerSpawnCount;
}

export function resetTotalBrokerSpawnCountForTests(): void {
  totalBrokerSpawnCount = 0;
}

function encodeNulSeparatedBase64(items: string[]): string {
  if (items.length === 0) {
    return "";
  }
  const buffers: Buffer[] = [];
  for (const item of items) {
    buffers.push(Buffer.from(item, "utf-8"));
    buffers.push(Buffer.from([0]));
  }
  return Buffer.concat(buffers).toString("base64");
}

export function buildBrokerRequestLine(req: BrokerLaunchRequest): string {
  const flags = req.simulateAssignFailure ? 1 : 0;
  const exeB64 = Buffer.from(req.executable, "utf-8").toString("base64");
  const cwdB64 = Buffer.from(req.cwd, "utf-8").toString("base64");
  const pidFileB64 = Buffer.from(req.pidTrackFilePath ?? "", "utf-8").toString("base64");
  const fullArgv = [req.executable, ...req.args];
  const argsB64 = encodeNulSeparatedBase64(fullArgv);
  const envEntries = Object.entries(req.env).map(([k, v]) => `${k}=${v}`);
  const envB64 = encodeNulSeparatedBase64(envEntries);

  return [
    "CWBROKER1",
    String(req.timeoutMs),
    String(req.maxStdoutBytes),
    String(req.maxStderrBytes),
    String(flags),
    exeB64,
    cwdB64,
    pidFileB64,
    argsB64,
    envB64,
  ].join("\t") + "\n";
}

export async function probeWindowsBroker(
  brokerExecutablePath: string
): Promise<ValidationResult<BrokerProbeResponse>> {
  return new Promise((resolve) => {
    totalBrokerSpawnCount++;
    let stdoutText = "";
    let settled = false;

    const proc = spawn(brokerExecutablePath, ["--probe"], {
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });

    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        try {
          proc.kill();
        } catch {
          // ignore
        }
        resolve({ ok: false, error: "Broker probe timed out" });
      }
    }, 5000);

    proc.stdout.on("data", (chunk: Buffer) => {
      stdoutText += chunk.toString("utf-8");
    });

    proc.on("error", (err) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        resolve({ ok: false, error: `Failed to spawn broker: ${err.message}` });
      }
    });

    proc.on("close", (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (code !== 0) {
        resolve({ ok: false, error: `Broker probe exited with code ${String(code)}` });
        return;
      }
      try {
        const parsed = JSON.parse(stdoutText.trim()) as BrokerProbeResponse;
        if (
          !parsed.ok ||
          parsed.protocol !== "CWBROKER1" ||
          parsed.nonInheritableJobHandle !== true ||
          parsed.killOnJobClose !== true ||
          parsed.breakawayAllowed !== false
        ) {
          resolve({
            ok: false,
            error: `Broker probe returned insufficient capabilities: ${stdoutText.trim()}`,
          });
          return;
        }
        resolve({ ok: true, value: parsed });
      } catch (err) {
        resolve({
          ok: false,
          error: `Broker probe returned invalid JSON: ${err instanceof Error ? err.message : String(err)}`,
        });
      }
    });
  });
}

export async function executeViaWindowsBroker(
  req: BrokerLaunchRequest,
  abortSignal?: AbortSignal
): Promise<BrokerLaunchOutcome> {
  // If already aborted before launching the broker, return a clean cancelled outcome
  // with zero child processes spawned and cleanupConfirmed: true (Round 2 Issue #3).
  if (abortSignal?.aborted) {
    return {
      status: "cancelled",
      exitCode: null,
      childPid: null,
      stdoutRaw: Buffer.alloc(0),
      stderrRaw: Buffer.alloc(0),
      stdoutUtf8Valid: true,
      stderrUtf8Valid: true,
      stdoutText: "",
      stderrText: "",
      cleanupConfirmed: true,
      activeProcessesRemaining: 0,
    };
  }

  let reqLine: string;
  try {
    reqLine = buildBrokerRequestLine(req);
  } catch (err) {
    return {
      status: "broker_error",
      exitCode: null,
      childPid: null,
      stdoutRaw: Buffer.alloc(0),
      stderrRaw: Buffer.alloc(0),
      stdoutUtf8Valid: true,
      stderrUtf8Valid: true,
      stdoutText: "",
      stderrText: "",
      cleanupConfirmed: false,
      activeProcessesRemaining: -1,
      brokerErrorDetail: `Failed to build broker request: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  return new Promise((resolve) => {
    totalBrokerSpawnCount++;
    let settled = false;
    let requestWriteFailed = false;
    let stdinErrorMessage: string | null = null;
    const outChunks: Buffer[] = [];
    const errChunks: Buffer[] = [];

    const recordStdinError = (context: string, err: Error | null | undefined) => {
      if (!err) return;
      const msg = `${context}: ${err.message || String(err)}`;
      if (stdinErrorMessage === null) {
        stdinErrorMessage = msg;
      } else if (!stdinErrorMessage.includes(msg)) {
        stdinErrorMessage = `${stdinErrorMessage}; ${msg}`;
      }
    };

    const appendStdinErrorDetail = (baseDetail?: string): string | undefined => {
      if (!stdinErrorMessage) {
        return baseDetail;
      }
      if (!baseDetail || baseDetail.trim().length === 0) {
        return stdinErrorMessage;
      }
      return `${baseDetail} [stdin: ${stdinErrorMessage}]`;
    };

    const proc = spawn(req.brokerExecutablePath, [], {
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    });

    if (proc.stdin) {
      proc.stdin.on("error", (err: Error) => {
        recordStdinError("Broker stdin stream error", err);
      });
    }

    const onAbort = () => {
      try {
        if (proc.stdin && !proc.stdin.destroyed && proc.stdin.writable) {
          proc.stdin.write("CANCEL\n", (err) => {
            if (err) {
              recordStdinError("Failed to write CANCEL to broker stdin", err);
            }
          });
        } else {
          recordStdinError(
            "Failed to write CANCEL to broker stdin",
            new Error("stdin already closed or destroyed")
          );
        }
      } catch (err) {
        recordStdinError(
          "Failed to write CANCEL to broker stdin",
          err instanceof Error ? err : new Error(String(err))
        );
      }
    };

    const finishOnce = (outcome: BrokerLaunchOutcome) => {
      if (settled) return;
      settled = true;
      if (abortSignal) {
        abortSignal.removeEventListener("abort", onAbort);
      }
      resolve(outcome);
    };

    proc.stdout.on("data", (chunk: Buffer) => {
      outChunks.push(chunk);
    });

    proc.stderr.on("data", (chunk: Buffer) => {
      errChunks.push(chunk);
    });

    proc.on("error", (err) => {
      try {
        if (proc.stdin && !proc.stdin.destroyed) {
          proc.stdin.destroy();
        }
      } catch {
        // ignore
      }
      finishOnce({
        status: "broker_error",
        exitCode: null,
        childPid: null,
        stdoutRaw: Buffer.alloc(0),
        stderrRaw: Buffer.alloc(0),
        stdoutUtf8Valid: true,
        stderrUtf8Valid: true,
        stdoutText: "",
        stderrText: "",
        cleanupConfirmed: false,
        activeProcessesRemaining: -1,
        brokerErrorDetail: appendStdinErrorDetail(`Broker spawn error: ${err.message}`),
      });
    });

    proc.on("close", (code, signal) => {
      try {
        if (proc.stdin && !proc.stdin.destroyed) {
          proc.stdin.destroy();
        }
      } catch {
        // ignore
      }

      const rawBrokerOut = Buffer.concat(outChunks).toString("utf-8").trim();
      const rawBrokerErr = Buffer.concat(errChunks).toString("utf-8").trim();

      if (rawBrokerOut.length === 0) {
        const sigInfo = signal ? ` (signal=${signal})` : "";
        const errSuffix = rawBrokerErr.length > 0 ? `: ${rawBrokerErr}` : "";
        finishOnce({
          status: "broker_error",
          exitCode: null,
          childPid: null,
          stdoutRaw: Buffer.alloc(0),
          stderrRaw: Buffer.alloc(0),
          stdoutUtf8Valid: true,
          stderrUtf8Valid: true,
          stdoutText: "",
          stderrText: "",
          cleanupConfirmed: false,
          activeProcessesRemaining: -1,
          brokerErrorDetail: appendStdinErrorDetail(
            `Broker exited with code ${String(code)}${sigInfo}${errSuffix}`
          ),
        });
        return;
      }

      try {
        const packet = JSON.parse(rawBrokerOut) as {
          status: string;
          exitCode?: number;
          childPid?: number;
          stdoutBytes?: number;
          stderrBytes?: number;
          cleanupConfirmed?: boolean;
          activeProcessesRemaining?: number;
          suspendedChildTerminated?: boolean;
          win32Error?: number;
          stdoutB64?: string;
          stderrB64?: string;
          error?: string;
        };

        const stdoutRaw = packet.stdoutB64 ? Buffer.from(packet.stdoutB64, "base64") : Buffer.alloc(0);
        const stderrRaw = packet.stderrB64 ? Buffer.from(packet.stderrB64, "base64") : Buffer.alloc(0);

        const outUtf8 = decodeStrictUtf8(stdoutRaw);
        const errUtf8 = decodeStrictUtf8(stderrRaw);

        const validStatuses = new Set<BrokerRunStatus>([
          "completed",
          "cancelled",
          "timed_out",
          "stdout_overflow",
          "stderr_overflow",
          "assign_failed",
          "spawn_failed",
          "broker_error",
        ]);
        const parsedStatus: BrokerRunStatus = validStatuses.has(packet.status as BrokerRunStatus)
          ? (packet.status as BrokerRunStatus)
          : "broker_error";

        if (requestWriteFailed) {
          finishOnce({
            status: "broker_error",
            exitCode: typeof packet.exitCode === "number" ? packet.exitCode : null,
            childPid: typeof packet.childPid === "number" ? packet.childPid : null,
            stdoutRaw,
            stderrRaw,
            stdoutUtf8Valid: outUtf8.ok,
            stderrUtf8Valid: errUtf8.ok,
            stdoutText: outUtf8.ok ? outUtf8.value : stdoutRaw.toString("utf-8"),
            stderrText: errUtf8.ok ? errUtf8.value : stderrRaw.toString("utf-8"),
            cleanupConfirmed: false,
            activeProcessesRemaining:
              typeof packet.activeProcessesRemaining === "number"
                ? packet.activeProcessesRemaining
                : -1,
            suspendedChildTerminated: packet.suspendedChildTerminated,
            win32Error: packet.win32Error,
            brokerErrorDetail: appendStdinErrorDetail(
              packet.error ?? "Failed to write complete request to broker stdin"
            ),
          });
          return;
        }

        finishOnce({
          status: parsedStatus,
          exitCode: typeof packet.exitCode === "number" ? packet.exitCode : null,
          childPid: typeof packet.childPid === "number" ? packet.childPid : null,
          stdoutRaw,
          stderrRaw,
          stdoutUtf8Valid: outUtf8.ok,
          stderrUtf8Valid: errUtf8.ok,
          stdoutText: outUtf8.ok ? outUtf8.value : stdoutRaw.toString("utf-8"),
          stderrText: errUtf8.ok ? errUtf8.value : stderrRaw.toString("utf-8"),
          cleanupConfirmed: packet.cleanupConfirmed === true,
          activeProcessesRemaining:
            typeof packet.activeProcessesRemaining === "number" ? packet.activeProcessesRemaining : -1,
          suspendedChildTerminated: packet.suspendedChildTerminated,
          win32Error: packet.win32Error,
          brokerErrorDetail: appendStdinErrorDetail(packet.error),
        });
      } catch (err) {
        finishOnce({
          status: "broker_error",
          exitCode: null,
          childPid: null,
          stdoutRaw: Buffer.alloc(0),
          stderrRaw: Buffer.alloc(0),
          stdoutUtf8Valid: true,
          stderrUtf8Valid: true,
          stdoutText: "",
          stderrText: "",
          cleanupConfirmed: false,
          activeProcessesRemaining: -1,
          brokerErrorDetail: appendStdinErrorDetail(
            `Invalid JSON from broker (exit=${String(code)}): ${err instanceof Error ? err.message : String(err)}`
          ),
        });
      }
    });

    // ALWAYS write the CWBROKER1 request line FIRST before registering abort or sending CANCEL\n.
    // Never resolve prematurely on synchronous/asynchronous stdin write failure before proc closes.
    try {
      if (!proc.stdin || proc.stdin.destroyed || !proc.stdin.writable) {
        requestWriteFailed = true;
        recordStdinError(
          "Failed to write request to broker stdin",
          new Error("stdin is not writable")
        );
      } else {
        proc.stdin.write(reqLine, (err) => {
          if (err) {
            requestWriteFailed = true;
            recordStdinError("Failed to write request to broker stdin", err);
          }
        });
      }
    } catch (err) {
      requestWriteFailed = true;
      recordStdinError(
        "Failed to write request to broker stdin",
        err instanceof Error ? err : new Error(String(err))
      );
    }

    if (abortSignal) {
      if (abortSignal.aborted) {
        onAbort();
      } else {
        abortSignal.addEventListener("abort", onAbort, { once: true });
      }
    }
  });
}
