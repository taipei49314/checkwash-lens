#!/usr/bin/env node
/**
 * scripts/build_bundled.js
 *
 * Transparent, verifiable, zero-dependency builder for Checkwash Lens runtime artifacts:
 * 1. Reads pinned upstream source contract from `bundled/upstream.json`.
 * 2. Downloads `bundled/checkwash.pyz` from the official GitHub Release URL (or reuses an
 *    already-present copy ONLY if exact byte count and SHA-256 match) and fails closed on
 *    any hash or size mismatch.
 * 3. Compiles the platform-native `CWBROKER1` process-tree lifecycle broker directly from C
 *    source (`native/checkwash_broker.c` on Windows x64, `native/checkwash_broker_posix.c`
 *    on Linux x64), verifies binary format, scans for leaked local developer paths, and runs
 *    `--probe` to confirm broker capabilities.
 * 4. Emits `bundled/manifest.json` with exact observed byte sizes and SHA-256 digests for
 *    runtime admission verification (`src/runtime/admission.ts`) and VSIX packaging.
 *
 * Usage:
 *   node scripts/build_bundled.js [--target current|win32-x64|linux-x64] [--force-download] [--skip-probe]
 */

"use strict";

const cp = require("child_process");
const crypto = require("crypto");
const fs = require("fs");
const https = require("https");
const os = require("os");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const BUNDLED_DIR = path.join(ROOT, "bundled");
const UPSTREAM_PATH = path.join(BUNDLED_DIR, "upstream.json");
const MANIFEST_PATH = path.join(BUNDLED_DIR, "manifest.json");

const ALLOWED_DOWNLOAD_HOSTS = new Set([
  "github.com",
  "objects.githubusercontent.com",
  "release-assets.githubusercontent.com",
]);
const MAX_REDIRECTS = 5;
const MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024;
const HTTP_TIMEOUT_MS = 60_000;

function sha256Hex(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function escapeRegexLiteral(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function buildForbiddenDeveloperPathMatchers() {
  const regexes = [
    /[a-z]:[\\/]+users[\\/]+(?!public\b|default\b)[a-z0-9._-]+/i,
    /\/(?:home|users)\/(?!root\b|node\b|app\b|user\b|ubuntu\b|debian\b|vscode\b|runner\b|builder\b|tester\b)[a-z0-9._-]+/i,
    /\b(?:laptop|desktop)\x2d[a-z0-9]{4,}\b/i,
  ];
  try {
    const home = (os.homedir() || "").trim();
    if (home.length >= 6 && home !== "/root") {
      const normalizedSegs = home
        .split(/[\\/]+/)
        .filter((seg) => seg.length > 0)
        .map(escapeRegexLiteral);
      if (normalizedSegs.length >= 2) {
        const prefix = home.startsWith("/") ? "/" : "";
        regexes.push(new RegExp(prefix + normalizedSegs.join("[\\\\/]+"), "i"));
      }
    }
  } catch {
    // Ignore in restricted containers
  }
  try {
    const user = (os.userInfo().username || "").trim();
    if (
      user.length >= 3 &&
      !/^(?:root|node|app|user|ubuntu|debian|vscode|runner|builder|tester)$/i.test(user)
    ) {
      const escUser = escapeRegexLiteral(user);
      regexes.push(
        new RegExp(`[a-z]:[\\\\/]+users[\\\\/]+${escUser}|\\/(?:home|users)\\/${escUser}`, "i")
      );
    }
  } catch {
    // Ignore in UID-only containers
  }
  return regexes;
}

function assertNoDeveloperPathLeak(filePath, relLabel) {
  const rawLatin1 = fs.readFileSync(filePath).toString("latin1");
  for (const re of buildForbiddenDeveloperPathMatchers()) {
    if (re.test(rawLatin1)) {
      throw new Error(
        `Built artifact '${relLabel}' contains a hardcoded local developer path (matched ${re})`
      );
    }
  }
}

function parseArgs(argv) {
  const opts = {
    target: "current",
    forceDownload: false,
    skipProbe: false,
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--target" && i + 1 < argv.length) {
      opts.target = argv[++i].trim();
    } else if (a.startsWith("--target=")) {
      opts.target = a.slice("--target=".length).trim();
    } else if (a === "--force-download") {
      opts.forceDownload = true;
    } else if (a === "--skip-probe") {
      opts.skipProbe = true;
    } else if (a === "--help" || a === "-h") {
      console.log(
        "Usage: node scripts/build_bundled.js [--target current|win32-x64|linux-x64] [--force-download] [--skip-probe]"
      );
      process.exit(0);
    } else {
      throw new Error(`Unknown argument: ${a}`);
    }
  }
  return opts;
}

function resolveTarget(rawTarget) {
  if (rawTarget === "win32-x64" || rawTarget === "linux-x64") {
    return rawTarget;
  }
  if (rawTarget !== "current") {
    throw new Error(
      `Unsupported --target '${rawTarget}' (expected 'current', 'win32-x64', or 'linux-x64')`
    );
  }
  if (process.platform === "win32" && process.arch === "x64") {
    return "win32-x64";
  }
  if (process.platform === "linux" && process.arch === "x64") {
    return "linux-x64";
  }
  throw new Error(
    `Unsupported host platform '${process.platform}-${process.arch}' (supported targets: win32-x64, linux-x64)`
  );
}

function downloadHttpsBuffer(rawUrl, redirectDepth = 0) {
  return new Promise((resolve, reject) => {
    if (redirectDepth > MAX_REDIRECTS) {
      reject(new Error(`Exceeded maximum HTTPS redirects (${MAX_REDIRECTS})`));
      return;
    }
    let urlObj;
    try {
      urlObj = new URL(rawUrl);
    } catch (err) {
      reject(new Error(`Invalid download URL '${rawUrl}': ${err.message}`));
      return;
    }
    if (urlObj.protocol !== "https:") {
      reject(new Error(`Refusing non-HTTPS download URL: ${rawUrl}`));
      return;
    }
    if (!ALLOWED_DOWNLOAD_HOSTS.has(urlObj.hostname.toLowerCase())) {
      reject(new Error(`Refusing download from non-allowlisted host '${urlObj.hostname}'`));
      return;
    }

    const req = https.get(
      {
        hostname: urlObj.hostname,
        port: urlObj.port || 443,
        path: urlObj.pathname + urlObj.search,
        headers: {
          "User-Agent": "checkwash-lens-build/0.2",
        },
        timeout: HTTP_TIMEOUT_MS,
      },
      (res) => {
        const status = res.statusCode || 0;
        if (status >= 300 && status < 400 && res.headers.location) {
          res.resume();
          const nextUrl = new URL(res.headers.location, urlObj).toString();
          downloadHttpsBuffer(nextUrl, redirectDepth + 1).then(resolve, reject);
          return;
        }
        if (status !== 200) {
          res.resume();
          reject(new Error(`HTTP ${status} downloading ${rawUrl}`));
          return;
        }
        const chunks = [];
        let total = 0;
        res.on("data", (chunk) => {
          total += chunk.length;
          if (total > MAX_DOWNLOAD_BYTES) {
            req.destroy();
            reject(new Error(`Download exceeded safety limit (${MAX_DOWNLOAD_BYTES} bytes)`));
            return;
          }
          chunks.push(chunk);
        });
        res.on("end", () => resolve(Buffer.concat(chunks)));
        res.on("error", reject);
      }
    );

    req.on("timeout", () => {
      req.destroy(new Error(`Timed out after ${HTTP_TIMEOUT_MS}ms downloading ${rawUrl}`));
    });
    req.on("error", reject);
  });
}

async function ensureVerifiedCheckwashPyz(upstreamCheckwash, forceDownload) {
  const pyzPath = path.join(ROOT, upstreamCheckwash.relativePath);
  const expectedBytes = upstreamCheckwash.bytes;
  const expectedSha256 = String(upstreamCheckwash.sha256 || "").toLowerCase();

  if (!Number.isInteger(expectedBytes) || expectedBytes <= 0 || !/^[0-9a-f]{64}$/.test(expectedSha256)) {
    throw new Error("bundled/upstream.json checkwash bytes or sha256 pin is invalid");
  }

  if (!forceDownload && fs.existsSync(pyzPath)) {
    const existingBuf = fs.readFileSync(pyzPath);
    const existingSha = sha256Hex(existingBuf);
    if (existingBuf.length === expectedBytes && existingSha === expectedSha256) {
      return {
        status: "reused_verified",
        bytes: existingBuf.length,
        sha256: existingSha,
      };
    }
  }

  const downloaded = await downloadHttpsBuffer(upstreamCheckwash.downloadUrl);
  const actualBytes = downloaded.length;
  const actualSha = sha256Hex(downloaded);

  // Fail closed on any size or SHA-256 mismatch before writing the target artifact.
  if (actualBytes !== expectedBytes || actualSha !== expectedSha256) {
    throw new Error(
      `Fail-closed checkwash.pyz integrity mismatch from ${upstreamCheckwash.downloadUrl}: ` +
        `got ${actualBytes} bytes (sha256=${actualSha}), expected ${expectedBytes} bytes (sha256=${expectedSha256})`
    );
  }

  fs.mkdirSync(path.dirname(pyzPath), { recursive: true });
  const tmpPath = `${pyzPath}.download.${process.pid}`;
  fs.writeFileSync(tmpPath, downloaded);
  try {
    fs.renameSync(tmpPath, pyzPath);
  } catch (err) {
    try {
      fs.unlinkSync(tmpPath);
    } catch {
      // ignore
    }
    throw err;
  }

  return {
    status: "downloaded_verified",
    bytes: actualBytes,
    sha256: actualSha,
  };
}

function commandExists(cmd) {
  const probeArgs = cmd.toLowerCase() === "cl" || cmd.toLowerCase() === "cl.exe" ? [] : ["--version"];
  const res = cp.spawnSync(cmd, probeArgs, {
    cwd: ROOT,
    stdio: "ignore",
    windowsHide: true,
  });
  return !res.error;
}

function selectCompiler(target) {
  const override = (process.env.CW_CC || process.env.CC || "").trim();
  if (override) {
    return override;
  }
  const candidates =
    target === "win32-x64"
      ? ["gcc", "clang", "cl"]
      : ["gcc", "cc", "clang"];
  for (const cand of candidates) {
    if (commandExists(cand)) {
      return cand;
    }
  }
  throw new Error(
    `No supported C compiler found for ${target} (tried: ${candidates.join(", ")}; override via CW_CC or CC)`
  );
}

function isMsvcCompiler(cc) {
  const base = path.basename(cc).toLowerCase();
  return base === "cl" || base === "cl.exe";
}

function hasPeHeader(filePath) {
  try {
    const fd = fs.openSync(filePath, "r");
    const buf = Buffer.alloc(2);
    const n = fs.readSync(fd, buf, 0, 2, 0);
    fs.closeSync(fd);
    return n === 2 && buf[0] === 0x4d && buf[1] === 0x5a;
  } catch {
    return false;
  }
}

function hasElfHeader(filePath) {
  try {
    const fd = fs.openSync(filePath, "r");
    const buf = Buffer.alloc(4);
    const n = fs.readSync(fd, buf, 0, 4, 0);
    fs.closeSync(fd);
    return n === 4 && buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46;
  } catch {
    return false;
  }
}

function compileBroker(target, brokerSpec) {
  const srcRel = brokerSpec.sourceRelativePath;
  const outRel = brokerSpec.relativePath;
  const srcFull = path.join(ROOT, srcRel);
  const outFull = path.join(ROOT, outRel);

  if (!fs.existsSync(srcFull)) {
    throw new Error(`Missing broker C source file: ${srcRel}`);
  }
  fs.mkdirSync(path.dirname(outFull), { recursive: true });

  const cc = selectCompiler(target);
  const rootPosix = ROOT.replace(/\\/g, "/");
  let args;
  let tmpObjDir = null;

  if (target === "win32-x64") {
    if (isMsvcCompiler(cc)) {
      tmpObjDir = fs.mkdtempSync(path.join(os.tmpdir(), "cw-broker-obj-"));
      args = [
        "/nologo",
        "/O2",
        "/W3",
        "/MT",
        `/Fo${tmpObjDir}${path.sep}`,
        `/Fe:${outRel.replace(/\//g, "\\")}`,
        srcRel.replace(/\//g, "\\"),
        "/link",
        "kernel32.lib",
      ];
    } else {
      args = [
        "-O2",
        "-Wall",
        "-Wextra",
        "-s",
        "-fno-ident",
        `-ffile-prefix-map=${ROOT}=.`,
        `-ffile-prefix-map=${rootPosix}=.`,
        "-static-libgcc",
        "-o",
        outRel,
        srcRel,
        "-lkernel32",
      ];
    }
  } else {
    args = [
      "-O2",
      "-Wall",
      "-Wextra",
      "-pthread",
      "-s",
      "-fno-ident",
      `-ffile-prefix-map=${ROOT}=.`,
      "-o",
      outRel,
      srcRel,
    ];
  }

  const res = cp.spawnSync(cc, args, {
    cwd: ROOT,
    encoding: "utf8",
    windowsHide: true,
  });

  if (tmpObjDir) {
    try {
      fs.rmSync(tmpObjDir, { recursive: true, force: true });
    } catch {
      // best-effort cleanup
    }
  }

  if (res.error || res.status !== 0) {
    const detail = res.error ? res.error.message : (res.stderr || res.stdout || "").trim();
    throw new Error(`Broker compilation failed (${cc} ${args.join(" ")}): ${detail}`);
  }

  if (target === "linux-x64") {
    fs.chmodSync(outFull, 0o755);
    if (!hasElfHeader(outFull)) {
      throw new Error(`Compiled Linux broker '${outRel}' does not have a valid ELF header`);
    }
  } else {
    if (!hasPeHeader(outFull)) {
      throw new Error(`Compiled Windows broker '${outRel}' does not have a valid PE (MZ) header`);
    }
  }

  assertNoDeveloperPathLeak(outFull, outRel);

  const buf = fs.readFileSync(outFull);
  return {
    compiler: cc,
    relativePath: outRel,
    bytes: buf.length,
    sha256: sha256Hex(buf),
  };
}

function probeCompiledBroker(brokerFullPath, expectedProtocol) {
  const res = cp.spawnSync(brokerFullPath, ["--probe"], {
    cwd: os.tmpdir(),
    encoding: "utf8",
    timeout: 5000,
    windowsHide: true,
  });
  if (res.error || res.status !== 0) {
    const detail = res.error ? res.error.message : (res.stderr || res.stdout || "").trim();
    throw new Error(`Compiled broker --probe failed (exit=${res.status}): ${detail}`);
  }
  const parsed = JSON.parse((res.stdout || "").trim());
  if (
    parsed.ok !== true ||
    parsed.protocol !== expectedProtocol ||
    parsed.nonInheritableJobHandle !== true ||
    parsed.killOnJobClose !== true ||
    parsed.breakawayAllowed !== false
  ) {
    throw new Error(`Compiled broker --probe returned unexpected capabilities: ${res.stdout.trim()}`);
  }
  return parsed;
}

function buildBrokerManifestEntryIfPresent(spec, validatorFn) {
  if (!spec || !spec.relativePath) return undefined;
  const full = path.join(ROOT, spec.relativePath);
  if (!fs.existsSync(full) || !validatorFn(full)) {
    return undefined;
  }
  const buf = fs.readFileSync(full);
  return {
    protocol: spec.protocol,
    relativePath: spec.relativePath,
    sourceRelativePath: spec.sourceRelativePath,
    bytes: buf.length,
    sha256: sha256Hex(buf),
  };
}

async function main() {
  const opts = parseArgs(process.argv);
  const target = resolveTarget(opts.target);

  if (!fs.existsSync(UPSTREAM_PATH)) {
    throw new Error("Missing bundled/upstream.json — cannot build bundled artifacts");
  }
  const upstream = JSON.parse(fs.readFileSync(UPSTREAM_PATH, "utf8"));
  if (!upstream || !upstream.checkwash || !upstream.windowsBroker || !upstream.linuxBroker) {
    throw new Error("bundled/upstream.json is missing required checkwash or broker definitions");
  }

  // 1. Download (or reuse verified) checkwash.pyz with fail-closed SHA-256 enforcement
  const pyzResult = await ensureVerifiedCheckwashPyz(upstream.checkwash, opts.forceDownload);

  // 2. Compile target platform native broker from C source
  const targetBrokerSpec =
    target === "win32-x64" ? upstream.windowsBroker : upstream.linuxBroker;
  const brokerBuild = compileBroker(target, targetBrokerSpec);

  // 3. Probe freshly compiled broker when executing on the matching host OS
  let probeResult = null;
  const matchesHostOs =
    (target === "win32-x64" && process.platform === "win32") ||
    (target === "linux-x64" && process.platform === "linux");
  if (!opts.skipProbe && matchesHostOs) {
    probeResult = probeCompiledBroker(
      path.join(ROOT, targetBrokerSpec.relativePath),
      targetBrokerSpec.protocol
    );
  }

  // 4. Generate bundled/manifest.json with exact live hashes
  const windowsBrokerEntry = buildBrokerManifestEntryIfPresent(upstream.windowsBroker, hasPeHeader);
  const linuxBrokerEntry = buildBrokerManifestEntryIfPresent(upstream.linuxBroker, hasElfHeader);

  if (target === "win32-x64" && !windowsBrokerEntry) {
    throw new Error("Windows broker entry missing after build");
  }
  if (target === "linux-x64" && !linuxBrokerEntry) {
    throw new Error("Linux broker entry missing after build");
  }

  const manifest = {
    schemaVersion: upstream.schemaVersion || 1,
    checkwash: {
      version: upstream.checkwash.version,
      relativePath: upstream.checkwash.relativePath,
      bytes: pyzResult.bytes,
      sha256: pyzResult.sha256,
      downloadUrl: upstream.checkwash.downloadUrl,
      artifactBuildSourceCommit: upstream.checkwash.artifactBuildSourceCommit,
      releaseTagCommit: upstream.checkwash.releaseTagCommit,
      ...(upstream.checkwash.releaseTagObject
        ? { releaseTagObject: upstream.checkwash.releaseTagObject }
        : {}),
      findingsSchemaVersion: upstream.checkwash.findingsSchemaVersion,
      sarifVersion: upstream.checkwash.sarifVersion,
    },
    ...(windowsBrokerEntry ? { windowsBroker: windowsBrokerEntry } : {}),
    ...(linuxBrokerEntry ? { linuxBroker: linuxBrokerEntry } : {}),
    proveAdapter: upstream.proveAdapter,
  };

  const tmpManifest = `${MANIFEST_PATH}.tmp.${process.pid}`;
  fs.writeFileSync(tmpManifest, JSON.stringify(manifest, null, 2) + "\n", "utf8");
  fs.renameSync(tmpManifest, MANIFEST_PATH);

  console.log(
    JSON.stringify(
      {
        ok: true,
        target,
        checkwash: {
          version: manifest.checkwash.version,
          ...pyzResult,
        },
        broker: brokerBuild,
        brokerProbe: probeResult,
        manifestPath: "bundled/manifest.json",
        brokersInManifest: [
          ...(windowsBrokerEntry ? ["win32-x64"] : []),
          ...(linuxBrokerEntry ? ["linux-x64"] : []),
        ],
      },
      null,
      2
    )
  );
}

main().catch((err) => {
  console.error(`build_bundled failed: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
