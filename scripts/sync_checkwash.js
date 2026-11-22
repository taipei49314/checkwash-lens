#!/usr/bin/env node
/**
 * scripts/sync_checkwash.js
 *
 * Zero-dependency maintainer helper to sync `bundled/upstream.json` (and optionally
 * local `bundled/checkwash.pyz`) with an official Checkwash GitHub Release.
 *
 * Usage:
 *   node scripts/sync_checkwash.js [--tag v0.13.1 | --latest] [--repo taipei49314/checkwash] [--dry-run] [--no-write-pyz]
 *
 * Guarantees:
 * - Never guesses or trusts unverified hashes: always downloads `checkwash.pyz` over HTTPS
 *   from GitHub Release hosts, validates ZIP/zipapp structure, verifies GitHub asset size
 *   and SHA-256 digest (when reported by the API), and computes exact byte size and SHA-256.
 * - Resolves exact Git tag object, peeled tag commit, and `Release-Merge:` build commit.
 * - Reports whether compile-time security pins in `src/` match `bundled/upstream.json`.
 */

"use strict";

const crypto = require("crypto");
const fs = require("fs");
const https = require("https");
const os = require("os");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const UPSTREAM_PATH = path.join(ROOT, "bundled", "upstream.json");
const PYZ_PATH = path.join(ROOT, "bundled", "checkwash.pyz");

const ALLOWED_DOWNLOAD_HOSTS = new Set([
  "github.com",
  "api.github.com",
  "objects.githubusercontent.com",
  "release-assets.githubusercontent.com",
]);
const MAX_REDIRECTS = 5;
const MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024; // 50 MiB safety ceiling
const HTTP_TIMEOUT_MS = 60_000;

function sha256Hex(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function parseArgs(argv) {
  const opts = {
    tag: null,
    latest: false,
    repo: null,
    dryRun: false,
    writePyz: true,
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--tag" && i + 1 < argv.length) {
      opts.tag = argv[++i].trim();
    } else if (a.startsWith("--tag=")) {
      opts.tag = a.slice("--tag=".length).trim();
    } else if (a === "--repo" && i + 1 < argv.length) {
      opts.repo = argv[++i].trim();
    } else if (a.startsWith("--repo=")) {
      opts.repo = a.slice("--repo=".length).trim();
    } else if (a === "--latest") {
      opts.latest = true;
    } else if (a === "--dry-run") {
      opts.dryRun = true;
    } else if (a === "--no-write-pyz") {
      opts.writePyz = false;
    } else if (a === "--help" || a === "-h") {
      console.log(
        "Usage: node scripts/sync_checkwash.js [--tag vX.Y.Z | --latest] [--repo owner/name] [--dry-run] [--no-write-pyz]"
      );
      process.exit(0);
    } else {
      throw new Error(`Unknown argument: ${a}`);
    }
  }
  return opts;
}

function getAuthHeaders(urlObj) {
  const headers = {
    "User-Agent": "checkwash-lens-sync/0.2",
  };
  if (urlObj.hostname === "api.github.com") {
    headers["Accept"] = "application/vnd.github+json";
    headers["X-GitHub-Api-Version"] = "2022-11-28";
    const token = (process.env.GITHUB_TOKEN || process.env.GH_TOKEN || "").trim();
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
  }
  return headers;
}

function httpsGetBuffer(rawUrl, redirectDepth = 0) {
  return new Promise((resolve, reject) => {
    if (redirectDepth > MAX_REDIRECTS) {
      reject(new Error(`Exceeded maximum HTTPS redirects (${MAX_REDIRECTS})`));
      return;
    }
    let urlObj;
    try {
      urlObj = new URL(rawUrl);
    } catch (err) {
      reject(new Error(`Invalid URL '${rawUrl}': ${err.message}`));
      return;
    }
    if (urlObj.protocol !== "https:") {
      reject(new Error(`Refusing non-HTTPS URL: ${rawUrl}`));
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
        headers: getAuthHeaders(urlObj),
        timeout: HTTP_TIMEOUT_MS,
      },
      (res) => {
        const status = res.statusCode || 0;
        if (status >= 300 && status < 400 && res.headers.location) {
          res.resume();
          const nextUrl = new URL(res.headers.location, urlObj).toString();
          httpsGetBuffer(nextUrl, redirectDepth + 1).then(resolve, reject);
          return;
        }
        if (status !== 200) {
          const errChunks = [];
          res.on("data", (c) => {
            if (errChunks.length < 8) errChunks.push(c);
          });
          res.on("end", () => {
            const snippet = Buffer.concat(errChunks).toString("utf8").slice(0, 300);
            reject(new Error(`HTTP ${status} fetching ${rawUrl}: ${snippet}`));
          });
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
        res.on("end", () => {
          resolve(Buffer.concat(chunks));
        });
        res.on("error", reject);
      }
    );

    req.on("timeout", () => {
      req.destroy(new Error(`Timed out after ${HTTP_TIMEOUT_MS}ms fetching ${rawUrl}`));
    });
    req.on("error", reject);
  });
}

async function fetchGitHubJson(apiPath) {
  const buf = await httpsGetBuffer(`https://api.github.com${apiPath}`);
  return JSON.parse(buf.toString("utf8"));
}

function assertValidZipAppBuffer(buf) {
  // Python zipapps either start directly with PK\x03\x04 or with a `#!` shebang followed by PK\x03\x04.
  const headSlice = buf.subarray(0, Math.min(buf.length, 512));
  const pkSig = Buffer.from([0x50, 0x4b, 0x03, 0x04]);
  if (headSlice.indexOf(pkSig) < 0) {
    throw new Error("Downloaded checkwash.pyz does not contain a valid ZIP (PK\\x03\\x04) header");
  }
}

function checkSourcePinDrift(checkwashMeta) {
  const checks = [
    {
      file: "src/core/reportJoiner.ts",
      patterns: [
        { label: "PINNED_CHECKWASH_VERSION", expected: `"${checkwashMeta.version}"` },
        { label: "PINNED_CHECKWASH_PYZ_SHA256", expected: `"${checkwashMeta.sha256}"` },
        { label: "PINNED_CHECKWASH_BUILD_COMMIT", expected: `"${checkwashMeta.artifactBuildSourceCommit}"` },
      ],
    },
    {
      file: "src/runtime/admission.ts",
      patterns: [
        { label: "EXPECTED_CHECKWASH_VERSION", expected: `"${checkwashMeta.version}"` },
        { label: "EXPECTED_CHECKWASH_BYTES", expected: String(checkwashMeta.bytes) },
        { label: "EXPECTED_CHECKWASH_SHA256", expected: `"${checkwashMeta.sha256}"` },
        { label: "EXPECTED_CHECKWASH_BUILD_COMMIT", expected: `"${checkwashMeta.artifactBuildSourceCommit}"` },
      ],
    },
    {
      file: "src/ui/diagnostics.ts",
      patterns: [
        { label: "CHECKWASH_DIAGNOSTIC_SOURCE", expected: `"Checkwash (v${checkwashMeta.version})"` },
      ],
    },
  ];

  const drift = [];
  for (const item of checks) {
    const full = path.join(ROOT, item.file);
    if (!fs.existsSync(full)) continue;
    const text = fs.readFileSync(full, "utf8");
    for (const p of item.patterns) {
      if (!text.includes(p.expected)) {
        drift.push({ file: item.file, symbol: p.label, expected: p.expected });
      }
    }
  }
  return drift;
}

async function main() {
  const opts = parseArgs(process.argv);
  const existing = fs.existsSync(UPSTREAM_PATH)
    ? JSON.parse(fs.readFileSync(UPSTREAM_PATH, "utf8"))
    : {};

  const repo = opts.repo || existing.checkwash?.repository || "taipei49314/checkwash";
  if (!/^[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/.test(repo)) {
    throw new Error(`Invalid GitHub repository slug '${repo}'`);
  }

  let release;
  if (opts.latest) {
    release = await fetchGitHubJson(`/repos/${repo}/releases/latest`);
  } else {
    const tag = opts.tag || existing.checkwash?.tag;
    if (!tag) {
      throw new Error("Specify --tag vX.Y.Z or --latest (no default tag found in bundled/upstream.json)");
    }
    release = await fetchGitHubJson(`/repos/${repo}/releases/tags/${encodeURIComponent(tag)}`);
  }

  if (release.draft || release.prerelease) {
    throw new Error(`Refusing draft/prerelease tag '${release.tag_name}'`);
  }

  const tagName = String(release.tag_name || "");
  const version = tagName.replace(/^v/, "");
  if (!/^\d+\.\d+\.\d+$/.test(version)) {
    throw new Error(`Unexpected Checkwash release tag '${tagName}' (expected vX.Y.Z)`);
  }

  const pyzAsset = (release.assets || []).find((a) => a.name === "checkwash.pyz");
  if (!pyzAsset || !pyzAsset.browser_download_url) {
    throw new Error(`Release '${tagName}' on '${repo}' does not contain a 'checkwash.pyz' asset`);
  }

  // Resolve exact Git tag object, peeled tag commit, and Release-Merge build commit
  const tagRef = await fetchGitHubJson(
    `/repos/${repo}/git/refs/tags/${encodeURIComponent(tagName)}`
  );
  let releaseTagObject = null;
  let releaseTagCommit = null;
  let artifactBuildSourceCommit = null;

  if (tagRef.object?.type === "tag") {
    releaseTagObject = tagRef.object.sha;
    const tagObj = await fetchGitHubJson(`/repos/${repo}/git/tags/${releaseTagObject}`);
    releaseTagCommit = tagObj.object?.sha || null;
    const mergeMatch = String(tagObj.message || "").match(/Release-Merge:\s*([0-9a-f]{40})\b/i);
    artifactBuildSourceCommit = mergeMatch ? mergeMatch[1].toLowerCase() : releaseTagCommit;
  } else if (tagRef.object?.type === "commit") {
    releaseTagCommit = tagRef.object.sha;
    artifactBuildSourceCommit = releaseTagCommit;
  }

  if (!releaseTagCommit || !/^[0-9a-f]{40}$/i.test(releaseTagCommit)) {
    throw new Error(`Could not resolve 40-char commit SHA for tag '${tagName}'`);
  }

  // Download checkwash.pyz and independently verify byte length, ZIP signature, and SHA-256
  const pyzBuf = await httpsGetBuffer(pyzAsset.browser_download_url);
  assertValidZipAppBuffer(pyzBuf);

  const actualBytes = pyzBuf.length;
  const actualSha256 = sha256Hex(pyzBuf);

  if (typeof pyzAsset.size === "number" && actualBytes !== pyzAsset.size) {
    throw new Error(
      `Downloaded checkwash.pyz size mismatch: got ${actualBytes} bytes, GitHub API reported ${pyzAsset.size} bytes`
    );
  }
  if (typeof pyzAsset.digest === "string" && pyzAsset.digest.startsWith("sha256:")) {
    const apiSha256 = pyzAsset.digest.slice("sha256:".length).toLowerCase();
    if (actualSha256 !== apiSha256) {
      throw new Error(
        `Downloaded checkwash.pyz SHA-256 mismatch: computed ${actualSha256}, GitHub API reported ${apiSha256}`
      );
    }
  }

  const nextUpstream = {
    schemaVersion: existing.schemaVersion || 1,
    checkwash: {
      version,
      tag: tagName,
      repository: repo,
      relativePath: "bundled/checkwash.pyz",
      bytes: actualBytes,
      sha256: actualSha256,
      downloadUrl: pyzAsset.browser_download_url,
      artifactBuildSourceCommit,
      releaseTagCommit,
      ...(releaseTagObject ? { releaseTagObject } : {}),
      findingsSchemaVersion: existing.checkwash?.findingsSchemaVersion || 2,
      sarifVersion: existing.checkwash?.sarifVersion || "2.1.0",
    },
    windowsBroker: existing.windowsBroker || {
      protocol: "CWBROKER1",
      relativePath: "bundled/checkwash-broker.exe",
      sourceRelativePath: "native/checkwash_broker.c",
    },
    linuxBroker: existing.linuxBroker || {
      protocol: "CWBROKER1",
      relativePath: "bundled/checkwash-broker-linux-x64",
      sourceRelativePath: "native/checkwash_broker_posix.c",
    },
    proveAdapter: existing.proveAdapter || {
      version: "0.1.0",
      sourceCommit: "582f1339ea48f4db48b4414648ca21316aeb0713",
      catalogueVersion: "v0.5-m2",
      generatorSha256: "67096f7340a281585aaeaf801ae0ac29c4eb1a777c358ee973f02058cc7f4e14",
    },
  };

  if (!opts.dryRun) {
    fs.mkdirSync(path.dirname(UPSTREAM_PATH), { recursive: true });
    const tmpUpstream = path.join(os.tmpdir(), `checkwash-upstream-${process.pid}.json`);
    fs.writeFileSync(tmpUpstream, JSON.stringify(nextUpstream, null, 2) + "\n", "utf8");
    fs.copyFileSync(tmpUpstream, UPSTREAM_PATH);
    fs.unlinkSync(tmpUpstream);

    if (opts.writePyz) {
      const tmpPyz = `${PYZ_PATH}.tmp.${process.pid}`;
      fs.writeFileSync(tmpPyz, pyzBuf);
      fs.renameSync(tmpPyz, PYZ_PATH);
    }
  }

  const pinDrift = checkSourcePinDrift(nextUpstream.checkwash);

  console.log(
    JSON.stringify(
      {
        ok: true,
        dryRun: opts.dryRun,
        wrotePyz: !opts.dryRun && opts.writePyz,
        upstreamFile: "bundled/upstream.json",
        checkwash: nextUpstream.checkwash,
        compileTimeSourcePinDrift: pinDrift,
      },
      null,
      2
    )
  );

  if (pinDrift.length > 0) {
    console.error(
      `NOTE: ${pinDrift.length} compile-time pin(s) in src/ differ from bundled/upstream.json (update them before compiling).`
    );
  }
}

main().catch((err) => {
  console.error(`sync_checkwash failed: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
