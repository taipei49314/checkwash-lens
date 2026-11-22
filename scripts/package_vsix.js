#!/usr/bin/env node
/**
 * scripts/package_vsix.js
 *
 * Deterministic, zero-dependency VSIX (Open Packaging Conventions ZIP) packager
 * and security/hygiene auditor for Checkwash Lens (`win32-x64` and `linux-x64`).
 *
 * Enforces:
 * 1. Exact SHA-256 and byte size verification of `bundled/checkwash.pyz`,
 *    `bundled/checkwash-broker.exe`, and `bundled/checkwash-broker-linux-x64`.
 * 2. Platform-specific packaging (`win32-x64` carries only `checkwash-broker.exe` and `"os": ["win32"]`;
 *    `linux-x64` carries only `checkwash-broker-linux-x64` with UNIX `0755` executable mode and `"os": ["linux"]`).
 * 3. Strict production file inclusion (`package.json`, `README.md`, `LICENSE`, `media/`, `bundled/`, `docs/`,
 *    and production `dist/*.js` excluding `dist/test/` and source maps).
 * 4. Zero leakage of test suites (`dist/test`), TypeScript sources (`src`), fixtures, evidence, native C sources,
 *    or local developer filesystem paths (`C:\Users\<user>`, `/home/<user>`) and host identifiers inside distributable `.vsix` archives.
 */

"use strict";

const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const zlib = require("zlib");

const ROOT = path.resolve(__dirname, "..");

const CRC32_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[i] = c >>> 0;
  }
  return table;
})();

function crc32(buf) {
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    crc = CRC32_TABLE[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function sha256Hex(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function escapeXml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function collectFilesRecursive(baseDir, relPrefix = "") {
  const entries = fs.readdirSync(baseDir, { withFileTypes: true });
  entries.sort((a, b) => a.name.localeCompare(b.name));
  const out = [];
  for (const entry of entries) {
    const rel = relPrefix ? `${relPrefix}/${entry.name}` : entry.name;
    const full = path.join(baseDir, entry.name);
    if (entry.isDirectory()) {
      out.push(...collectFilesRecursive(full, rel));
    } else if (entry.isFile()) {
      out.push({ rel, full });
    }
  }
  return out;
}

function buildZipArchive(entries, useUnixPermissions) {
  // Deterministic DOS timestamp: 2026-01-01 00:00:00
  const dosTime = 0x0000;
  const dosDate = ((2026 - 1980) << 9) | (1 << 5) | 1;

  const localParts = [];
  const centralParts = [];
  let offset = 0;

  for (const item of entries) {
    const nameBuf = Buffer.from(item.zipPath, "utf8");
    const rawBuf = item.data;
    const crc = crc32(rawBuf);
    const deflated = zlib.deflateRawSync(rawBuf, { level: 9 });
    const useDeflate = deflated.length < rawBuf.length;
    const method = useDeflate ? 8 : 0;
    const payload = useDeflate ? deflated : rawBuf;

    // UTF-8 filename flag (bit 11 = 0x0800)
    const flags = 0x0800;

    const localHeader = Buffer.alloc(30);
    localHeader.writeUInt32LE(0x04034b50, 0); // signature
    localHeader.writeUInt16LE(20, 4); // version needed (2.0)
    localHeader.writeUInt16LE(flags, 6);
    localHeader.writeUInt16LE(method, 8);
    localHeader.writeUInt16LE(dosTime, 10);
    localHeader.writeUInt16LE(dosDate, 12);
    localHeader.writeUInt32LE(crc, 14);
    localHeader.writeUInt32LE(payload.length, 18);
    localHeader.writeUInt32LE(rawBuf.length, 22);
    localHeader.writeUInt16LE(nameBuf.length, 26);
    localHeader.writeUInt16LE(0, 28); // extra len

    localParts.push(localHeader, nameBuf, payload);

    const versionMadeBy = useUnixPermissions ? ((3 << 8) | 20) : 20;
    const unixMode = item.executable ? 0o100755 : 0o100644;
    const externalAttrs = useUnixPermissions ? ((unixMode << 16) >>> 0) : 0;

    const centralHeader = Buffer.alloc(46);
    centralHeader.writeUInt32LE(0x02014b50, 0); // signature
    centralHeader.writeUInt16LE(versionMadeBy, 4); // version made by
    centralHeader.writeUInt16LE(20, 6); // version needed
    centralHeader.writeUInt16LE(flags, 8);
    centralHeader.writeUInt16LE(method, 10);
    centralHeader.writeUInt16LE(dosTime, 12);
    centralHeader.writeUInt16LE(dosDate, 14);
    centralHeader.writeUInt32LE(crc, 16);
    centralHeader.writeUInt32LE(payload.length, 20);
    centralHeader.writeUInt32LE(rawBuf.length, 24);
    centralHeader.writeUInt16LE(nameBuf.length, 28);
    centralHeader.writeUInt16LE(0, 30); // extra len
    centralHeader.writeUInt16LE(0, 32); // comment len
    centralHeader.writeUInt16LE(0, 34); // disk start
    centralHeader.writeUInt16LE(0, 36); // internal attrs
    centralHeader.writeUInt32LE(externalAttrs, 38); // external attrs
    centralHeader.writeUInt32LE(offset, 42); // local header offset

    centralParts.push(centralHeader, nameBuf);
    offset += localHeader.length + nameBuf.length + payload.length;
  }

  const centralDirBuf = Buffer.concat(centralParts);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(centralDirBuf.length, 12);
  eocd.writeUInt32LE(offset, 16);
  eocd.writeUInt16LE(0, 20);

  return Buffer.concat([...localParts, centralDirBuf, eocd]);
}

function readZipCentralDirectory(zipBuf) {
  let eocdOffset = -1;
  for (let i = zipBuf.length - 22; i >= Math.max(0, zipBuf.length - 65557); i--) {
    if (zipBuf.readUInt32LE(i) === 0x06054b50) {
      eocdOffset = i;
      break;
    }
  }
  if (eocdOffset < 0) {
    throw new Error("Invalid VSIX archive: EOCD signature not found");
  }
  const totalEntries = zipBuf.readUInt16LE(eocdOffset + 10);
  const cdOffset = zipBuf.readUInt32LE(eocdOffset + 16);
  const items = [];
  let cursor = cdOffset;
  for (let i = 0; i < totalEntries; i++) {
    if (zipBuf.readUInt32LE(cursor) !== 0x02014b50) {
      throw new Error(`Invalid Central Directory header at offset ${cursor}`);
    }
    const versionMadeBy = zipBuf.readUInt16LE(cursor + 4);
    const externalAttrs = zipBuf.readUInt32LE(cursor + 38);
    const nameLen = zipBuf.readUInt16LE(cursor + 28);
    const extraLen = zipBuf.readUInt16LE(cursor + 30);
    const commentLen = zipBuf.readUInt16LE(cursor + 32);
    const name = zipBuf.subarray(cursor + 46, cursor + 46 + nameLen).toString("utf8");
    items.push({ name, versionMadeBy, externalAttrs });
    cursor += 46 + nameLen + extraLen + commentLen;
  }
  return items;
}

function parseTargetPlatforms(argv) {
  let targetArg = "all";
  for (let i = 2; i < argv.length; i++) {
    if (argv[i] === "--target" && i + 1 < argv.length) {
      targetArg = argv[++i];
    } else if (argv[i].startsWith("--target=")) {
      targetArg = argv[i].slice("--target=".length);
    }
  }
  if (targetArg === "all") {
    return ["win32-x64", "linux-x64"];
  }
  if (targetArg === "win32-x64" || targetArg === "linux-x64") {
    return [targetArg];
  }
  throw new Error(`Unsupported --target '${targetArg}' (expected 'win32-x64', 'linux-x64', or 'all')`);
}

function verifyPinnedFile(relPath, expectedBytes, expectedSha256) {
  const full = path.join(ROOT, relPath);
  if (!fs.existsSync(full)) {
    throw new Error(`Missing pinned bundled artifact: ${relPath}`);
  }
  const buf = fs.readFileSync(full);
  const hash = sha256Hex(buf);
  if (buf.length !== expectedBytes || hash !== expectedSha256.toLowerCase()) {
    throw new Error(
      `${relPath} integrity mismatch: bytes=${buf.length} (expected ${expectedBytes}), sha256=${hash} (expected ${expectedSha256})`
    );
  }
}

function buildPlatformVsix(pkg, bundledManifest, allProdFiles, targetPlatform) {
  const isLinux = targetPlatform === "linux-x64";
  const includedBrokerSpec = isLinux
    ? bundledManifest.linuxBroker
    : bundledManifest.windowsBroker;
  if (!includedBrokerSpec || !includedBrokerSpec.relativePath) {
    throw new Error(
      `bundled/manifest.json is missing broker entry for '${targetPlatform}' — run \`npm run build:bundled\` for ${targetPlatform} first`
    );
  }
  const excludedBrokerRel = isLinux
    ? (bundledManifest.windowsBroker && bundledManifest.windowsBroker.relativePath) ||
      "bundled/checkwash-broker.exe"
    : (bundledManifest.linuxBroker && bundledManifest.linuxBroker.relativePath) ||
      "bundled/checkwash-broker-linux-x64";
  const includedBrokerRel = includedBrokerSpec.relativePath;

  const targetFiles = allProdFiles.filter(
    (f) => f.rel !== excludedBrokerRel && f.rel !== "bundled/upstream.json"
  );
  if (!targetFiles.some((f) => f.rel === includedBrokerRel)) {
    throw new Error(`Target VSIX '${targetPlatform}' is missing required broker '${includedBrokerRel}'`);
  }

  // Stamp platform-specific os/cpu in packaged extension/package.json
  const stampedPkg = {
    ...pkg,
    os: [isLinux ? "linux" : "win32"],
    cpu: ["x64"],
  };
  const stampedPkgBuffer = Buffer.from(JSON.stringify(stampedPkg, null, 2) + "\n", "utf8");

  // Stamp platform-specific bundled/manifest.json containing only the target platform's broker
  const stampedManifest = {
    schemaVersion: bundledManifest.schemaVersion,
    checkwash: bundledManifest.checkwash,
    ...(isLinux
      ? { linuxBroker: bundledManifest.linuxBroker }
      : { windowsBroker: bundledManifest.windowsBroker }),
    proveAdapter: bundledManifest.proveAdapter,
  };
  const stampedManifestBuffer = Buffer.from(JSON.stringify(stampedManifest, null, 2) + "\n", "utf8");

  const categories = Array.isArray(pkg.categories) ? pkg.categories.join(",") : "Linters,Testing";
  const tags = Array.isArray(pkg.keywords) ? pkg.keywords.join(",") : "";
  const hasIcon = typeof pkg.icon === "string" && pkg.icon.trim().length > 0;
  const iconZipPath = hasIcon ? `extension/${pkg.icon.replace(/\\/g, "/")}` : "";
  const hasChangelog = targetFiles.some((f) => f.rel === "CHANGELOG.md");
  const repoUrl =
    typeof pkg.repository === "string"
      ? pkg.repository
      : pkg.repository && typeof pkg.repository.url === "string"
        ? pkg.repository.url
        : "";
  const bugsUrl =
    typeof pkg.bugs === "string"
      ? pkg.bugs
      : pkg.bugs && typeof pkg.bugs.url === "string"
        ? pkg.bugs.url
        : "";
  const homepageUrl = typeof pkg.homepage === "string" ? pkg.homepage : "";
  const bannerColor =
    pkg.galleryBanner && typeof pkg.galleryBanner.color === "string"
      ? pkg.galleryBanner.color
      : "";
  const bannerTheme =
    pkg.galleryBanner && typeof pkg.galleryBanner.theme === "string"
      ? pkg.galleryBanner.theme
      : "";
  const vsixManifestXml = [
    '<?xml version="1.0" encoding="utf-8"?>',
    '<PackageManifest Version="2.0.0" xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011" xmlns:d="http://schemas.microsoft.com/developer/vsx-schema-design/2011">',
    "  <Metadata>",
    `    <Identity Language="en-US" Id="${escapeXml(pkg.name)}" Version="${escapeXml(pkg.version)}" Publisher="${escapeXml(pkg.publisher)}" TargetPlatform="${targetPlatform}" />`,
    `    <DisplayName>${escapeXml(pkg.displayName || pkg.name)}</DisplayName>`,
    `    <Description xml:space="preserve">${escapeXml(pkg.description || "")}</Description>`,
    ...(tags ? [`    <Tags>${escapeXml(tags)}</Tags>`] : []),
    `    <Categories>${escapeXml(categories)}</Categories>`,
    "    <Properties>",
    `      <Property Id="Microsoft.VisualStudio.Code.Engine" Value="${escapeXml(pkg.engines.vscode)}" />`,
    '      <Property Id="Microsoft.VisualStudio.Code.ExtensionDependencies" Value="" />',
    '      <Property Id="Microsoft.VisualStudio.Code.ExtensionPack" Value="" />',
    '      <Property Id="Microsoft.VisualStudio.Code.ExtensionKind" Value="workspace" />',
    '      <Property Id="Microsoft.VisualStudio.Services.GitHubFlavoredMarkdown" Value="true" />',
    ...(bannerColor
      ? [`      <Property Id="Microsoft.VisualStudio.Services.Branding.Color" Value="${escapeXml(bannerColor)}" />`]
      : []),
    ...(bannerTheme
      ? [`      <Property Id="Microsoft.VisualStudio.Services.Branding.Theme" Value="${escapeXml(bannerTheme)}" />`]
      : []),
    ...(repoUrl
      ? [
          `      <Property Id="Microsoft.VisualStudio.Services.Links.Source" Value="${escapeXml(repoUrl)}" />`,
          `      <Property Id="Microsoft.VisualStudio.Services.Links.GitHub" Value="${escapeXml(repoUrl)}" />`,
        ]
      : []),
    ...(bugsUrl
      ? [`      <Property Id="Microsoft.VisualStudio.Services.Links.Support" Value="${escapeXml(bugsUrl)}" />`]
      : []),
    ...(homepageUrl
      ? [`      <Property Id="Microsoft.VisualStudio.Services.Links.Learn" Value="${escapeXml(homepageUrl)}" />`]
      : []),
    "    </Properties>",
    "    <License>extension/LICENSE</License>",
    ...(hasIcon ? [`    <Icon>${escapeXml(iconZipPath)}</Icon>`] : []),
    "  </Metadata>",
    "  <Installation>",
    '    <InstallationTarget Id="Microsoft.VisualStudio.Code" />',
    "  </Installation>",
    "  <Dependencies />",
    "  <Assets>",
    '    <Asset Type="Microsoft.VisualStudio.Code.Manifest" Path="extension/package.json" Addressable="true" />',
    '    <Asset Type="Microsoft.VisualStudio.Services.Content.Details" Path="extension/README.md" Addressable="true" />',
    ...(hasChangelog
      ? [
          '    <Asset Type="Microsoft.VisualStudio.Services.Content.Changelog" Path="extension/CHANGELOG.md" Addressable="true" />',
        ]
      : []),
    '    <Asset Type="Microsoft.VisualStudio.Services.Content.License" Path="extension/LICENSE" Addressable="true" />',
    ...(hasIcon
      ? [
          `    <Asset Type="Microsoft.VisualStudio.Services.Icons.Default" Path="${escapeXml(iconZipPath)}" Addressable="true" />`,
        ]
      : []),
    "  </Assets>",
    "</PackageManifest>",
    "",
  ].join("\n");

  const contentTypesLines = [
    '<?xml version="1.0" encoding="utf-8"?>',
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">',
    '  <Default Extension="json" ContentType="application/json" />',
    '  <Default Extension="js" ContentType="application/javascript" />',
    '  <Default Extension="md" ContentType="text/markdown" />',
    '  <Default Extension="png" ContentType="image/png" />',
    '  <Default Extension="svg" ContentType="image/svg+xml" />',
    '  <Default Extension="pyz" ContentType="application/octet-stream" />',
    '  <Default Extension="exe" ContentType="application/octet-stream" />',
    '  <Default Extension="vsixmanifest" ContentType="text/xml" />',
    '  <Override PartName="/extension/LICENSE" ContentType="text/plain" />',
  ];
  if (isLinux) {
    contentTypesLines.push(
      `  <Override PartName="/extension/${includedBrokerRel}" ContentType="application/octet-stream" />`
    );
  }
  contentTypesLines.push("</Types>", "");
  const contentTypesXml = contentTypesLines.join("\n");

  const zipEntries = [
    { zipPath: "[Content_Types].xml", data: Buffer.from(contentTypesXml, "utf8"), executable: false },
    { zipPath: "extension.vsixmanifest", data: Buffer.from(vsixManifestXml, "utf8"), executable: false },
    ...targetFiles.map((f) => ({
      zipPath: `extension/${f.rel}`,
      data:
        f.rel === "package.json"
          ? stampedPkgBuffer
          : f.rel === "bundled/manifest.json"
            ? stampedManifestBuffer
            : fs.readFileSync(f.full),
      executable: isLinux && f.rel === includedBrokerRel,
    })),
  ];

  const vsixBuffer = buildZipArchive(zipEntries, isLinux);
  const outName = `${pkg.name}-${pkg.version}-${targetPlatform}.vsix`;
  const outPath = path.join(ROOT, outName);
  fs.writeFileSync(outPath, vsixBuffer);

  const cdEntries = readZipCentralDirectory(fs.readFileSync(outPath));
  if (cdEntries.length !== zipEntries.length) {
    throw new Error(
      `VSIX entry count mismatch for ${outName}: expected ${zipEntries.length}, got ${cdEntries.length}`
    );
  }
  if (isLinux) {
    const brokerEntry = cdEntries.find((e) => e.name === `extension/${includedBrokerRel}`);
    const expectedExecAttr = (0o100755 << 16) >>> 0;
    if (!brokerEntry || brokerEntry.externalAttrs !== expectedExecAttr) {
      throw new Error(
        `Linux broker ZIP entry missing UNIX 0755 executable permission in ${outName}`
      );
    }
  }

  return {
    targetPlatform,
    vsixFile: outName,
    vsixBytes: vsixBuffer.length,
    vsixSha256: sha256Hex(vsixBuffer),
    entryCount: cdEntries.length,
    entries: cdEntries.map((e) => e.name),
  };
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
    // Ignore homedir lookup errors in restricted containers
  }
  try {
    const user = (os.userInfo().username || "").trim();
    if (
      user.length >= 3 &&
      !/^(?:root|node|app|user|ubuntu|debian|vscode|runner|builder|tester)$/i.test(user)
    ) {
      const escUser = escapeRegexLiteral(user);
      regexes.push(new RegExp(`[a-z]:[\\\\/]+users[\\\\/]+${escUser}|\\/(?:home|users)\\/${escUser}`, "i"));
    }
  } catch {
    // Ignore userInfo lookup errors in UID-only containers
  }
  return regexes;
}

function main() {
  const targets = parseTargetPlatforms(process.argv);
  const pkgPath = path.join(ROOT, "package.json");
  const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
  if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(String(pkg.version || ""))) {
    throw new Error(`Invalid package.json version '${String(pkg.version)}' (expected SemVer x.y.z)`);
  }
  const versionLocalPath = path.join(ROOT, "VERSION-LOCAL.json");
  let localVersionLabel = null;
  if (fs.existsSync(versionLocalPath)) {
    const versionLocal = JSON.parse(fs.readFileSync(versionLocalPath, "utf8"));
    if (versionLocal.publicVersion !== pkg.version) {
      throw new Error(
        `Public version mismatch: package.json version is '${pkg.version}' but VERSION-LOCAL.json publicVersion is '${versionLocal.publicVersion}'`
      );
    }
    const expectedPublicPrefix = `${versionLocal.publicSeries}.`;
    if (!String(pkg.version).startsWith(expectedPublicPrefix)) {
      throw new Error(
        `External package.json version '${pkg.version}' violates pinned publicSeries '${versionLocal.publicSeries}' in VERSION-LOCAL.json`
      );
    }
    if (typeof versionLocal.localVersion !== "string" || versionLocal.localVersion.trim().length === 0) {
      throw new Error("VERSION-LOCAL.json is missing a valid localVersion string");
    }
    localVersionLabel = versionLocal.localVersion;
  }

  const manifestPath = path.join(ROOT, "bundled", "manifest.json");
  if (!fs.existsSync(manifestPath)) {
    throw new Error(
      "bundled/manifest.json is missing — run `npm run build:bundled` before packaging"
    );
  }
  const bundledManifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));

  // Cross-check generated bundled/manifest.json against tracked bundled/upstream.json
  const upstreamPath = path.join(ROOT, "bundled", "upstream.json");
  if (fs.existsSync(upstreamPath)) {
    const upstream = JSON.parse(fs.readFileSync(upstreamPath, "utf8"));
    if (
      !upstream.checkwash ||
      bundledManifest.checkwash.version !== upstream.checkwash.version ||
      bundledManifest.checkwash.bytes !== upstream.checkwash.bytes ||
      String(bundledManifest.checkwash.sha256 || "").toLowerCase() !==
        String(upstream.checkwash.sha256 || "").toLowerCase()
    ) {
      throw new Error(
        "bundled/manifest.json checkwash pin is out of sync with bundled/upstream.json — re-run `npm run build:bundled`"
      );
    }
  }

  // 1. Verify required root metadata & media files
  for (const reqFile of [
    "package.json",
    "README.md",
    "CHANGELOG.md",
    "LICENSE",
    "media/icon.png",
    "media/checkwash-activity.svg",
  ]) {
    if (!fs.existsSync(path.join(ROOT, reqFile))) {
      throw new Error(`Missing required root packaging file: ${reqFile}`);
    }
  }

  // 2. Verify pinned bundled artifacts required for the requested target(s)
  verifyPinnedFile(
    bundledManifest.checkwash.relativePath,
    bundledManifest.checkwash.bytes,
    bundledManifest.checkwash.sha256
  );
  if (targets.includes("win32-x64")) {
    if (!bundledManifest.windowsBroker) {
      throw new Error(
        "bundled/manifest.json is missing windowsBroker — run `npm run build:bundled` on win32-x64"
      );
    }
    verifyPinnedFile(
      bundledManifest.windowsBroker.relativePath,
      bundledManifest.windowsBroker.bytes,
      bundledManifest.windowsBroker.sha256
    );
  }
  if (targets.includes("linux-x64")) {
    if (!bundledManifest.linuxBroker) {
      throw new Error(
        "bundled/manifest.json is missing linuxBroker — run `npm run build:bundled` on linux-x64"
      );
    }
    verifyPinnedFile(
      bundledManifest.linuxBroker.relativePath,
      bundledManifest.linuxBroker.bytes,
      bundledManifest.linuxBroker.sha256
    );
  }

  // 3. Collect production files strictly matching .vscodeignore allowlist contract
  const prodFiles = [
    { rel: "package.json", full: path.join(ROOT, "package.json") },
    { rel: "README.md", full: path.join(ROOT, "README.md") },
    { rel: "CHANGELOG.md", full: path.join(ROOT, "CHANGELOG.md") },
    { rel: "LICENSE", full: path.join(ROOT, "LICENSE") },
    ...collectFilesRecursive(path.join(ROOT, "media"), "media"),
    ...collectFilesRecursive(path.join(ROOT, "bundled"), "bundled").filter(
      (f) => f.rel !== "bundled/upstream.json"
    ),
    ...collectFilesRecursive(path.join(ROOT, "docs"), "docs").filter(
      (f) => f.rel !== "docs/PHASE0-EXIT-REPORT.md"
    ),
    ...collectFilesRecursive(path.join(ROOT, "dist"), "dist").filter(
      (f) => !f.rel.startsWith("dist/test/") && f.rel.endsWith(".js")
    ),
  ];

  if (!prodFiles.some((f) => f.rel === "dist/extension.js")) {
    throw new Error("dist/extension.js is missing — run `npm run compile` before packaging");
  }

  // 4. Security & hygiene audit on every packaged file (text + binary developer path scan + VERSION-LOCAL exclusion)
  const forbiddenPrefixes = [
    "dist/test/",
    "src/",
    "fixtures/",
    "evidence/",
    "native/",
    "scripts/",
    ".vscode/",
    "node_modules/",
  ];
  const forbiddenExactFiles = new Set([
    "VERSION-LOCAL.json",
    "docs/PHASE0-EXIT-REPORT.md",
  ]);
  const forbiddenDeveloperPathMatchers = buildForbiddenDeveloperPathMatchers();

  for (const item of prodFiles) {
    if (forbiddenExactFiles.has(item.rel)) {
      throw new Error(`Forbidden local-only file in VSIX payload: ${item.rel}`);
    }
    for (const prefix of forbiddenPrefixes) {
      if (item.rel.startsWith(prefix)) {
        throw new Error(`Forbidden non-production file in VSIX payload: ${item.rel}`);
      }
    }
    const rawLatin1 = fs.readFileSync(item.full).toString("latin1");
    for (const re of forbiddenDeveloperPathMatchers) {
      if (re.test(rawLatin1)) {
        throw new Error(
          `Hardcoded developer machine path leaked in packaged file '${item.rel}' (matched ${re})`
        );
      }
    }
  }

  const builtTargets = targets.map((t) =>
    buildPlatformVsix(pkg, bundledManifest, prodFiles, t)
  );
  for (const target of builtTargets) {
    if (target.entries.some((e) => /VERSION-LOCAL\.json/i.test(e))) {
      throw new Error(`VERSION-LOCAL.json leaked into VSIX archive '${target.vsixFile}'`);
    }
  }

  if (builtTargets.length === 1) {
    console.log(
      JSON.stringify(
        {
          ok: true,
          publicVersion: pkg.version,
          ...(localVersionLabel ? { localVersion: localVersionLabel } : {}),
          ...builtTargets[0],
        },
        null,
        2
      )
    );
  } else {
    console.log(
      JSON.stringify(
        {
          ok: true,
          version: pkg.version,
          publicVersion: pkg.version,
          ...(localVersionLabel ? { localVersion: localVersionLabel } : {}),
          packages: builtTargets,
        },
        null,
        2
      )
    );
  }
}

main();
