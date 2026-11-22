#!/usr/bin/env node
/**
 * scripts/generate_media_assets.js
 *
 * Deterministically generates:
 * 1. `media/checkwash-activity.svg` — crisp 24x24 monochrome `currentColor` icon for VS Code Activity Bar.
 * 2. `media/icon.png` — crisp 128x128 anti-aliased RGBA PNG extension icon for Checkwash Lens.
 *
 * Zero external dependencies (uses Node built-in `zlib`).
 */

"use strict";

const fs = require("fs");
const path = require("path");
const zlib = require("zlib");

const ROOT = path.resolve(__dirname, "..");
const MEDIA_DIR = path.join(ROOT, "media");

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

function makePngChunk(typeAscii, dataBuf) {
  const typeBuf = Buffer.from(typeAscii, "ascii");
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32BE(dataBuf.length, 0);
  const crcBuf = Buffer.alloc(4);
  crcBuf.writeUInt32BE(crc32(Buffer.concat([typeBuf, dataBuf])), 0);
  return Buffer.concat([lenBuf, typeBuf, dataBuf, crcBuf]);
}

function encodeRgbaPng(width, height, rgba) {
  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; // 8-bit depth
  ihdr[9] = 6; // RGBA
  ihdr[10] = 0;
  ihdr[11] = 0;
  ihdr[12] = 0;

  const stride = width * 4;
  const rawScanlines = Buffer.alloc((stride + 1) * height);
  for (let y = 0; y < height; y++) {
    const rowStart = y * (stride + 1);
    rawScanlines[rowStart] = 0; // Filter type 0 (None)
    rgba.copy(rawScanlines, rowStart + 1, y * stride, (y + 1) * stride);
  }

  const compressed = zlib.deflateSync(rawScanlines, { level: 9 });
  return Buffer.concat([
    signature,
    makePngChunk("IHDR", ihdr),
    makePngChunk("IDAT", compressed),
    makePngChunk("IEND", Buffer.alloc(0)),
  ]);
}

function clamp01(v) {
  return v < 0 ? 0 : v > 1 ? 1 : v;
}

function smoothstep(edge0, edge1, x) {
  const t = clamp01((x - edge0) / (edge1 - edge0));
  return t * t * (3 - 2 * t);
}

function lerp(a, b, t) {
  return a + (b - a) * t;
}

function distToSegment(px, py, ax, ay, bx, by) {
  const vx = bx - ax;
  const vy = by - ay;
  const wx = px - ax;
  const wy = py - ay;
  const c1 = vx * wx + vy * wy;
  if (c1 <= 0) return Math.hypot(px - ax, py - ay);
  const c2 = vx * vx + vy * vy;
  if (c2 <= c1) return Math.hypot(px - bx, py - by);
  const b = c1 / c2;
  return Math.hypot(px - (ax + b * vx), py - (ay + b * vy));
}

function sdRoundedBox(px, py, cx, cy, hx, hy, r) {
  const qx = Math.abs(px - cx) - hx + r;
  const qy = Math.abs(py - cy) - hy + r;
  return Math.hypot(Math.max(qx, 0), Math.max(qy, 0)) + Math.min(Math.max(qx, qy), 0) - r;
}

function shieldHalfWidthAtY(y) {
  // Shield spans y in [20, 106], center x = 64
  if (y < 20 || y > 106) return -1;
  if (y <= 54) {
    const t = (y - 20) / 34;
    return 35 * (0.86 + 0.14 * Math.sin(t * Math.PI * 0.5));
  }
  const t = (y - 54) / 52;
  return 35 * (1 - Math.pow(t, 1.45));
}

function samplePixelColor(x, y) {
  // Background rounded squircle: center (64,64), half-size 58, radius 26
  const dBg = sdRoundedBox(x, y, 64, 64, 58, 58, 26);
  const bgAlpha = 1 - smoothstep(-0.7, 0.7, dBg);
  if (bgAlpha <= 0.001) {
    return [0, 0, 0, 0];
  }

  // Deep slate radial + diagonal gradient (#0B1220 -> #17253B)
  const diagT = clamp01((x * 0.4 + y * 0.6) / 128);
  let r = lerp(13, 24, diagT);
  let g = lerp(21, 38, diagT);
  let b = lerp(38, 62, diagT);

  // Subtle ambient cyan/emerald glow behind shield
  const glowDist = Math.hypot(x - 64, y - 60) / 52;
  const glow = Math.pow(clamp01(1 - glowDist), 2.2) * 0.25;
  r = lerp(r, 20, glow);
  g = lerp(g, 168, glow);
  b = lerp(b, 196, glow);

  // Outer squircle crisp border
  const borderMask = (1 - smoothstep(0.6, 2.0, Math.abs(dBg + 1.4))) * 0.55;
  r = lerp(r, 71, borderMask);
  g = lerp(g, 104, borderMask);
  b = lerp(b, 145, borderMask);

  // Shield geometry: top arch from y=20..30 + side curves down to y=108
  const topY = 22 + 6.5 * Math.pow(Math.abs(x - 64) / 35, 1.6);
  let insideShield = false;
  let shieldEdgeDist = 999;

  const hw = shieldHalfWidthAtY(y);
  if (hw >= 0 && y >= topY) {
    const dxEdge = hw - Math.abs(x - 64);
    const dyTop = y - topY;
    const minIn = Math.min(dxEdge, dyTop);
    if (minIn >= 0) {
      insideShield = true;
      shieldEdgeDist = minIn;
    } else {
      shieldEdgeDist = -minIn;
    }
  } else {
    // Approximate exterior distance to shield boundary for anti-aliasing
    const clampedY = Math.max(22, Math.min(106, y));
    const hwClamped = Math.max(0, shieldHalfWidthAtY(clampedY));
    const topAtX = 22 + 6.5 * Math.pow(Math.min(1.4, Math.abs(x - 64) / 35), 1.6);
    const dx = Math.max(0, Math.abs(x - 64) - hwClamped);
    const dy = y < topAtX ? topAtX - y : y > 106 ? y - 106 : 0;
    shieldEdgeDist = Math.hypot(dx, dy);
  }

  // Fill inside shield (#0F2942 -> #0D3B3E)
  const signedShield = insideShield ? -shieldEdgeDist : shieldEdgeDist;
  const shieldFillMask = 1 - smoothstep(-0.8, 0.8, signedShield);
  if (shieldFillMask > 0) {
    const st = clamp01((y - 22) / 84);
    const sr = lerp(16, 13, st);
    const sg = lerp(49, 68, st);
    const sb = lerp(78, 74, st);
    r = lerp(r, sr, shieldFillMask * 0.92);
    g = lerp(g, sg, shieldFillMask * 0.92);
    b = lerp(b, sb, shieldFillMask * 0.92);
  }

  // Shield stroke (cyan #38BDF8 at top -> emerald #10B981 at bottom), thickness ~3.6px
  const shieldStrokeMask = 1 - smoothstep(1.35, 2.55, Math.abs(signedShield));
  if (shieldStrokeMask > 0) {
    const st = clamp01((y - 22) / 84);
    const br = lerp(56, 16, st);
    const bg = lerp(189, 185, st);
    const bb = lerp(248, 129, st);
    r = lerp(r, br, shieldStrokeMask);
    g = lerp(g, bg, shieldStrokeMask);
    b = lerp(b, bb, shieldStrokeMask);
  }

  // Centered diff bars inside upper shield (red `-` vs green `+` lens)
  const dMinusBar = sdRoundedBox(x, y, 54, 43, 7.5, 2.1, 2.0);
  const minusMask = 1 - smoothstep(-0.6, 0.6, dMinusBar);
  if (minusMask > 0) {
    r = lerp(r, 248, minusMask * 0.88);
    g = lerp(g, 113, minusMask * 0.88);
    b = lerp(b, 113, minusMask * 0.88);
  }
  const dPlusBar = sdRoundedBox(x, y, 74, 43, 7.5, 2.1, 2.0);
  const plusMask = 1 - smoothstep(-0.6, 0.6, dPlusBar);
  if (plusMask > 0) {
    r = lerp(r, 74, plusMask * 0.9);
    g = lerp(g, 222, plusMask * 0.9);
    b = lerp(b, 128, plusMask * 0.9);
  }

  // Crisp bold checkmark inside shield: (46, 66) -> (58, 78) -> (83, 53)
  const dCheck1 = distToSegment(x, y, 46.5, 65.5, 58.0, 77.5);
  const dCheck2 = distToSegment(x, y, 58.0, 77.5, 82.5, 52.5);
  const dCheck = Math.min(dCheck1, dCheck2);
  const checkMask = 1 - smoothstep(3.6, 4.9, dCheck);
  if (checkMask > 0) {
    const ct = clamp01((x - 46) / 38);
    const cr = lerp(110, 236, ct);
    const cg = lerp(231, 253, ct);
    const cb = lerp(183, 245, ct);
    r = lerp(r, cr, checkMask);
    g = lerp(g, cg, checkMask);
    b = lerp(b, cb, checkMask);
  }

  return [
    Math.round(clamp01(r / 255) * 255),
    Math.round(clamp01(g / 255) * 255),
    Math.round(clamp01(b / 255) * 255),
    Math.round(bgAlpha * 255),
  ];
}

function generateIconPngBuffer() {
  const width = 128;
  const height = 128;
  const rgba = Buffer.alloc(width * height * 4);
  // 2x2 supersampling for clean anti-aliased curves
  const offsets = [0.25, 0.75];

  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      let accR = 0;
      let accG = 0;
      let accB = 0;
      let accA = 0;
      for (const oy of offsets) {
        for (const ox of offsets) {
          const [sr, sg, sb, sa] = samplePixelColor(x + ox, y + oy);
          const aNorm = sa / 255;
          accR += sr * aNorm;
          accG += sg * aNorm;
          accB += sb * aNorm;
          accA += aNorm;
        }
      }
      const outIdx = (y * width + x) * 4;
      const finalA = accA / 4;
      if (finalA <= 0.001) {
        rgba[outIdx] = 0;
        rgba[outIdx + 1] = 0;
        rgba[outIdx + 2] = 0;
        rgba[outIdx + 3] = 0;
      } else {
        rgba[outIdx] = Math.round(Math.min(255, accR / accA));
        rgba[outIdx + 1] = Math.round(Math.min(255, accG / accA));
        rgba[outIdx + 2] = Math.round(Math.min(255, accB / accA));
        rgba[outIdx + 3] = Math.round(Math.min(255, finalA * 255));
      }
    }
  }
  return encodeRgbaPng(width, height, rgba);
}

const ACTIVITY_SVG = [
  '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">',
  '  <path d="M12 2.25L4.5 5.5V11.4C4.5 16.52 7.69 21.02 12 22.5C16.31 21.02 19.5 16.52 19.5 11.4V5.5L12 2.25Z" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"/>',
  '  <path d="M8.5 8.25H10.75" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>',
  '  <path d="M13.25 8.25H15.5" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>',
  '  <path d="M8.6 13.1L10.9 15.4L15.6 10.6" stroke="currentColor" stroke-width="1.85" stroke-linecap="round" stroke-linejoin="round"/>',
  "</svg>",
  "",
].join("\n");

function main() {
  fs.mkdirSync(MEDIA_DIR, { recursive: true });
  const svgPath = path.join(MEDIA_DIR, "checkwash-activity.svg");
  const pngPath = path.join(MEDIA_DIR, "icon.png");

  fs.writeFileSync(svgPath, ACTIVITY_SVG, "utf8");
  const pngBuf = generateIconPngBuffer();
  fs.writeFileSync(pngPath, pngBuf);

  console.log(
    JSON.stringify(
      {
        ok: true,
        svgBytes: Buffer.byteLength(ACTIVITY_SVG, "utf8"),
        pngBytes: pngBuf.length,
      },
      null,
      2
    )
  );
}

main();
