'use strict';
/*
 * panel/portal/public/js/qr.js — a QR encoder, byte mode, error level M.
 *
 * ── Why this is written rather than loaded ──────────────────────────────────
 *
 * The portal's Content-Security-Policy is `script-src 'self'`, and it is that
 * way on purpose: this page shows people private keys. A CDN script tag would
 * mean a third party could change what runs on the page that hands out
 * credentials, which is not a trade worth making to avoid three hundred lines.
 * Rendering the code on the server instead would need the same encoder in Node
 * and a second copy of it.
 *
 * ── A wrong QR is worse than no QR ──────────────────────────────────────────
 *
 * The adapters already say so: `qr: 1` means "a camera will actually resolve
 * this", not "this is a string", because a code that imports a broken tunnel
 * looks like it worked. The same standard applies to the encoder. So every
 * table below is cross-checkable rather than trusted, and
 * panel/scripts/portal-selftest.js checks all of it:
 *
 *   - the block table is verified against the published total codeword count
 *     for each version, which is an independent number: a typo in any of the
 *     eighty figures makes the two disagree;
 *   - the module layout is verified against that same count, since the number
 *     of modules left over after every function pattern is placed must be
 *     exactly 8 x codewords + remainder bits;
 *   - the two BCH computations are pinned to published bit strings from the
 *     specification, so neither is trusted to be right because it looks right.
 *
 * Between them those three catch the whole class of "it renders a plausible
 * square that no phone can read".
 *
 * ── Scope ───────────────────────────────────────────────────────────────────
 *
 * Byte mode only — a configuration file is arbitrary bytes, so the alphanumeric
 * and numeric modes would never be reachable. Error level M only: it is the
 * level that survives a phone camera at an angle in poor light, which is the
 * actual use. Versions 1 to 20, which is 666 bytes at level M. Past that the
 * modules are too fine to scan from a screen anyway, so `encode` returns null
 * and the page says the file is too large for a code rather than drawing one
 * that cannot be read.
 */

var VPN55_QR = (function () {
  /* ── GF(256), the field the error correction lives in ───────────────────── */
  var EXP = new Uint8Array(512);
  var LOG = new Uint8Array(256);
  (function () {
    var x = 1;
    for (var i = 0; i < 255; i++) {
      EXP[i] = x;
      LOG[x] = i;
      x <<= 1;
      if (x & 0x100) x ^= 0x11d;      /* the QR primitive polynomial */
    }
    for (var j = 255; j < 512; j++) EXP[j] = EXP[j - 255];
  }());

  function gmul(a, b) {
    if (a === 0 || b === 0) return 0;
    return EXP[LOG[a] + LOG[b]];
  }

  /* The generator polynomial for n error-correction codewords: the product of
     (x - a^i) for i in 0..n-1. Coefficients run highest power first. */
  function rsGenerator(n) {
    var g = [1];
    for (var i = 0; i < n; i++) {
      var next = [];
      for (var k = 0; k <= g.length; k++) next.push(0);
      for (var j = 0; j < g.length; j++) {
        next[j] ^= g[j];                       /* x * g */
        next[j + 1] ^= gmul(g[j], EXP[i]);     /* a^i * g */
      }
      g = next;
    }
    return g;
  }

  /* Polynomial long division; the remainder is the error correction. */
  function rsEncode(data, ecLen) {
    var gen = rsGenerator(ecLen);
    var buf = new Uint8Array(data.length + ecLen);
    buf.set(data, 0);
    for (var i = 0; i < data.length; i++) {
      var factor = buf[i];
      if (factor === 0) continue;
      for (var j = 0; j < gen.length; j++) buf[i + j] ^= gmul(gen[j], factor);
    }
    return buf.subarray(data.length);
  }

  /* ── The tables ──────────────────────────────────────────────────────────
   *
   * Level M only. Per version: error-correction codewords PER BLOCK, then the
   * two block groups as [count, data codewords each]. A version with one group
   * has zeroes in the second.
   *
   * TOTAL is the published total codeword count and is NOT derived from the row
   * beside it — that is the point of carrying it. The self-test asserts
   *
   *     g1 * (d1 + ec) + g2 * (d2 + ec) === TOTAL[v]
   *
   * for every version, so a mistyped figure anywhere in either table is a
   * failed check rather than a code that encodes to the wrong length. */
  var BLOCKS = {
    /*  v: [ec, g1, d1, g2, d2] */
    1: [10, 1, 16, 0, 0],
    2: [16, 1, 28, 0, 0],
    3: [26, 1, 44, 0, 0],
    4: [18, 2, 32, 0, 0],
    5: [24, 2, 43, 0, 0],
    6: [16, 4, 27, 0, 0],
    7: [18, 4, 31, 0, 0],
    8: [22, 2, 38, 2, 39],
    9: [22, 3, 36, 2, 37],
    10: [26, 4, 43, 1, 44],
    11: [30, 1, 50, 4, 51],
    12: [22, 6, 36, 2, 37],
    13: [22, 8, 37, 1, 38],
    14: [24, 4, 40, 5, 41],
    15: [24, 5, 41, 5, 42],
    16: [28, 7, 45, 3, 46],
    17: [28, 10, 46, 1, 47],
    18: [26, 9, 43, 4, 44],
    19: [26, 3, 44, 11, 45],
    20: [26, 3, 41, 13, 42]
  };

  var TOTAL = {
    1: 26, 2: 44, 3: 70, 4: 100, 5: 134, 6: 172, 7: 196, 8: 242, 9: 292,
    10: 346, 11: 404, 12: 466, 13: 532, 14: 581, 15: 655, 16: 733, 17: 815,
    18: 901, 19: 991, 20: 1085
  };

  /* Bits left over after the last whole codeword. Part of the module count the
     self-test checks the layout against. */
  function remainderBits(version) {
    if (version === 1) return 0;
    if (version <= 6) return 7;
    if (version <= 13) return 0;
    return 3;                            /* 14-20 */
  }

  /* Alignment pattern centre coordinates, per version. */
  var ALIGN = {
    1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34],
    7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 50],
    11: [6, 30, 54], 12: [6, 32, 58], 13: [6, 34, 62],
    14: [6, 26, 46, 66], 15: [6, 26, 48, 70], 16: [6, 26, 50, 74],
    17: [6, 30, 54, 78], 18: [6, 30, 56, 82], 19: [6, 30, 58, 86],
    20: [6, 34, 62, 90]
  };

  var MIN_VERSION = 1;
  var MAX_VERSION = 20;

  /* How many data BYTES fit at this version, allowing for the mode indicator,
     the character count field and the terminator. */
  function capacity(version) {
    var t = BLOCKS[version];
    var dataCodewords = t[1] * t[2] + t[3] * t[4];
    var countBits = version <= 9 ? 8 : 16;
    /* 4 bits of mode indicator, then the count field. */
    return Math.floor((dataCodewords * 8 - 4 - countBits) / 8);
  }

  /* ── BCH, for the two metadata strips ────────────────────────────────────
   *
   * Both are pinned to published values in the self-test rather than trusted.
   * A wrong format strip is the failure that looks most like success: the code
   * draws, it is the right size, and no reader will touch it. */

  /** 15 bits: 2 of error level, 3 of mask, 10 of BCH, XOR 0x5412. */
  function formatBits(ecBits, mask) {
    var data = (ecBits << 3) | mask;
    var rem = data;
    for (var i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
    return ((data << 10) | rem) ^ 0x5412;
  }

  /** 18 bits: 6 of version, 12 of BCH. Only used from version 7 up. */
  function versionBits(version) {
    var rem = version;
    for (var i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
    return (version << 12) | rem;
  }

  /* Level M is 0b00. The four levels are NOT in numeric order in this field —
     L is 01 and M is 00 — which is exactly the sort of thing worth writing down
     rather than deriving. */
  var EC_BITS_M = 0;

  /* ── The matrix ──────────────────────────────────────────────────────────
   *
   * Two grids of the same size: the modules themselves, and a mask of which
   * ones are function patterns. The second is what stops the data placement
   * writing over a finder, and what the mask patterns are not applied to. */

  function newGrid(size, value) {
    var g = [];
    for (var i = 0; i < size; i++) {
      var row = [];
      for (var j = 0; j < size; j++) row.push(value);
      g.push(row);
    }
    return g;
  }

  function placeFunctionPatterns(version) {
    var size = version * 4 + 17;
    var m = newGrid(size, 0);
    var fn = newGrid(size, false);

    function set(r, c, dark) {
      m[r][c] = dark ? 1 : 0;
      fn[r][c] = true;
    }

    /* Finder patterns and their separators, in three corners. */
    function finder(r0, c0) {
      for (var dr = -1; dr <= 7; dr++) {
        for (var dc = -1; dc <= 7; dc++) {
          var r = r0 + dr;
          var c = c0 + dc;
          if (r < 0 || r >= size || c < 0 || c >= size) continue;
          var d = Math.max(Math.abs(dr - 3), Math.abs(dc - 3));
          set(r, c, d !== 2 && d !== 4);
        }
      }
    }
    finder(0, 0);
    finder(0, size - 7);
    finder(size - 7, 0);

    /* Timing patterns, row and column 6. */
    for (var i = 8; i < size - 8; i++) {
      set(6, i, i % 2 === 0);
      set(i, 6, i % 2 === 0);
    }

    /* Alignment patterns, everywhere a centre pair does not collide with a
       finder. The three corner combinations are the excluded ones. */
    var centres = ALIGN[version];
    for (var a = 0; a < centres.length; a++) {
      for (var b = 0; b < centres.length; b++) {
        var last = centres.length - 1;
        if ((a === 0 && b === 0) || (a === 0 && b === last) || (a === last && b === 0)) continue;
        var cr = centres[a];
        var cc = centres[b];
        for (var dr2 = -2; dr2 <= 2; dr2++) {
          for (var dc2 = -2; dc2 <= 2; dc2++) {
            set(cr + dr2, cc + dc2, Math.max(Math.abs(dr2), Math.abs(dc2)) !== 1);
          }
        }
      }
    }

    /* Reserve the two format strips. Their real values are written once the
       mask is chosen; reserving them now is what keeps the data out.
       Index 6 is skipped in BOTH directions because row 6 and column 6 are the
       timing patterns: (8,6) and (6,8) belong to those and were set above. The
       format strip steps over them rather than through them, and reserving them
       here would blank two timing modules — a code that draws at the right size
       and that no reader will lock on to. */
    for (var k = 0; k < 9; k++) {
      if (k !== 6) { set(8, k, false); set(k, 8, false); }
    }
    for (var q = 0; q < 8; q++) {
      set(8, size - 1 - q, false);
      set(size - 1 - q, 8, false);
    }
    /* The dark module. Always set, always at this one place. */
    set(size - 8, 8, true);

    /* Version information, from version 7. Two 3x6 blocks. */
    if (version >= 7) {
      var bits = versionBits(version);
      for (var p = 0; p < 18; p++) {
        var bit = ((bits >>> p) & 1) === 1;
        var rr = Math.floor(p / 3);
        var cc2 = p % 3;
        set(rr, size - 11 + cc2, bit);
        set(size - 11 + cc2, rr, bit);
      }
    }

    return { modules: m, functional: fn, size: size };
  }

  /** Every module a data bit may be written to, in placement order. */
  function dataPositions(fn, size) {
    var out = [];
    var upward = true;
    for (var right = size - 1; right >= 1; right -= 2) {
      /* Column 6 is the vertical timing pattern and is skipped entirely, not
         merely stepped over: the column pairs to its left are shifted by one. */
      if (right === 6) right = 5;
      for (var step = 0; step < size; step++) {
        var row = upward ? (size - 1 - step) : step;
        for (var c = 0; c < 2; c++) {
          var col = right - c;
          if (fn[row][col]) continue;
          out.push([row, col]);
        }
      }
      upward = !upward;
    }
    return out;
  }

  /* ── Mask selection ──────────────────────────────────────────────────────
   * The eight masks, and the four penalty rules the standard scores them by.
   * The lowest total wins; picking one arbitrarily produces codes that scan
   * badly in exactly the cases the rules exist to avoid. */
  var MASKS = [
    function (i, j) { return (i + j) % 2 === 0; },
    function (i) { return i % 2 === 0; },
    function (i, j) { return j % 3 === 0; },
    function (i, j) { return (i + j) % 3 === 0; },
    function (i, j) { return (Math.floor(i / 2) + Math.floor(j / 3)) % 2 === 0; },
    function (i, j) { return ((i * j) % 2) + ((i * j) % 3) === 0; },
    function (i, j) { return (((i * j) % 2) + ((i * j) % 3)) % 2 === 0; },
    function (i, j) { return ((((i + j) % 2) + ((i * j) % 3)) % 2) === 0; }
  ];

  function penalty(m, size) {
    var score = 0;
    var i;
    var j;
    var run;
    var prev;

    /* Rule 1 — runs of five or more of the same colour, each way. */
    for (i = 0; i < size; i++) {
      run = 1; prev = m[i][0];
      for (j = 1; j < size; j++) {
        if (m[i][j] === prev) { run++; } else { if (run >= 5) score += 3 + (run - 5); run = 1; prev = m[i][j]; }
      }
      if (run >= 5) score += 3 + (run - 5);

      run = 1; prev = m[0][i];
      for (j = 1; j < size; j++) {
        if (m[j][i] === prev) { run++; } else { if (run >= 5) score += 3 + (run - 5); run = 1; prev = m[j][i]; }
      }
      if (run >= 5) score += 3 + (run - 5);
    }

    /* Rule 2 — every 2x2 block of one colour. */
    for (i = 0; i < size - 1; i++) {
      for (j = 0; j < size - 1; j++) {
        var v = m[i][j];
        if (m[i][j + 1] === v && m[i + 1][j] === v && m[i + 1][j + 1] === v) score += 3;
      }
    }

    /* Rule 3 — the finder-lookalike sequence, either orientation, each way. */
    var A = [1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0];
    var B = [0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1];
    function matches(get, at, pat) {
      for (var k = 0; k < pat.length; k++) if (get(at + k) !== pat[k]) return false;
      return true;
    }
    for (i = 0; i < size; i++) {
      for (j = 0; j + 11 <= size; j++) {
        /* eslint-disable no-loop-func */
        var rowGet = (function (r) { return function (x) { return m[r][x]; }; }(i));
        var colGet = (function (c) { return function (x) { return m[x][c]; }; }(i));
        /* eslint-enable no-loop-func */
        if (matches(rowGet, j, A) || matches(rowGet, j, B)) score += 40;
        if (matches(colGet, j, A) || matches(colGet, j, B)) score += 40;
      }
    }

    /* Rule 4 — how far the dark proportion is from half. */
    var dark = 0;
    for (i = 0; i < size; i++) for (j = 0; j < size; j++) dark += m[i][j];
    var percent = (dark * 100) / (size * size);
    score += Math.floor(Math.abs(percent - 50) / 5) * 10;

    return score;
  }

  /* ── Encoding ────────────────────────────────────────────────────────────*/

  function bitStream() {
    var bits = [];
    return {
      push: function (value, length) {
        for (var i = length - 1; i >= 0; i--) bits.push((value >>> i) & 1);
      },
      bits: bits
    };
  }

  function buildCodewords(bytes, version) {
    var t = BLOCKS[version];
    var ec = t[0];
    var groups = [[t[1], t[2]], [t[3], t[4]]];
    var dataCodewords = t[1] * t[2] + t[3] * t[4];

    var bs = bitStream();
    bs.push(0b0100, 4);                                   /* byte mode */
    bs.push(bytes.length, version <= 9 ? 8 : 16);
    for (var i = 0; i < bytes.length; i++) bs.push(bytes[i], 8);

    /* Terminator: up to four zero bits, then to a byte boundary. */
    var capacityBits = dataCodewords * 8;
    var pad = Math.min(4, capacityBits - bs.bits.length);
    bs.push(0, pad);
    while (bs.bits.length % 8 !== 0) bs.bits.push(0);

    var data = [];
    for (var b = 0; b < bs.bits.length; b += 8) {
      var v = 0;
      for (var k = 0; k < 8; k++) v = (v << 1) | bs.bits[b + k];
      data.push(v);
    }
    /* The two published pad bytes, alternating, to the end. */
    var padBytes = [0xec, 0x11];
    var p = 0;
    while (data.length < dataCodewords) { data.push(padBytes[p % 2]); p++; }

    /* Split into blocks, compute error correction for each. */
    var dataBlocks = [];
    var ecBlocks = [];
    var at = 0;
    for (var g = 0; g < groups.length; g++) {
      for (var n = 0; n < groups[g][0]; n++) {
        var block = Uint8Array.from(data.slice(at, at + groups[g][1]));
        at += groups[g][1];
        dataBlocks.push(block);
        ecBlocks.push(rsEncode(block, ec));
      }
    }

    /* Interleave: all the first data codewords, then all the seconds, and so
       on; then the same for the error correction. Blocks are not equal length,
       so a block that has run out is skipped rather than padded. */
    var out = [];
    var longest = 0;
    for (var d = 0; d < dataBlocks.length; d++) longest = Math.max(longest, dataBlocks[d].length);
    for (var col = 0; col < longest; col++) {
      for (var db = 0; db < dataBlocks.length; db++) {
        if (col < dataBlocks[db].length) out.push(dataBlocks[db][col]);
      }
    }
    for (var ecol = 0; ecol < ec; ecol++) {
      for (var eb = 0; eb < ecBlocks.length; eb++) out.push(ecBlocks[eb][ecol]);
    }
    return out;
  }

  /** UTF-8 bytes, without depending on TextEncoder being present. */
  function utf8(text) {
    if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(text);
    var out = [];
    var s = unescape(encodeURIComponent(String(text)));
    for (var i = 0; i < s.length; i++) out.push(s.charCodeAt(i) & 0xff);
    return Uint8Array.from(out);
  }

  /**
   * Encode text to a module grid.
   *
   * Returns { size, modules, version } or NULL when the text does not fit in
   * version 20. Null is a real answer the caller must handle: the page says the
   * file is too large to photograph and offers the download, which is the
   * honest outcome. Drawing a version-40 code nobody can scan would not be.
   */
  function encode(text) {
    var bytes = utf8(text);
    var version = -1;
    for (var v = MIN_VERSION; v <= MAX_VERSION; v++) {
      if (bytes.length <= capacity(v)) { version = v; break; }
    }
    if (version < 0) return null;

    var codewords = buildCodewords(bytes, version);
    var built = placeFunctionPatterns(version);
    var size = built.size;
    var fn = built.functional;
    var base = built.modules;

    /* Data, zigzag, skipping every function module. The remainder bits at the
       end are simply never written, and stay zero. */
    var positions = dataPositions(fn, size);
    var bitAt = 0;
    for (var i = 0; i < positions.length; i++) {
      var byteIndex = bitAt >>> 3;
      var bit = byteIndex < codewords.length
        ? (codewords[byteIndex] >>> (7 - (bitAt & 7))) & 1
        : 0;
      base[positions[i][0]][positions[i][1]] = bit;
      bitAt++;
    }

    /* Try every mask against the penalty rules and keep the best. */
    var best = null;
    var bestScore = Infinity;
    for (var mi = 0; mi < MASKS.length; mi++) {
      var candidate = [];
      for (var r = 0; r < size; r++) candidate.push(base[r].slice());
      for (var rr = 0; rr < size; rr++) {
        for (var cc = 0; cc < size; cc++) {
          if (fn[rr][cc]) continue;
          if (MASKS[mi](rr, cc)) candidate[rr][cc] ^= 1;
        }
      }
      writeFormat(candidate, size, mi);
      var score = penalty(candidate, size);
      if (score < bestScore) { bestScore = score; best = candidate; }
    }

    return { size: size, modules: best, version: version };
  }

  /**
   * The two copies of the format strip, for a chosen mask.
   *
   * ⚠ THE ORDER IS NOT SYMMETRIC, and getting it mirrored is the single most
   * expensive mistake available in this file. The region a format strip
   * occupies looks the same transposed, so a code with the bits written the
   * wrong way round is exactly the right size, has correct finders, correct
   * timing and correct data — and no reader will lock on to it, because the
   * first thing a reader does is read these fifteen bits to learn the mask.
   *
   * Bit 0 lands at (row 0, column 8) in the first copy and at
   * (row 8, column size-1) in the second. Those two are pinned in
   * panel/scripts/portal-selftest.js rather than trusted, for that reason.
   */
  function writeFormat(m, size, mask) {
    var bits = formatBits(EC_BITS_M, mask);
    var i;

    /* Copy one, wrapped around the top-left finder: up column 8, then left
       along row 8. It steps OVER the timing modules at (6,8) and (8,6). */
    for (i = 0; i <= 5; i++) m[i][8] = (bits >>> i) & 1;
    m[7][8] = (bits >>> 6) & 1;
    m[8][8] = (bits >>> 7) & 1;
    m[8][7] = (bits >>> 8) & 1;
    for (i = 9; i < 15; i++) m[8][14 - i] = (bits >>> i) & 1;

    /* Copy two, split between the other two corners: the low eight bits run
       leftwards along row 8 from the right edge, the high seven run downwards
       in column 8 to the bottom edge. */
    for (i = 0; i < 8; i++) m[8][size - 1 - i] = (bits >>> i) & 1;
    for (i = 8; i < 15; i++) m[size - 15 + i][8] = (bits >>> i) & 1;

    /* The dark module. Always set, in every code ever made, and it sits in the
       middle of the second copy's column — which is why it is written after. */
    m[size - 8][8] = 1;
  }

  /* ── Drawing ─────────────────────────────────────────────────────────────
   *
   * One <path> rather than a rectangle per module: a version 12 code is 4,489
   * modules and half of them dark, and two thousand SVG nodes is a visible
   * pause on the phones this is for.
   *
   * Built with createElementNS and setAttribute. There is no innerHTML in this
   * file or anywhere else in the portal — the text being encoded came from a
   * service on this host, and that is exactly where an attacker who got that
   * far would put something. */
  function draw(text, options) {
    var opts = options || {};
    var code = encode(text);
    if (!code) return null;

    var quiet = opts.quiet === undefined ? 4 : opts.quiet;
    var span = code.size + quiet * 2;

    var svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 ' + span + ' ' + span);
    svg.setAttribute('width', '100%');
    svg.setAttribute('role', 'img');
    if (opts.label) svg.setAttribute('aria-label', opts.label);
    /* shape-rendering, because a fractional device-pixel ratio otherwise
       antialiases the module edges into grey and costs a scan. */
    svg.setAttribute('shape-rendering', 'crispEdges');

    /* The quiet zone is part of the code, not padding around it: a reader needs
       four modules of background on every side. It is drawn rather than left to
       whatever the page happens to have behind it. */
    var bg = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
    bg.setAttribute('width', String(span));
    bg.setAttribute('height', String(span));
    bg.setAttribute('fill', opts.light || '#ffffff');
    svg.appendChild(bg);

    var d = '';
    for (var r = 0; r < code.size; r++) {
      for (var c = 0; c < code.size; c++) {
        if (!code.modules[r][c]) continue;
        d += 'M' + (c + quiet) + ' ' + (r + quiet) + 'h1v1h-1z';
      }
    }
    var path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', d);
    /* Fixed black and white, NOT theme tokens. A QR code is read by a camera,
       not by a person, and a low-contrast pair that looks tasteful in a dark
       theme is a code that does not scan. This is the one place in the portal
       that does not follow the theme, and that is the reason. */
    path.setAttribute('fill', opts.dark || '#000000');
    svg.appendChild(path);

    return { svg: svg, version: code.version, size: code.size };
  }

  return {
    encode: encode,
    draw: draw,
    capacity: capacity,
    MAX_BYTES: capacity(MAX_VERSION),
    /* Exported for panel/scripts/portal-selftest.js. See the header: these
       tables are checked against published values rather than believed. */
    _internals: {
      BLOCKS: BLOCKS,
      TOTAL: TOTAL,
      ALIGN: ALIGN,
      MIN_VERSION: MIN_VERSION,
      MAX_VERSION: MAX_VERSION,
      remainderBits: remainderBits,
      formatBits: formatBits,
      versionBits: versionBits,
      placeFunctionPatterns: placeFunctionPatterns,
      dataPositions: dataPositions,
      buildCodewords: buildCodewords,
      rsEncode: rsEncode,
      rsGenerator: rsGenerator,
      EC_BITS_M: EC_BITS_M
    }
  };
}());

/* Loadable in Node for the self-test, and a plain global in the browser. The
   guard is what lets one file be both without a build step. */
if (typeof module !== 'undefined' && module.exports) module.exports = VPN55_QR;
