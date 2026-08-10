#!/usr/bin/env python3
"""
MEDUSA Image-Embedded Threat Scanner

Detects commands / instructions hidden INSIDE image files — the class where a
coding agent ingests a PNG referenced from a repo (e.g. AGENTS.md) and follows a
hidden directive, and where an "image" is secretly also a script. MEDUSA
otherwise never opens image files, so these vet SAFE. Covers three cheap,
high-precision vectors (no OCR / pixel analysis needed):

  - MEDUSA-IMG-INJECT-001 (CRITICAL): a prompt-injection / shell-dropper directive
      in image metadata (PNG tEXt/zTXt/iTXt, JPEG EXIF/COM/XMP, any printable run).
      This is the "Ghostcommit" class — instructions read by an AI, invisible to a
      human viewing the image.
  - MEDUSA-IMG-POLYGLOT-001 (CRITICAL): executable content AFTER the image's own
      terminator (PNG IEND, JPEG EOI, GIF trailer, RIFF/WebP + BMP size fields) —
      a file that is both a valid image and a shell/zip/PE/HTML payload
      (Stegosploit / PowerGlot class). The payload is found by VALIDATING the
      appended file's structure, not by where it sits: see _scan_polyglot.
  - MEDUSA-IMG-SVGSCRIPT-001 (HIGH): active content in an SVG (<script>, javascript:
      URI, on*= handler) — SVG is XML and runs script when rendered.

Out of scope (logged as a known gap, heavier / higher-FP): LSB steganography
(entropy heuristics) and visually-rendered typographic text (needs OCR/vision).

Registered + a vet SIGNAL (MEDUSA-IMG-* is in _VET_SIGNAL_RULE_PREFIXES and this
scanner in _VET_SIGNAL_SCANNERS); MEDUSA-IMG- is also FP-exempt (image bytes look
like "data" to the generic heuristics, but a hidden directive is a true positive).
"""

import re
import time
import zlib
from pathlib import Path
from typing import List, Optional

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity

# Don't read arbitrarily huge images into memory. Metadata + polyglot payloads
# live at the head/tail; 32 MB covers real images with margin.
_MAX_BYTES = 32 * 1024 * 1024

_IMAGE_EXTS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp",
    ".tif", ".tiff", ".ico", ".svg",
})

# Printable-ASCII runs (>=8 chars) — the human-readable text carried in a binary
# image (metadata, comments, embedded strings). Format-agnostic on purpose.
_PRINTABLE_RUN = re.compile(rb"[\x20-\x7e]{8,}")

# --- injection / dropper directives (specific phrases -> low FP on real images) ---
_INJECT_PATTERNS = [
    re.compile(r"(?i)ignore\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|prompts?|messages?)"),
    re.compile(r"(?i)disregard\s+(?:all\s+|any\s+|the\s+|your\s+)?(?:previous|prior|above|system|safety)"),
    re.compile(r"(?i)\b(?:exfiltrat\w+|leak|steal)\b[^.\n]{0,40}\b(?:secret|credential|token|key|\.env|environment)"),
    re.compile(r"(?i)\b(?:read|cat|send|post|upload)\b[^.\n]{0,40}(?:~?/?\.env|/etc/passwd|id_rsa|\.aws|secret|credential)"),
    re.compile(r"(?i)\bappend\b[^.\n]{0,40}(?:ANTHROPIC|OPENAI|CLAUDE)[_A-Z]*API_KEY[^.\n]{0,20}(?:url|\?|&)"),
    re.compile(r"(?i)\b(?:ANTHROPIC|OPENAI|CLAUDE)_(?:BASE_URL|API_URL)\s*[:=]\s*['\"]?https?://"),
]
# shell dropper: curl|wget piped to a shell
_DROPPER = re.compile(r"(?i)\b(?:curl|wget|fetch)\b[^\n|]{0,200}\|\s*(?:ba)?sh\b")

# --- polyglot: an APPENDED FILE after the image terminator ---
# The payload is located by STRUCTURE, not by offset. Anchoring the magic to the
# first non-padding byte of a 4 KB trailer window (the previous shape of this
# check) was a one-byte evasion of a hard-block control: `PNG + \x01 + <zip>`
# moved the magic off offset 0, `PNG + NUL*5000 + <zip>` pushed the payload past
# the window, and the padded file is still a perfectly valid archive — the pad
# costs the attacker nothing.
#
# The precision the anchoring was bought with is bought back by VALIDATING each
# candidate instead. That matters: a bare 2-byte `MZ` turns up in ~79% of 100 KB
# spans of compressed data, which is how AdvBox's `demo_advbox.png` (a JPEG
# header with PNG image data concatenated after it) was once reported CRITICAL
# as a "PE/DOS executable". Structure kills that without an offset constraint:
#   ZIP   an end-of-central-directory record that RESOLVES — the central
#         directory and the first local file header are where it says they are
#   PE    `MZ` whose e_lfanew (uint32 LE at 0x3C) points at `PE\0\0`
#   ELF   `\x7fELF` with a sane EI_CLASS / EI_DATA / EI_VERSION
#   #!    a line-anchored shebang naming a real interpreter, inside a text region
_ZIP_LOCAL = b"PK\x03\x04"
_ZIP_CENTRAL = b"PK\x01\x02"
_ZIP_EOCD = b"PK\x05\x06"
# Compression methods ISO/IEC 21320 + PKWARE APPNOTE actually assign. A chance
# `PK\x03\x04` in compressed data lands outside this set ~99.97% of the time.
_ZIP_METHODS = frozenset({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 18, 19,
                          93, 94, 95, 96, 97, 98, 99})
_ZIP_MAX_FIELD = 4096          # sane bound on filename / extra-field lengths
_ZIP_MAX_VERSION = 63          # APPNOTE 6.3.x tops out at 6.3 -> 63
_PE_STUB_WINDOW = 0x400        # DOS-header region searched for the NT signature
# Bound every candidate walk: a trailer of nothing but `MZ` must not turn into a
# quadratic scan. Real files carry a handful of candidates, not thousands.
_MAX_CANDIDATES = 4096

# A shebang is only 3 bytes of signal, so it is the one magic that stays
# conservative: it must name a plausible interpreter, sit at the start of a line
# (or at the padding-stripped boundary), and live in a region that is text. Two
# of the three would fire on compressed bytes; all three do not.
_SHEBANG = re.compile(
    rb"#!\s{0,8}/[\w./+-]{0,64}?"
    rb"\b(?:sh|bash|zsh|ksh|dash|ash|fish|csh|tcsh|python[0-9.]*|perl|ruby|node"
    rb"|php|env|pwsh|osascript|expect|lua|awk|sed)\b")

# Appended TEXT payloads (an HTML/PHP page served out of the same file). These
# never had to sit at the boundary, and they must not be capped at 4 KB either —
# but a short ASCII signature is only meaningful inside a region that reads as
# text, never inside compressed image bytes.
_TRAILER_TEXT = [
    (re.compile(rb"(?i)<\s*script"), "HTML <script>"),
    (re.compile(rb"(?i)<\?php"), "PHP code"),
    (re.compile(rb"(?i)<\s*html"), "HTML document"),
    (re.compile(rb"(?i)\beval\s*\("), "eval() call"),
]
# Bytes a human-readable payload is made of (printable ASCII + ordinary
# whitespace). A region must be overwhelmingly these to be searched as text.
_TEXTY = frozenset(range(0x20, 0x7f)) | {0x09, 0x0a, 0x0d}
_TEXTY_RATIO = 0.9
_TEXTY_SAMPLE = 512
# The region is measured FORWARD from the hit — an HTML payload appended after
# 5 KB of NUL padding is still text, and judging it on the padding in front of it
# would miss it. Only when too few bytes follow (a signature sitting at the very
# end of the file, where a 7-byte run reads as "100% text") is the window
# extended backwards, so a fragment inside compressed bytes can't qualify.
_TEXTY_MIN = 32

_PNG_SIG = b"\x89PNG\r\n\x1a\n"
_PADDING = b"\x00\r\n\t "

# --- SVG active content ---
_SVG_ACTIVE = [
    (re.compile(r"(?i)<\s*script\b"), "SVG <script> element"),
    (re.compile(r"(?i)\son\w+\s*="), "SVG inline event handler (on*=)"),
    (re.compile(r"(?i)javascript\s*:"), "SVG javascript: URI"),
    (re.compile(r"(?i)<\s*foreignObject\b"), "SVG <foreignObject> (HTML embedding)"),
]


class ImageEmbeddedThreatScanner(BaseScanner):
    """Vets image files for embedded commands, polyglot payloads, and SVG script."""

    display_name = "Image Embedded Threat"
    description = (
        "Detects commands/instructions hidden in image metadata (Ghostcommit), "
        "polyglot image+script files, and active content in SVGs."
    )

    def get_tool_name(self) -> str:
        return "python"

    def get_file_extensions(self) -> List[str]:
        return list(_IMAGE_EXTS)

    def can_scan(self, file_path: Path) -> bool:
        return file_path.suffix.lower() in _IMAGE_EXTS

    def get_confidence_score(self, file_path: Path,
                             content_head: Optional[str] = None) -> int:
        return 90 if self.can_scan(file_path) else 0

    def is_available(self) -> bool:
        return True

    def scan_file(self, file_path: Path) -> ScannerResult:
        start = time.time()
        issues: List[ScannerIssue] = []
        try:
            with open(file_path, "rb") as fh:
                data = fh.read(_MAX_BYTES + 1)
        except (OSError, IOError) as e:
            return ScannerResult(self.name, str(file_path), [], time.time() - start, False, str(e))
        if len(data) > _MAX_BYTES:
            data = data[:_MAX_BYTES]

        suffix = file_path.suffix.lower()

        # SVG is text/XML — check for active content directly.
        if suffix == ".svg":
            issues.extend(self._scan_svg(data))

        # Metadata / embedded-text injection (all raster formats + svg text).
        issues.extend(self._scan_embedded_text(data))

        # Polyglot: executable content after the image terminator.
        issues.extend(self._scan_polyglot(data, suffix))

        return ScannerResult(self.name, str(file_path), issues, time.time() - start, True)

    # ------------------------------------------------------------------ #
    def _scan_embedded_text(self, data: bytes) -> List[ScannerIssue]:
        issues: List[ScannerIssue] = []
        seen: set = set()
        # Include zTXt/iTXt decompressed PNG text so a compressed hidden directive
        # is not missed, then all printable runs across the file.
        texts = self._png_text_chunks(data)
        for m in _PRINTABLE_RUN.finditer(data):
            try:
                texts.append(m.group(0).decode("ascii", "ignore"))
            except Exception:
                continue
        blob = "\n".join(texts)

        for pat in _INJECT_PATTERNS:
            hit = pat.search(blob)
            if hit and pat.pattern not in seen:
                seen.add(pat.pattern)
                issues.append(ScannerIssue(
                    severity=Severity.CRITICAL, line=1, rule_id="MEDUSA-IMG-INJECT-001",
                    cwe_id=506,
                    message=("Image metadata contains a hidden prompt-injection / exfiltration "
                             f"directive: '{hit.group(0)[:80]}' — a directive an AI agent reads "
                             "from the image but a human viewing it never sees (Ghostcommit class)"),
                ))
        drop = _DROPPER.search(blob)
        if drop:
            issues.append(ScannerIssue(
                severity=Severity.CRITICAL, line=1, rule_id="MEDUSA-IMG-INJECT-001", cwe_id=506,
                message=("Image metadata contains a shell dropper command: "
                         f"'{drop.group(0)[:80]}'"),
            ))
        return issues

    def _png_text_chunks(self, data: bytes) -> List[str]:
        """Extract PNG tEXt/zTXt/iTXt payloads (zTXt decompressed)."""
        out: List[str] = []
        if not data.startswith(b"\x89PNG\r\n\x1a\n"):
            return out
        i = 8
        n = len(data)
        while i + 8 <= n:
            try:
                length = int.from_bytes(data[i:i + 4], "big")
                ctype = data[i + 4:i + 8]
            except Exception:
                break
            body = data[i + 8:i + 8 + length]
            if ctype == b"tEXt":
                out.append(body.replace(b"\x00", b" ").decode("latin-1", "ignore"))
            elif ctype == b"zTXt":
                try:
                    kw, rest = body.split(b"\x00", 1)
                    out.append(zlib.decompress(rest[1:]).decode("latin-1", "ignore"))
                except Exception:
                    pass
            elif ctype == b"iTXt":
                out.append(body.replace(b"\x00", b" ").decode("utf-8", "ignore"))
            if ctype == b"IEND":
                break
            i += 12 + length  # length + type + data + crc
            if length < 0 or i <= 0:
                break
        return out

    def _scan_polyglot(self, data: bytes, suffix: str) -> List[ScannerIssue]:
        # Find the image's own terminator; anything of substance after it is a
        # polyglot payload. The WHOLE trailer is searched — a fixed window meant
        # 5 KB of free padding hid the payload completely.
        term = self._image_end(data)
        if term is None or term >= len(data):
            return []
        tail = data[term:]
        if not tail.strip(_PADDING):
            return []  # padding only — nothing was appended

        # Offsets inside a ZIP are relative to the archive base, which a reader
        # derives from the file end, so the ZIP check runs against the whole
        # buffer and is merely required to live past the terminator.
        if self._find_zip(data, term):
            return [self._polyglot_issue("ZIP archive")]
        if self._find_pe(data, term):
            return [self._polyglot_issue("PE/DOS executable")]
        if self._find_elf(data, term):
            return [self._polyglot_issue("ELF executable")]
        if self._find_shebang(tail):
            return [self._polyglot_issue("shell/interpreter shebang")]
        for pat, desc in _TRAILER_TEXT:
            for m in pat.finditer(tail):
                if self._texty_at(tail, m.start()):
                    return [self._polyglot_issue(desc)]
        return []

    # --- image terminators ------------------------------------------------- #
    @staticmethod
    def _image_end(data: bytes) -> Optional[int]:
        """Offset just past the image's own terminator, or None if unknown.

        Parsed FORWARD wherever the container allows it. `rfind`-ing the
        terminator — the previous approach — let an attacker relocate the
        boundary by planting the terminator bytes INSIDE their own payload
        (`PNG + <PE> + b"IEND"`, or a zip entry literally named `IEND`), which
        moved the boundary past the payload and hid it. Forward parsing is
        authoritative; the old rfind heuristic stays as the fallback for the
        malformed/truncated images a strict parser cannot walk.
        """
        n = len(data)
        if data.startswith(_PNG_SIG):
            end = ImageEmbeddedThreatScanner._png_end(data)
            if end is not None:
                return end
            idx = data.rfind(b"IEND")
            return idx + 8 if idx != -1 else None  # IEND + 4-byte CRC
        if data[:2] == b"\xff\xd8":  # JPEG
            end = ImageEmbeddedThreatScanner._jpeg_end(data)
            if end is not None:
                return end
            idx = data.rfind(b"\xff\xd9")
            return idx + 2 if idx != -1 else None
        if data[:6] in (b"GIF87a", b"GIF89a"):
            end = ImageEmbeddedThreatScanner._gif_end(data)
            if end is not None:
                return end
            idx = data.rfind(b"\x00\x3b")  # block terminator + trailer
            return idx + 2 if idx != -1 else None
        # RIFF/WebP and BMP both carry an EXACT size field, so their boundary is
        # read rather than searched. They had no terminator handling at all,
        # which meant 100% of appended payloads in a .webp/.bmp were missed.
        if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
            size = int.from_bytes(data[4:8], "little")
            end = 8 + size + (size & 1)  # RIFF chunks are word-aligned
            return end if 12 <= size and end <= n else None
        if data[:2] == b"BM" and n >= 26:
            size = int.from_bytes(data[2:6], "little")
            # Writers that leave this field 0/garbage must not turn the pixel
            # data itself into a "trailer".
            return size if 26 <= size <= n else None
        return None

    @staticmethod
    def _png_end(data: bytes) -> Optional[int]:
        """Walk the PNG chunk chain to the real IEND (length+type+data+CRC)."""
        n = len(data)
        i = 8
        while i + 12 <= n:
            length = int.from_bytes(data[i:i + 4], "big")
            if data[i + 4:i + 8] == b"IEND":
                return min(i + 12, n)
            nxt = i + 12 + length
            if nxt <= i or nxt > n:
                return None
            i = nxt
        return None

    @staticmethod
    def _jpeg_end(data: bytes) -> Optional[int]:
        """Walk JPEG markers to the real EOI.

        Segment lengths are honoured, so an EXIF thumbnail's own EOI is skipped;
        entropy-coded data is scanned with FF-stuffing and restart markers
        accounted for, so a raw \\xff\\xd9 there is genuinely the end of image.
        """
        n = len(data)
        i = 2
        while i + 1 < n:
            if data[i] != 0xFF:
                return None  # malformed — caller falls back to rfind
            j = i + 1
            while j < n and data[j] == 0xFF:  # fill bytes before the marker
                j += 1
            if j >= n:
                return None
            marker = data[j]
            if marker == 0xD9:  # EOI
                return j + 1
            if marker == 0x01 or 0xD0 <= marker <= 0xD8:  # standalone markers
                i = j + 1
                continue
            if j + 3 > n:
                return None
            seg = int.from_bytes(data[j + 1:j + 3], "big")
            if seg < 2:
                return None
            i = j + 1 + seg
            if marker == 0xDA:  # SOS — entropy-coded data follows the header
                k = i
                while True:
                    k = data.find(b"\xff", k)
                    if k == -1 or k + 1 >= n:
                        return None
                    nxt = data[k + 1]
                    if nxt == 0x00:            # stuffed FF, part of the stream
                        k += 2
                    elif 0xD0 <= nxt <= 0xD7:  # restart marker
                        k += 2
                    elif nxt == 0xFF:          # fill byte
                        k += 1
                    else:
                        break
                i = k
        return None

    @staticmethod
    def _gif_end(data: bytes) -> Optional[int]:
        """Walk GIF blocks to the 0x3B trailer."""
        n = len(data)
        if n < 13:
            return None
        packed = data[10]
        i = 13
        if packed & 0x80:  # global colour table
            i += 3 * (2 ** ((packed & 0x07) + 1))
        while i < n:
            block = data[i]
            if block == 0x3B:  # trailer
                return i + 1
            if block == 0x21:  # extension: introducer + label, then sub-blocks
                i += 2
            elif block == 0x2C:  # image descriptor
                if i + 10 > n:
                    return None
                local = data[i + 9]
                i += 10
                if local & 0x80:  # local colour table
                    i += 3 * (2 ** ((local & 0x07) + 1))
                i += 1  # LZW minimum code size
            else:
                return None
            while i < n and data[i]:  # sub-block chain
                i += 1 + data[i]
            if i >= n:
                return None
            i += 1  # the zero-length block terminator
        return None

    # --- appended-file validators ------------------------------------------ #
    @staticmethod
    def _find_zip(data: bytes, term: int) -> bool:
        """True if a real ZIP is appended.

        Primary check is the end-of-central-directory record, read backwards
        from the file end the way every ZIP reader does: the archive base is
        `eocd - cd_size - cd_offset`, and a genuine archive has `PK\\x01\\x02`
        at the central-directory offset and `PK\\x03\\x04` where that entry says
        its local header lives. Two computed 4-byte hits do not happen by
        chance; a coincidental `PK\\x03\\x04` in compressed data has neither.
        """
        n = len(data)
        end = n
        for _ in range(_MAX_CANDIDATES):
            pos = data.rfind(_ZIP_EOCD, term, end)
            if pos == -1:
                break
            end = pos  # next iteration looks strictly earlier
            if pos + 22 > n:
                continue
            entries = int.from_bytes(data[pos + 10:pos + 12], "little")
            cd_size = int.from_bytes(data[pos + 12:pos + 16], "little")
            cd_off = int.from_bytes(data[pos + 16:pos + 20], "little")
            base = pos - cd_size - cd_off
            if base < 0 or base > pos:
                continue
            if entries == 0:
                # An empty archive is nothing but the EOCD; require it to
                # actually terminate the file, comment length included.
                comment = int.from_bytes(data[pos + 20:pos + 22], "little")
                if cd_size == 0 and pos + 22 + comment == n:
                    return True
                continue
            cd = base + cd_off
            if data[cd:cd + 4] != _ZIP_CENTRAL:
                continue
            local = int.from_bytes(data[cd + 42:cd + 46], "little")
            if data[base + local:base + local + 4] == _ZIP_LOCAL:
                return True
        # Fallback: a streamed or truncated append carries local file headers
        # with no EOCD. Then the header itself has to be coherent — 4 magic
        # bytes plus five agreeing fields, not a 4-byte coincidence.
        start = term
        for _ in range(_MAX_CANDIDATES):
            pos = data.find(_ZIP_LOCAL, start)
            if pos == -1:
                return False
            start = pos + 4
            if ImageEmbeddedThreatScanner._zip_local_header_ok(data, pos):
                return True
        return False

    @staticmethod
    def _zip_local_header_ok(data: bytes, pos: int) -> bool:
        if pos + 30 > len(data):
            return False
        def u16(off: int) -> int:
            return int.from_bytes(data[pos + off:pos + off + 2], "little")

        version, flags, method = u16(4), u16(6), u16(8)
        name_len, extra_len = u16(26), u16(28)
        if version > _ZIP_MAX_VERSION or flags & 0xF000:
            return False
        if method not in _ZIP_METHODS:
            return False
        if name_len > _ZIP_MAX_FIELD or extra_len > _ZIP_MAX_FIELD:
            return False
        name = data[pos + 30:pos + 30 + name_len]
        if len(name) != name_len:
            return False
        # ZIP names are CP437/UTF-8 paths — never control characters.
        return all(b >= 0x20 and b != 0x7f for b in name)

    @staticmethod
    def _find_pe(data: bytes, term: int) -> bool:
        """True if a real PE is appended. `MZ` alone is two bytes of noise; the
        NT signature reached through e_lfanew is what makes it an executable."""
        n = len(data)
        start = term
        for _ in range(_MAX_CANDIDATES):
            pos = data.find(b"MZ", start)
            if pos == -1:
                return False
            start = pos + 2
            if pos + 0x40 > n:
                return False
            e_lfanew = int.from_bytes(data[pos + 0x3c:pos + 0x40], "little")
            if 4 <= e_lfanew and pos + e_lfanew + 4 <= n and \
                    data[pos + e_lfanew:pos + e_lfanew + 4] == b"PE\x00\x00":
                return True
            # Hand-built / truncated stubs put the NT signature inline instead of
            # behind a valid e_lfanew. Still four exact bytes inside the DOS
            # header region, so the AdvBox chance-`MZ` case stays dead (a 1 KB
            # window of compressed data carries `PE\0\0` at odds of ~2e-7).
            if b"PE\x00\x00" in data[pos:pos + _PE_STUB_WINDOW]:
                return True
        return False

    @staticmethod
    def _find_elf(data: bytes, term: int) -> bool:
        n = len(data)
        start = term
        for _ in range(_MAX_CANDIDATES):
            pos = data.find(b"\x7fELF", start)
            if pos == -1:
                return False
            start = pos + 4
            if pos + 7 > n:
                return False
            # EI_CLASS 32/64-bit, EI_DATA little/big-endian, EI_VERSION current.
            if data[pos + 4] in (1, 2) and data[pos + 5] in (1, 2) \
                    and data[pos + 6] == 1:
                return True
        return False

    @staticmethod
    def _find_shebang(tail: bytes) -> bool:
        for m in _SHEBANG.finditer(tail):
            pos = m.start()
            # Must open a line. Position 0 of the trailer counts, and so does a
            # position reached over nothing but padding — that IS the boundary.
            if pos and tail[pos - 1:pos] != b"\n" and tail[:pos].strip(_PADDING):
                continue
            if ImageEmbeddedThreatScanner._texty_at(tail, pos):
                return True
        return False

    @staticmethod
    def _polyglot_issue(desc: str) -> ScannerIssue:
        return ScannerIssue(
            severity=Severity.CRITICAL, line=1, rule_id="MEDUSA-IMG-POLYGLOT-001",
            cwe_id=506,
            message=(f"Polyglot file: {desc} appended after the image terminator — the "
                     "file is both a valid image and executable content"),
        )

    @staticmethod
    def _texty_at(tail: bytes, pos: int) -> bool:
        """True if the payload starting at `pos` reads as text. Bounded window
        instead of the head of the trailer, so a text payload appended after
        binary padding is judged on itself and not on the padding."""
        hi = min(len(tail), pos + _TEXTY_SAMPLE)
        lo = pos if hi - pos >= _TEXTY_MIN else max(0, hi - _TEXTY_MIN)
        return ImageEmbeddedThreatScanner._is_text(tail[lo:hi])

    @staticmethod
    def _is_text(region: bytes) -> bool:
        """True if a region reads as human text rather than binary. Short ASCII
        signatures (`<script`, `eval(`, `#!/bin/sh`) turn up by chance in
        compressed image data, so they only mean something inside text."""
        sample = region[:_TEXTY_SAMPLE]
        if not sample:
            return False
        return sum(b in _TEXTY for b in sample) / len(sample) >= _TEXTY_RATIO

    def _scan_svg(self, data: bytes) -> List[ScannerIssue]:
        text = data.decode("utf-8", "ignore")
        if "<svg" not in text.lower():
            return []
        issues: List[ScannerIssue] = []
        for pat, desc in _SVG_ACTIVE:
            if pat.search(text):
                issues.append(ScannerIssue(
                    severity=Severity.HIGH, line=1, rule_id="MEDUSA-IMG-SVGSCRIPT-001",
                    cwe_id=79,
                    message=f"Active content in SVG: {desc} — runs when the SVG is rendered",
                ))
        return issues
