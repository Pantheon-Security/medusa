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
      terminator (PNG IEND / JPEG EOI) — a file that is both a valid image and a
      shell/zip/PE/HTML payload (Stegosploit / PowerGlot class).
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

# --- polyglot: executable magic AFTER the image terminator ---
_TRAILER_SIGNATURES = [
    (rb"#!\s*/", "shell/interpreter shebang"),
    (rb"PK\x03\x04", "ZIP archive"),
    (rb"MZ", "PE/DOS executable"),
    (rb"\x7fELF", "ELF executable"),
    (rb"(?i)<\s*script", "HTML <script>"),
    (rb"(?i)<\?php", "PHP code"),
    (rb"(?i)<\s*html", "HTML document"),
    (rb"(?i)\beval\s*\(", "eval() call"),
]

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
        # polyglot payload.
        term = None
        if data.startswith(b"\x89PNG\r\n\x1a\n"):
            idx = data.rfind(b"IEND")
            if idx != -1:
                term = idx + 8  # IEND + 4-byte CRC
        elif data[:2] == b"\xff\xd8":  # JPEG
            idx = data.rfind(b"\xff\xd9")
            if idx != -1:
                term = idx + 2
        elif data[:6] in (b"GIF87a", b"GIF89a"):
            idx = data.rfind(b"\x00\x3b")  # trailer
            if idx != -1:
                term = idx + 2
        if term is None or term >= len(data):
            return []
        trailer = data[term:term + 4096]
        if not trailer.strip(b"\x00\r\n\t "):
            return []
        for sig, desc in _TRAILER_SIGNATURES:
            if re.search(sig, trailer):
                return [ScannerIssue(
                    severity=Severity.CRITICAL, line=1, rule_id="MEDUSA-IMG-POLYGLOT-001",
                    cwe_id=506,
                    message=(f"Polyglot file: {desc} appended after the image terminator — the "
                             "file is both a valid image and executable content"),
                )]
        return []

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
