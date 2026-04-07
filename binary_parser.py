"""
Binary Parser — Format Detection & Structure Extraction
Handles: ELF (.so / executables), PE, Mach-O, DEX,
         ZIP/APK, GZIP, ZLIB, LZ4, ZSTD, LZMA, BZ2, RAW.
Low-entropy pass → deep structural scan.
High-entropy pass → defer to cross-correlation stage.
"""

from __future__ import annotations
import struct, io, os, math, zlib, gzip, lzma, bz2, base64, re
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple
from enum import Enum

# ── Optional deps ────────────────────────────────────────────────────────────
try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    from elftools.elf.dynamic import DynamicSection
    PYELFTOOLS = True
except ImportError:
    PYELFTOOLS = False

try:
    import lz4.frame as lz4f
    LZ4_OK = True
except ImportError:
    LZ4_OK = False

try:
    import zstandard as zstd
    ZSTD_OK = True
except ImportError:
    ZSTD_OK = False

# ── Format catalogue ─────────────────────────────────────────────────────────

class BinaryFormat(str, Enum):
    UNKNOWN   = "UNKNOWN"
    ELF       = "ELF"
    PE        = "PE/COFF"
    MACHO     = "Mach-O"
    DEX       = "DEX"
    ZIP       = "ZIP/APK"
    GZIP      = "GZIP"
    ZLIB      = "ZLIB"
    LZ4       = "LZ4"
    ZSTD      = "ZSTD"
    LZMA      = "LZMA/XZ"
    BZ2       = "BZ2"
    PNG       = "PNG"
    RAW       = "RAW"


MAGIC_TABLE: List[Tuple[bytes, BinaryFormat]] = [
    (b'\x7fELF',             BinaryFormat.ELF),
    (b'MZ',                  BinaryFormat.PE),
    (b'\xca\xfe\xba\xbe',   BinaryFormat.MACHO),
    (b'\xce\xfa\xed\xfe',   BinaryFormat.MACHO),
    (b'\xcf\xfa\xed\xfe',   BinaryFormat.MACHO),
    (b'dex\n',               BinaryFormat.DEX),
    (b'PK\x03\x04',          BinaryFormat.ZIP),
    (b'\x1f\x8b',            BinaryFormat.GZIP),
    (b'\x78\x9c',            BinaryFormat.ZLIB),
    (b'\x78\x01',            BinaryFormat.ZLIB),
    (b'\x78\xda',            BinaryFormat.ZLIB),
    (b'\x04\x22\x4d\x18',   BinaryFormat.LZ4),
    (b'\x02\x21\x4c\x18',   BinaryFormat.LZ4),
    (b'\x28\xb5\x2f\xfd',   BinaryFormat.ZSTD),
    (b'\xfd7zXZ\x00',        BinaryFormat.LZMA),
    (b'BZh',                 BinaryFormat.BZ2),
    (b'\x89PNG',             BinaryFormat.PNG),
]

ELF_ARCH_MAP = {
    0x03: 'x86',   0x3e: 'x86_64',
    0x28: 'ARM',   0xb7: 'AArch64',
    0x08: 'MIPS',  0x16: 'PowerPC',
    0xf3: 'RISC-V',
}

# ── Data classes ─────────────────────────────────────────────────────────────

@dataclass
class BinSection:
    name:    str
    offset:  int
    size:    int
    vaddr:   int   = 0
    flags:   str   = ""
    entropy: float = 0.0
    # Small data preview (first 256 bytes)
    preview: bytes = field(default=b'', repr=False)


@dataclass
class BinSymbol:
    name:    str
    address: int
    size:    int
    kind:    str


@dataclass
class EmbeddedRegion:
    offset:    int
    kind:      str         # GZIP / ZLIB / ELF / ZIP / …
    size_hint: int
    entropy:   float
    decompressed_data: Optional[bytes] = field(default=None, repr=False)


@dataclass
class ParseResult:
    fmt:       BinaryFormat         = BinaryFormat.UNKNOWN
    arch:      str                  = "unknown"
    bits:      int                  = 0
    endian:    str                  = "little"
    entry:     int                  = 0
    sections:  List[BinSection]     = field(default_factory=list)
    symbols:   List[BinSymbol]      = field(default_factory=list)
    imports:   List[str]            = field(default_factory=list)
    strings:   List[str]            = field(default_factory=list)
    deobfuscated_strings: List[str]   = field(default_factory=list)
    embedded:  List[EmbeddedRegion] = field(default_factory=list)
    size:      int                  = 0
    errors:    List[str]            = field(default_factory=list)
    raw:       bytes                = field(default=b'', repr=False)
    # If this binary was decompressed from a parent
    decomp_from: Optional[str]      = None
    # Recursively parsed inner binary (after decompression)
    inner:     Optional['ParseResult'] = None


# ── Pure functions ────────────────────────────────────────────────────────────

def calc_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    cnt = [0] * 256
    for b in data:
        cnt[b] += 1
    n   = len(data)
    H   = 0.0
    for c in cnt:
        if c:
            p = c / n
            H -= p * math.log2(p)
    return H


def detect_format(data: bytes) -> BinaryFormat:
    for magic, fmt in MAGIC_TABLE:
        if data[:len(magic)] == magic:
            return fmt
    return BinaryFormat.UNKNOWN


def try_decompress(data: bytes) -> Optional[Tuple[str, bytes]]:
    """Attempt all known decompression methods in order."""
    # ZLIB
    try:
        return ('ZLIB', zlib.decompress(data))
    except Exception:
        pass
    # GZIP
    try:
        return ('GZIP', gzip.decompress(data))
    except Exception:
        pass
    # LZMA / XZ
    try:
        return ('LZMA', lzma.decompress(data))
    except Exception:
        pass
    # BZ2
    try:
        return ('BZ2', bz2.decompress(data))
    except Exception:
        pass
    # LZ4
    if LZ4_OK:
        try:
            return ('LZ4', lz4f.decompress(data))
        except Exception:
            pass
    # ZSTD
    if ZSTD_OK:
        try:
            dctx = zstd.ZstdDecompressor()
            return ('ZSTD', dctx.decompress(data, max_output_size=200 * 1024 * 1024))
        except Exception:
            pass
    return None


def extract_strings(data: bytes, min_len: int = 5) -> List[str]:
    """Extract printable ASCII strings of minimum length."""
    result, buf = [], []
    for b in data:
        if 0x20 <= b < 0x7f:
            buf.append(chr(b))
        else:
            if len(buf) >= min_len:
                result.append(''.join(buf))
            buf = []
    if len(buf) >= min_len:
        result.append(''.join(buf))
    return result[:500]


def _is_printable(text: str) -> bool:
    return all(0x20 <= ord(ch) < 0x7f for ch in text)


def _decode_xor_candidates(data: bytes, min_len: int = 6) -> List[str]:
    candidates = []
    if not data:
        return candidates
    for key in range(1, 256):
        decoded = bytes(b ^ key for b in data)
        try:
            text = decoded.decode('utf-8', errors='ignore')
        except Exception:
            continue
        if len(text) >= min_len and _is_printable(text[:min_len]):
            candidates.append(text)
    return candidates[:20]


def _decode_base64_strings(strings: List[str]) -> List[str]:
    decoded = []
    for s in strings:
        if len(s) < 8 or len(s) % 4 != 0:
            continue
        if re.fullmatch(r'[A-Za-z0-9+/=]+', s):
            try:
                raw = base64.b64decode(s, validate=True)
                if _is_printable(raw.decode('utf-8', errors='ignore')):
                    decoded.append(raw.decode('utf-8', errors='ignore'))
            except Exception:
                pass
    return decoded


def decode_obfuscated_strings(data: bytes, min_len: int = 5) -> List[str]:
    """Try math-based and heuristic decoding on raw bytes to recover hidden strings."""
    result = []
    raw_strings = extract_strings(data, min_len=min_len)

    # Keep discovered raw strings
    result.extend(raw_strings)

    # Detect and decode base64-encoded strings
    result.extend(_decode_base64_strings(raw_strings))

    # XOR-sweep a small sample to detect obfuscated strings
    sample = data[:4096]
    result.extend(_decode_xor_candidates(sample, min_len=min_len))

    # Numeric arithmetic patterns (e.g. "65+66")
    exprs = re.findall(r'(?:\d{2,3}[\+\-\*/]\d{2,3}){1,3}', data.decode('utf-8', errors='ignore'))
    for expr in exprs:
        try:
            value = eval(expr)
            if isinstance(value, int) and 32 <= value < 127:
                result.append(chr(value))
        except Exception:
            pass

    unique = []
    for item in result:
        if item not in unique and len(item) >= min_len:
            unique.append(item)
    return unique[:500]


def scan_embedded(data: bytes, step: int = 128) -> List[EmbeddedRegion]:
    """
    Slide over the file and look for embedded magic signatures.
    Low-entropy sections: attempt decompression immediately.
    High-entropy sections: record for later correlation.
    """
    PATTERNS = [
        (b'\x7fELF',             'ELF'),
        (b'\x1f\x8b',            'GZIP'),
        (b'\x78\x9c',            'ZLIB'),
        (b'\x78\xda',            'ZLIB_MAX'),
        (b'\x78\x01',            'ZLIB_LOW'),
        (b'\x28\xb5\x2f\xfd',   'ZSTD'),
        (b'\xfd7zXZ\x00',        'XZ/LZMA'),
        (b'PK\x03\x04',          'ZIP'),
        (b'\x04\x22\x4d\x18',   'LZ4'),
        (b'BZh',                 'BZ2'),
    ]
    regions: List[EmbeddedRegion] = []
    seen_offsets = set()
    n = len(data)

    i = 0
    while i < n - 4:
        for magic, kind in PATTERNS:
            ml = len(magic)
            if data[i:i + ml] == magic and i not in seen_offsets:
                seen_offsets.add(i)
                window = data[i: min(i + 1024, n)]
                ent    = calc_entropy(window)
                size_hint = min(n - i, 8 * 1024 * 1024)

                decomp = None
                if ent < 7.0:          # Low entropy → try decompression now
                    res = try_decompress(data[i: i + size_hint])
                    if res:
                        decomp = res[1]

                regions.append(EmbeddedRegion(
                    offset=i, kind=kind,
                    size_hint=size_hint,
                    entropy=ent,
                    decompressed_data=decomp,
                ))
                break
        i += step

    return regions


# ── ELF parser ───────────────────────────────────────────────────────────────

def _parse_elf_basic(data: bytes, result: ParseResult):
    """Minimal ELF parsing without pyelftools (header only)."""
    if len(data) < 64:
        result.errors.append("ELF file too short for header")
        return
    ei_class = data[4]
    ei_data  = data[5]
    result.bits   = 64 if ei_class == 2 else 32
    result.endian = 'big' if ei_data == 2 else 'little'
    e_mach = struct.unpack_from('<H', data, 18)[0]
    result.arch = ELF_ARCH_MAP.get(e_mach, f'e_machine=0x{e_mach:x}')
    fmt_e = '<Q' if result.bits == 64 else '<I'
    off_e = 24
    result.entry = struct.unpack_from(fmt_e, data, off_e)[0]

    # Section headers (best-effort without pyelftools)
    if result.bits == 64:
        sh_off_off, sh_ent, sh_num, sh_str_idx = 40, 64, struct.unpack_from('<H', data, 60)[0], struct.unpack_from('<H', data, 62)[0]
        e_shoff = struct.unpack_from('<Q', data, 40)[0]
    else:
        e_shoff = struct.unpack_from('<I', data, 32)[0]
        sh_ent  = struct.unpack_from('<H', data, 46)[0]
        sh_num  = struct.unpack_from('<H', data, 48)[0]
        sh_str_idx = struct.unpack_from('<H', data, 50)[0]

    result.sections.append(BinSection(
        name='(raw)', offset=0, size=len(data),
        entropy=calc_entropy(data[:4096])
    ))


def _parse_elf_full(data: bytes, result: ParseResult):
    """Full ELF parsing via pyelftools."""
    try:
        f   = ELFFile(io.BytesIO(data))
        result.arch   = f.get_machine_arch()
        result.bits   = f.elfclass
        result.endian = 'big' if not f.little_endian else 'little'
        result.entry  = f.header.e_entry

        for sec in f.iter_sections():
            raw = sec.data() or b''
            result.sections.append(BinSection(
                name    = sec.name,
                offset  = sec['sh_offset'],
                size    = sec['sh_size'],
                vaddr   = sec['sh_addr'],
                flags   = hex(sec['sh_flags']),
                entropy = calc_entropy(raw),
                preview = raw[:256],
            ))

        for sec in f.iter_sections():
            if isinstance(sec, SymbolTableSection):
                for sym in sec.iter_symbols():
                    if sym.name:
                        result.symbols.append(BinSymbol(
                            name    = sym.name,
                            address = sym['st_value'],
                            size    = sym['st_size'],
                            kind    = sym['st_info']['type'],
                        ))

        for sec in f.iter_sections():
            if isinstance(sec, DynamicSection):
                for tag in sec.iter_tags():
                    if tag.entry.d_tag == 'DT_NEEDED':
                        result.imports.append(tag.needed)

    except Exception as ex:
        result.errors.append(f"pyelftools error: {ex}")
        _parse_elf_basic(data, result)


def _parse_pe_basic(data: bytes, result: ParseResult):
    """PE/COFF minimal header parse."""
    result.arch = "x86/x86_64"
    result.bits = 32
    try:
        if len(data) >= 0x40:
            pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
            if pe_offset + 6 < len(data):
                machine = struct.unpack_from('<H', data, pe_offset + 4)[0]
                if machine == 0x8664:
                    result.arch = 'x86_64'
                    result.bits = 64
                elif machine == 0x014c:
                    result.arch = 'x86'
                    result.bits = 32
                elif machine == 0x01c4:
                    result.arch = 'ARMv7'
                elif machine == 0xaa64:
                    result.arch = 'AArch64'
                    result.bits = 64
    except Exception as ex:
        result.errors.append(f"PE parse: {ex}")


# ── Main entry ────────────────────────────────────────────────────────────────

def parse_binary(data: bytes,
                 medical_unit=None,
                 recurse: bool = True) -> ParseResult:
    """
    Parse a binary blob:
    1. Detect format via magic bytes
    2. Extract structure (ELF sections, PE header, …)
    3. Compute entropy per section
    4. Scan for embedded regions
    5. Recurse on decompressed data (if recurse=True)
    """

    def _run() -> ParseResult:
        result = ParseResult(fmt=detect_format(data), size=len(data), raw=data)

        if result.fmt == BinaryFormat.ELF:
            if PYELFTOOLS:
                _parse_elf_full(data, result)
            else:
                result.errors.append(
                    "pyelftools not installed — basic ELF parsing only")
                _parse_elf_basic(data, result)

        elif result.fmt == BinaryFormat.PE:
            _parse_pe_basic(data, result)

        elif result.fmt in (BinaryFormat.GZIP, BinaryFormat.ZLIB,
                            BinaryFormat.LZ4, BinaryFormat.ZSTD,
                            BinaryFormat.LZMA, BinaryFormat.BZ2):
            decomp = try_decompress(data)
            if decomp and recurse:
                method, inner_data = decomp
                result.inner = parse_binary(inner_data, medical_unit, recurse=False)
                result.inner.decomp_from = method
            elif not decomp:
                result.errors.append("Decompression failed despite matching magic")

        # Always scan for embedded regions
        result.embedded = scan_embedded(data)

        # Extract strings (first 1 MB)
        result.strings = extract_strings(data[:1_048_576])
        result.deobfuscated_strings = decode_obfuscated_strings(data[:1_048_576])

        # Compute overall section entropies
        for sec in result.sections:
            if sec.entropy == 0.0 and sec.size > 0:
                off  = sec.offset
                blob = data[off: off + min(sec.size, 65536)]
                sec.entropy = calc_entropy(blob)

        return result

    if medical_unit:
        ok, res, err = medical_unit.guard('BinaryParser', _run)
        if not ok:
            r = ParseResult(errors=[err or 'parse failed'])
            return r
        return res
    return _run()


# ── Entropy-based pre-filter ─────────────────────────────────────────────────

def entropy_prefilter(result: ParseResult,
                      low_thresh: float = 3.0,
                      high_thresh: float = 7.5) -> Dict[str, List]:
    """
    Split sections into three buckets:
      low_entropy   → may contain ELF, compressed data, etc. → deep scan
      mid_entropy   → standard code/data → standard analysis
      high_entropy  → encrypted / already compressed → defer to correlation
    """
    low, mid, high = [], [], []
    for sec in result.sections:
        if sec.entropy < low_thresh:
            low.append(sec)
        elif sec.entropy > high_thresh:
            high.append(sec)
        else:
            mid.append(sec)
    return {'low': low, 'mid': mid, 'high': high}


def section_summary(result: ParseResult) -> str:
    lines = [
        f"Format  : {result.fmt.value}",
        f"Arch    : {result.arch}  ({result.bits}-bit {result.endian}-endian)",
        f"Entry   : 0x{result.entry:08x}",
        f"Size    : {result.size:,} bytes",
        f"Sections: {len(result.sections)}",
        f"Symbols : {len(result.symbols)}",
        f"Imports : {len(result.imports)}",
        f"Embedded: {len(result.embedded)}",
        f"Strings : {len(result.strings)}",
    ]
    if result.errors:
        lines.append(f"Errors  : {len(result.errors)}")
    if result.sections:
        lines.append("")
        lines.append("SECTIONS:")
        lines.append(f"  {'Name':<20} {'Offset':>10} {'Size':>10} {'Entropy':>8}")
        lines.append("  " + "-" * 52)
        for s in result.sections[:30]:
            bar  = "█" * int(s.entropy)
            lines.append(
                f"  {s.name:<20} 0x{s.offset:08x} {s.size:>10,}  {s.entropy:6.3f} {bar}"
            )
    if result.embedded:
        lines.append("")
        lines.append("EMBEDDED REGIONS:")
        for e in result.embedded[:15]:
            tag = "✓ decompressed" if e.decompressed_data else ""
            lines.append(
                f"  0x{e.offset:08x}  {e.kind:<12} H={e.entropy:.2f}  {tag}"
            )
    return "\n".join(lines)
