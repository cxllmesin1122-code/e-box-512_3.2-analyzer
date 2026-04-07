"""
Decompiler Engine — Capstone Disassembly + Pseudo-C Generation
Supports: x86/x86_64 / ARM / AArch64 / MIPS
Outputs: Raw ASM  |  Annotated ASM  |  Pseudo-C  |  String map
"""

from __future__ import annotations
import struct, io, math, os, tempfile
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple

# ── Optional: Capstone ────────────────────────────────────────────────────────
try:
    import capstone as cs
    from capstone import x86_const, arm_const
    CS_OK = True
except ImportError:
    CS_OK = False

# ── Optional: pyelftools (find .text section) ─────────────────────────────────
try:
    from elftools.elf.elffile import ELFFile
    ELF_OK = True
except ImportError:
    ELF_OK = False


# ─────────────────────────────────────────────────────────────────────────────
#  Data structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Instr:
    addr:     int
    mnemonic: str
    op_str:   str
    raw:      bytes
    size:     int
    comment:  str = ""

    def asm_line(self) -> str:
        raw_hex = self.raw.hex()
        comment = f"  ; {self.comment}" if self.comment else ""
        return (f"  0x{self.addr:08x}  {raw_hex:<16}"
                f"  {self.mnemonic:<10} {self.op_str}{comment}")


@dataclass
class Function:
    start_addr:  int
    name:        str
    instructions: List[Instr] = field(default_factory=list)

    @property
    def size(self) -> int:
        if not self.instructions:
            return 0
        return (self.instructions[-1].addr + self.instructions[-1].size
                - self.instructions[0].addr)


@dataclass
class DecompResult:
    arch:         str            = "unknown"
    base_addr:    int            = 0
    instructions: List[Instr]   = field(default_factory=list)
    functions:    List[Function] = field(default_factory=list)
    strings:      List[str]      = field(default_factory=list)
    xrefs:        Dict[int, List[int]] = field(default_factory=dict)
    asm_text:     str            = ""
    pseudo_c:     str            = ""
    asm_path:     Optional[str]  = None
    pseudo_c_path: Optional[str] = None
    errors:       List[str]      = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
#  Architecture helpers
# ─────────────────────────────────────────────────────────────────────────────

ARCH_PROFILES: Dict[str, Tuple] = {}

def _build_arch_profiles():
    if not CS_OK:
        return
    ARCH_PROFILES.update({
        'x86':     (cs.CS_ARCH_X86,   cs.CS_MODE_32),
        'x86_64':  (cs.CS_ARCH_X86,   cs.CS_MODE_64),
        'ARM':     (cs.CS_ARCH_ARM,   cs.CS_MODE_ARM),
        'THUMB':   (cs.CS_ARCH_ARM,   cs.CS_MODE_THUMB),
        'AArch64': (cs.CS_ARCH_ARM64, cs.CS_MODE_ARM),
        'MIPS':    (cs.CS_ARCH_MIPS,  cs.CS_MODE_MIPS32 + cs.CS_MODE_LITTLE_ENDIAN),
        'MIPSBE':  (cs.CS_ARCH_MIPS,  cs.CS_MODE_MIPS32 + cs.CS_MODE_BIG_ENDIAN),
        'PPC':     (cs.CS_ARCH_PPC,   cs.CS_MODE_32 + cs.CS_MODE_BIG_ENDIAN),
        'PPC64':   (cs.CS_ARCH_PPC,   cs.CS_MODE_64 + cs.CS_MODE_BIG_ENDIAN),
        'SPARC':   (cs.CS_ARCH_SPARC, cs.CS_MODE_BIG_ENDIAN),
        'SPARC64': (cs.CS_ARCH_SPARC, cs.CS_MODE_V9),
        'RISCV':   (cs.CS_ARCH_RISCV, cs.CS_MODE_RISCV32),
        'RISCV64': (cs.CS_ARCH_RISCV, cs.CS_MODE_RISCV64),
    })

_build_arch_profiles()


def _dump_to_disk(text: str, suffix: str) -> str:
    fd, path = tempfile.mkstemp(suffix=suffix, prefix='ebox_decomp_')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', errors='replace') as f:
            f.write(text)
    except Exception:
        try:
            os.remove(path)
        except Exception:
            pass
        raise
    return path


def detect_arch_elf(data: bytes) -> str:
    """Infer arch from ELF e_machine / class fields."""
    if len(data) < 20 or data[:4] != b'\x7fELF':
        return 'x86_64'
    ei_class = data[4]
    e_mach   = struct.unpack_from('<H', data, 18)[0]
    tbl = {
        (0x03, 1): 'x86',    (0x03, 2): 'x86',
        (0x3e, 2): 'x86_64',
        (0x28, 1): 'ARM',    (0x28, 2): 'ARM',
        (0xb7, 2): 'AArch64',
        (0x08, 1): 'MIPS',   (0x08, 2): 'MIPSBE',
        (0x14, 1): 'PPC',    (0x15, 2): 'PPC64',
        (0x02, 1): 'SPARC',  (0x02, 2): 'SPARC64',
        (0xf3, 1): 'RISCV',  (0xf3, 2): 'RISCV64',
    }
    return tbl.get((e_mach, ei_class), 'x86_64')


def find_text_section(data: bytes) -> Tuple[int, int, int]:
    """Return (file_offset, size, vaddr) of .text section."""
    if not ELF_OK:
        return 0, len(data), 0
    try:
        f    = ELFFile(io.BytesIO(data))
        text = f.get_section_by_name('.text')
        if text:
            return text['sh_offset'], text['sh_size'], text['sh_addr']
        # Fallback: first PROGBITS section with SHF_EXECINSTR
        for sec in f.iter_sections():
            if sec['sh_type'] == 'SHT_PROGBITS' and (sec['sh_flags'] & 0x4):
                return sec['sh_offset'], sec['sh_size'], sec['sh_addr']
    except Exception:
        pass
    return 0, min(len(data), 256 * 1024), 0


# ─────────────────────────────────────────────────────────────────────────────
#  Disassembler
# ─────────────────────────────────────────────────────────────────────────────

MAX_INSTRS = 20_000
MAX_BYTES  = 200 * 1024     # 200 KB of code max for analysis


def disassemble(code: bytes,
                arch:      str = 'x86_64',
                base_addr: int = 0) -> List[Instr]:
    if not CS_OK or not code:
        return []
    profile = ARCH_PROFILES.get(arch)
    if not profile:
        profile = ARCH_PROFILES.get('x86_64')

    md = cs.Cs(*profile)
    md.detail = True

    result: List[Instr] = []
    for insn in md.disasm(code[:MAX_BYTES], base_addr):
        result.append(Instr(
            addr     = insn.address,
            mnemonic = insn.mnemonic,
            op_str   = insn.op_str,
            raw      = bytes(insn.bytes),
            size     = insn.size,
        ))
        if len(result) >= MAX_INSTRS:
            break
            break
    return result


# ─────────────────────────────────────────────────────────────────────────────
#  Function slicer
# ─────────────────────────────────────────────────────────────────────────────

def slice_functions(instrs: List[Instr], arch: str) -> List[Function]:
    """
    Heuristic function boundary detection.
    x86/x86_64: push rbp / push ebp prologue.
    ARM:        stmfd sp! / push {lr} / push {r4-...}.
    Fallback: label every 'ret' epilogue block.
    """
    fns: List[Function] = []
    cur: Optional[Function] = None
    ret_mnemonics = {'ret', 'retn', 'retq', 'bx lr', 'pop {pc}', 'blr'}

    for i, ins in enumerate(instrs):
        mn  = ins.mnemonic.lower()
        ops = ins.op_str.lower()

        # ─ x86 prologue ──
        is_prologue_x86 = (
            mn == 'push' and ('rbp' in ops or 'ebp' in ops)
        )
        # ─ ARM prologue ──
        is_prologue_arm = (
            (mn in ('push', 'stmfd', 'stmdb')) and ('lr' in ops or 'r4' in ops)
        )

        if is_prologue_x86 or is_prologue_arm:
            if cur:
                fns.append(cur)
            idx = len(fns)
            cur = Function(start_addr=ins.addr,
                           name=f'sub_{ins.addr:08x}')

        if cur:
            cur.instructions.append(ins)

        # ─ epilogue → close function ──
        if mn in ret_mnemonics or (mn == 'bx' and 'lr' in ops):
            if cur:
                fns.append(cur)
                cur = None

    if cur and cur.instructions:
        fns.append(cur)

    return fns[:300]


# ─────────────────────────────────────────────────────────────────────────────
#  Pseudo-C generator
# ─────────────────────────────────────────────────────────────────────────────

# x86_64 register → readable C name
REG_NAMES = {
    'rax':'acc',   'eax':'acc',   'ax':'acc_lo',  'al':'acc_b',
    'rbx':'base',  'ebx':'base',
    'rcx':'count', 'ecx':'count',
    'rdx':'data',  'edx':'data',
    'rsi':'src',   'esi':'src',
    'rdi':'dst',   'edi':'dst',
    'rsp':'sp',    'esp':'sp',
    'rbp':'bp',    'ebp':'bp',
    'r8':'r8',     'r9':'r9',   'r10':'r10',
    'r11':'r11',   'r12':'r12', 'r13':'r13',
    'r14':'r14',   'r15':'r15',
}

ARITH_OPS = {
    'add':'+', 'sub':'-', 'imul':'*', 'mul':'*', 'idiv':'/', 'div':'/',
    'and':'&', 'or':'|',  'xor':'^',
    'shl':'<<','shr':'>>','sar':'>>','sal':'<<',
}

JCC_MAP = {
    'je':'==', 'jz':'==', 'jne':'!=', 'jnz':'!=',
    'jl':'<',  'jle':'<=','jg':'>',   'jge':'>=',
    'jb':'<',  'jbe':'<=','ja':'>',   'jae':'>=',
    'js':'< 0 (sign)', 'jns':'>= 0 (sign)',
}


class PseudoCGen:
    """Converts a list of Instr objects to Pseudo-C source."""

    def __init__(self):
        self._ind = 0
        self._cmp_ctx = ""      # Track last 'cmp' operands

    def _i(self) -> str:
        return "    " * self._ind

    def _reg(self, name: str) -> str:
        return REG_NAMES.get(name.lower(), name)

    def _operand(self, op: str) -> str:
        op = op.strip()
        # Memory deref
        if op.startswith('[') and op.endswith(']'):
            inner = op[1:-1].strip()
            return f'*({self._operand(inner)})'
        # Immediate
        if op.startswith('0x') or op.startswith('-0x'):
            return op
        try:
            int(op, 0)
            return op
        except ValueError:
            pass
        # Register (complex expression)
        parts = op.replace('+', ' + ').replace('-', ' - ').split()
        out   = []
        for p in parts:
            p2 = p.strip('+ -')
            if p2 in REG_NAMES:
                out.append(p.replace(p2, REG_NAMES[p2]))
            else:
                out.append(p)
        return ''.join(out)

    def generate(self, fn: Function, arch: str = 'x86_64') -> str:
        self._ind = 0
        self._cmp_ctx = ""
        lines  = [f"// {fn.name}  @ 0x{fn.start_addr:08x}  (size ~{fn.size} bytes)",
                  f"void* {fn.name}(void) {{"]
        self._ind = 1

        for ins in fn.instructions:
            mn   = ins.mnemonic.lower()
            ops  = ins.op_str
            addr = ins.addr
            line = self._translate_x86(mn, ops, addr)
            if line is not None:
                lines.append(f"{self._i()}{line}")

        self._ind = 0
        lines.append("}")
        return "\n".join(lines)

    def _translate_x86(self, mn: str, ops: str, addr: int) -> Optional[str]:
        parts = [p.strip() for p in ops.split(',', 1)]

        # ─ NOP ─────────────────────────────────────────────────
        if mn == 'nop':
            return None  # skip

        # ─ PROLOGUE / EPILOGUE ─────────────────────────────────
        if mn == 'push' and parts and parts[0].lower() in ('rbp', 'ebp'):
            return "// --- function prologue ---"
        if mn in ('ret', 'retn', 'retq'):
            return "return;  // --- epilogue ---"

        # ─ MOV ──────────────────────────────────────────────────
        if mn == 'mov' and len(parts) == 2:
            d, s = self._operand(parts[0]), self._operand(parts[1])
            return f"{d} = {s};  // 0x{addr:08x}"

        # ─ LEA ──────────────────────────────────────────────────
        if mn == 'lea' and len(parts) == 2:
            d = self._operand(parts[0])
            s = self._operand(parts[1].strip('[]'))
            return f"{d} = &{s};  // 0x{addr:08x}"

        # ─ ARITHMETIC ───────────────────────────────────────────
        if mn in ARITH_OPS and len(parts) == 2:
            d, s = self._operand(parts[0]), self._operand(parts[1])
            sym  = ARITH_OPS[mn]
            if mn == 'xor' and parts[0].lower() == parts[1].lower():
                return f"{d} = 0;  // 0x{addr:08x} (zero idiom)"
            return f"{d} {sym}= {s};  // 0x{addr:08x}"

        if mn == 'not' and parts:
            d = self._operand(parts[0])
            return f"{d} = ~{d};  // 0x{addr:08x}"

        if mn == 'neg' and parts:
            d = self._operand(parts[0])
            return f"{d} = -{d};  // 0x{addr:08x}"

        # ─ COMPARE ──────────────────────────────────────────────
        if mn == 'cmp' and len(parts) == 2:
            a, b = self._operand(parts[0]), self._operand(parts[1])
            self._cmp_ctx = f"{a}, {b}"
            return f"// cmp {a}, {b}  @ 0x{addr:08x}"

        if mn == 'test' and len(parts) == 2:
            a, b = self._operand(parts[0]), self._operand(parts[1])
            self._cmp_ctx = f"{a} & {b}"
            return f"// test {a}, {b}  @ 0x{addr:08x}"

        # ─ JUMPS ────────────────────────────────────────────────
        if mn == 'jmp':
            tgt = ops.strip()
            return f"goto lbl_{tgt};  // 0x{addr:08x}"

        if mn in JCC_MAP:
            cond = JCC_MAP[mn]
            tgt  = ops.strip()
            ctx  = f"({self._cmp_ctx} {cond} 0)" if self._cmp_ctx else f"(flags {cond} 0)"
            return f"if {ctx} goto lbl_{tgt};  // 0x{addr:08x}"

        # ─ CALL ─────────────────────────────────────────────────
        if mn == 'call':
            tgt = ops.strip()
            return f"sub_{tgt}();  // 0x{addr:08x}"

        # ─ PUSH / POP ───────────────────────────────────────────
        if mn == 'push':
            v = self._operand(ops)
            return f"PUSH({v});  // 0x{addr:08x}"
        if mn == 'pop':
            v = self._operand(ops)
            return f"{v} = POP();  // 0x{addr:08x}"

        # ─ Fallback ─────────────────────────────────────────────
        return f"/* {mn} {ops} */  // 0x{addr:08x}"


# ─────────────────────────────────────────────────────────────────────────────
#  Cross-reference builder
# ─────────────────────────────────────────────────────────────────────────────

def build_xrefs(instrs: List[Instr]) -> Dict[int, List[int]]:
    """Map call/jmp targets → list of source addresses."""
    xrefs: Dict[int, List[int]] = {}
    for ins in instrs:
        if ins.mnemonic.lower() in ('call', 'jmp', 'je', 'jne', 'jl', 'jle',
                                    'jg', 'jge', 'jz', 'jnz'):
            try:
                target = int(ins.op_str.strip(), 0)
                xrefs.setdefault(target, []).append(ins.addr)
            except ValueError:
                pass
    return xrefs


# ─────────────────────────────────────────────────────────────────────────────
#  String extractor
# ─────────────────────────────────────────────────────────────────────────────

def extract_strings(data: bytes, min_len: int = 5) -> List[str]:
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
    return result[:1000]


# ─────────────────────────────────────────────────────────────────────────────
#  Public API
# ─────────────────────────────────────────────────────────────────────────────

def _dump_to_disk(text: str, suffix: str) -> str:
    fd, path = tempfile.mkstemp(suffix=suffix, prefix='ebox_decomp_')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', errors='replace') as f:
            f.write(text)
    except Exception:
        try:
            os.remove(path)
        except Exception:
            pass
        raise
    return path


def decompile(data: bytes,
              arch: Optional[str] = None,
              base_addr: int = 0,
              start_offset: Optional[int] = None,
              end_offset: Optional[int] = None,
              medical_unit=None) -> DecompResult:
    """
    Full decompilation pipeline:
    1. Detect arch (or use provided)
    2. Find .text section (ELF) or use specified offset range
    3. Disassemble with Capstone
    4. Slice into functions
    5. Build pseudo-C per function
    6. Extract strings + cross-refs
    """

    def _run() -> DecompResult:
        result = DecompResult()

        if not CS_OK:
            result.errors.append(
                "Capstone not installed. Run: pip install capstone")
            result.asm_text = "// Capstone unavailable — install it first"
            result.pseudo_c = "// No disassembly available"
            return result

        # ── 1. Detect arch ────────────────────────────────────
        detected = arch or detect_arch_elf(data)
        result.arch = detected

        # ── 2. Locate executable region ───────────────────────
        if start_offset is not None and end_offset is not None:
            if start_offset < 0 or end_offset > len(data) or start_offset >= end_offset:
                result.errors.append(
                    f"Invalid offset range: start=0x{start_offset:x}, end=0x{end_offset:x}, data_len=0x{len(data):x}")
                result.asm_text = "// Invalid offset range"
                result.pseudo_c = "// No disassembly available"
                return result
            code_off = start_offset
            code_sz = end_offset - start_offset
            code_va = base_addr
        else:
            code_off, code_sz, code_va = find_text_section(data)
        code_data = data[code_off: code_off + code_sz]
        result.base_addr = code_va or base_addr

        # ── 3. Disassemble ────────────────────────────────────
        result.instructions = disassemble(code_data, detected, result.base_addr)

        # ── 4. Annotated ASM text ─────────────────────────────
        hdr = [
            f";; E-BOX Disassembly",
            f";; Arch      : {detected}",
            f";; Base addr : 0x{result.base_addr:08x}",
            f";; Code size : {len(code_data):,} bytes",
            f";; Instrs    : {len(result.instructions)}",
        ]
        if start_offset is not None and end_offset is not None:
            hdr.append(f";; Offset    : 0x{start_offset:08x}-0x{end_offset:08x}")
        hdr.append("")
        result.asm_text = "\n".join(hdr + [i.asm_line() for i in result.instructions])
        result.asm_path = _dump_to_disk(result.asm_text, '.asm')

        # ── 5. Function slicing ───────────────────────────────
        result.functions = slice_functions(result.instructions, detected)

        # ── 6. Pseudo-C generation ────────────────────────────
        gen    = PseudoCGen()
        c_parts = [
            "/*",
            " * Pseudo-C — auto-generated by E-BOX RE Tool",
            f" * Arch: {detected}  |  Functions: {len(result.functions)}",
            " * Variable names are heuristic approximations.",
            " */",
            "",
            "#include <stdint.h>",
            "#include <stdlib.h>",
            "",
        ]
        for fn in result.functions[:100]:
            try:
                c_parts.append(gen.generate(fn, detected))
                c_parts.append("")
            except Exception as ex:
                c_parts.append(f"// Failed to generate {fn.name}: {ex}")
        result.pseudo_c = "\n".join(c_parts)
        result.pseudo_c_path = _dump_to_disk(result.pseudo_c, '.c')

        # Release bulky text from memory after writing to disk.
        result.asm_text = ''
        result.pseudo_c = ''

        # ── 7. Strings + XRefs ────────────────────────────────
        result.strings = extract_strings(data[:1_048_576])
        result.xrefs   = build_xrefs(result.instructions)

        return result

    if medical_unit:
        ok, res, err = medical_unit.guard('DecompilerEngine', _run)
        if not ok:
            r = DecompResult()
            r.errors.append(err or 'Decompilation failed')
            r.pseudo_c = f"// Error: {err}"
            r.asm_text = f"; Error: {err}"
            return r
        return res
    return _run()
