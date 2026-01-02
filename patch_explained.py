#!/usr/bin/env python3
"""
================================================================================
LITERATE BINARY PATCH FOR ROSETTA 2 cvttpd2dq BUG
================================================================================

This script patches x86-64 binaries to work around a bug in Apple's Rosetta 2
emulator where the `cvttpd2dq` instruction incorrectly corrupts its source
register.

TABLE OF CONTENTS
-----------------
1. Background: The Bug
2. x86-64 Instruction Encoding Primer
3. Finding cvttpd2dq Instructions
4. Code Caves: Finding Space for Patches
5. The Trampoline Technique
6. Putting It All Together

================================================================================
1. BACKGROUND: THE BUG
================================================================================

The `cvttpd2dq` instruction converts packed double-precision floats to packed
32-bit integers with truncation:

    cvttpd2dq %xmm0, %xmm1

This should:
    - READ two doubles from xmm0
    - WRITE two truncated integers to the low 64 bits of xmm1
    - Leave xmm0 UNCHANGED

Under Rosetta 2, xmm0 is incorrectly overwritten with the truncated values.

References:
    - Intel® 64 and IA-32 Architectures Software Developer's Manual, Vol. 2A
      Instruction Set Reference (A-L), see CVTTPD2DQ entry
      https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html

    - Bun issue discussing this bug under Rosetta:
      https://github.com/oven-sh/bun/issues/19677

================================================================================
2. x86-64 INSTRUCTION ENCODING PRIMER
================================================================================

x86-64 instructions are variable-length, consisting of:

    [Prefixes] [Opcode] [ModR/M] [SIB] [Displacement] [Immediate]

For cvttpd2dq with register operands:

    66 0F E6 ModRM
    │  │  │  └── ModR/M byte specifying registers
    │  │  └── Opcode byte 3
    │  └── Two-byte opcode escape
    └── Mandatory prefix (operand size override, required for this instruction)

The ModR/M byte encodes operands:

    ┌─────┬─────────┬─────────┐
    │ mod │   reg   │   r/m   │
    │ 7-6 │   5-3   │   2-0   │
    └─────┴─────────┴─────────┘

    mod = 11 (binary): register-to-register operation
    reg = destination register (0-7 for xmm0-xmm7)
    r/m = source register (0-7 for xmm0-xmm7)

Example: cvttpd2dq %xmm0, %xmm1
    ModRM = 11 001 000 = 0xC8
            │   │   └── src = xmm0
            │   └── dst = xmm1
            └── mod = 3 (register mode)

References:
    - Intel® 64 and IA-32 Architectures Software Developer's Manual, Vol. 2A
      Chapter 2 "Instruction Format"

    - Agner Fog's optimization manuals, particularly "Optimizing subroutines
      in assembly language" which covers x86 instruction encoding
      https://www.agner.org/optimize/

================================================================================
"""

import sys
import struct

# ==============================================================================
# 3. FINDING cvttpd2dq INSTRUCTIONS
# ==============================================================================

def find_cvttpd2dq(data: bytes) -> list:
    """
    Scan binary for cvttpd2dq instructions with register-register encoding.

    We search for the byte sequence: 66 0F E6 followed by a ModR/M byte
    where mod=11 (indicating register-to-register form).

    The memory-operand forms (mod != 11) are more complex to patch and less
    common in the hot paths that cause problems, so we skip them.

    Returns a list of dicts with:
        - offset: byte position in file
        - src: source XMM register number (0-7)
        - dst: destination XMM register number (0-7)
        - same_reg: True if src == dst (no bug in this case)
        - next_len: length of following instruction
        - next_relocatable: whether following instruction can be moved
        - next_bytes: raw bytes of following instruction
    """
    results = []
    i = 0

    # The cvttpd2dq opcode with mandatory 66 prefix
    CVTTPD2DQ_OPCODE = b'\x66\x0f\xe6'

    while i < len(data) - 3:
        if data[i:i+3] == CVTTPD2DQ_OPCODE:
            modrm = data[i+3]

            # Extract ModR/M fields
            mod = (modrm >> 6) & 0x3   # Bits 7-6
            dst = (modrm >> 3) & 0x7   # Bits 5-3 (reg field)
            src = modrm & 0x7          # Bits 2-0 (r/m field)

            # Only handle register-register form (mod == 3)
            if mod == 3:
                # Analyze the instruction that follows
                next_len, relocatable = decode_next_instruction(data, i + 4)

                results.append({
                    'offset': i,
                    'src': src,
                    'dst': dst,
                    'same_reg': src == dst,
                    'next_len': next_len,
                    'next_relocatable': relocatable,
                    'next_bytes': data[i+4:i+4+next_len] if next_len > 0 else b''
                })
        i += 1

    return results


def decode_next_instruction(data: bytes, offset: int) -> tuple:
    """
    Decode the instruction following cvttpd2dq to determine:
    1. Its length in bytes
    2. Whether it can be safely relocated to a trampoline

    An instruction is "relocatable" if it doesn't use position-relative
    addressing (RIP-relative, jumps, calls). Non-relocatable instructions
    would break if moved to a different address.

    This is a simplified decoder covering common cases. A production tool
    would use a proper disassembler like Capstone.

    References:
        - Intel® 64 and IA-32 Architectures Software Developer's Manual, Vol. 2
          Appendix A "Opcode Map"

        - Capstone disassembly framework: https://www.capstone-engine.org/
    """
    if offset >= len(data):
        return 0, False

    b = data[offset]

    # Handle REX prefix (0x40-0x4F)
    # REX extends registers to R8-R15 and enables 64-bit operands
    rex = 0
    if 0x40 <= b <= 0x4F:
        rex = b
        offset += 1
        if offset >= len(data):
            return 1, False
        b = data[offset]

    # === Instructions that CAN be relocated ===

    # NOP (0x90) - single byte, no operands
    if b == 0x90:
        return 1 + (1 if rex else 0), True

    # PUSH/POP (0x50-0x5F) - register encoded in opcode
    if 0x50 <= b <= 0x5F:
        return 1 + (1 if rex else 0), True

    # === Instructions that CANNOT be relocated ===

    # RET (0xC3) - control flow, ends function
    if b == 0xC3:
        return 1, False

    # CALL rel32 (0xE8) / JMP rel32 (0xE9) - relative addressing
    if b in (0xE8, 0xE9):
        return 5, False

    # Short JMP/Jcc (0xEB, 0x70-0x7F) - relative addressing
    if b == 0xEB or (0x70 <= b <= 0x7F):
        return 2, False

    # === Two-byte opcodes (0F xx) ===
    if b == 0x0F:
        if offset + 2 >= len(data):
            return 0, False
        b2 = data[offset + 1]

        # Jcc rel32 (0F 80-8F) - conditional jumps, relative addressing
        if 0x80 <= b2 <= 0x8F:
            return 6, False

        # Other 0F instructions with ModR/M
        modrm = data[offset + 2]
        if (modrm >> 6) == 3:  # Register-register form
            return 3 + (1 if rex else 0), True

        return 0, False

    # === SSE instructions with mandatory prefix (66/F2/F3 0F xx) ===
    if b in (0x66, 0xF2, 0xF3):
        if offset + 3 >= len(data) or data[offset + 1] != 0x0F:
            return 0, False
        modrm = data[offset + 3]
        if (modrm >> 6) == 3:  # Register-register form
            return 4 + (1 if rex else 0), True
        return 0, False

    # === MOV variants (0x89, 0x8B) ===
    if b in (0x89, 0x8B):
        if offset + 1 >= len(data):
            return 0, False
        modrm = data[offset + 1]
        mod = (modrm >> 6) & 0x3
        rm = modrm & 0x7

        if mod == 3:  # Register-register
            return 2 + (1 if rex else 0), True

        # RIP-relative addressing (mod=0, rm=5) - CANNOT relocate
        if mod == 0 and rm == 5:
            return 0, False

        return 0, False

    # === ALU with immediate (0x83) ===
    if rex and (rex & 0x08) and b == 0x83:
        if offset + 2 >= len(data):
            return 0, False
        modrm = data[offset + 1]
        if (modrm >> 6) == 3:
            return 4, True  # REX + opcode + ModRM + imm8

    # Unknown instruction - be conservative
    return 0, False


# ==============================================================================
# 4. CODE CAVES: FINDING SPACE FOR PATCHES
# ==============================================================================

def find_code_caves(data: bytes, min_size: int = 64) -> list:
    """
    Find "code caves" - regions of padding bytes where we can insert code.

    Compilers and linkers often insert padding for alignment:
        - 0x90 (NOP) - explicit no-operation
        - 0xCC (INT3) - debug breakpoint, used as padding

    These regions are safe to overwrite because they're never executed.

    We need caves large enough for our trampolines (~35-40 bytes each).

    References:
        - "The Art of Assembly Language" by R. Hyde
          Section on code alignment and padding

        - "Practical Binary Analysis" by D. Andriesse
          Chapter 7 "Binary Instrumentation"
    """
    caves = []
    i = 0

    PADDING_BYTES = (0x90, 0xCC)  # NOP and INT3

    while i < len(data):
        if data[i] in PADDING_BYTES:
            start = i
            fill = data[i]

            # Measure the extent of the padding
            while i < len(data) and data[i] == fill:
                i += 1

            length = i - start
            if length >= min_size:
                caves.append({
                    'offset': start,
                    'size': length
                })
        else:
            i += 1

    return caves


# ==============================================================================
# 5. THE TRAMPOLINE TECHNIQUE
# ==============================================================================

def build_trampoline(src_xmm: int, dst_xmm: int, next_bytes: bytes) -> bytes:
    """
    Build a "trampoline" - a small code snippet that:

    1. Saves the source XMM register (which Rosetta will corrupt)
    2. Executes the original cvttpd2dq instruction
    3. Restores the source XMM register
    4. Executes the displaced "next" instruction
    5. Jumps back to the original code

    This technique is used in binary instrumentation and hooking:

        Original code:          Patched code:
        ┌─────────────────┐     ┌─────────────────┐
        │ cvttpd2dq       │ ──► │ jmp trampoline  │
        │ next_instr      │     │ nop nop...      │
        │ ...             │     │ ...             │
        └─────────────────┘     └─────────────────┘

                                Trampoline (in code cave):
                                ┌─────────────────────────┐
                                │ sub rsp, 16             │ ◄── allocate stack
                                │ movdqu [rsp], xmmN      │ ◄── save source
                                │ cvttpd2dq xmmN, xmmM    │ ◄── original insn
                                │ movdqu xmmN, [rsp]      │ ◄── restore source
                                │ add rsp, 16             │ ◄── deallocate
                                │ <next_instr>            │ ◄── displaced insn
                                │ jmp back                │ ◄── return
                                └─────────────────────────┘

    Why we also move the "next" instruction:
        cvttpd2dq is 4 bytes, but JMP rel32 needs 5 bytes. We "borrow" space
        from the following instruction by relocating it into the trampoline.

    References:
        - "Static Binary Rewriting without Supplemental Information"
          Smithson et al., IEEE WCRE 2013
          https://terpconnect.umd.edu/~barua/smithson-WCRE-2013.pdf

        - Frida dynamic instrumentation: https://frida.re/
    """
    code = bytearray()

    # ─── Prologue: Save source register ───

    # sub rsp, 16
    # Make room on the stack for one XMM register (128 bits = 16 bytes)
    # Encoding: REX.W (48) + SUB r/m64,imm8 (83 /5) + ModRM + imm8
    code += b'\x48\x83\xec\x10'

    # movdqu [rsp], xmmN
    # Store source XMM to stack (unaligned move, safe for any stack alignment)
    # Encoding: F3 0F 7F /r
    # ModRM for [rsp]: mod=00, rm=100 (SIB follows), reg=xmmN
    # SIB for [rsp]: scale=00, index=100 (none), base=100 (rsp)
    code += b'\xf3\x0f\x7f'
    code += bytes([0x04 | (src_xmm << 3), 0x24])

    # ─── Execute the original instruction (will corrupt source) ───

    # cvttpd2dq xmmSRC, xmmDST
    # Encoding: 66 0F E6 ModRM
    modrm = 0xC0 | (dst_xmm << 3) | src_xmm
    code += bytes([0x66, 0x0f, 0xe6, modrm])

    # ─── Epilogue: Restore source register ───

    # movdqu xmmN, [rsp]
    # Encoding: F3 0F 6F /r
    code += b'\xf3\x0f\x6f'
    code += bytes([0x04 | (src_xmm << 3), 0x24])

    # add rsp, 16
    # Encoding: REX.W (48) + ADD r/m64,imm8 (83 /0) + ModRM + imm8
    code += b'\x48\x83\xc4\x10'

    # ─── Displaced instruction ───
    code += next_bytes

    # ─── Return jump (offset filled in later) ───
    # jmp rel32
    # Encoding: E9 + 32-bit signed offset
    code += b'\xe9\x00\x00\x00\x00'

    return bytes(code)


# ==============================================================================
# 6. PUTTING IT ALL TOGETHER
# ==============================================================================

def patch_binary(data: bytes, instances: list, caves: list) -> tuple:
    """
    Apply trampoline patches to the binary.

    For each cvttpd2dq where src != dst:
    1. Find a code cave with enough space
    2. Build a trampoline
    3. Write trampoline to cave
    4. Replace original instruction with JMP to trampoline

    The JMP instruction:
        E9 xx xx xx xx

    Where xx xx xx xx is a 32-bit signed offset relative to the address
    AFTER the JMP instruction (i.e., from JMP_addr + 5).

    References:
        - Intel® 64 and IA-32 Architectures Software Developer's Manual
          Vol. 2A, Section 3.2 "JMP—Jump"
    """
    patched = bytearray(data)
    cave_used = {c['offset']: 0 for c in caves}
    count = 0

    for inst in instances:
        # Skip if src == dst (no bug when registers are the same)
        if inst['same_reg']:
            continue

        # Skip if we can't relocate the following instruction
        if inst['next_len'] < 1 or not inst['next_relocatable']:
            continue

        # Find a cave with enough space (~40 bytes needed)
        cave = None
        for c in caves:
            if c['size'] - cave_used[c['offset']] >= 40:
                cave = c
                break

        if not cave:
            continue

        offset = inst['offset']
        trampoline_addr = cave['offset'] + cave_used[cave['offset']]
        return_addr = offset + 4 + inst['next_len']  # After patched region

        # Build trampoline
        trampoline = bytearray(build_trampoline(
            inst['src'], inst['dst'], inst['next_bytes']))

        # Calculate return jump offset
        # JMP is at end of trampoline, offset is relative to after JMP
        jmp_addr = trampoline_addr + len(trampoline)
        trampoline[-4:] = struct.pack('<i', return_addr - jmp_addr)

        # Write trampoline to cave
        patched[trampoline_addr:trampoline_addr+len(trampoline)] = trampoline
        cave_used[cave['offset']] += len(trampoline)

        # Replace original with JMP + NOPs
        # JMP rel32: offset relative to address after JMP
        jmp_rel = trampoline_addr - (offset + 5)
        patched[offset] = 0xE9
        patched[offset+1:offset+5] = struct.pack('<i', jmp_rel)

        # NOP out any remaining bytes
        for i in range(5, 4 + inst['next_len']):
            patched[offset + i] = 0x90

        count += 1
        print(f"  Patched 0x{offset:x}: xmm{inst['src']} -> xmm{inst['dst']}")

    return bytes(patched), count


# ==============================================================================
# MAIN
# ==============================================================================

def main():
    """
    Usage: python3 patch_explained.py <input-binary> <output-binary>

    Example:
        python3 patch_explained.py /usr/local/bin/node ./node-patched
        chmod +x ./node-patched
    """
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input> <output>")
        print(__doc__[:2000] + "...")  # Print beginning of documentation
        sys.exit(1)

    with open(sys.argv[1], 'rb') as f:
        data = f.read()

    # Step 1: Find all cvttpd2dq instructions
    instances = find_cvttpd2dq(data)
    problematic = [i for i in instances if not i['same_reg']]

    # Step 2: Find code caves
    caves = find_code_caves(data)

    print(f"Found {len(instances)} cvttpd2dq instructions")
    print(f"  {len(problematic)} need patching (different src/dst)")
    print(f"Found {len(caves)} code caves")

    # Step 3: Apply patches
    patched, count = patch_binary(data, instances, caves)
    print(f"\nPatched {count} instructions")

    with open(sys.argv[2], 'wb') as f:
        f.write(patched)
    print(f"Written to {sys.argv[2]}")


if __name__ == '__main__':
    main()
