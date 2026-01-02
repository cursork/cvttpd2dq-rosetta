#!/usr/bin/env python3
"""
Binary patch for Rosetta 2 cvttpd2dq/cvtpd2dq bug.

The bug: Both cvttpd2dq and cvtpd2dq corrupt the source XMM register with
the converted value under Apple's Rosetta 2 emulator.

Fix: Replace each instruction with a jump to a trampoline that saves and
restores the source register around the instruction.

This unified script handles two strategies for finding space for trampolines:
  1. Code caves: NOP/INT3 padding regions (works for most binaries)
  2. Segment gap: Zero-padding between ELF segments (fallback for tightly packed binaries)

Usage: python3 patch.py <input-binary> <output-binary>

Tested on: Node.js 25, Bun, Dyalog APL
"""
import sys
import struct


# =============================================================================
# INSTRUCTION FINDING
# =============================================================================

def find_cvt_instructions(data):
    """
    Find all cvttpd2dq and cvtpd2dq instructions with register-register encoding.

    cvttpd2dq (truncate): 66 0F E6 ModRM
    cvtpd2dq (round):     F2 0F E6 ModRM
    ModRM for reg-reg: 11 DDD SSS (mod=3, dst=DDD, src=SSS)
    """
    results = []
    i = 0
    while i < len(data) - 3:
        if data[i:i+3] == b'\x66\x0f\xe6' or data[i:i+3] == b'\xf2\x0f\xe6':
            modrm = data[i+3]
            mod = (modrm >> 6) & 0x3
            dst = (modrm >> 3) & 0x7
            src = modrm & 0x7
            if mod == 3:  # register-register form
                opcode = 'cvttpd2dq' if data[i] == 0x66 else 'cvtpd2dq'
                next_len, relocatable = decode_next_instruction(data, i + 4)
                results.append({
                    'offset': i,
                    'src': src,
                    'dst': dst,
                    'same_reg': src == dst,
                    'next_len': next_len,
                    'next_relocatable': relocatable,
                    'next_bytes': data[i+4:i+4+next_len] if next_len > 0 else b'',
                    'opcode': opcode
                })
        i += 1
    return results


def decode_next_instruction(data, offset):
    """
    Decode the instruction following cvttpd2dq/cvtpd2dq to determine if it can
    be safely relocated into the trampoline.

    Returns (length, can_relocate) tuple.
    """
    if offset >= len(data):
        return 0, False

    b = data[offset]

    # Handle REX prefix
    rex = 0
    if 0x40 <= b <= 0x4F:
        rex = b
        offset += 1
        if offset >= len(data):
            return 1, False
        b = data[offset]

    # Instructions that can be safely relocated
    if b == 0x90:  # NOP
        return 1 + (1 if rex else 0), True
    if 0x50 <= b <= 0x5F:  # PUSH/POP
        return 1 + (1 if rex else 0), True

    # Instructions with relative addressing - cannot relocate
    if b == 0xC3:  # RET
        return 1, False
    if b in (0xE8, 0xE9):  # CALL/JMP rel32
        return 5, False
    if b == 0xEB or (0x70 <= b <= 0x7F):  # Short JMP/Jcc
        return 2, False

    # Two-byte opcodes (0F xx)
    if b == 0x0F:
        if offset + 2 >= len(data):
            return 0, False
        b2 = data[offset + 1]
        if 0x80 <= b2 <= 0x8F:  # Jcc rel32
            return 6, False
        modrm = data[offset + 2]
        if (modrm >> 6) == 3:  # reg-reg form
            return 3 + (1 if rex else 0), True
        return 0, False

    # SSE with mandatory prefix (66/F2/F3 0F xx)
    if b in (0x66, 0xF2, 0xF3):
        if offset + 3 >= len(data) or data[offset + 1] != 0x0F:
            return 0, False
        modrm = data[offset + 3]
        mod = (modrm >> 6) & 0x3
        rm = modrm & 0x7
        base_len = 4 + (1 if rex else 0)

        if mod == 3:  # reg-reg form
            return base_len, True

        # Memory operand forms - can relocate unless RIP-relative
        if mod == 0 and rm == 5:  # RIP-relative - cannot relocate
            return 0, False
        if mod == 0 and rm == 4:  # SIB, no displacement
            return base_len + 1, True
        if mod == 0:  # [reg], no displacement
            return base_len, True
        if mod == 1 and rm == 4:  # SIB + disp8
            return base_len + 2, True
        if mod == 1:  # [reg + disp8]
            return base_len + 1, True
        if mod == 2 and rm == 4:  # SIB + disp32
            return base_len + 5, True
        if mod == 2:  # [reg + disp32]
            return base_len + 4, True

        return 0, False

    # MOV reg, reg
    if b in (0x89, 0x8B):
        if offset + 1 >= len(data):
            return 0, False
        modrm = data[offset + 1]
        mod = (modrm >> 6) & 0x3
        rm = modrm & 0x7
        if mod == 3:  # reg-reg
            return 2 + (1 if rex else 0), True
        if mod == 0 and rm == 5:  # RIP-relative - cannot relocate
            return 0, False
        return 0, False

    # ADD/SUB/CMP reg, imm8
    if rex and (rex & 0x08) and b == 0x83:
        if offset + 2 >= len(data):
            return 0, False
        modrm = data[offset + 1]
        if (modrm >> 6) == 3:
            return 4, True

    return 0, False


# =============================================================================
# CODE CAVE FINDING (Strategy 1: NOP/INT3 padding)
# =============================================================================

def find_code_caves(data, min_size=64):
    """Find padding areas (NOP/INT3 sequences) that can hold trampolines."""
    caves = []
    i = 0
    while i < len(data):
        if data[i] in (0x90, 0xCC):  # NOP or INT3
            start = i
            fill = data[i]
            while i < len(data) and data[i] == fill:
                i += 1
            if i - start >= min_size:
                caves.append({'offset': start, 'size': i - start})
        else:
            i += 1
    return caves


# =============================================================================
# SEGMENT GAP FINDING (Strategy 2: ELF segment gap)
# =============================================================================

def parse_elf_segments(data):
    """Parse ELF program headers to find segment boundaries."""
    if data[:4] != b'\x7fELF':
        return None  # Not an ELF file

    e_phoff = struct.unpack('<Q', data[32:40])[0]
    e_phnum = struct.unpack('<H', data[56:58])[0]
    e_phentsize = struct.unpack('<H', data[54:56])[0]

    segments = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = struct.unpack('<I', data[off:off+4])[0]
        if p_type == 1:  # PT_LOAD
            p_flags = struct.unpack('<I', data[off+4:off+8])[0]
            p_offset = struct.unpack('<Q', data[off+8:off+16])[0]
            p_filesz = struct.unpack('<Q', data[off+32:off+40])[0]
            segments.append({
                'offset': p_offset,
                'size': p_filesz,
                'flags': p_flags,
                'executable': bool(p_flags & 1),
                'phdr_offset': off
            })
    return sorted(segments, key=lambda s: s['offset'])


def find_segment_gap_cave(data):
    """
    Find usable space in the gap after the executable segment.

    The gap between segments is zero-padded and falls within executable
    pages at runtime due to page alignment.
    """
    segments = parse_elf_segments(data)
    if not segments:
        return None

    for i, seg in enumerate(segments):
        if seg['executable'] and i + 1 < len(segments):
            seg_end = seg['offset'] + seg['size']
            next_seg_start = segments[i + 1]['offset']
            gap = next_seg_start - seg_end

            if gap > 64:  # Need at least 64 bytes
                # Verify it's zeros
                if all(b == 0 for b in data[seg_end:next_seg_start]):
                    return {'offset': seg_end, 'size': gap, 'is_segment_gap': True}

    return None


def extend_exec_segment(data, new_end):
    """
    Extend the executable segment to include the trampoline area.

    Modifies the p_filesz and p_memsz fields of the executable segment's
    program header so the trampolines are mapped as executable.
    """
    patched = bytearray(data)

    e_phoff = struct.unpack('<Q', data[32:40])[0]
    e_phnum = struct.unpack('<H', data[56:58])[0]
    e_phentsize = struct.unpack('<H', data[54:56])[0]

    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = struct.unpack('<I', data[off:off+4])[0]
        if p_type == 1:  # PT_LOAD
            p_flags = struct.unpack('<I', data[off+4:off+8])[0]
            if p_flags & 1:  # Executable segment
                p_offset = struct.unpack('<Q', data[off+8:off+16])[0]
                old_filesz = struct.unpack('<Q', data[off+32:off+40])[0]

                new_filesz = new_end - p_offset
                new_memsz = new_filesz

                patched[off+32:off+40] = struct.pack('<Q', new_filesz)
                patched[off+40:off+48] = struct.pack('<Q', new_memsz)

                print(f"  Extended exec segment: filesz 0x{old_filesz:x} -> 0x{new_filesz:x}")
                break

    return bytes(patched)


# =============================================================================
# TRAMPOLINE BUILDING
# =============================================================================

def build_trampoline(src_xmm, dst_xmm, next_bytes, opcode='cvttpd2dq'):
    """
    Build trampoline that:
    1. Saves source XMM register
    2. Executes cvttpd2dq/cvtpd2dq (which will corrupt source - but we saved it)
    3. Restores source XMM register
    4. Executes the relocated next instruction
    5. Jumps back
    """
    code = bytearray()

    # sub rsp, 16
    code += b'\x48\x83\xec\x10'

    # movdqu [rsp], xmmN (save source)
    code += b'\xf3\x0f\x7f'
    code += bytes([0x04 | (src_xmm << 3), 0x24])

    # cvttpd2dq or cvtpd2dq xmmSRC, xmmDST (the buggy instruction)
    modrm = 0xC0 | (dst_xmm << 3) | src_xmm
    prefix = 0x66 if opcode == 'cvttpd2dq' else 0xF2
    code += bytes([prefix, 0x0f, 0xe6, modrm])

    # movdqu xmmN, [rsp] (restore source)
    code += b'\xf3\x0f\x6f'
    code += bytes([0x04 | (src_xmm << 3), 0x24])

    # add rsp, 16
    code += b'\x48\x83\xc4\x10'

    # Relocated next instruction
    code += next_bytes

    # jmp rel32 (placeholder)
    code += b'\xe9\x00\x00\x00\x00'

    return bytes(code)


# =============================================================================
# PATCHING
# =============================================================================

def patch_binary(data, instances, caves):
    """Apply trampoline patches to the binary."""
    patched = bytearray(data)
    cave_used = {c['offset']: 0 for c in caves}
    count = 0
    skipped_same_reg = 0
    skipped_not_relocatable = 0
    skipped_no_space = 0

    for inst in instances:
        if inst['same_reg']:
            skipped_same_reg += 1
            continue
        if inst['next_len'] < 1 or not inst['next_relocatable']:
            skipped_not_relocatable += 1
            continue

        # Find a cave with space
        cave = None
        for c in caves:
            if c['size'] - cave_used[c['offset']] >= 40:
                cave = c
                break
        if not cave:
            skipped_no_space += 1
            continue

        offset = inst['offset']
        trampoline_addr = cave['offset'] + cave_used[cave['offset']]
        return_addr = offset + 4 + inst['next_len']

        # Build and place trampoline
        trampoline = bytearray(build_trampoline(
            inst['src'], inst['dst'], inst['next_bytes'], inst['opcode']))

        # Fix up return jump
        jmp_addr = trampoline_addr + len(trampoline)
        trampoline[-4:] = struct.pack('<i', return_addr - jmp_addr)

        patched[trampoline_addr:trampoline_addr+len(trampoline)] = trampoline
        cave_used[cave['offset']] += len(trampoline)

        # Replace original with JMP to trampoline + NOPs
        jmp_rel = trampoline_addr - (offset + 5)
        patched[offset] = 0xE9
        patched[offset+1:offset+5] = struct.pack('<i', jmp_rel)
        for i in range(5, 4 + inst['next_len']):
            patched[offset + i] = 0x90

        count += 1
        print(f"  Patched 0x{offset:x}: {inst['opcode']} xmm{inst['src']} -> xmm{inst['dst']}")

    if skipped_same_reg or skipped_not_relocatable or skipped_no_space:
        print(f"\nSkipped: {skipped_same_reg} same-reg, {skipped_not_relocatable} non-relocatable, {skipped_no_space} no-space")

    # Calculate total cave usage
    total_used = sum(cave_used.values())
    total_available = sum(c['size'] for c in caves)
    print(f"Cave usage: {total_used}/{total_available} bytes")

    # Return the cave end offset for segment extension if needed
    max_cave_end = max((c['offset'] + cave_used[c['offset']] for c in caves), default=0)

    return bytes(patched), count, max_cave_end


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input> <output>")
        sys.exit(1)

    with open(sys.argv[1], 'rb') as f:
        data = f.read()

    # Find instructions to patch
    instances = find_cvt_instructions(data)
    problematic = [i for i in instances if not i['same_reg']]

    cvttpd2dq_count = len([i for i in instances if i['opcode'] == 'cvttpd2dq'])
    cvtpd2dq_count = len([i for i in instances if i['opcode'] == 'cvtpd2dq'])
    print(f"Found {len(instances)} conversion instructions:")
    print(f"  {cvttpd2dq_count} cvttpd2dq (truncate)")
    print(f"  {cvtpd2dq_count} cvtpd2dq (round)")
    print(f"  {len(problematic)} need patching (different src/dst)")

    # Strategy 1: Try code caves first (NOP/INT3 padding)
    caves = find_code_caves(data)
    used_segment_gap = False

    if caves:
        print(f"Found {len(caves)} code caves")
    else:
        # Strategy 2: Fall back to segment gap
        print("No code caves found, trying segment gap...")
        gap_cave = find_segment_gap_cave(data)
        if gap_cave:
            print(f"Using segment gap: 0x{gap_cave['offset']:x} ({gap_cave['size']} bytes)")
            caves = [gap_cave]
            used_segment_gap = True
        else:
            print("ERROR: No code caves or segment gap found!")
            sys.exit(1)

    # Apply patches
    patched, count, cave_end = patch_binary(data, instances, caves)
    print(f"\nPatched {count} instructions")

    # If we used segment gap, extend the executable segment
    if used_segment_gap and count > 0:
        patched = extend_exec_segment(patched, cave_end)

    with open(sys.argv[2], 'wb') as f:
        f.write(patched)
    print(f"Written to {sys.argv[2]}")


if __name__ == '__main__':
    main()
