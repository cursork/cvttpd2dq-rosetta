#!/usr/bin/env python3
"""
Binary patch for Rosetta 2 cvttpd2dq/cvtpd2dq bug.

The bug: Both cvttpd2dq and cvtpd2dq corrupt xmmSRC with the converted value.

Fix: Replace each instruction with a jump to a trampoline that saves and
restores the source register around the instruction.

Usage: python3 patch.py <input-binary> <output-binary>
"""
import sys
import struct


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
    Decode the instruction following cvttpd2dq to determine if it can be
    safely relocated into the trampoline.

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
        if (modrm >> 6) == 3:  # reg-reg form
            return 4 + (1 if rex else 0), True
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


def patch_binary(data, instances, caves):
    """Apply trampoline patches to the binary."""
    patched = bytearray(data)
    cave_used = {c['offset']: 0 for c in caves}
    count = 0

    for inst in instances:
        if inst['same_reg']:  # No bug when src == dst
            continue
        if inst['next_len'] < 1 or not inst['next_relocatable']:
            continue

        # Find a cave with space
        cave = None
        for c in caves:
            if c['size'] - cave_used[c['offset']] >= 40:
                cave = c
                break
        if not cave:
            continue

        offset = inst['offset']
        trampoline_addr = cave['offset'] + cave_used[cave['offset']]
        return_addr = offset + 4 + inst['next_len']

        # Build and place trampoline
        trampoline = bytearray(build_trampoline(
            inst['src'], inst['dst'], inst['next_bytes'], inst.get('opcode', 'cvttpd2dq')))

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
        print(f"  Patched 0x{offset:x}: {inst.get('opcode', 'cvttpd2dq')} xmm{inst['src']} -> xmm{inst['dst']}")

    return bytes(patched), count


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input> <output>")
        sys.exit(1)

    with open(sys.argv[1], 'rb') as f:
        data = f.read()

    instances = find_cvt_instructions(data)
    problematic = [i for i in instances if not i['same_reg']]
    caves = find_code_caves(data)

    cvttpd2dq_count = len([i for i in instances if i.get('opcode') == 'cvttpd2dq'])
    cvtpd2dq_count = len([i for i in instances if i.get('opcode') == 'cvtpd2dq'])
    print(f"Found {len(instances)} conversion instructions:")
    print(f"  {cvttpd2dq_count} cvttpd2dq (truncate)")
    print(f"  {cvtpd2dq_count} cvtpd2dq (round)")
    print(f"  {len(problematic)} need patching (different src/dst)")
    print(f"Found {len(caves)} code caves")

    patched, count = patch_binary(data, instances, caves)
    print(f"\nPatched {count} instructions")

    with open(sys.argv[2], 'wb') as f:
        f.write(patched)
    print(f"Written to {sys.argv[2]}")


if __name__ == '__main__':
    main()
