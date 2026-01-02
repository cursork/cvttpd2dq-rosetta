# Rosetta 2 Float Bug

A bug in Apple's Rosetta 2 x86-64 emulator corrupts floating-point values. This affects Node.js 25+, Bun, and other Clang-compiled software running under Rosetta on Apple Silicon.

**NOTA BENE** this was tested only on an M1 MacBook with OS version 15.6.1
(24G90). No guarantees are made re. reproducability on other systems or OS
versions.

## TL;DR

Run the walkthrough. Bish bash bosh.

```bash
./walkthrough
```

![Walkthrough demo](walkthrough.gif)

Or read `patch_explained.py` (I haven't fully verified it). You do you.

## The Problem

```bash
$ docker run --platform linux/amd64 --rm node:25-slim node -e "console.log(0.25)"
0

$ docker run --platform linux/amd64 --rm node:25-slim node -e "console.log(1/4)"
0

$ docker run --platform linux/amd64 --rm node:25-slim node -e "console.log(Math.PI)"
3
```

Floating-point numbers are silently truncated to integers.

## Root Cause

Two x86-64 packed double-to-integer conversion instructions have bugs in Rosetta 2:

| Instruction | Opcode | Operation |
|-------------|--------|-----------|
| `cvttpd2dq` | `66 0F E6` | Truncate (toward zero) |
| `cvtpd2dq` | `F2 0F E6` | Round (to nearest) |

```asm
cvttpd2dq %xmm0, %xmm1    ; Convert doubles in xmm0 to ints in xmm1
cvtpd2dq  %xmm0, %xmm1    ; Same, but rounds instead of truncates
```

**Expected:** xmm0 unchanged, xmm1 contains converted integers
**Rosetta 2:** xmm0 **also** gets overwritten with the converted value

This breaks any code that uses the source register after the conversion - which is exactly what happens in V8's float parsing and Dyalog APL's number literal parsing.

## Why Node 24 Works

| Version | Compiler | Instruction Used | Works? |
|---------|----------|------------------|--------|
| Node 24 | GCC | `cvttsd2si` (scalar) | Yes |
| Node 25 | Clang 19 | `cvttpd2dq` (packed) | No |

GCC and Clang generate different instructions for the same C code. Clang's choice triggers the Rosetta bug.

## Minimal C Reproducer

```c
// test.c - compile with: gcc -O0 test.c -o test
#include <stdio.h>

int main(void) {
    double before, after;
    double val = 0.25;

    // Load 0.25 into xmm0
    __asm__ volatile("movsd %0, %%xmm0" : : "m"(val) : "xmm0");
    __asm__ volatile("movsd %%xmm0, %0" : "=m"(before));

    // This instruction should NOT modify xmm0
    __asm__ volatile("cvttpd2dq %%xmm0, %%xmm1" : : : "xmm0", "xmm1");

    __asm__ volatile("movsd %%xmm0, %0" : "=m"(after));

    printf("Before: %g\n", before);
    printf("After:  %g\n", after);

    if (before != after) {
        printf("BUG: xmm0 was corrupted!\n");
        return 1;
    }
    printf("OK\n");
    return 0;
}
```

**Native x86-64:** `Before: 0.25, After: 0.25, OK`
**Rosetta 2:** `Before: 0.25, After: 0, BUG: xmm0 was corrupted!`

## Quick Test

```bash
# Build and run the test
docker build -t rosetta-bug .
docker run --platform linux/amd64 --rm rosetta-bug
```

## The Fix

The included patch scripts binary-patch executables to work around the bug:

| Script | Use Case |
|--------|----------|
| `patch.py` | General binaries with NOP/INT3 code caves (e.g., Node.js, Bun) |
| `patch_dyalog.py` | Binaries without code caves, uses segment gap (e.g., Dyalog APL) |

The patching process:
1. Finds all `cvttpd2dq` and `cvtpd2dq` instructions where source != destination
2. Replaces each with a jump to a trampoline that:
   - Saves the source register
   - Executes the conversion instruction
   - Restores the source register
   - Returns to the original code

```bash
# Patch Node.js or similar (has NOP padding for trampolines)
python3 patch.py /path/to/binary /path/to/binary-patched

# Patch Dyalog APL or similar (uses segment gap for trampolines)
python3 patch_dyalog.py /path/to/binary /path/to/binary-patched

chmod +x /path/to/binary-patched
```

## Verify the Fix

```bash
# Build with patch
docker build -t rosetta-bug .
docker run --platform linux/amd64 --rm rosetta-bug

# Output:
# === Test C reproducer ===
# Before: 0.25
# After:  0
# BUG: xmm0 was corrupted!
#
# === Unpatched Node 25 ===
# 0.25 = 0 | 1.5 = 1
#
# === Patched Node 25 ===
# 0.25 = 0.25 | 1.5 = 1.5
```

## Related

- https://github.com/oven-sh/bun/issues/19677
