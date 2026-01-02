#!/bin/bash
#
# Test script for Rosetta 2 cvttpd2dq/cvtpd2dq patch
#
# This script tests the patch against Node.js, Bun, and Dyalog APL.
# Binaries are NOT included in this repo - you must provide them.
#
# PREREQUISITES
# =============
#
# 1. Docker Desktop with Rosetta emulation enabled
# 2. Python 3
# 3. An Apple Silicon Mac (M1/M2/M3/M4)
#
# OBTAINING BINARIES
# ==================
#
# Node.js and Bun can be extracted from Docker images automatically.
# Dyalog APL requires a .deb file you must obtain separately.
#
# Option A: Automatic extraction (Node.js + Bun only)
#   ./test-all.sh --extract
#
# Option B: Manual setup
#   mkdir -p binaries
#
#   # Node.js - extract from Docker
#   docker run --platform linux/amd64 --rm -v "$(pwd)/binaries:/out" \
#     node:25-slim cp /usr/local/bin/node /out/node
#
#   # Bun - extract from Docker
#   docker run --platform linux/amd64 --rm -v "$(pwd)/binaries:/out" \
#     oven/bun:latest cp /usr/local/bin/bun /out/bun
#
#   # Dyalog APL - extract from .deb (must obtain separately)
#   # Place dyalog-unicode_*.deb in current directory, then:
#   mkdir -p binaries/dyalog-extract
#   bsdtar -xf dyalog-unicode_*.deb -C binaries/dyalog-extract
#   bsdtar -xf binaries/dyalog-extract/data.tar.* -C binaries/dyalog-extract
#   cp binaries/dyalog-extract/opt/mdyalog/*/64/unicode/dyalog binaries/dyalog
#
# USAGE
# =====
#
#   ./test-all.sh              # Run tests (binaries must exist)
#   ./test-all.sh --extract    # Extract Node.js + Bun from Docker, then test
#   ./test-all.sh --help       # Show this help
#

set -e

BINARIES_DIR="binaries"
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
}

print_test() {
    echo -e "${YELLOW}► $1${NC}"
}

print_pass() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_fail() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "  $1"
}

extract_binaries() {
    print_header "Extracting binaries from Docker"
    mkdir -p "$BINARIES_DIR"

    print_test "Extracting Node.js 25..."
    docker run --platform linux/amd64 --rm -v "$(pwd)/$BINARIES_DIR:/out" \
        node:25-slim cp /usr/local/bin/node /out/node 2>/dev/null
    print_pass "Node.js extracted to $BINARIES_DIR/node"

    print_test "Extracting Bun..."
    docker run --platform linux/amd64 --rm -v "$(pwd)/$BINARIES_DIR:/out" \
        oven/bun:latest cp /usr/local/bin/bun /out/bun 2>/dev/null
    print_pass "Bun extracted to $BINARIES_DIR/bun"

    echo ""
    print_info "Note: Dyalog APL must be obtained separately (proprietary)"
    print_info "Place dyalog-unicode_*.deb in current directory and run:"
    print_info "  mkdir -p $BINARIES_DIR/dyalog-extract"
    print_info "  bsdtar -xf dyalog-unicode_*.deb -C $BINARIES_DIR/dyalog-extract"
    print_info "  bsdtar -xf $BINARIES_DIR/dyalog-extract/data.tar.* -C $BINARIES_DIR/dyalog-extract"
    print_info "  cp $BINARIES_DIR/dyalog-extract/opt/mdyalog/*/64/unicode/dyalog $BINARIES_DIR/dyalog"
}

run_in_docker() {
    local binary="$1"
    shift
    docker run --platform linux/amd64 --rm \
        -v "$(pwd)/$BINARIES_DIR:/binaries:ro" \
        debian:bookworm-slim \
        "$@" 2>/dev/null
}

test_node() {
    local binary="$1"
    local label="$2"

    # Node.js needs libatomic, use node image as base
    result=$(docker run --platform linux/amd64 --rm \
        -v "$(pwd)/$BINARIES_DIR:/binaries:ro" \
        node:25-slim /binaries/"$binary" -e "console.log(0.25)" 2>/dev/null || echo "ERROR")
    if [ "$result" = "0.25" ]; then
        print_pass "$label: 0.25 = $result"
        return 0
    else
        print_fail "$label: 0.25 = $result (expected 0.25)"
        return 1
    fi
}

test_bun() {
    local binary="$1"
    local label="$2"

    result=$(run_in_docker "$binary" /binaries/"$binary" -e "console.log(0.25)" 2>/dev/null || echo "ERROR")
    if [ "$result" = "0.25" ]; then
        print_pass "$label: 0.25 = $result"
        return 0
    else
        print_fail "$label: 0.25 = $result (expected 0.25)"
        return 1
    fi
}

test_dyalog() {
    local binary="$1"
    local label="$2"

    # Dyalog needs its libraries
    result=$(docker run --platform linux/amd64 --rm \
        -v "$(pwd)/$BINARIES_DIR:/binaries:ro" \
        -v "$(pwd)/$BINARIES_DIR/dyalog-extract/opt/mdyalog:/opt/mdyalog:ro" \
        -e "LD_LIBRARY_PATH=/opt/mdyalog/20.0/64/unicode/lib" \
        debian:bookworm-slim \
        sh -c "echo '1.5+2.5' | /binaries/$binary -s 2>/dev/null | head -1" 2>/dev/null || echo "ERROR")

    # Trim whitespace
    result=$(echo "$result" | tr -d '[:space:]')

    if [ "$result" = "4" ]; then
        print_pass "$label: 1.5+2.5 = $result"
        return 0
    else
        print_fail "$label: 1.5+2.5 = $result (expected 4)"
        return 1
    fi
}

patch_binary() {
    local input="$1"
    local output="$2"

    python3 patch.py "$BINARIES_DIR/$input" "$BINARIES_DIR/$output" > /dev/null
    chmod +x "$BINARIES_DIR/$output"
}

run_tests() {
    local tested=0
    local passed=0
    local failed=0

    # Node.js
    if [ -f "$BINARIES_DIR/node" ]; then
        print_header "Node.js 25"

        print_test "Testing unpatched..."
        if test_node "node" "Unpatched"; then
            print_info "(Bug not triggered - may be fixed in this version)"
        fi

        print_test "Patching..."
        patch_binary "node" "node.patched"
        print_info "$(python3 patch.py "$BINARIES_DIR/node" /dev/null 2>&1 | grep -E '^Found|^  [0-9]|code caves' | head -4)"

        print_test "Testing patched..."
        if test_node "node.patched" "Patched"; then
            ((passed++))
        else
            ((failed++))
        fi
        ((tested++))
    else
        print_header "Node.js 25"
        print_info "Skipped - $BINARIES_DIR/node not found"
        print_info "Run: ./test-all.sh --extract"
    fi

    # Bun
    if [ -f "$BINARIES_DIR/bun" ]; then
        print_header "Bun"

        print_test "Testing unpatched..."
        test_bun "bun" "Unpatched" || true

        print_test "Patching..."
        patch_binary "bun" "bun.patched"
        print_info "$(python3 patch.py "$BINARIES_DIR/bun" /dev/null 2>&1 | grep -E '^Found|^  [0-9]|code caves' | head -4)"

        print_test "Testing patched..."
        if test_bun "bun.patched" "Patched"; then
            ((passed++))
        else
            ((failed++))
        fi
        ((tested++))
    else
        print_header "Bun"
        print_info "Skipped - $BINARIES_DIR/bun not found"
        print_info "Run: ./test-all.sh --extract"
    fi

    # Dyalog APL
    if [ -f "$BINARIES_DIR/dyalog" ]; then
        print_header "Dyalog APL"

        print_test "Testing unpatched..."
        test_dyalog "dyalog" "Unpatched" || true

        print_test "Patching..."
        patch_binary "dyalog" "dyalog.patched"
        print_info "$(python3 patch.py "$BINARIES_DIR/dyalog" /dev/null 2>&1 | grep -E '^Found|^  [0-9]|segment gap|code caves' | head -5)"

        print_test "Testing patched..."
        if test_dyalog "dyalog.patched" "Patched"; then
            ((passed++))
        else
            ((failed++))
        fi
        ((tested++))
    else
        print_header "Dyalog APL"
        print_info "Skipped - $BINARIES_DIR/dyalog not found"
        print_info "Dyalog is proprietary. See instructions at top of this script."
    fi

    # Summary
    print_header "Summary"
    if [ $tested -eq 0 ]; then
        print_info "No binaries found to test!"
        print_info "Run: ./test-all.sh --extract"
        exit 1
    fi

    echo ""
    print_info "Tested: $tested binaries"
    print_info "Passed: $passed"
    print_info "Failed: $failed"

    if [ $failed -gt 0 ]; then
        exit 1
    fi
}

show_help() {
    head -50 "$0" | grep -E '^#' | sed 's/^# \?//'
}

# Main
case "${1:-}" in
    --extract)
        extract_binaries
        echo ""
        run_tests
        ;;
    --help|-h)
        show_help
        ;;
    "")
        run_tests
        ;;
    *)
        echo "Unknown option: $1"
        echo "Usage: $0 [--extract|--help]"
        exit 1
        ;;
esac
