#!/usr/bin/env bash
# Check a built PTX before it is used or committed (monorepo issue 67, ZKVM-114):
#
#   rand-zkvm-cuda/ptx/check-ptx.sh <file.ptx> [expected-sha256 | file.sha256]
#
# 1. every one of the eleven kernels `gpu-kernels/src/main.rs` defines is a `.visible .entry`
#    of the file (a PTX missing one loads and then fails at the first launch of it);
# 2. the file's sha256 is printed, and compared when an expected digest is given — as 64 hex
#    digits or as a `sha256sum`-format file. With no digest given, a sibling `<file>.sha256` is
#    used if it exists.
#
# It does not check the parameter ABI (`PTX_BUILD.md`, checklist step 1) or run anything.
set -euo pipefail

KERNELS=(scale_pow bit_reverse zero_extend to_col_major to_row_major dif_stage dif_tiles copy_columns poseidon2_rows poseidon2_compress poseidon2_inject)

if [ $# -lt 1 ] || [ ! -f "$1" ]; then
  echo "usage: $0 <file.ptx> [expected-sha256 | file.sha256]" >&2
  exit 2
fi
ptx="$1"

missing=()
for k in "${KERNELS[@]}"; do
  grep -Eq "^[[:space:]]*\.visible[[:space:]]+\.entry[[:space:]]+${k}[[:space:]]*\(" "$ptx" || missing+=("$k")
done
if [ ${#missing[@]} -ne 0 ]; then
  echo "FAIL: $ptx has no .visible .entry for: ${missing[*]}" >&2
  exit 1
fi
echo "ok: all ${#KERNELS[@]} kernel entries present"

if command -v sha256sum >/dev/null 2>&1; then
  digest=$(sha256sum "$ptx" | awk '{print $1}')
else
  digest=$(shasum -a 256 "$ptx" | awk '{print $1}')
fi
echo "sha256: $digest  $(basename "$ptx")"

expected="${2:-}"
if [ -z "$expected" ] && [ -f "$ptx.sha256" ]; then
  expected="$ptx.sha256"
fi
if [ -n "$expected" ]; then
  if [ -f "$expected" ]; then
    expected=$(awk 'NR==1 {print $1}' "$expected")
  fi
  if [ "$digest" != "$expected" ]; then
    echo "FAIL: sha256 mismatch: expected $expected" >&2
    exit 1
  fi
  echo "ok: sha256 matches the expected digest"
else
  echo "note: no expected digest given and no $ptx.sha256 — nothing to compare with"
fi
