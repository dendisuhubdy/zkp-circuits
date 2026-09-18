#!/usr/bin/env bash
# Replaces the deleted `guests-compiled/evm/Makefile`'s `contracts` target (recovered at
# a43b801:guests-compiled/evm/Makefile). Recompiles ERC20.sol and diffs the result against the
# committed runtime bytecode. Needs the exact solc `contracts/SOLC.md` pins — a different 0.8.x
# optimises differently and the hex will differ, so the version is asserted rather than trusted.
# With no solc on PATH this says so and succeeds, so it is safe to run anywhere; no test needs it.
#
# Usage: bash guests-compiled/evm/contracts/build.sh
#        SOLC=/path/to/solc bash guests-compiled/evm/contracts/build.sh
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

SOLC="${SOLC:-solc}"
SOLC_FLAGS=(--optimize --optimize-runs 200 --evm-version shanghai --bin-runtime)
SOLC_VERSION="0.8.37"

if ! command -v "$SOLC" >/dev/null 2>&1; then
	echo "contracts: no '$SOLC' on PATH — see contracts/SOLC.md for the pinned binary; nothing to check"
	exit 0
fi

v=$("$SOLC" --version | tail -1)
echo "contracts: $v"
case "$v" in
*"$SOLC_VERSION"*) ;;
*)
	echo "contracts: FAIL — this is not the pinned solc $SOLC_VERSION (contracts/SOLC.md); its output will differ" >&2
	exit 1
	;;
esac

tmp=$(mktemp -t erc20.runtime.hex)
trap 'rm -f "$tmp"' EXIT INT TERM
"$SOLC" "${SOLC_FLAGS[@]}" contracts/ERC20.sol | tail -1 > "$tmp"
diff -u contracts/erc20.runtime.hex "$tmp" && echo "contracts: erc20.runtime.hex reproduces"
