#!/usr/bin/env bash
# Replaces the deleted `guests-compiled/evm/Makefile`'s `contracts` target (recovered from
# 4df7cea:guests-compiled/evm/Makefile, a commit on main). Recompiles ERC20.sol (shanghai),
# Cancun.sol (cancun) and Osaka.sol (osaka) and diffs each against its committed runtime bytecode. Needs the exact solc `contracts/SOLC.md` pins — a different 0.8.x
# optimises differently and the hex will differ, so the version is asserted rather than trusted.
# With no solc on PATH this says so and succeeds, so it is safe to run anywhere; no test needs it.
#
# Usage: bash guests-compiled/evm/contracts/build.sh
#        SOLC=/path/to/solc bash guests-compiled/evm/contracts/build.sh
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

SOLC="${SOLC:-solc}"
SOLC_FLAGS=(--optimize --optimize-runs 200 --bin-runtime)
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

tmp=$(mktemp -t runtime.hex)
trap 'rm -f "$tmp"' EXIT INT TERM
status=0
# source, --evm-version, committed hex
for spec in "ERC20 shanghai erc20" "Cancun cancun cancun" "Osaka osaka osaka"; do
	read -r src evm hex <<<"$spec"
	"$SOLC" "${SOLC_FLAGS[@]}" --evm-version "$evm" "contracts/$src.sol" | tail -1 > "$tmp"
	if diff -u "contracts/$hex.runtime.hex" "$tmp"; then
		echo "contracts: $hex.runtime.hex reproduces"
	else
		status=1
	fi
done
exit "$status"
