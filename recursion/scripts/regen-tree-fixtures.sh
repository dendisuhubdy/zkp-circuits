#!/usr/bin/env bash
# Regenerate the test-profile tree fixtures (monorepo issue 55, ZKVM-102): one command, on a
# host with the memory.
#
#   recursion/scripts/regen-tree-fixtures.sh            # generate, then check
#   recursion/scripts/regen-tree-fixtures.sh --check    # only check what is cached
#   recursion/scripts/regen-tree-fixtures.sh --dry-run  # print what would run
#
# What it runs:
#   1. `tests/tree.rs::generate_test_tree_fixtures` (ignored in the suite): proves whatever
#      $RECURSION_FIXTURES lacks or holds stale — up to four tier-16 RV32 bundle proofs, four
#      tier-18 rVM leaves, the foreign leaf, two steps and the root, one at a time.
#   2. the tree suite with RECURSION_REQUIRE_TREE_FIXTURES=1, so a missing or stale fixture is
#      a failure and not a skip. A failure here after a clean step 1 means stale *pins*: the
#      lines the script prints at the end are the values to re-record.
#
# Memory: recursion/docs/08 §5 prices this at about 34 GB (the step and root proofs; 34.35 and
# 33.21 GB maximum RSS when last run, at tier 19 before phase 4 — the steps are tier 18 now and
# this has not been re-measured; the script records the new figure). It refuses to start below
# MIN_GB (default 40) unless FORCE=1. Run it from a plain terminal: an agent harness kills
# background commands past roughly 20 GB.
#
# Environment: RECURSION_FIXTURES (default recursion/target/recursion-fixtures), THREADS
# (default: all cores), MIN_GB, FORCE, CARGO (default cargo).
set -euo pipefail

mode=generate
for arg in "$@"; do
  case "$arg" in
    --check) mode=check ;;
    --dry-run) mode=dry ;;
    -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$here"

CARGO="${CARGO:-cargo}"
MIN_GB="${MIN_GB:-40}"
export RECURSION_FIXTURES="${RECURSION_FIXTURES:-$here/target/recursion-fixtures}"

case "$(uname -s)" in
  Darwin)
    mem_gb=$(( $(sysctl -n hw.memsize) / 1073741824 ))
    cores=$(sysctl -n hw.ncpu)
    keep_awake=(caffeinate -is)
    time_cmd=(/usr/bin/time -l)
    ;;
  *)
    mem_gb=$(( $(awk '/MemTotal/ {print $2}' /proc/meminfo) / 1048576 ))
    cores=$(nproc)
    keep_awake=()
    if [ -x /usr/bin/time ]; then time_cmd=(/usr/bin/time -v); else time_cmd=(); fi
    ;;
esac
export RAYON_NUM_THREADS="${THREADS:-$cores}"

stamp="$(date -u +%F)"
log_dir="$here/docs/measurements"
gen_log="$log_dir/$stamp-tree-test-fixtures-regen.log"
suite_log="$log_dir/$stamp-tree-test-suite-after-regen.log"

gen_cmd=("${keep_awake[@]}" "${time_cmd[@]}" "$CARGO" test --release --features parallel --test tree generate_test_tree_fixtures -- --ignored --exact --nocapture)
suite_cmd=("$CARGO" test --release --features parallel --test tree -- --nocapture --test-threads=1)

echo "host: $(uname -sm), ${mem_gb} GB, ${cores} cores; RAYON_NUM_THREADS=$RAYON_NUM_THREADS"
echo "fixtures: $RECURSION_FIXTURES"
echo "commit: $(git rev-parse HEAD 2>/dev/null || echo unknown)"

if [ "$mode" = dry ]; then
  echo "would run (1): ${gen_cmd[*]}"
  echo "         log: $gen_log"
  echo "would run (2): RECURSION_REQUIRE_TREE_FIXTURES=1 ${suite_cmd[*]}"
  echo "         log: $suite_log"
  exit 0
fi

mkdir -p "$log_dir" "$RECURSION_FIXTURES/tree"

if [ "$mode" = generate ]; then
  if [ "$mem_gb" -lt "$MIN_GB" ] && [ "${FORCE:-0}" != 1 ]; then
    echo "refusing: this host has ${mem_gb} GB and the regeneration is priced at about 34 GB (MIN_GB=$MIN_GB); set FORCE=1 to try anyway" >&2
    exit 3
  fi
  echo "== (1) generating; log: $gen_log"
  "${gen_cmd[@]}" 2>&1 | tee "$gen_log"
fi

echo "== (2) the tree suite, fixtures required; log: $suite_log"
set +e
RECURSION_REQUIRE_TREE_FIXTURES=1 "${suite_cmd[@]}" 2>&1 | tee "$suite_log"
suite_status=${PIPESTATUS[0]}
set -e

echo
echo "== values printed by this run (re-record the ones that differ from tests/pins.json and tests/tree.rs):"
grep -hE '^(TREE_TEST_|TREE-FIXTURES)|maximum resident set size|Maximum resident set size' "$gen_log" "$suite_log" 2>/dev/null | sort -u || true
echo
if [ "$suite_status" -eq 0 ]; then
  cat <<MSG
The tree suite passed with fixtures required. To finish:
  1. set \`state = current\` in tests/tree-fixtures.status, with \`recorded_leaf_cpu_rows\` =
     pins.json's aggregate_test_n1_cpu_rows and \`recorded_at\` = this commit;
  2. copy $RECURSION_FIXTURES/tree/ to every box that runs the suite;
  3. commit the two logs under docs/measurements/ and restate the host memory in docs/08 §5
     from the "maximum resident set size" lines above.
MSG
else
  cat <<MSG
The tree suite failed with fixtures required (exit $suite_status). If step (1) completed, the
fixtures are fresh and the failures are stale pins — tests/tree-fixtures.status lists them
(\`stale_pins\`). Re-record them from the TREE_TEST_* lines above (the failing assertions print
the measured values), re-run with --check, and only then set \`state = current\`.
MSG
fi
exit "$suite_status"
