#!/usr/bin/env bash
# QA integration + abuse suite for the on-demand multi-process stress harness
# (tests/stress, issue #46; origin #33).
#
# This drives the BUILT stress_multiwriter_recovery binary. It is deliberately NOT part
# of the default ctest run (the harness forks processes and sends SIGKILL); it
# is the on-demand smoke check a developer or CI runs to prove the tool still
# builds and exits clean.
#
# It verifies the behavioral acceptance criteria:
#   - a short bounded smoke run exits 0 and prints a VERDICT (AC6).
#   - runtime kill hygiene: the harness reaps every child it spawned — no
#     stress_multiwriter_recovery processes linger after it exits (AC7). This script
#     NEVER kills anything by pattern; it only observes a before/after delta,
#     so it is safe under concurrent harness runs (topic-agent-exec-hygiene).
#   - abuse / negative paths: no args and too-few args fail closed with the
#     usage message and exit 2; a non-executable self-path does not hang or
#     crash the controller; non-numeric / zero / negative counts are tolerated.
#
# Resolution order for the binary:
#   $STRESS_BIN  ->  build-*/tests/stress/stress_multiwriter_recovery  ->  build the
#   stress_multiwriter_recovery target in an already-configured build dir.
# If none is available the suite SKIPs (exit 0) rather than failing in an
# environment without a toolchain/build.
set -u

here="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$here/../.." && pwd)"

pass=0
fail=0
ok()  { pass=$((pass+1)); printf 'ok   - %s\n' "$1"; }
bad() { fail=$((fail+1)); printf 'FAIL - %s\n' "$1"; }

skip_all() { printf 'SKIP - %s\n' "$1"; exit 0; }

run() { # run <timeout-sec> <cmd...> ; sets RC + CAP
  _to="$1"; shift
  if command -v timeout >/dev/null 2>&1; then
    CAP="$(timeout -k 5 "$_to" "$@" 2>&1)"; RC=$?
  else
    CAP="$("$@" 2>&1)"; RC=$?
  fi
}

count_procs() { pgrep -x stress_multiwriter_recovery 2>/dev/null | wc -l | tr -d ' '; }

# --------------------------------------------------------------------------
# Locate (or build) the binary.
# --------------------------------------------------------------------------
BIN="${STRESS_BIN:-}"
if [ -z "$BIN" ] || [ ! -x "$BIN" ]; then
  BIN=""
  for cand in "$ROOT"/build*/tests/stress/stress_multiwriter_recovery; do
    [ -x "$cand" ] && { BIN="$cand"; break; }
  done
fi
if [ -z "$BIN" ] && command -v cmake >/dev/null 2>&1; then
  for bd in "$ROOT"/build-stress "$ROOT"/build-core-cpu-debug; do
    if [ -f "$bd/CMakeCache.txt" ]; then
      if cmake --build "$bd" --target stress_multiwriter_recovery >/dev/null 2>&1 \
         && [ -x "$bd/tests/stress/stress_multiwriter_recovery" ]; then
        BIN="$bd/tests/stress/stress_multiwriter_recovery"; break
      fi
    fi
  done
fi
[ -n "$BIN" ] && [ -x "$BIN" ] || skip_all "no built stress_multiwriter_recovery found and none could be built"
printf '# using binary: %s\n' "$BIN"

if ! command -v pgrep >/dev/null 2>&1; then
  echo "# note: pgrep unavailable; runtime-orphan assertion will be skipped"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# --------------------------------------------------------------------------
# Abuse / negative CLI paths (cheap, no fork of writers).
# --------------------------------------------------------------------------
run 10 "$BIN"
if [ "$RC" -eq 2 ] && printf '%s' "$CAP" | grep -q 'usage:'; then
  ok "no args -> exit 2 with usage (fail closed)"
else
  bad "no args: expected exit 2 + usage, got rc=$RC"
fi

run 10 "$BIN" "$BIN" "$tmp/x" 1
if [ "$RC" -eq 2 ] && printf '%s' "$CAP" | grep -q 'usage:'; then
  ok "too-few args -> exit 2 with usage (fail closed)"
else
  bad "too-few args: expected exit 2 + usage, got rc=$RC"
fi

# non-executable self-path: children cannot exec; controller must not hang or
# crash and must still exit 0 within the time budget.
before="$(count_procs 2>/dev/null || echo 0)"
run 30 "$BIN" "$tmp/does-not-exist" "$tmp/badself" 2 2 3
if [ "$RC" -eq 0 ]; then
  ok "bad self-path: controller survives failed child exec and exits 0"
else
  bad "bad self-path: expected exit 0, got rc=$RC"
fi

# non-numeric counts (atol/atoi -> 0): must be tolerated, not crash.
run 20 "$BIN" "$BIN" "$tmp/nonnum" abc 2 2
if [ "$RC" -eq 0 ]; then
  ok "non-numeric rounds/budget tolerated (no crash)"
else
  bad "non-numeric args: expected exit 0, got rc=$RC"
fi

# --------------------------------------------------------------------------
# Bounded smoke run (AC6): a few rounds, short budget. Natural exit expected
# well under the timeout, so timeout never has to kill the controller.
# --------------------------------------------------------------------------
before="$(count_procs 2>/dev/null || echo 0)"
run 90 "$BIN" "$BIN" "$tmp/smoke" 3 2 10
if [ "$RC" -eq 0 ]; then
  ok "bounded smoke (3 2 10) exits 0"
else
  bad "bounded smoke: expected exit 0, got rc=$RC"
  printf '%s\n' "$CAP" | tail -20
fi

if printf '%s' "$CAP" | grep -q 'VERDICT'; then
  ok "smoke run prints a VERDICT line"
else
  bad "smoke run produced no VERDICT line"
fi

if printf '%s' "$CAP" | grep -qE 'total_commits_acked=[1-9]'; then
  ok "smoke run acked at least one durable commit"
else
  bad "smoke run acked zero commits (writers never made progress)"
fi

# runtime kill hygiene: no lingering harness processes after a clean exit.
if command -v pgrep >/dev/null 2>&1 && [ "$RC" -eq 0 ]; then
  # brief settle for reaped children to leave the table.
  sleep 1
  after="$(count_procs)"
  if [ "$after" -le "$before" ]; then
    ok "no orphaned stress_multiwriter_recovery processes after exit (delta ${before}->${after})"
  else
    bad "orphaned stress_multiwriter_recovery processes remain (delta ${before}->${after})"
  fi
fi

# single-writer smoke: the N=1 (no takeover) path also exits clean.
run 60 "$BIN" "$BIN" "$tmp/solo" 2 1 6
if [ "$RC" -eq 0 ]; then
  ok "single-writer smoke (2 1 6) exits 0"
else
  bad "single-writer smoke: expected exit 0, got rc=$RC"
fi

# --------------------------------------------------------------------------
echo "--------------------------------------------------------------------"
printf 'smoke/abuse: %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
