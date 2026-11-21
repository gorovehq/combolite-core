#!/usr/bin/env bash
# QA static gate suite for the on-demand multi-process stress harness
# (tests/stress, issue #46; origin of the #33 "sound archive rejected with
# CDB_E_CORRUPT" investigation).
#
# These checks are deterministic, hermetic, and fast: no build, no fork, no
# network, no clock. They assert the acceptance criteria that can be decided by
# inspecting the delivered files:
#   - kill hygiene: the harness signals ONLY its own tracked child PIDs
#     (kill(pids[i], SIGKILL)) and never pattern-kills, broadcasts, shells out,
#     or signals itself/ancestors (AC7, topic-agent-exec-hygiene).
#   - NO AI attribution anywhere in the delivered files (repo git rule, AC10).
#   - NO conflict/patch markers in the sources and NO .patch/.rej/.orig tracked
#     in the tree (edit hygiene, AC9).
#   - CMake wiring: root option CDB_BUILD_STRESS defaults OFF and the stress
#     subdir is guarded by it; tests/stress registers NO add_test(), so the
#     default ctest run is unaffected (AC1, AC3/AC4-exclusion).
#   - C99 marker + CLI contract + README coverage.
#   - clang-format clean against the repo style (AC2) when clang-format exists.
#
# Each content gate is ALSO chaos-validated: it is run against a crafted
# known-bad fixture and MUST go red (verify the gate actually fails) — a guard
# never seen to fail is unproven.
#
# Exit 0 = all gates pass. Non-zero = at least one gate failed.
set -u

here="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$here/../.." && pwd)"
SRC="$ROOT/tests/stress/stress_multiwriter_recovery.c"
STRESS_CMAKE="$ROOT/tests/stress/CMakeLists.txt"
README="$ROOT/tests/stress/README.md"
ROOT_CMAKE="$ROOT/CMakeLists.txt"

# Delivered files whose *content* the hygiene gates scan.
DELIVERED="$SRC $STRESS_CMAKE $README $ROOT_CMAKE"

pass=0
fail=0
skip=0
ok()   { pass=$((pass+1)); printf 'ok   - %s\n' "$1"; }
bad()  { fail=$((fail+1)); printf 'FAIL - %s\n' "$1"; }
skp()  { skip=$((skip+1)); printf 'SKIP - %s\n' "$1"; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# --------------------------------------------------------------------------
# Reusable scanners. Each returns 0 when the file is CLEAN (gate passes),
# 1 when it is DIRTY (gate trips). This lets us run them on the real files
# (expect clean) and on bad fixtures (expect dirty).
# --------------------------------------------------------------------------

# Kill hygiene over a single C source: clean iff
#   (a) there is NO forbidden kill-ish construct, and
#   (b) every non-comment line that calls kill( uses the tracked form
#       kill(pids[i], SIGKILL) only.
scan_kill_hygiene() {
  f="$1"
  # (a) forbidden broadcast / pattern / self / shell-out constructs.
  if grep -nEq 'pkill|killall|killpg|getppid|\bsystem[[:space:]]*\(|\bpopen[[:space:]]*\(|[^a-zA-Z_]kill[[:space:]]*\([[:space:]]*0|[^a-zA-Z_]kill[[:space:]]*\([[:space:]]*-|[^a-zA-Z_]kill[[:space:]]*\([[:space:]]*getpid' "$f"; then
    return 1
  fi
  # (b) any CODE line that invokes kill( must match the tracked-PID form.
  #     Comment lines (leading * or // or /*) are ignored.
  viol="$(grep -nE '[^a-zA-Z_]kill[[:space:]]*\(' "$f" \
            | grep -vE '^[0-9]+:[[:space:]]*(\*|//|/\*)' \
            | grep -vE 'kill\(pids\[i\],[[:space:]]*SIGKILL\)' || true)"
  [ -z "$viol" ]
}

# AI-attribution scan: clean iff none of the banned tokens appear.
scan_no_attribution() {
  ! grep -rniEq 'co-authored-by|generated with|claude|chatgpt|copilot|openai|\banthropic\b|ai[-_ ]generated|written by (an )?ai|language model' "$@"
}

# Conflict / patch marker scan: clean iff none present. Git conflict markers
# are EXACTLY seven <,=,> (the 8th char differs), so decorative rules of many
# '=' in the source are not matched.
scan_no_markers() {
  ! grep -nEq '^(<<<<<<<([^<]|$)|=======([^=]|$)|>>>>>>>([^>]|$))|^diff --git |^@@ -[0-9]|^\*\*\* [0-9]+,[0-9]+ \*\*\*\*$' "$@"
}

# --------------------------------------------------------------------------
# 0. Files exist.
# --------------------------------------------------------------------------
all_present=1
for f in $SRC $STRESS_CMAKE $README $ROOT_CMAKE; do
  if [ -f "$f" ]; then :; else bad "missing delivered file: $f"; all_present=0; fi
done
[ "$all_present" -eq 1 ] && ok "all delivered files present"

if [ ! -f "$SRC" ]; then
  echo "cannot continue without source"; exit 1
fi

# --------------------------------------------------------------------------
# 1. Kill hygiene (AC7) — real source clean, bad fixture tripped.
# --------------------------------------------------------------------------
if scan_kill_hygiene "$SRC"; then
  ok "kill hygiene: only kill(pids[i], SIGKILL); no pattern/broadcast/self kill"
else
  bad "kill hygiene: forbidden kill construct or untracked kill() in $SRC"
fi

cat > "$tmp/bad_kill.c" <<'EOF'
#include <signal.h>
int main(void){ pkill("stress"); kill(getppid(), SIGKILL); kill(0, SIGTERM); return 0; }
EOF
if scan_kill_hygiene "$tmp/bad_kill.c"; then
  bad "kill-hygiene gate did NOT trip on a known-bad fixture (gate is broken)"
else
  ok "kill-hygiene gate trips on a known-bad fixture (chaos-validated)"
fi

# --------------------------------------------------------------------------
# 2. No AI attribution (AC10) — delivered files clean, bad fixture tripped.
# --------------------------------------------------------------------------
if scan_no_attribution $DELIVERED; then
  ok "no AI-attribution strings in delivered files"
else
  bad "AI-attribution string found in delivered files"
fi

printf 'Co-Authored-By: Claude\n' > "$tmp/bad_attr.txt"
if scan_no_attribution "$tmp/bad_attr.txt"; then
  bad "attribution gate did NOT trip on a known-bad fixture (gate is broken)"
else
  ok "attribution gate trips on a known-bad fixture (chaos-validated)"
fi

# --------------------------------------------------------------------------
# 3. No conflict/patch markers (AC9) — sources clean, bad fixture tripped.
# --------------------------------------------------------------------------
if scan_no_markers $DELIVERED; then
  ok "no conflict/patch markers in delivered files"
else
  bad "conflict/patch marker found in delivered files"
fi

{ printf '<<<<<<< HEAD\n'; printf '=======\n'; printf '>>>>>>> other\n'; } > "$tmp/bad_marks.txt"
if scan_no_markers "$tmp/bad_marks.txt"; then
  bad "marker gate did NOT trip on a known-bad fixture (gate is broken)"
else
  ok "marker gate trips on a known-bad fixture (chaos-validated)"
fi

# decorative '=' rules in the real source must NOT be mistaken for markers.
if grep -qE '={12,}' "$SRC" && scan_no_markers "$SRC"; then
  ok "decorative '=' banners in source are not flagged as conflict markers"
fi

# --------------------------------------------------------------------------
# 4. No tracked .patch/.rej/.orig in the tree (AC9), excluding third-party.
# --------------------------------------------------------------------------
if command -v git >/dev/null 2>&1 && git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1; then
  stray="$(git -C "$ROOT" ls-files | grep -E '\.(patch|rej|orig)$' | grep -vE '^third-party/' || true)"
  if [ -z "$stray" ]; then
    ok "no tracked .patch/.rej/.orig files in the tree"
  else
    bad "tracked patch artifacts present: $stray"
  fi
else
  skp "git not available: tracked-artifact check"
fi

# --------------------------------------------------------------------------
# 5. CMake wiring: default build/ctest unaffected (AC1, AC3/AC4).
# --------------------------------------------------------------------------
# 5a. root option exists and defaults OFF.
if grep -Eq 'option\(CDB_BUILD_STRESS.*[[:space:]]OFF\)' "$ROOT_CMAKE"; then
  ok "root CMake defines option(CDB_BUILD_STRESS ... OFF)"
else
  bad "root CMake missing option(CDB_BUILD_STRESS ... OFF)"
fi

# 5b. the stress subdir is only added under an if(CDB_BUILD_STRESS) guard.
guarded="$(awk '
  /if[[:space:]]*\(CDB_BUILD_STRESS\)/ {g=1}
  /endif[[:space:]]*\(/            {g=0}
  /add_subdirectory\([[:space:]]*tests\/stress[[:space:]]*\)/ { if (g) print "GUARDED"; else print "UNGUARDED" }
' "$ROOT_CMAKE")"
if printf '%s\n' "$guarded" | grep -q GUARDED && ! printf '%s\n' "$guarded" | grep -q UNGUARDED; then
  ok "add_subdirectory(tests/stress) is guarded by if(CDB_BUILD_STRESS)"
else
  bad "add_subdirectory(tests/stress) not guarded by CDB_BUILD_STRESS (default build affected)"
fi

# 5c. the stress CMake builds the target but registers NO ctest.
if [ -f "$STRESS_CMAKE" ]; then
  if grep -Eq 'add_executable\([[:space:]]*stress_multiwriter_recovery' "$STRESS_CMAKE"; then
    ok "tests/stress/CMakeLists.txt builds stress_multiwriter_recovery"
  else
    bad "tests/stress/CMakeLists.txt does not add_executable(stress_multiwriter_recovery)"
  fi
  # strip comments, then there must be no add_test(.
  if grep -vE '^[[:space:]]*#' "$STRESS_CMAKE" | grep -Eq 'add_test[[:space:]]*\('; then
    bad "tests/stress/CMakeLists.txt registers an add_test() — would enter default ctest"
  else
    ok "tests/stress/CMakeLists.txt registers NO add_test() (excluded from ctest)"
  fi
  if grep -q 'CDB_WARNINGS' "$STRESS_CMAKE"; then
    ok "stress target uses the repo \${CDB_WARNINGS} set"
  else
    bad "stress target does not apply \${CDB_WARNINGS}"
  fi
fi

# chaos-validate the add_test detector on a bad fixture.
printf 'add_executable(x x.c)\nadd_test(NAME x COMMAND x)\n' > "$tmp/bad.cmake"
if grep -vE '^[[:space:]]*#' "$tmp/bad.cmake" | grep -Eq 'add_test[[:space:]]*\('; then
  ok "add_test detector trips on a known-bad CMake fixture (chaos-validated)"
else
  bad "add_test detector did NOT trip on a known-bad fixture (gate is broken)"
fi

# 5d. a commented-out add_test must NOT be flagged (avoid false positive).
printf '# add_test(NAME nope COMMAND nope)\nadd_executable(y y.c)\n' > "$tmp/ok.cmake"
if grep -vE '^[[:space:]]*#' "$tmp/ok.cmake" | grep -Eq 'add_test[[:space:]]*\('; then
  bad "add_test detector false-positives on a commented-out line"
else
  ok "add_test detector ignores commented-out add_test (no false positive)"
fi

# --------------------------------------------------------------------------
# 6. C99 marker + CLI contract.
# --------------------------------------------------------------------------
if grep -q '#define _POSIX_C_SOURCE' "$SRC"; then
  ok "source sets _POSIX_C_SOURCE (POSIX/C99 feature test)"
else
  bad "source missing _POSIX_C_SOURCE define"
fi

if grep -q '<self-abs-path> <scratchdir> <rounds> <N> <budget-sec>' "$SRC"; then
  ok "CLI usage string matches the mandated contract"
else
  bad "CLI usage string drifted from <self-abs-path> <scratchdir> <rounds> <N> <budget-sec>"
fi

# N is clamped to the safe band (1..7) so entry = wid*BAND+k stays < 64.
if grep -Eq 'N[[:space:]]*>[[:space:]]*7' "$SRC" && grep -Eq 'N[[:space:]]*<[[:space:]]*1' "$SRC"; then
  ok "N is clamped to the documented 1..7 band"
else
  bad "N clamp (1..7) not found — writer bands could exceed the entry limit"
fi

# --------------------------------------------------------------------------
# 7. README coverage (what / build option / smoke / full / role).
# --------------------------------------------------------------------------
if [ -f "$README" ]; then
  miss=""
  for needle in '#46' '#33' 'CDB_BUILD_STRESS' 'smoke' 'kill'; do
    grep -qiF "$needle" "$README" || miss="$miss $needle"
  done
  if [ -z "$miss" ]; then
    ok "README documents #46/#33, the build option, smoke, and kill hygiene"
  else
    bad "README missing topics:$miss"
  fi
fi

# --------------------------------------------------------------------------
# 8. clang-format clean against repo style (AC2), if the tool exists.
# --------------------------------------------------------------------------
if command -v clang-format >/dev/null 2>&1 && [ -f "$ROOT/.clang-format" ]; then
  if ( cd "$ROOT" && clang-format --dry-run -Werror -style=file "tests/stress/stress_multiwriter_recovery.c" ) >/dev/null 2>&1; then
    ok "clang-format clean against repo .clang-format"
  else
    bad "clang-format reports formatting differences"
  fi
else
  skp "clang-format unavailable: formatting check"
fi

# --------------------------------------------------------------------------
echo "--------------------------------------------------------------------"
printf 'static gates: %d passed, %d failed, %d skipped\n' "$pass" "$fail" "$skip"
[ "$fail" -eq 0 ]
