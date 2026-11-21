# Multi-process stress harness (`stress_multiwriter_recovery`)

On-demand, real-OS multi-process stress harness for combolite coordinator /
multi-writer work (issue **#46**). It is the re-runnable validation harness for
the **#33** class of defect — _"parallel writers leave a sound archive that
won't open (`CDB_E_CORRUPT`)."_ Run it by hand against the current tree whenever
coordinator, slot take-over, or durability behaviour changes.

## What it does

A single binary with two roles:

- **controller** — forks and `exec`s `N` child processes, lets them run and
  commit, then sends `SIGKILL` at varied moments (near-simultaneous kill-all,
  and a stagger/take-over round where fresh joiners adopt a just-killed peer's
  slot while the cluster is still live). After each round it reopens the archive
  **without** `ACCEPT_LOSS` and checks for the #33 symptom:
  `open(no ACCEPT_LOSS) == CDB_E_CORRUPT` while the acked data is in fact intact
  under `ACCEPT_LOSS` (a sound archive wrongly rejected). On any `CDB_E_CORRUPT`
  it captures forensic state (dir listing, slot-file hexdumps, both open results,
  `ACCEPT_LOSS` data vs. the acked ground-truth logs) and snapshots the arena.
- **child** — opens the same archive read-write (no `ACCEPT_LOSS`), joins as a
  coordinator, and loops `begin -> put(REPLACE) -> commit` at `FULL` durability
  on its own disjoint entry band. After each acked commit it appends
  `(entry, counter)` to its own `fsync`'d ground-truth log, so the controller
  knows exactly what was durably committed before a kill.

It links the real POSIX host env (`cdb_hostenv`) and the core `combolite`
library — it exercises the production code paths, not a mock.

### Kill hygiene

The controller signals **only** the exact child PIDs it forked (tracked in a
`pids[]` array), with `kill(pid, SIGKILL)`. It **never** pattern-kills
(`pkill`/`killall`), never shells out, and never signals itself or an ancestor.
Every child is reaped with `waitpid` before its slot is reused, and the scratch
arena is recreated fresh each round.

## Build

The harness is **off by default** and is **never** registered with `ctest` — it
forks processes, sends `SIGKILL`, and runs for a time budget, so it is
non-deterministic and must not be part of the default test run. Enable it with
the `CDB_BUILD_STRESS` option (default `OFF`):

```bash
cmake --preset core-cpu-debug -DCDB_BUILD_STRESS=ON
cmake --build build-core-cpu-debug --target stress_multiwriter_recovery
```

A normal `cmake --preset core-cpu-debug` + `ctest --preset core-cpu-debug` is
unaffected when the option is left off (the stress subdirectory is not even
added to the build).

## Run

CLI (unchanged from the original repro tool):

```text
stress_multiwriter_recovery <self-abs-path> <scratchdir> <rounds> <N> <budget-sec>
```

- `self-abs-path` — absolute path to this binary (it re-`exec`s itself as a child)
- `scratchdir` — a caller-supplied, expendable scratch directory (recreated per round)
- `rounds` — number of kill rounds
- `N` — concurrent writer processes (clamped to `1..7`)
- `budget-sec` — wall-clock budget; the campaign stops when it is reached

### Bounded smoke run (seconds)

A quick sanity check — a few rounds with a short budget:

```bash
BIN="$PWD/build-core-cpu-debug/tests/stress/stress_multiwriter_recovery"
"$BIN" "$BIN" "$PWD/build-core-cpu-debug/stress-scratch" 3 2 10
```

It should finish in seconds and exit `0`.

### Full campaign (minutes)

Many rounds with a generous budget, e.g. the proven campaign shape:

```bash
BIN="$PWD/build-core-cpu-debug/tests/stress/stress_multiwriter_recovery"
"$BIN" "$BIN" "$PWD/build-core-cpu-debug/stress-scratch" 100000 7 600
```

The budget bounds the wall-clock regardless of the round count. A summary is
printed (and appended to `<scratchdir>/run.log`); `VERDICT:` reports whether the
#33 symptom was reproduced, whether any `CDB_E_CORRUPT` was genuine loss
(fail-closed working correctly), or whether the archive always reopened cleanly.

## Role

This is the validation harness for **#46** / coordinator and multi-writer
durability work, carried forward from the **#33** investigation. Run a full
campaign before and after changes to the coordinator, slot take-over, or
durability paths, and keep a short smoke run as a cheap pre-flight check.
