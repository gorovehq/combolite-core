# Contributing to combolite-core

Thanks for your interest in `combolite-core` — a pure **C99**, crash-safe, embeddable
multi-model database engine. Contributions (bug fixes, features, docs, tests) are welcome and
go through the **same review pipeline** as internal work: tracked by an issue, reviewed, and
never merged unreviewed.

> This file is the contributor-facing summary of the project's engineering rules. The
> authoritative, complete ruleset is **`db-combolite/CLAUDE.md`** (the umbrella repo). Where
> this file and `CLAUDE.md` differ, `CLAUDE.md` wins — please read it before a non-trivial
> change.

---

## Ground rules (non-negotiable)

- **C99 only.** No compiler extensions in the core; no C11/C++ features. Builds are
  **warnings-as-errors** (`-Werror`) with `-Wconversion -Wsign-conversion -Wvla` — **no VLAs**,
  and all narrowing conversions are **explicit casts**.
- **No heap allocation in the core.** Memory comes from **caller-owned buffers** (sized via the
  `cdb_*_buffers_size()` helpers) plus the optional env `alloc`/`free` hooks (`cdb_env.h`, host
  profile only). Readers return **views into caller memory**, not copies. Respect slot-pointer
  lifetime (valid until the next open of the same model, outside a tx/op scope — wrap multi-step
  work in `cdb_db_op_begin` / `cdb_db_op_end`).
- **Explicit byte order** via `cdb_endian.h` — **never** cast raw bytes to integers.
- **Canonical encoding.** Decoders/validators reject non-canonical encodings (spec §14.6.5).
- **Fail closed.** Fallible functions return `cdb_status`; on error or ambiguity, deny/abort —
  never proceed on partial/garbage data. Value-writer errors are sticky.
- **Never hand-roll crypto.** Clean-room, approved dependencies only (see `docs/spec/12-security.md`).
- **Treat all on-disk / wire / query input as untrusted** — validate at every boundary.

## Development environment

```bash
# Clone with the vendored submodules (Mbed TLS, xz, Unity).
git clone --recurse-submodules <url> && cd combolite-core

# Canonical test preset — ASan + UBSan (+ CUDA/Vulkan accel):
cmake --preset core-both-debug && cmake --build --preset core-both-debug
ctest --preset core-both-debug

# CPU-only (no CUDA/Vulkan SDKs needed):
cmake --preset core-cpu-debug && cmake --build --preset core-cpu-debug && ctest --preset core-cpu-debug
```

Reference docs: `docs/dev/` (architecture, memory model, testing) and `docs/spec/` (the on-disk
and query specification, §01–§15).

## Code style

- Formatting is enforced by **`.clang-format`** (4-space indent, Linux brace style, 100-col).
  Run `clang-format -i` on files you touch; CI checks changed lines with
  `clang-format --dry-run -Werror`. Guard deliberate hand-formatting (packed byte-tables) with
  `// clang-format off` / `// clang-format on`.
- Every **public** symbol carries a doc comment (purpose, params, return, errors, side effects).
- Prefer guard clauses / early return; keep functions single-purpose; name constants (no magic
  numbers). Make illegal states unrepresentable where practical.

## Tests (definition of "done")

- Every change ships tests (Unity). **Every bug fix adds a regression test that reproduces the
  defect first** (fails on the pre-fix commit, passes on the fix) — red→green.
- Code that parses/validates untrusted input or mutates persistent state ships **negative /
  abuse-path** tests; crash-safety is exercised with the fault devices (`cdb_faultdev` /
  `cdb_faultenv`).
- Register new tests via `cdb_add_test`; keep them deterministic and hermetic (no network /
  wall-clock / shared mutable state). The suite must be **ASan + UBSan clean**.
- Coverage must not regress (see `docs/dev/testing-and-coverage.md`).

## Git workflow

- Branch off `main`; name branches with an **underscore type prefix**:
  `feat_`, `fix_`, `test_`, `docs_`, `refactor_`, `build_`, `merge_` (e.g. `fix_null-deref-parser`).
- **Conventional Commits** (`type(scope): summary`), imperative, ≤72-char subject; atomic commits
  (one logical change). **Sign your commits.**
- Commit author email is the project norm — use your GitHub **noreply** address.
- **No AI-assistant attribution in commit messages or PRs.** Human + tooling attribution lives
  only in `ATTRIBUTIONS.md`.
- Merge to `main` is **`--no-ff`** and **merged branches are kept** (audit trail). `main` is
  always releasable; no direct pushes, no force-push.

## Pull requests

- Every change to `main` goes through a PR referencing its issue (`Fixes #N`). Use the PR
  template. At least one approving review; **security-relevant** changes get a security-focused
  review. All CI gates green before merge.
- Keep PRs small and single-purpose; large diffs get split.

## Reporting bugs & requesting features

- File an issue using the templates (bug report / feature request). Search first to avoid
  duplicates.
- **Security vulnerabilities:** do **not** open a public issue — use the private advisory flow
  (see [`SECURITY.md`](SECURITY.md)).

## Contributor recognition

External contributors are acknowledged in [`CONTRIBUTORS.md`](CONTRIBUTORS.md). By contributing
you agree your contributions are licensed under the repository's [`LICENSE`](LICENSE).
