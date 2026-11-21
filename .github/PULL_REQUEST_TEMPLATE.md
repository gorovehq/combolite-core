<!-- Keep PRs small and single-purpose. See CONTRIBUTING.md. -->

## What & why
<!-- What does this change do, and why? -->

Closes #<!-- issue number (required; file an issue first if none exists) -->

## Risk & impact
<!-- Blast radius. Does it touch a public contract (on-disk/wire format, public C99 API)?
     Any behaviour change for valid inputs? -->

## Test evidence
<!-- How it was verified. For a bug fix, show the red→green regression test (fails on the
     merge-base, passes on the fix). Paste the relevant ctest / sanitizer result. -->

## Security / privacy impact
<!-- Any effect on untrusted-input handling, crypto, memory safety, or data handling?
     Security-relevant PRs get a security-focused review. -->

## Checklist
- [ ] Branch named with an underscore type prefix (`feat_`/`fix_`/`test_`/`docs_`/…).
- [ ] C99, builds `-Werror` clean (`-Wconversion -Wsign-conversion -Wvla`, no VLAs, explicit casts).
- [ ] `clang-format` clean on changed lines; no new magic numbers; guard clauses over deep nesting.
- [ ] Honors the memory model (no heap in core; caller-owned buffers; views; slot-pointer lifetime).
- [ ] Tests added/updated; **regression test for any bug** (red→green); negative/abuse paths covered.
- [ ] `ctest` suite passes under **ASan + UBSan** (`core-both-debug` / `core-cpu-debug`); coverage not regressed.
- [ ] Public symbols documented; `docs/` (spec/FAQ/CHANGELOG) updated in this PR if behaviour/format/API changed.
- [ ] Commits are signed, Conventional-Commits, **no AI-assistant attribution**.
- [ ] No secrets committed; sensitive data redacted from logs.

<!-- Reviewer merges with --no-ff and keeps the branch (audit trail). -->
