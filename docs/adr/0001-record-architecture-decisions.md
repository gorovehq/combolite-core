# ADR-0001: Record architecture decisions

- **Status:** Accepted
- **Date:** 2026-11-21
- **Supersedes / Superseded by:** —

## Context

`combolite-core` has a rich, constraint-heavy design (no-heap core, caller-owned buffers, an
explicit on-disk/wire format, crash-safety guarantees, a CMBQL query language). Much of the "why"
lived only in the code, the dev notes (`docs/dev/`), and the specification (`docs/spec/`). New
contributors — and the maintainers after time passes — need a durable, discoverable record of the
*decisions* behind the design, separate from the specification of *what* the system does.

## Decision

Keep lightweight **Architecture Decision Records** in `docs/adr/`, following Michael Nygard's ADR
format. One record per significant decision; append-only (supersede, never rewrite). A decision is
"significant" when it establishes/alters a trust boundary, a public contract (on-disk/wire format,
public C99 API), the memory model, crash-safety, or anything a future contributor would otherwise
re-derive.

## Alternatives considered

- **Keep rationale only in `docs/dev/` prose** — already drifting and not decision-indexed.
- **Commit messages / PR descriptions only** — not discoverable or durable enough for architecture.
- **A wiki** — splits the record from the versioned source.

## Consequences

- Decisions become reviewable artifacts versioned with the code; `docs/adr/README.md` indexes them.
- Small ongoing cost: author an ADR when making a significant decision (noted in `CONTRIBUTING.md`).
- The specification (`docs/spec/`) stays the source of truth for *what*; ADRs capture *why*.
