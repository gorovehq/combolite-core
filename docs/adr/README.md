# Architecture Decision Records (ADRs)

This directory records **significant** architecture/design decisions for `combolite-core` — one
short, immutable record per decision: context, the decision, alternatives, and consequences. ADRs
are append-only: supersede an old one with a new record rather than rewriting history.

File a new ADR when a change establishes or alters a trust boundary, a public contract (on-disk /
wire format, the public C99 API), the memory model, crash-safety guarantees, or another choice a
future contributor would otherwise have to re-derive.

## Format

Use the template below; number sequentially (`NNNN-kebab-title.md`). Status is one of
`Proposed` / `Accepted` / `Superseded by ADR-XXXX` / `Deprecated`.

```markdown
# ADR-NNNN: <title>

- **Status:** Accepted
- **Date:** YYYY-MM-DD
- **Supersedes / Superseded by:** <ADR-XXXX | —>

## Context
<the forces at play; what problem/constraint this addresses>

## Decision
<what we decided, stated plainly>

## Alternatives considered
<options weighed, and why they were not chosen>

## Consequences
<results, trade-offs, follow-ups; what becomes easier/harder>
```

## Index

| ADR | Title | Status |
|---|---|---|
| [0001](0001-record-architecture-decisions.md) | Record architecture decisions | Accepted |
| [0002](0002-no-heap-caller-owned-memory-model.md) | No heap in the core; caller-owned buffers | Accepted |
| [0003](0003-decimal-downsample-avg-rounding.md) | Exact DECIMAL downsample aggregation and AVG rounding | Accepted |
