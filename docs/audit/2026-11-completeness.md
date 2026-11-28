# Per-slice completeness audit — 2026-11

A read-only audit of every data model and cross-cutting subsystem of `combolite-core`,
tracing each slice **from instantiation through use**, cross-referenced against the spec
(`docs/spec/`), the README ("Features as Built" / "Known Issues" / "ToDos" / "Provisioned but
Not Yet Implemented"), and `docs/BACKLOG.md`.

- **Scope:** 9 slices — relational tables · document pools + FTS · vector collections · graph
  links · time series · content-addressed blobs/codec/overflow · query engine
  (lexer/compiler/eval/exec/proc/triggers) · storage/pager/tx/lifecycle ·
  coordinator/crypto/audit/CRDT.
- **Method:** full-read of each slice's modules + the knowledge-graph call-chains for the
  instantiation→use path; every gap carries a `file:line` anchor and a documented? note.
- **Nature:** findings only — no code was changed. Remediation of each item is tracked in its
  issue and gated separately.

**Headline:** the per-model *engines* are largely feature-complete and robust (codecs,
validators, fail-closed status, memory model). The material gaps cluster at four seams:
1. the **query executor** — the multi-model search/graph operators are pass-through stubs, 8
   operators have no CMBQL-text production, and triggers are a no-op that the engine never
   dispatches;
2. **multi-writer coordination** — including the one CRITICAL (parallel writers can leave an
   archive that won't open);
3. **integration-light cross-cutting subsystems** — crypto verify + enclave page encryption,
   the audit event taxonomy, CRDT convergence;
4. the **blob store** is not the content-addressed / dedup / extent / external / compressible
   store the README and spec advertise.

Plus assorted correctness bugs (silent DECIMAL downsample over the money type, arrival-order
CRDT convergence) and a set of documented deferrals.

## Severity roll-up

| Severity | Count (deduped) | Where |
|---|---|---|
| CRITICAL | 1 | Parallel writers → unopenable archive (#33) |
| HIGH | ~6 | Executor stubs (#34), compiler wiring + triggers (#35), blob dedup (#39) |
| MED | ~18 | crypto/audit (#37), CRDT (#38), query limits (#36), TS DECIMAL (#40), storage/coord limits (#42), TS/model robustness (#40/#41) |
| LOW / INFO | remainder | per-model robustness, tuning, docs (#40–#43) |

> **Update 2026-11-21 — #33 resolved (not reproducible).** The CRITICAL "unopenable archive"
> was investigated two ways and found to be not a reachable defect: a deterministic proof + 180
> adversarial crash points, and a real multi-process stress campaign (1,079 kill-rounds / 6,355
> SIGKILLs / 0 false rejects). The fail-closed at `cdb_db.c:1762-1766` is correct; the symptom
> is a likely-since-fixed state (predates the sync-before-remove cleanup ordering), now locked
> behind a regression oracle (`tests/test_multiwriter_open.c`). See
> `docs/audit/2026-11-33-multiwriter-investigation.md`. #33 closed; the create-race + concurrency
> sub-items it had grouped remain valid and move to a follow-up. (Caveat: the saved
> `pipeline-4w-unopenable.cdbarch` artifact was not on this machine to re-open directly.)

## Issue index (EPIC #32)

| # | Theme | Triage |
|---|---|---|
| ~~#33~~ | ~~**[CRITICAL]** multi-writer coordination~~ — **resolved not-reproducible** (oracle landed); create-race/concurrency → follow-up | closed |
| #34 | query executor: search/graph operators are stubs (TEXT/VECTOR/TRAVERSE/HYBRID) | implement |
| #35 | query engine: 8 ops unreachable from CMBQL text + triggers no-op/never-dispatched | implement |
| #36 | query executor correctness + fixed limits | implement |
| #37 | crypto + audit integration | mixed |
| #38 | CRDT replication: primitives not integrated; arrival-order convergence | mixed |
| #39 | blob store not content-addressed/dedup/extent/external/compressible | implement/remediate |
| #40 | data-model robustness: silent DECIMAL downsample + table/doc/vector/graph/math | mixed |
| #41 | time-series completeness + bounded-buffer robustness | implement/remediate |
| #42 | storage + coordinator limits & provisioned paths | implement |
| #43 | docs accuracy: README over-claims + stale comments | remediate (docs) |

---

## Per-slice findings

Legend — triage: **implement** (feature/path not built) · **remediate** (built but
wrong/incomplete). Severity: crit / high / med / low. "doc" = documented deferral; "UNDOC" =
not previously called out.

### 1. Relational tables — *very complete*
`cdb_table/catalog/catroot/index/schema/key/rowgroup/colenc`. Full create→column-ops→index→
CRUD→scan→drop for row- **and** column-oriented layouts; schema history + read-time projection;
constraints. No stubs. (→ #40, #43)

| anchor | gap | doc? | triage | sev |
|---|---|---|---|---|
| `cdb_table.h:70-71` | stale comment: column-table row calls "not built/UNSUPPORTED" — they ARE implemented | UNDOC | remediate(docs) | low |
| `cdb_table.c:~1815-1878` | non-atomic table create (multi commit; crash → version==0, droppable) | doc | remediate | med |
| `cdb_table.c:1673,1711` | unique-index-duplicate leaks index pages (no drop on `CDB_E_EXISTS`) | doc | remediate | low-med |
| `cdb_table.c:80` | decimal/array/object/vector columns not indexable (no order-preserving key form) | doc | implement | med |
| `cdb_table.c:940-1018` | table-delete-refused-by-link leaves index-stage tombstones | doc | remediate | med |
| `cdb_key.h:8` | language-aware collation not implemented (raw UTF-8 order); active keys (spec 6.2) unimplemented | doc | implement | low/med |

### 2. Document pools + FTS — *core complete end-to-end*
`cdb_doc/cdb_fts`. put/get/revise/delta/checkpoint/tombstone/schema-validate + complete BM25.
The frequently-cited TEXT_SEARCH pass-through is in `cdb_exec.c` (#34), not here. (→ #40)

| anchor | gap | doc? | triage | sev |
|---|---|---|---|---|
| `cdb_doc.c:428,538` | signed-revision flag (spec §14.9.1 bit 2) read but never set/verified | UNDOC | implement | low |
| `cdb_doc.c:1193-1200` | principal attribution always 0 (envelope memset) | doc | implement | low |
| `cdb_doc.h:74-117` | no rollback-to-earlier-head op (spec §8.6 confirmed capability) | UNDOC | implement | med |
| `cdb_fts.h` + spec §8.5 | only "Declared" FTS indexing mode (spec lists 4; §8.10 narrows) | partial | implement/reconcile | low |

### 3. Vector collections — *engine complete; gaps at the edges*
`cdb_vec/cdb_math/cdb_fakeaccel`. All 5 element types + 4 measures + HNSW build/search complete.
Material gap is the executor (#34). (→ #34, #40)

| anchor | gap | doc? | triage | sev |
|---|---|---|---|---|
| `cdb_exec.c:2008` | VECTOR_SEARCH not wired to `cdb_vec_search` (fabricated score) | doc | implement | high → #34 |
| `cdb_vec.c:1695-1771` | refresh coverage walk quadratic >15k | doc | remediate(perf) | med |
| `cdb_vec.c:1980-2011` | `vec_mem` default provisional; memory not kept across refreshes | doc | remediate | low |
| `cdb_vec.c:2735-2787` | ANN recall gap (one stored passage 0/10) — walk entry-point selection | doc | remediate | med |
| `cdb_vec.c:57` | `DEFAULT_EXACT_BELOW=10000` provisional threshold | doc | remediate | low |
| `cdb_math.c:909-938` | `mat_det` only dim 1/2/3, `UNSUPPORTED` for 4×4+ (no general LU/cofactor) | UNDOC | implement/doc | low |

### 4. Graph links — *link store sound; traversal + ts-teardown edges*
`cdb_link`. Cardinality + refuse/cascade/tombstone + bidirectional lookup complete for
doc/table/vector ends. (→ #34, #40)

| anchor | gap | doc? | triage | sev |
|---|---|---|---|---|
| `cdb_exec.c:1886` | TRAVERSE pass-through stub (fixed `$depth`, no multi-hop/cycle) | doc | implement | high → #34 |
| `cdb_ts.c` + `cdb_link.c:924` | time-series-targeted links never cleaned on teardown; `on_delete` 16-byte prefix can't address a point | doc | implement | med |
| `cdb_link.c:746` | neuron-mapping weight learning/fade/prune not implemented | doc(OQ) | implement | low |
| `cdb_link.h:39-41` | "SET NULL" delete rule advertised (README:9) but enum has only TOMBSTONE/CASCADE/REFUSE | UNDOC | remediate(doc/add) | low |
| `cdb_link.c:513-539` | opaque/enclave link-end liveness coarse (admits link to nonexistent opaque end) | — (enclaves NYI) | remediate(@M27) | low |
| `cdb_link.c:981-1023` | list/get return tombstoned links unfiltered; no live-only; header silent | UNDOC | remediate | low |

### 5. Time series — *codecs solid; compaction/pushdown/truncation gaps*
`cdb_ts/tsbits/tsblock`. Append→block-pack→late-arrival→derive-downsample→range all wired.
`BACKLOG:145` is now **stale** (retention/downsampling/10.6/audit are implemented). (→ #40, #41)

| anchor | gap | doc? | triage | sev |
|---|---|---|---|---|
| `cdb_ts.c:2224-2241` | **downsample silently yields 0 for DECIMAL/non-numeric (money type)** — SUM/MIN/MAX/AVG wrong | UNDOC | remediate | **med-high** |
| `cdb_ts.c:2140` | spec 10.4 compact & threshold-compaction modes absent (only derive); recipes-as-procedures (M32) | partial | implement | med |
| `cdb_ts.c:1783-1848` | no rollup/downsample pushdown in range reads | doc | implement | med |
| `cdb_ts.h:88` | no series enumeration | doc | implement | med |
| `cdb_ts.c:1013-1048` | retention config non-transactional (not journaled; rollback can't undo) | doc | remediate | med |
| `cdb_ts.c:1427-1430` | collision replaced-value audit truncated to empty >512 B (spec 10.6) | UNDOC | remediate | low-med |
| `cdb_ts.c:2027-2127` | downsample FIRST/LAST truncated 128 B; bucket encode no writer-overflow check | UNDOC | remediate | low |
| `cdb_ts.c:752,838-855,1022` | `nfields==0` accepted (spec 10.1 ≥1); describe/getters incomplete; ~~dormant audit-series guards~~ *(→ #63 Item 1: `ts_series_in` now emits `CDB_AUDIT_SCHEMA` unattributed/principal 0 on series create)* | UNDOC | remediate/implement | low |

### 6. Blobs / codec / overflow — *overflow + codec solid; blob not content-addressed as advertised*
`cdb_blob/cdb_overflow/cdb_codec`. Overflow chain + nib-tail + LZMA2 (incl. F4 dict-bound fix)
complete. (→ #39, #43)

| anchor | gap | doc? | triage | sev |
|---|---|---|---|---|
| `cdb_blob.c:111,332` + `cdb_catroot.c:43,80` | content-hash **dedup index entirely unimplemented** (`dedup_root` provisioned, unused); no refcount | UNDOC (README markets "Content-Addressed") | implement | high |
| `cdb_blob.h:26` | external-file attachments (flags bit 0) provisioned, never implemented | UNDOC | implement | med |
| `cdb_proc.c:776-797` + `cdb_compiler.c:2740-2792` | query layer can FREE a blob but has no create/read opcode (C-API only) | UNDOC | implement/doc | med |
| `cdb_blob.c:183-317` | integrity verify is opt-in, not default | oblique | remediate | low-med |
| `cdb_blob.c:68-285` | blobs stored as a linked chain, not contiguous extents (spec §14.15; `page_count` advisory) | UNDOC | remediate/amend-spec | low-med |
| `cdb_blob.c:233-340` | loose per-page length check; 32-bit `total_len` truncation on free | UNDOC | remediate | low |
| `cdb_codec.c` callers | compression wired only for column chunks; doc-body/journal/page uses (spec §15.3) missing | README "built" overstated; spec15 Draft | implement | med |

### 7. Query engine (CMBQL) — *VM + codec + evaluator complete; big executor/compiler/trigger gaps*
`cdb_lexer/compiler/eval/exec/query/proc/trigger`. Proc VM (18 opcodes), tri-state evaluator,
depth-bounded wire codec all complete. (→ #34, #35, #36)

| anchor | gap | doc? | triage | sev |
|---|---|---|---|---|
| `cdb_exec.c:1886/1947/2008` | TRAVERSE / TEXT_SEARCH / VECTOR_SEARCH pass-through stubs (no real search) | doc | implement | high → #34 |
| `cdb_exec.c:2098` | HYBRID_RANK RRF **is** implemented; README overstates "stubbed"; only branches are fake | README wrong | implement(via branches)+fix README | med → #34 |
| `cdb_compiler.c` | **8 of 15 executor ops have no CMBQL-text production** (AGGREGATE/UNION/TRAVERSE/TEXT/VECTOR/HYBRID/ASOF/UNNEST) | partial (only aggregates) | implement | high → #35 |
| `cdb_trigger.c:74` + `cdb_db.c` | trigger dispatch is a **no-op** AND the engine **never dispatches** triggers | UNDOC | implement | high → #35 |
| `cdb_exec.c:2583` | no public `cdb_db_query(text)` entry (proc-VM/tests only) | UNDOC | implement/confirm | med → #35 |
| `cdb_exec.c:1511/1611` | window only tumbling (step ignored); asof ignores match cond + O(n·m) rescan | doc | implement | med → #36 |
| `cdb_exec.c:574/1090` | caps: ≤16 output fields (17-col table truncates), ≤256 sort rows | doc | implement | med → #36 |
| `cdb_compiler.c:522-674` | no literal dot in field name (silent 255 B cut); reserved words can't name fields; `count(*)` rejected | doc | implement | med → #36 |
| `cdb_exec.c:371-446` | vec/ts/link scans yield bare IDs; count lags open store | doc | implement | med → #36 |

### 8. Storage / pager / tx / lifecycle — *complete + robust; 1 CRITICAL*
`cdb_db/pager/page/nib/header/journal/slots/varint/value`. varint/value/slots/header/page-seal/
overflow/nib/journal/pager-mirror/tx-commit/savepoint all verified complete; compact+reclaim
wired. (→ #33, #42)

| anchor | gap | doc? | triage | sev |
|---|---|---|---|---|
| `cdb_db.c:1762-1766` | **CRITICAL** multi-writer DB becomes unopenable (`CDB_E_CORRUPT`); sound archive rejected at open; data-loss-class | doc symptom / UNDOC root | remediate(investigate) | **crit** → #33 |
| `cdb_hostfile.c:152` | concurrent-create race (`O_CREAT` no `O_EXCL`, not coord-claimed) | doc | remediate | med → #33 |
| `cdb_db.c:2294-2310` | per-tx 21-block entry-ID ceiling (21,504 ids) → `OUT_OF_BUDGET` | doc | implement | med → #42 |
| `cdb_db.c:2906-2960` | savepoint rollback doesn't undo non-journaled state (ts-retention/enclave/key/RBAC/trigger) | doc | implement | med → #42 |
| `cdb_db.c:598-611` | savepoint drop-range cap 32 (`CDB_TX_MAX_DROPS`) | UNDOC | implement(raise/doc) | low → #42 |
| `cdb_pager.c:925-926`, `cdb_pager.h:42`, `cdb_page.c:105-112` | variable/per-store page sizes, multi-page extents, compact-page encryption all provisioned-unimplemented | doc | implement/deferred | med/low → #42 |
| `cdb_journal.c:299-327` | commit/prepare records unsigned; principal always 0 (M32) | doc | implement/deferred | low-med → #42 |
| `cdb_overflow.c:63` | shared-tail nibblet packing only on 64-bit-address files | UNDOC | implement/deferred | low → #42 |

### 9. Coordinator / crypto / audit / CRDT — *primitive-complete, integration-light*
`cdb_coord/worker/crypto/audit/crdt/hostenv/hostfile`. Worker pool + journal adoption +
AEAD/HKDF/sign/wrap complete (GHSA-2xx7 nonce bug genuinely fixed). (→ #33, #37, #38, #42)

| anchor | gap | doc? | triage | sev |
|---|---|---|---|---|
| `cdb_db.c` coord paths | multi-writer defects (unopenable=crit, collide-every-tx, can't-close-while-live, `CDB_E_STATE`) | doc | remediate | high/med → #33 |
| `cdb_coord.h:44` | Step-6 primary election + dynamic slots absent (fixed 64) | doc | implement | med → #42 |
| `cdb_db.c:2574-2586` | prepared-tx collision wait ignores holder estimate + no cap (liveness stall); estimate only for baton/commit | doc/UNDOC | implement | med → #42 |
| `cdb_crypto.c:417-497` | RNG hardcodes `/dev/urandom`, bypasses `cdb_env->ops->random` (MCU-unsafe; defeats env abstraction) | UNDOC | remediate | med → #37 |
| `cdb_crypto.c:437,515` | commit records signed but `cdb_identity_verify` never called (write-only signing, no tamper detection) | UNDOC | remediate | med → #37 |
| `cdb_db.c` page writes | enclave page encryption ineffective — no store sets `domain_id`, pages always unencrypted; SEAL/REPL subkeys + unwrap unused | doc(M27) | implement | med → #37 |
| `cdb_audit.h:22-26` | 5 of 6 audit event types never emitted (only COLLISION); key-rotation/baton/schema unaudited; events unsigned (spec 12.5 default); chain per-process/uncoordinated | UNDOC | implement/remediate | med → #37 |
| `cdb_crdt.c` + `cdb_db.c:4480-4512` | merge primitives (LWW/PN/AWORSet/commutative-TS) not integrated; convergence is arrival-order with a faked (non-exported) HLC | UNDOC(draft) | remediate | med → #38 |
| `cdb_crdt.c:~322` | two-way handshake codec unused; automated P2P gossip/discovery NYI | doc | implement | low → #38 |

---

_Audit date: 2026-11-21. Method: 9 parallel read-only slice auditors + knowledge-graph call
tracing. No code changed. Remediation is tracked per issue (EPIC #32) through the gated SDLC._

---

## Remediation status — FINAL (2026-11-23, EPIC #32 closed)

All 12 grouped children remediated or documented-and-deferred through the gated SDLC and merged to `main`. Each change: signed, red→green or invariant-pinned, `--no-ff` merge with the curation branch kept.

| Issue | Outcome | PR / commit |
|---|---|---|
| #33 | CRITICAL multi-writer — **resolved not-reproducible** (fail-closed proven correct; 180-point crash matrix + real multi-process stress = 0 false rejects) + regression oracle | PR #45; successor #46 |
| #46 | multi-writer create-race (O_EXCL) + contention — **fixed** | PR #59 (contention → #60) |
| #34 | query executor search/graph operators wired to real engines — **implemented** | PR #48 |
| #35 | CMBQL grammar for 8 ops + triggers dispatch — **implemented** | PR #49 |
| #36 | query executor correctness + bounded limits — **fixed** | PR #51 (Q9 → #52) |
| #37 | crypto RNG env-routing + commit-sig verify + audit taxonomy — **fixed** | PR #53 (M27/residuals → #54) |
| #38 | CRDT deterministic convergence + PN-counter netting — **fixed** | PR #57 (transport → #58) |
| #39 | blob content-hash dedup + verify-on-read — **implemented** | PR #55 (ext/compression → #56) |
| #40 | data-model: DECIMAL money fix (a88622d) + index-reclaim / refused-delete rollback / live-only link list / signed revisions + principal — **fixed** | PR #64 (caps/signed-rev → #65) |
| #41 | time-series bounded buffers + series enum/config getters — **fixed** | PR #62 (compaction/pushdown → #63) |
| #42 | bounded prepared-tx collision wait + estimate coverage + savepoint-cap doc — **fixed** | PR #66 (21-block/Step-6/pages → #67) |
| #43 | docs accuracy (README/comments/BACKLOG) — **corrected** | PR #61 |

**Deferred-item follow-ups:** #52, #54, #56, #58, #60, #63, #65, #67 — all low/medium, spec-level or enhancement work, to be remediated through the gated SDLC.

Note: #40 and #42 went through design review; their implementations were verified directly (build + red→green + manual security review) and noted transparently in PRs #64 and #66.
