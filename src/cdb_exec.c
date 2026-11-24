/* Streaming query plan executor and cursor engine (CMBQL core).
 * Spec 11.5, 11.10; Spec 14.19.
 */
#include "cdb_exec.h"
#include "cdb_doc.h"
#include "cdb_endian.h"
#include "cdb_fts.h"
#include "cdb_link.h"
#include "cdb_math.h"
#include "cdb_table.h"
#include "cdb_ts.h"
#include "cdb_varint.h"
#include "cdb_vec.h"

#include <stdlib.h>
#include <string.h>

/* Alignment helper for arena allocations */
static size_t align_up(size_t n, size_t align)
{
    size_t rem = n % align;
    return (rem == 0) ? n : (n + align - rem);
}

void *cdb_exec_arena_alloc(cdb_exec_arena *arena, size_t size, size_t align)
{
    size_t aligned_used;
    void *ptr;

    if (arena == NULL || arena->buf == NULL || align == 0)
        return NULL;

    aligned_used = align_up(arena->used, align);
    if (aligned_used > arena->cap || size > arena->cap - aligned_used)
        return NULL; /* Out of arena memory */

    ptr = arena->buf + aligned_used;
    arena->used = aligned_used + size;
    memset(ptr, 0, size);
    return ptr;
}

void cdb_exec_row_copy(cdb_exec_row *dst, const cdb_exec_row *src)
{
    if (dst == NULL || src == NULL)
        return;
    *dst = *src;
}

size_t cdb_exec_cursor_size(void)
{
    return sizeof(cdb_exec_cursor);
}

size_t cdb_exec_row_size(void)
{
    return sizeof(cdb_exec_row);
}

/* --------------------------------------------------------------------------
 * Grown memory (host profile, spec 17.4): blocks from the environment's
 * allocator, counted against the query's budget, each on its owner's list
 * -------------------------------------------------------------------------- */
typedef struct cdb_exec_block {
    struct cdb_exec_block *next;
    size_t size; /* bytes after the header */
} cdb_exec_block;

#define BLOCK_HEAD 16u /* the header, rounded so what follows is aligned */

/* A new block of size bytes on *list, or NULL: the mcu profile, no
 * allocator, or over the budget */
static void *exec_grow(cdb_exec_cursor *cur, cdb_exec_block **list, size_t size)
{
    const cdb_env_ops *ops = cur->db != NULL ? cur->db->env.ops : NULL;
    cdb_exec_block *b;

    if (cur->mem_budget == 0 || ops == NULL || ops->alloc == NULL || ops->free == NULL
        || size > cur->mem_budget - cur->mem_used)
        return NULL;
    if ((b = (cdb_exec_block *)ops->alloc(cur->db->env.ctx, BLOCK_HEAD + size)) == NULL)
        return NULL;
    b->next = *list;
    b->size = size;
    *list = b;
    cur->mem_used += size;
    return (uint8_t *)b + BLOCK_HEAD;
}

/* Frees one block of *list (p as exec_grow returned it) */
static void exec_free_one(cdb_exec_cursor *cur, cdb_exec_block **list, void *p)
{
    cdb_exec_block **at;
    for (at = list; *at != NULL; at = &(*at)->next) {
        if ((uint8_t *)*at + BLOCK_HEAD == (uint8_t *)p) {
            cdb_exec_block *b = *at;
            *at = b->next;
            cur->mem_used -= b->size;
            cur->db->env.ops->free(cur->db->env.ctx, b);
            return;
        }
    }
}

static void exec_free_all(cdb_exec_cursor *cur, cdb_exec_block **list)
{
    while (*list != NULL) {
        cdb_exec_block *b = *list;
        *list = b->next;
        cur->mem_used -= b->size;
        cur->db->env.ops->free(cur->db->env.ctx, b);
    }
}

/* What buffered rows and values point to: the chunk being filled (first a
 * share of the arena), and on the host profile further chunks grown as
 * needed */
typedef struct cdb_exec_pool {
    cdb_exec_arena a;
    cdb_exec_block *blocks;
} cdb_exec_pool;

#define POOL_CHUNK (1u << 20)

static void *pool_alloc(cdb_exec_cursor *cur, cdb_exec_pool *p, size_t size, size_t align)
{
    void *x = cdb_exec_arena_alloc(&p->a, size, align);
    if (x == NULL) {
        size_t chunk = size + align > POOL_CHUNK ? size + align : POOL_CHUNK;
        uint8_t *buf = (uint8_t *)exec_grow(cur, &p->blocks, chunk);
        if (buf == NULL)
            return NULL;
        p->a.buf = buf;
        p->a.cap = chunk;
        p->a.used = 0;
        x = cdb_exec_arena_alloc(&p->a, size, align);
    }
    return x;
}

/* Gives a pipeline breaker (Sort, Aggregate) its share of the arena: a slot
 * array of n items of item_size, at most max_items and at most half of what
 * is left, and a pool of half of what remains, so a breaker opened after
 * this one (the one above it) still gets memory. */
static cdb_status carve_buffer(cdb_exec_arena *arena, size_t item_size, size_t max_items,
                               void **items, size_t *n, cdb_exec_pool *pool)
{
    size_t avail = (arena->cap > arena->used) ? (arena->cap - arena->used) : 0;
    size_t count = (avail / 2) / item_size, share;

    if (count > max_items)
        count = max_items;
    if (count < 1)
        return CDB_E_OUT_OF_BUDGET;
    *items = cdb_exec_arena_alloc(arena, item_size * count, sizeof(void *));
    if (*items == NULL)
        return CDB_E_OUT_OF_BUDGET;
    *n = count;

    share = ((arena->cap > arena->used) ? (arena->cap - arena->used) : 0) / 2;
    pool->blocks = NULL;
    pool->a.buf = (uint8_t *)cdb_exec_arena_alloc(arena, share, sizeof(void *));
    pool->a.cap = pool->a.buf != NULL ? share : 0;
    pool->a.used = 0;
    return CDB_OK;
}

/* Values point into the buffer they were read from: a scan's record buffer,
 * which the next row overwrites, or the evaluator's scratch, which each
 * cdb_exec_next resets. A buffered value is copied into the pool first. */
static cdb_status pin_value(cdb_exec_cursor *cur, cdb_exec_pool *pool, cdb_value *v)
{
    uint8_t *copy;

    if (v->start != NULL && v->encoded_len > 0) {
        if ((copy = (uint8_t *)pool_alloc(cur, pool, v->encoded_len, 1)) == NULL)
            return CDB_E_OUT_OF_BUDGET;
        memcpy(copy, v->start, v->encoded_len);
        return cdb_value_read(copy, v->encoded_len, cur->order, v);
    }
    /* Computed strings and binaries carry only a payload */
    if (v->payload != NULL && v->payload_len > 0) {
        if ((copy = (uint8_t *)pool_alloc(cur, pool, v->payload_len, 1)) == NULL)
            return CDB_E_OUT_OF_BUDGET;
        memcpy(copy, v->payload, v->payload_len);
        v->payload = copy;
    }
    return CDB_OK;
}

static cdb_status pin_bytes(cdb_exec_cursor *cur, cdb_exec_pool *pool, const uint8_t **data,
                            size_t len)
{
    uint8_t *copy;

    if (*data == NULL || len == 0)
        return CDB_OK;
    if ((copy = (uint8_t *)pool_alloc(cur, pool, len, 1)) == NULL)
        return CDB_E_OUT_OF_BUDGET;
    memcpy(copy, *data, len);
    *data = copy;
    return CDB_OK;
}

/* A compact copy of src in the pool, with only its fields and with
 * everything it points to copied too */
static cdb_status store_row(cdb_exec_cursor *cur, cdb_exec_pool *pool, const cdb_exec_row *src,
                            cdb_exec_row **out)
{
    cdb_exec_row *r =
        (cdb_exec_row *)pool_alloc(cur, pool, CDB_EXEC_ROW_SIZE(src->n_fields), sizeof(void *));
    cdb_status s;
    size_t i;

    if (r == NULL)
        return CDB_E_OUT_OF_BUDGET;
    memcpy(r, src, CDB_EXEC_ROW_SIZE(src->n_fields));
    for (i = 0; i < r->n_fields; i++)
        if ((s = pin_value(cur, pool, &r->fields[i].val)) != CDB_OK)
            return s;
    if ((s = pin_bytes(cur, pool, &r->record_data, r->record_len)) != CDB_OK)
        return s;
    if ((s = pin_bytes(cur, pool, &r->right_record_data, r->right_record_len)) != CDB_OK)
        return s;
    *out = r;
    return CDB_OK;
}

/* The full row from a compact copy */
static void load_row(cdb_exec_row *dst, const cdb_exec_row *src)
{
    memcpy(dst, src, CDB_EXEC_ROW_SIZE(src->n_fields));
}

/* Custom field resolver hook to look up fields on an executed row */
static cdb_status row_field_resolver(void *user_data, const char *path, size_t path_len,
                                     cdb_value *out_val, int *found)
{
    const cdb_exec_row *row = (const cdb_exec_row *)user_data;
    size_t i;

    if (row == NULL || path == NULL || out_val == NULL || found == NULL)
        return CDB_E_INVALID_ARG;

    *found = 0;

    /* Check explicit fields (aliases/projected/joined) */
    for (i = 0; i < row->n_fields; i++) {
        if (row->fields[i].name_len == path_len
            && memcmp(row->fields[i].name, path, path_len) == 0) {
            *out_val = row->fields[i].val;
            *found = 1;
            return CDB_OK;
        }
    }

    /* Every executed row has an entry ID; the record is resolved after this
     * returns not found (cdb_eval_resolve_field). */
    if ((path_len == 3 && memcmp(path, "$id", 3) == 0)
        || (path_len == 9 && memcmp(path, "$entry_id", 9) == 0)) {
        cdb_eval_make_int(out_val, (int64_t)row->entry_id);
        *found = 1;
    }

    return CDB_OK;
}

cdb_status cdb_exec_row_get_field(const cdb_exec_row *row, cdb_eval_ctx *eval_ctx, const char *name,
                                  size_t name_len, cdb_value *out_val, int *found)
{
    cdb_status s;

    if (row == NULL || eval_ctx == NULL || name == NULL || out_val == NULL || found == NULL)
        return CDB_E_INVALID_ARG;

    *found = 0;

    /* Setup evaluation context for this row */
    eval_ctx->entry_id = row->entry_id;
    eval_ctx->score = (double)row->score;
    eval_ctx->timestamp = row->timestamp;
    eval_ctx->record_data = row->record_data;
    eval_ctx->record_len = row->record_len;
    eval_ctx->store_id = row->store_id;

    cdb_eval_ctx_set_custom_resolver(eval_ctx, row_field_resolver, (void *)row);

    s = cdb_eval_resolve_field(eval_ctx, name, name_len, out_val, found);
    return s;
}

/* --------------------------------------------------------------------------
 * Operator 0x01: SCAN
 * -------------------------------------------------------------------------- */

/* A cdb_ts_list continuation token holds one series key; this covers the
 * time-series series-key limit (cdb_ts.c KEY_MAX). */
#define SCAN_TS_CURSOR_CAP 512u

/* A whole link serialized for a LINK-store scan row: type (8), source ref
 * (store 8, entry 8, ts 8, flags 4 = 28), target ref (28), weight bits (4),
 * time (8), flags (1), removal count (4) -- fixed, big-endian, no padding. */
#define SCAN_LINK_REF_LEN 28u
#define SCAN_LINK_REC_LEN (8u + 2u * SCAN_LINK_REF_LEN + 4u + 8u + 1u + 4u) /* 81 */

static void scan_link_put_ref(uint8_t *p, const cdb_ref *r)
{
    cdb_store_u64(p, r->store, CDB_ORDER_BIG);
    cdb_store_u64(p + 8, r->entry, CDB_ORDER_BIG);
    cdb_store_u64(p + 16, (uint64_t)r->ts, CDB_ORDER_BIG);
    cdb_store_u32(p + 24, r->flags, CDB_ORDER_BIG);
}

/* Serializes a live link into out (at least SCAN_LINK_REC_LEN bytes), the
 * whole-link record a LINK scan row carries; returns the byte length. */
static size_t scan_link_serialize(const cdb_link *l, uint8_t *out)
{
    uint32_t wbits;
    cdb_store_u64(out, l->type, CDB_ORDER_BIG);
    scan_link_put_ref(out + 8, &l->source);
    scan_link_put_ref(out + 8 + SCAN_LINK_REF_LEN, &l->target);
    memcpy(&wbits, &l->weight, sizeof wbits);
    cdb_store_u32(out + 8 + 2u * SCAN_LINK_REF_LEN, wbits, CDB_ORDER_BIG);
    cdb_store_u64(out + 12u + 2u * SCAN_LINK_REF_LEN, (uint64_t)l->time, CDB_ORDER_BIG);
    out[20u + 2u * SCAN_LINK_REF_LEN] = l->flags;
    cdb_store_u32(out + 21u + 2u * SCAN_LINK_REF_LEN, l->removed, CDB_ORDER_BIG);
    return SCAN_LINK_REC_LEN;
}

/* Per-scan enumeration cursor state for the time-series and link models, kept
 * off the operator struct (and so out of the query memory budget for the other
 * models): allocated from the arena only for a live scan, like rec_buf. */
typedef struct cdb_scan_model_cursor {
    uint8_t ts_token[SCAN_TS_CURSOR_CAP]; /* cdb_ts_list continuation token */
    cdb_link link_last;                   /* resume cdb_link_scan after this link */
} cdb_scan_model_cursor;

typedef struct cdb_exec_scan {
    cdb_exec_op base;
    const char *store_name;
    size_t store_name_len;
    uint64_t store_id;
    uint32_t model;
    uint64_t cur_entry_id;
    uint64_t max_entry_id;

    /* The current entry's record (spec 14.6 object), overwritten by each row */
    uint8_t *rec_buf;
    size_t rec_cap;
    cdb_table_cursor tcur; /* tables: entry order */

    /* Per-model enumeration cursor (#52), allocated from the arena for a live
     * scan (NULL otherwise). Holds the time-series continuation token and the
     * last link returned; the lengths/flags that drive them stay inline. */
    cdb_scan_model_cursor *mc;
    size_t ts_cursor_len; /* cdb_ts_list token length (0: start / finished) */
    int ts_done;          /* the per-series enumeration reached its end */
    int link_started;     /* at least one live link has been returned */
    int link_done;        /* the link enumeration reached its end */

    /* For mock/standalone testing without a live database */
    const cdb_exec_row *mock_rows;
    size_t n_mock_rows;
    size_t mock_idx;
} cdb_exec_scan;

static cdb_status scan_open(cdb_exec_op *op, cdb_exec_cursor *cur)
{
    cdb_exec_scan *s = (cdb_exec_scan *)op;
    cdb_store_info info;
    cdb_status st;

    s->cur_entry_id = 0;
    memset(&s->tcur, 0, sizeof s->tcur);
    s->mock_idx = 0;
    s->ts_cursor_len = 0;
    s->ts_done = 0;
    s->link_started = 0;
    s->link_done = 0;

    /* A store the catalog does not have is an error, not an empty result: a
     * misspelt name must not read as "no rows match" */
    if (cur->cat != NULL) {
        int found = 0;
        if ((st = cdb_catalog_find_store(cur->cat, s->store_name, s->store_name_len, &s->store_id,
                                         &found))
            != CDB_OK)
            return st;
        if (!found)
            return CDB_E_NOT_FOUND;
        if ((st = cdb_catalog_get_store(cur->cat, s->store_id, &info)) != CDB_OK)
            return st;
        s->model = info.model;
        s->max_entry_id = info.next_entry_id;
    }

    return CDB_OK;
}

static cdb_status scan_reset(cdb_exec_op *op, cdb_exec_cursor *cur)
{
    cdb_exec_scan *s = (cdb_exec_scan *)op;
    (void)cur;
    s->cur_entry_id = 0;
    memset(&s->tcur, 0, sizeof s->tcur);
    s->mock_idx = 0;
    s->ts_cursor_len = 0;
    s->ts_done = 0;
    s->link_started = 0;
    s->link_done = 0;
    return CDB_OK;
}

static void scan_close(cdb_exec_op *op, cdb_exec_cursor *cur)
{
    (void)op;
    (void)cur;
}

/* Reads entry eid's committed record into rec_buf: a table row through its
 * current columns, a document's current revision, or a vector entry's encoded
 * $vector value (#52: materialized, no longer force-zeroed). Time series and
 * the link store do not use this path -- their records come from the per-model
 * live enumeration in scan_next. CDB_E_NOT_FOUND: no such entry (deleted). */
static cdb_status scan_read(cdb_exec_scan *s, cdb_exec_cursor *cur, uint64_t eid, size_t *len)
{
    uint64_t src_store, src_entry;

    *len = 0;
    switch (s->model) {
    case CDB_MODEL_RELATIONAL:
        return cdb_table_get(cur->db, s->store_id, eid, s->rec_buf, s->rec_cap, len);
    case CDB_MODEL_DOCUMENT:
        return cdb_doc_get(cur->db, s->store_id, eid, 0, s->rec_buf, s->rec_cap, len, NULL, 0, NULL,
                           NULL);
    case CDB_MODEL_VECTOR:
        /* The encoded $vector value flows to the row record (#52); src_store /
         * src_entry are read but unused by the scan. On CDB_E_BUFFER_TOO_SMALL
         * *len holds the needed size so scan_load can grow and re-read. */
        return cdb_vec_get(cur->db, s->store_id, eid, s->rec_buf, s->rec_cap, len, &src_store,
                           &src_entry);
    default: return CDB_OK;
    }
}

/* scan_read, growing the record buffer for a larger record on the host
 * profile (spec 17.3: up to the largest document body, or a large $vector
 * value); a record past the profile's buffer is CDB_E_OUT_OF_BUDGET */
static cdb_status scan_load(cdb_exec_scan *s, cdb_exec_cursor *cur, uint64_t eid, size_t *len)
{
    cdb_status st = scan_read(s, cur, eid, len);
    uint8_t *grown, *old = s->rec_buf;

    if (st != CDB_E_BUFFER_TOO_SMALL)
        return st;
    if (*len <= s->rec_cap || (grown = (uint8_t *)exec_grow(cur, &cur->blocks, *len)) == NULL)
        return CDB_E_OUT_OF_BUDGET;
    s->rec_buf = grown;
    s->rec_cap = *len;
    if (cur->blocks->next != NULL && (uint8_t *)cur->blocks->next + BLOCK_HEAD == old)
        exec_free_one(cur, &cur->blocks, old);
    return scan_read(s, cur, eid, len);
}

static cdb_status scan_next(cdb_exec_op *op, cdb_exec_cursor *cur, cdb_exec_row *out_row,
                            int *has_row)
{
    cdb_exec_scan *s = (cdb_exec_scan *)op;

    *has_row = 0;

    /* Check mock rows first if registered */
    if (s->mock_rows != NULL && s->mock_idx < s->n_mock_rows) {
        cdb_exec_row_copy(out_row, &s->mock_rows[s->mock_idx++]);
        *has_row = 1;
        return CDB_OK;
    }

    /* Live store scan if db and catalog are available. Every model walks its
     * own committed live entries through the model's live enumeration -- never
     * counting entry IDs up to the catalog's next_entry_id, which is claimed in
     * blocks and lags an open store (#52): tables via cdb_table_scan, documents
     * via cdb_doc_next_live, vectors via cdb_vec_next_live (then the $vector
     * value via cdb_vec_get), time series per live series via cdb_ts_list (#41),
     * and links per live link via cdb_link_scan (reusing the #40/#60 live
     * filter). An enumeration error propagates and emits no row (fail closed). */
    if (cur->db != NULL && s->store_id != 0) {
        for (;;) {
            uint64_t eid = 0;
            const uint8_t *rec = NULL;
            size_t rlen = 0;
            cdb_status st;

            if (s->model == CDB_MODEL_RELATIONAL) {
                size_t n = 0;
                if ((st = cdb_table_scan(cur->db, s->store_id, CDB_TABLE_NO_INDEX, NULL, 0, NULL, 0,
                                         &s->tcur, &eid, 1, &n))
                    != CDB_OK)
                    return st;
                if (n == 0)
                    break;
                s->cur_entry_id = eid;
                if ((st = scan_load(s, cur, eid, &rlen)) == CDB_E_NOT_FOUND)
                    continue;
                if (st != CDB_OK)
                    return st;
                rec = rlen > 0 ? s->rec_buf : NULL;
            } else if (s->model == CDB_MODEL_DOCUMENT) {
                int done = 0;
                if ((st = cdb_doc_next_live(cur->db, s->store_id, s->cur_entry_id, &eid, &done))
                    != CDB_OK)
                    return st;
                if (done)
                    break;
                s->cur_entry_id = eid;
                if ((st = scan_load(s, cur, eid, &rlen)) == CDB_E_NOT_FOUND)
                    continue;
                if (st != CDB_OK)
                    return st;
                rec = rlen > 0 ? s->rec_buf : NULL;
            } else if (s->model == CDB_MODEL_VECTOR) {
                int done = 0;
                if ((st = cdb_vec_next_live(cur->db, s->store_id, s->cur_entry_id, &eid, &done))
                    != CDB_OK)
                    return st;
                if (done)
                    break;
                s->cur_entry_id = eid;
                /* Materialize the $vector value (#52). A concurrent delete
                 * between enumeration and read leaves the entry missing: skip. */
                if ((st = scan_load(s, cur, eid, &rlen)) == CDB_E_NOT_FOUND)
                    continue;
                if (st != CDB_OK)
                    return st;
                rec = rlen > 0 ? s->rec_buf : NULL;
            } else if (s->model == CDB_MODEL_TIME_SERIES) {
                cdb_ts_entry ent;
                size_t got = 0;
                if (s->ts_done || s->mc == NULL)
                    break;
                if ((st = cdb_ts_list(cur->db, s->store_id, s->mc->ts_token, SCAN_TS_CURSOR_CAP,
                                      &s->ts_cursor_len, &ent, 1, s->rec_buf, s->rec_cap, &got))
                    != CDB_OK)
                    return st;
                if (got == 0) {
                    s->ts_done = 1;
                    break;
                }
                if (s->ts_cursor_len == 0)
                    s->ts_done = 1; /* that series was the last */
                eid = ent.series;
                rlen = ent.len;
                rec = ent.len > 0 ? s->rec_buf + ent.off : NULL;
            } else if (s->model == CDB_MODEL_LINK) {
                cdb_link one;
                size_t got = 0;
                if (s->link_done || s->mc == NULL)
                    break;
                if ((st = cdb_link_scan(cur->db, s->link_started ? &s->mc->link_last : NULL, &one,
                                        1, &got))
                    != CDB_OK)
                    return st;
                if (got == 0) {
                    s->link_done = 1;
                    break;
                }
                s->mc->link_last = one;
                s->link_started = 1;
                /* A link has no single entry ID; its identity is the record. */
                eid = 0;
                rlen = scan_link_serialize(&one, s->rec_buf);
                rec = s->rec_buf;
            } else {
                break;
            }

            memset(out_row, 0, sizeof(*out_row));
            out_row->store_id = s->store_id;
            out_row->entry_id = eid;
            out_row->model = s->model;
            if (rec != NULL && rlen > 0) {
                out_row->record_data = rec;
                out_row->record_len = rlen;
            }
            *has_row = 1;
            return CDB_OK;
        }
    }

    return CDB_OK;
}

static const cdb_exec_vtab scan_vtab = {scan_open, scan_next, scan_reset, scan_close};

/* --------------------------------------------------------------------------
 * Operator 0x02: FILTER
 * -------------------------------------------------------------------------- */
typedef struct cdb_exec_filter {
    cdb_exec_op base;
    cdb_exec_op *input;
    const uint8_t *pred_wire;
    size_t pred_len;
} cdb_exec_filter;

static cdb_status filter_open(cdb_exec_op *op, cdb_exec_cursor *cur)
{
    cdb_exec_filter *f = (cdb_exec_filter *)op;
    return f->input->vtab->open(f->input, cur);
}

static cdb_status filter_reset(cdb_exec_op *op, cdb_exec_cursor *cur)
{
    cdb_exec_filter *f = (cdb_exec_filter *)op;
    return f->input->vtab->reset(f->input, cur);
}

static void filter_close(cdb_exec_op *op, cdb_exec_cursor *cur)
{
    cdb_exec_filter *f = (cdb_exec_filter *)op;
    f->input->vtab->close(f->input, cur);
}

static cdb_status filter_next(cdb_exec_op *op, cdb_exec_cursor *cur, cdb_exec_row *out_row,
                              int *has_row)
{
    cdb_exec_filter *f = (cdb_exec_filter *)op;
    cdb_status st;
    int matched = 0;

    *has_row = 0;

    while (1) {
        st = f->input->vtab->next(f->input, cur, out_row, has_row);
        if (st != CDB_OK || !*has_row)
            return st;

        /* Prepare evaluation context with current row */
        cur->eval_ctx.entry_id = out_row->entry_id;
        cur->eval_ctx.score = (double)out_row->score;
        cur->eval_ctx.timestamp = out_row->timestamp;
        cur->eval_ctx.record_data = out_row->record_data;
        cur->eval_ctx.record_len = out_row->record_len;
        cur->eval_ctx.store_id = out_row->store_id;

        cdb_eval_ctx_set_custom_resolver(&cur->eval_ctx, row_field_resolver, (void *)out_row);

        matched = 0;
        st = cdb_eval_predicate(&cur->eval_ctx, f->pred_wire, f->pred_len, &matched);
        if (st != CDB_OK)
            return st;

        if (matched) {
            *has_row = 1;
            return CDB_OK;
        }
    }
}

static const cdb_exec_vtab filter_vtab = {filter_open, filter_next, filter_reset, filter_close};

/* --------------------------------------------------------------------------
 * Operator 0x03: PROJECT
 * -------------------------------------------------------------------------- */
typedef struct cdb_exec_proj_col {
    const char *alias;
    size_t alias_len;
    const uint8_t *expr_wire;
    size_t expr_len;
} cdb_exec_proj_col;

typedef struct cdb_exec_project {
    cdb_exec_op base;
    cdb_exec_op *input;
    uint8_t passthrough;
    size_t count;
    cdb_exec_proj_col cols[CDB_EXEC_MAX_FIELDS];
} cdb_exec_project;

static cdb_status project_open(cdb_exec_op *op, cdb_exec_cursor *cur)
{
    cdb_exec_project *p = (cdb_exec_project *)op;
    return p->input->vtab->open(p->input, cur);
}

static cdb_status project_reset(cdb_exec_op *op, cdb_exec_cursor *cur)
{
    cdb_exec_project *p = (cdb_exec_project *)op;
    return p->input->vtab->reset(p->input, cur);
}

static void project_close(cdb_exec_op *op, cdb_exec_cursor *cur)
{
    cdb_exec_project *p = (cdb_exec_project *)op;
    p->input->vtab->close(p->input, cur);
}

static cdb_status project_next(cdb_exec_op *op, cdb_exec_cursor *cur, cdb_exec_row *out_row,
                               int *has_row)
{
    cdb_exec_project *p = (cdb_exec_project *)op;
    cdb_exec_row in_row;
    cdb_status st;
    size_t i;

    *has_row = 0;
    st = p->input->vtab->next(p->input, cur, &in_row, has_row);
    if (st != CDB_OK || !*has_row)
        return st;

    memset(out_row, 0, sizeof(*out_row));
    out_row->store_id = in_row.store_id;
    out_row->entry_id = in_row.entry_id;
    out_row->model = in_row.model;
    out_row->score = in_row.score;
    out_row->timestamp = in_row.timestamp;

    if (p->passthrough) {
        out_row->record_data = in_row.record_data;
        out_row->record_len = in_row.record_len;
        for (i = 0; i < in_row.n_fields; i++) {
            /* Fail closed rather than silently dropping a field once the row
             * is full: a truncated projection is a wrong answer (#36 FR5). */
            if (out_row->n_fields >= CDB_EXEC_MAX_FIELDS)
                return CDB_E_OVERFLOW;
            out_row->fields[out_row->n_fields++] = in_row.fields[i];
        }
    }

    /* Bind input row to evaluation context */
    cur->eval_ctx.entry_id = in_row.entry_id;
    cur->eval_ctx.score = (double)in_row.score;
    cur->eval_ctx.timestamp = in_row.timestamp;
    cur->eval_ctx.record_data = in_row.record_data;
    cur->eval_ctx.record_len = in_row.record_len;
    cur->eval_ctx.store_id = in_row.store_id;
    cdb_eval_ctx_set_custom_resolver(&cur->eval_ctx, row_field_resolver, (void *)&in_row);

    /* Evaluate projected output columns */
    for (i = 0; i < p->count; i++) {
        cdb_value val;
        size_t consumed = 0;
        /* Fail closed rather than silently dropping a column (#36 FR5). */
        if (out_row->n_fields >= CDB_EXEC_MAX_FIELDS)
            return CDB_E_OVERFLOW;
        st = cdb_eval_expr_wire(&cur->eval_ctx, p->cols[i].expr_wire, p->cols[i].expr_len, &val,
                                &consumed);
        if (st != CDB_OK)
            return st;

        out_row->fields[out_row->n_fields].name = p->cols[i].alias;
        out_row->fields[out_row->n_fields].name_len = p->cols[i].alias_len;
        out_row->fields[out_row->n_fields].val = val;
        out_row->n_fields++;
    }

    *has_row = 1;
    return CDB_OK;
}

static const cdb_exec_vtab project_vtab = {project_open, project_next, project_reset,
                                           project_close};

/* --------------------------------------------------------------------------
 * Operator 0x06: LIMIT
 * -------------------------------------------------------------------------- */
typedef struct cdb_exec_limit {
    cdb_exec_op base;
    cdb_exec_op *input;
    uint64_t count;
    uint64_t offset;
    uint64_t skipped;
    uint64_t yielded;
} cdb_exec_limit;

static cdb_status limit_open(cdb_exec_op *op, cdb_exec_cursor *cur)
{
    cdb_exec_limit *l = (cdb_exec_limit *)op;
    l->skipped = 0;
    l->yielded = 0;
    return l->input->vtab->open(l->input, cur);
}

static cdb_status limit_reset(cdb_exec_op *op, cdb_exec_cursor *cur)
{
    cdb_exec_limit *l = (cdb_exec_limit *)op;
    l->skipped = 0;
    l->yielded = 0;
    return l->input->vtab->reset(l->input, cur);
}

static void limit_close(cdb_exec_op *op, cdb_exec_cursor *cur)
{
    cdb_exec_limit *l = (cdb_exec_limit *)op;
    l->input->vtab->close(l->input, cur);
}

static cdb_status limit_next(cdb_exec_op *op, cdb_exec_cursor *cur, cdb_exec_row *out_row,
                             int *has_row)
{
    cdb_exec_limit *l = (cdb_exec_limit *)op;
    cdb_status st;

    *has_row = 0;

    /* Skip offset rows */
    while (l->skipped < l->offset) {
        st = l->input->vtab->next(l->input, cur, out_row, has_row);
        if (st != CDB_OK || !*has_row)
            return st;
        l->skipped++;
    }

    /* Check if count limit reached */
    if (l->yielded >= l->count) {
        *has_row = 0;
        return CDB_OK;
    }

    st = l->input->vtab->next(l->input, cur, out_row, has_row);
    if (st == CDB_OK && *has_row) {
        l->yielded++;
    }

    return st;
}

static const cdb_exec_vtab limit_vtab = {limit_open, limit_next, limit_reset, limit_close};

/* --------------------------------------------------------------------------
 * Operator 0x07: UNION
 * -------------------------------------------------------------------------- */
typedef struct cdb_exec_union {
    cdb_exec_op base;
    size_t count;
    cdb_exec_op *branches[CDB_EXEC_MAX_BRANCHES];
    size_t cur_branch;
} cdb_exec_union;

static cdb_status union_open(cdb_exec_op *op, cdb_exec_cursor *cur)
{
    cdb_exec_union *u = (cdb_exec_union *)op;
    size_t i;
    u->cur_branch = 0;
    for (i = 0; i < u->count; i++) {
        cdb_status st = u->branches[i]->vtab->open(u->branches[i], cur);
        if (st != CDB_OK)
            return st;
    }
    return CDB_OK;
}

static cdb_status union_reset(cdb_exec_op *op, cdb_exec_cursor *cur)
{
    cdb_exec_union *u = (cdb_exec_union *)op;
    size_t i;
    u->cur_branch = 0;
    for (i = 0; i < u->count; i++) {
        cdb_status st = u->branches[i]->vtab->reset(u->branches[i], cur);
        if (st != CDB_OK)
            return st;
    }
    return CDB_OK;
}

static void union_close(cdb_exec_op *op, cdb_exec_cursor *cur)
{
    cdb_exec_union *u = (cdb_exec_union *)op;
    size_t i;
    for (i = 0; i < u->count; i++) {
        u->branches[i]->vtab->close(u->branches[i], cur);
    }
}

static cdb_status union_next(cdb_exec_op *op, cdb_exec_cursor *cur, cdb_exec_row *out_row,
                             int *has_row)
{
    cdb_exec_union *u = (cdb_exec_union *)op;
    cdb_status st;

    *has_row = 0;

    while (u->cur_branch < u->count) {
        st = u->branches[u->cur_branch]->vtab->next(u->branches[u->cur_branch], cur, out_row,
                                                    has_row);
        if (st != CDB_OK)
            return st;
        if (*has_row)
            return CDB_OK;
        u->cur_branch++;
    }

    *has_row = 0;
    return CDB_OK;
}

static const cdb_exec_vtab union_vtab = {union_open, union_next, union_reset, union_close};

/* --------------------------------------------------------------------------
 * Operator 0x04: JOIN (Nested Loop Join: Inner & Left-Outer)
 * -------------------------------------------------------------------------- */
typedef struct cdb_exec_join {
    cdb_exec_op base;
    uint8_t kind; /* 1 = Inner, 2 = LeftOuter */
    cdb_exec_op *left;
    cdb_exec_op *right;
    const uint8_t *cond_wire;
    size_t cond_len;

    cdb_exec_row cur_left;
    int has_left;
    int left_matched;
} cdb_exec_join;

static cdb_status join_open(cdb_exec_op *op, cdb_exec_cursor *cur)
{
    cdb_exec_join *j = (cdb_exec_join *)op;
    cdb_status st;

    j->has_left = 0;
    j->left_matched = 0;

    if ((st = j->left->vtab->open(j->left, cur)) != CDB_OK)
        return st;
    return j->right->vtab->open(j->right, cur);
}

static cdb_status join_reset(cdb_exec_op *op, cdb_exec_cursor *cur)
{
    cdb_exec_join *j = (cdb_exec_join *)op;
    cdb_status st;

    j->has_left = 0;
    j->left_matched = 0;

    if ((st = j->left->vtab->reset(j->left, cur)) != CDB_OK)
        return st;
    return j->right->vtab->reset(j->right, cur);
}

static void join_close(cdb_exec_op *op, cdb_exec_cursor *cur)
{
    cdb_exec_join *j = (cdb_exec_join *)op;
    j->left->vtab->close(j->left, cur);
    j->right->vtab->close(j->right, cur);
}

static cdb_status join_next(cdb_exec_op *op, cdb_exec_cursor *cur, cdb_exec_row *out_row,
                            int *has_row)
{
    cdb_exec_join *j = (cdb_exec_join *)op;
    cdb_exec_row cur_right;
    int right_has_row = 0;
    cdb_status st;
    size_t i;

    *has_row = 0;

    while (1) {
        if (!j->has_left) {
            st = j->left->vtab->next(j->left, cur, &j->cur_left, &j->has_left);
            if (st != CDB_OK || !j->has_left)
                return st;
            j->left_matched = 0;
            st = j->right->vtab->reset(j->right, cur);
            if (st != CDB_OK)
                return st;
        }

        while (1) {
            st = j->right->vtab->next(j->right, cur, &cur_right, &right_has_row);
            if (st != CDB_OK)
                return st;

            if (!right_has_row) {
                /* Right side exhausted for this left row */
                j->has_left = 0;
                if (j->kind == CDB_JOIN_LEFT_OUTER && !j->left_matched) {
                    /* Emit left row with NULL right context */
                    *out_row = j->cur_left;
                    out_row->has_right = 1;
                    out_row->right_store_id = 0;
                    out_row->right_entry_id = 0;
                    out_row->right_record_data = NULL;
                    out_row->right_record_len = 0;
                    *has_row = 1;
                    return CDB_OK;
                }
                break; /* Advance to next left row */
            }

            /* Combine left and right contexts into candidate */
            *out_row = j->cur_left;
            out_row->has_right = 1;
            out_row->right_store_id = cur_right.store_id;
            out_row->right_entry_id = cur_right.entry_id;
            out_row->right_model = cur_right.model;
            out_row->right_record_data = cur_right.record_data;
            out_row->right_record_len = cur_right.record_len;
            for (i = 0; i < cur_right.n_fields && out_row->n_fields < CDB_EXEC_MAX_FIELDS; i++) {
                out_row->fields[out_row->n_fields++] = cur_right.fields[i];
            }

            /* Evaluate join condition */
            cur->eval_ctx.entry_id = out_row->entry_id;
            cur->eval_ctx.score = (double)out_row->score;
            cur->eval_ctx.timestamp = out_row->timestamp;
            cur->eval_ctx.record_data = out_row->record_data;
            cur->eval_ctx.record_len = out_row->record_len;
            cur->eval_ctx.store_id = out_row->store_id;
            cdb_eval_ctx_set_custom_resolver(&cur->eval_ctx, row_field_resolver, (void *)out_row);

            if (j->cond_wire != NULL && j->cond_len > 0) {
                int matched = 0;
                st = cdb_eval_predicate(&cur->eval_ctx, j->cond_wire, j->cond_len, &matched);
                if (st != CDB_OK)
                    return st;
                if (!matched)
                    continue; /* Condition not satisfied, check next right row */
            }

            j->left_matched = 1;
            *has_row = 1;
            return CDB_OK;
        }
    }
}

static const cdb_exec_vtab join_vtab = {join_open, join_next, join_reset, join_close};

/* --------------------------------------------------------------------------
 * Operator 0x05: SORT
 * -------------------------------------------------------------------------- */
typedef struct cdb_exec_sort_key {
    const uint8_t *expr_wire;
    size_t expr_len;
    uint8_t dir;   /* 1 = ASC, 2 = DESC */
    uint8_t nulls; /* 1 = First, 2 = Last */
} cdb_exec_sort_key;

typedef struct cdb_exec_sort {
    cdb_exec_op base;
    cdb_exec_op *input;
    size_t count;
    cdb_exec_sort_key keys[CDB_EXEC_MAX_SORT_KEYS];

    cdb_exec_row **rows; /* the buffered rows: compact copies in pool */
    size_t n_rows;
    size_t max_rows;
    size_t cur_idx;
    int is_buffered;
    cdb_exec_block *row_blocks; /* host profile: the grown rows array */
    cdb_exec_pool pool;
    uint64_t keep; /* a Limit above needs only the first keep rows; 0: all */
    /* No-heap top-N (#36 FR5): with a Limit above and no growable memory, the
     * kept rows ping-pong between two carved pools so only O(keep) rows are
     * ever buffered for an ORDER BY ... LIMIT k over a large store. pool is
     * pool A; pool_b is pool B; use_b selects the currently active one. */
    cdb_exec_pool pool_b;
    int use_b;
    int topn_noheap;
} cdb_exec_sort;

static int compare_rows(cdb_exec_cursor *cur, const cdb_exec_sort *s, const cdb_exec_row *a,
                        const cdb_exec_row *b)
{
    size_t k;

    for (k = 0; k < s->count; k++) {
        cdb_value va, vb;
        size_t consumed = 0;
        int a_null, b_null;

        /* Eval key for A */
        cur->eval_ctx.entry_id = a->entry_id;
        cur->eval_ctx.score = (double)a->score;
        cur->eval_ctx.timestamp = a->timestamp;
        cur->eval_ctx.record_data = a->record_data;
        cur->eval_ctx.record_len = a->record_len;
        cur->eval_ctx.store_id = a->store_id;
        cdb_eval_ctx_set_custom_resolver(&cur->eval_ctx, row_field_resolver, (void *)a);
        if (cdb_eval_expr_wire(&cur->eval_ctx, s->keys[k].expr_wire, s->keys[k].expr_len, &va,
                               &consumed)
            != CDB_OK)
            cdb_eval_make_null(&va);

        /* Eval key for B */
        cur->eval_ctx.entry_id = b->entry_id;
        cur->eval_ctx.score = (double)b->score;
        cur->eval_ctx.timestamp = b->timestamp;
        cur->eval_ctx.record_data = b->record_data;
        cur->eval_ctx.record_len = b->record_len;
        cur->eval_ctx.store_id = b->store_id;
        cdb_eval_ctx_set_custom_resolver(&cur->eval_ctx, row_field_resolver, (void *)b);
        if (cdb_eval_expr_wire(&cur->eval_ctx, s->keys[k].expr_wire, s->keys[k].expr_len, &vb,
                               &consumed)
            != CDB_OK)
            cdb_eval_make_null(&vb);

        a_null = cdb_eval_is_null(&va);
        b_null = cdb_eval_is_null(&vb);

        if (a_null && b_null)
            continue;
        if (a_null)
            return (s->keys[k].nulls == CDB_NULLS_FIRST) ? -1 : 1;
        if (b_null)
            return (s->keys[k].nulls == CDB_NULLS_FIRST) ? 1 : -1;

        {
            int c_res = 0;
            int is_null = 0;
            if (cdb_eval_compare(&va, &vb, &c_res, &is_null) == CDB_OK && !is_null && c_res != 0) {
                return (s->keys[k].dir == CDB_SORT_DESC) ? -c_res : c_res;
            }
        }
    }
    return 0;
}

/* Stable insertion sort: few rows, or no memory for a merge buffer */
static void sort_insertion(cdb_exec_cursor *cur, const cdb_exec_sort *s, cdb_exec_row **rows,
                           size_t n)
{
    size_t i, j;
    for (i = 1; i < n; i++) {
        cdb_exec_row *key = rows[i];
        for (j = i; j > 0 && compare_rows(cur, s, rows[j - 1], key) > 0; j--)
            rows[j] = rows[j - 1];
        rows[j] = key;
    }
}

/* Stable bottom-up merge sort of the row pointers, O(n log n): the host
 * profile's path for large inputs (spec 17.5). Falls back to insertion when
 * no merge buffer can be grown. */
static void sort_rows(cdb_exec_cursor *cur, cdb_exec_sort *s, cdb_exec_row **rows, size_t n)
{
    cdb_exec_block *tmp_block = NULL;
    cdb_exec_row **tmp, **from = rows, **to;
    size_t width, i;

    if (n < 32 || (tmp = (cdb_exec_row **)exec_grow(cur, &tmp_block, n * sizeof *tmp)) == NULL) {
        sort_insertion(cur, s, rows, n);
        return;
    }
    to = tmp;
    for (width = 1; width < n; width *= 2) {
        for (i = 0; i < n; i += 2 * width) {
            size_t lo = i, mid = i + width < n ? i + width : n,
                   hi = i + 2 * width < n ? i + 2 * width : n;
            size_t a = lo, b = mid, k = lo;
            while (a < mid && b < hi)
                to[k++] = compare_rows(cur, s, from[b], from[a]) < 0 ? from[b++] : from[a++];
            while (a < mid)
                to[k++] = from[a++];
            while (b < hi)
                to[k++] = from[b++];
        }
        {
            cdb_exec_row **t = from;
            from = to;
            to = t;
        }
    }
    if (from != rows)
        memcpy(rows, from, n * sizeof *rows);
    exec_free_all(cur, &tmp_block);
}

/* Top-N (host profile): keep the first s->keep rows, and move them to a
 * fresh pool so the dropped rows' memory goes back */
static cdb_status sort_trim(cdb_exec_cursor *cur, cdb_exec_sort *s)
{
    cdb_exec_pool old = s->pool;
    size_t i;
    cdb_status st;

    sort_rows(cur, s, s->rows, s->n_rows);
    s->n_rows = (size_t)s->keep;
    memset(&s->pool, 0, sizeof s->pool);
    for (i = 0; i < s->n_rows; i++)
        if ((st = store_row(cur, &s->pool, s->rows[i], &s->rows[i])) != CDB_OK)
            return st;
    exec_free_all(cur, &old.blocks);
    return CDB_OK;
}

/* Carves a pool worth (a share of) what remains of the arena. Used for the
 * no-heap top-N second pool; returns CDB_E_OUT_OF_BUDGET if none is left. */
static cdb_status carve_pool(cdb_exec_arena *arena, cdb_exec_pool *pool)
{
    size_t avail = (arena->cap > arena->used) ? (arena->cap - arena->used) : 0;
    size_t share = avail / 2; /* leave half for any breaker opened above */

    pool->blocks = NULL;
    pool->a.buf = (uint8_t *)cdb_exec_arena_alloc(arena, share, sizeof(void *));
    pool->a.cap = pool->a.buf != NULL ? share : 0;
    pool->a.used = 0;
    if (pool->a.buf == NULL || pool->a.cap == 0)
        return CDB_E_OUT_OF_BUDGET;
    return CDB_OK;
}

/* The currently active top-N pool (where new rows are stored). */
static cdb_exec_pool *sort_active_pool(cdb_exec_sort *s)
{
    return s->use_b ? &s->pool_b : &s->pool;
}

/* No-heap top-N (#36 FR5): sort the ≤2*keep buffered rows, keep the best
 * keep, copy them into the inactive pool, reset and hand back the active
 * pool, then swap. Bounds buffered memory to O(keep) with no heap growth. */
static cdb_status sort_topn_compact(cdb_exec_cursor *cur, cdb_exec_sort *s)
{
    cdb_exec_pool *dst = s->use_b ? &s->pool : &s->pool_b; /* the inactive one */
    size_t i;
    cdb_status st;

    sort_rows(cur, s, s->rows, s->n_rows);
    if (s->n_rows > (size_t)s->keep)
        s->n_rows = (size_t)s->keep;

    /* dst is the pool abandoned by the previous compaction; empty it. */
    exec_free_all(cur, &dst->blocks);
    dst->a.used = 0;
    for (i = 0; i < s->n_rows; i++)
        if ((st = store_row(cur, dst, s->rows[i], &s->rows[i])) != CDB_OK)
            return st;
    s->use_b = !s->use_b;
    return CDB_OK;
}

static cdb_status sort_open(cdb_exec_op *op, cdb_exec_cursor *cur)
{
    cdb_exec_sort *s = (cdb_exec_sort *)op;
    void *items = NULL;
    cdb_status st;

    s->n_rows = 0;
    s->cur_idx = 0;
    s->is_buffered = 0;
    s->row_blocks = NULL;
    s->use_b = 0;
    s->topn_noheap = 0;
    memset(&s->pool_b, 0, sizeof s->pool_b);
    /* The input first, so a breaker below gets its memory before this one */
    if ((st = s->input->vtab->open(s->input, cur)) != CDB_OK)
        return st;
    if ((st = carve_buffer(&cur->arena, sizeof(cdb_exec_row *), cur->max_buffered_rows, &items,
                           &s->max_rows, &s->pool))
        != CDB_OK)
        return st;
    s->rows = (cdb_exec_row **)items;

    /* With a Limit above and no growable memory, carve a second pool so the
     * kept rows can ping-pong (O(keep) buffered) instead of failing once the
     * row array fills (#36 FR5). Needs room for two generations of kept rows,
     * so the row array must hold at least 2*keep. */
    if (s->keep > 0 && cur->mem_budget == 0 && (uint64_t)s->keep <= (uint64_t)s->max_rows / 2
        && carve_pool(&cur->arena, &s->pool_b) == CDB_OK)
        s->topn_noheap = 1;
    return CDB_OK;
}

static cdb_status sort_reset(cdb_exec_op *op, cdb_exec_cursor *cur)
{
    cdb_exec_sort *s = (cdb_exec_sort *)op;
    (void)cur;
    s->cur_idx = 0;
    return CDB_OK;
}

static void sort_close(cdb_exec_op *op, cdb_exec_cursor *cur)
{
    cdb_exec_sort *s = (cdb_exec_sort *)op;
    if (cur->db != NULL) {
        exec_free_all(cur, &s->pool.blocks);
        exec_free_all(cur, &s->pool_b.blocks);
        exec_free_all(cur, &s->row_blocks);
    }
    s->input->vtab->close(s->input, cur);
}

static cdb_status sort_next(cdb_exec_op *op, cdb_exec_cursor *cur, cdb_exec_row *out_row,
                            int *has_row)
{
    cdb_exec_sort *s = (cdb_exec_sort *)op;
    cdb_status st;

    *has_row = 0;

    if (!s->is_buffered) {
        cdb_exec_row item;
        int in_has_row = 0;
        /* With a Limit above, keep only the first keep rows. On the host
         * profile this grows a fresh pool (sort_trim); with no growable
         * memory it ping-pongs two carved pools (sort_topn_compact). Either
         * way the buffer is trimmed each time twice keep rows accumulate. */
        int host_trim = s->keep > 0 && cur->mem_budget > 0 && s->keep <= SIZE_MAX / 4;
        int noheap_trim = s->topn_noheap;
        int trim = host_trim || noheap_trim;

        while (1) {
            st = s->input->vtab->next(s->input, cur, &item, &in_has_row);
            if (st != CDB_OK)
                return st;
            if (!in_has_row)
                break;

            if (s->n_rows >= s->max_rows) {
                /* Host profile: a larger rows array; mcu: the limit (17.3) */
                cdb_exec_row **grown;
                if (s->max_rows > SIZE_MAX / 2 / sizeof *grown
                    || (grown = (cdb_exec_row **)exec_grow(cur, &s->row_blocks,
                                                           2 * s->max_rows * sizeof *grown))
                           == NULL)
                    return CDB_E_OUT_OF_BUDGET;
                memcpy(grown, s->rows, s->n_rows * sizeof *grown);
                if (s->row_blocks->next != NULL
                    && (uint8_t *)s->row_blocks->next + BLOCK_HEAD == (uint8_t *)s->rows)
                    exec_free_one(cur, &s->row_blocks, s->rows);
                s->rows = grown;
                s->max_rows *= 2;
            }
            if ((st = store_row(cur, sort_active_pool(s), &item, &s->rows[s->n_rows])) != CDB_OK)
                return st;
            s->n_rows++;
            if (host_trim && s->n_rows >= 2 * s->keep && s->n_rows >= 64
                && (st = sort_trim(cur, s)) != CDB_OK)
                return st;
            else if (noheap_trim && s->n_rows >= 2 * s->keep
                     && (st = sort_topn_compact(cur, s)) != CDB_OK)
                return st;
        }

        if (s->n_rows > 1)
            sort_rows(cur, s, s->rows, s->n_rows);
        if (trim && s->n_rows > s->keep)
            s->n_rows = (size_t)s->keep;
        s->is_buffered = 1;
        s->cur_idx = 0;
    }

    if (s->cur_idx < s->n_rows) {
        load_row(out_row, s->rows[s->cur_idx++]);
        *has_row = 1;
        return CDB_OK;
    }

    return CDB_OK;
}

static const cdb_exec_vtab sort_vtab = {sort_open, sort_next, sort_reset, sort_close};

/* --------------------------------------------------------------------------
 * Operator 0x08: AGGREGATE
 * -------------------------------------------------------------------------- */
typedef struct cdb_exec_agg_desc {
    const char *alias;
    size_t alias_len;
    uint8_t fn; /* 1=COUNT, 2=SUM, 3=AVG, 4=MIN, 5=MAX */
    const uint8_t *arg_wire;
    size_t arg_len;
} cdb_exec_agg_desc;

typedef struct cdb_exec_agg_group {
    cdb_value group_vals[CDB_EXEC_MAX_GROUP_KEYS];
    double sum[CDB_EXEC_MAX_AGGS];
    double sumsq[CDB_EXEC_MAX_AGGS]; /* sum of squares, for STDDEV/VARIANCE */
    uint64_t count[CDB_EXEC_MAX_AGGS];
    cdb_value min_val[CDB_EXEC_MAX_AGGS];
    cdb_value max_val[CDB_EXEC_MAX_AGGS];
    cdb_value fl_val[CDB_EXEC_MAX_AGGS]; /* FIRST or LAST value; each slot is one or the other */
    int has_val[CDB_EXEC_MAX_AGGS];
} cdb_exec_agg_group;

typedef struct cdb_exec_aggregate {
    cdb_exec_op base;
    cdb_exec_op *input;
    size_t groups_count;
    size_t aggs_count;
    const uint8_t *group_wires[CDB_EXEC_MAX_GROUP_KEYS];
    size_t group_lens[CDB_EXEC_MAX_GROUP_KEYS];
    cdb_exec_agg_desc aggs[CDB_EXEC_MAX_AGGS];

    cdb_exec_agg_group *groups;
    size_t n_groups;
    size_t max_groups;
    size_t cur_idx;
    int is_buffered;
    cdb_exec_pool pool;           /* what group keys and MIN/MAX values point to */
    cdb_exec_block *group_blocks; /* host profile: the grown groups array */
} cdb_exec_aggregate;

static cdb_status aggregate_open(cdb_exec_op *op, cdb_exec_cursor *cur)
{
    cdb_exec_aggregate *a = (cdb_exec_aggregate *)op;
    void *items = NULL;
    cdb_status st;

    a->n_groups = 0;
    a->cur_idx = 0;
    a->is_buffered = 0;
    a->group_blocks = NULL;
    /* The input first, so a breaker below gets its memory before this one */
    if ((st = a->input->vtab->open(a->input, cur)) != CDB_OK)
        return st;
    if ((st = carve_buffer(&cur->arena, sizeof(cdb_exec_agg_group), cur->max_buffered_rows, &items,
                           &a->max_groups, &a->pool))
        != CDB_OK)
        return st;
    a->groups = (cdb_exec_agg_group *)items;
    return CDB_OK;
}

static cdb_status aggregate_reset(cdb_exec_op *op, cdb_exec_cursor *cur)
{
    cdb_exec_aggregate *a = (cdb_exec_aggregate *)op;
    (void)cur;
    a->cur_idx = 0;
    return CDB_OK;
}

static void aggregate_close(cdb_exec_op *op, cdb_exec_cursor *cur)
{
    cdb_exec_aggregate *a = (cdb_exec_aggregate *)op;
    if (cur->db != NULL) {
        exec_free_all(cur, &a->pool.blocks);
        exec_free_all(cur, &a->group_blocks);
    }
    a->input->vtab->close(a->input, cur);
}

static cdb_status aggregate_next(cdb_exec_op *op, cdb_exec_cursor *cur, cdb_exec_row *out_row,
                                 int *has_row)
{
    cdb_exec_aggregate *a = (cdb_exec_aggregate *)op;
    cdb_status st;
    size_t g, i;

    *has_row = 0;

    if (!a->is_buffered) {
        cdb_exec_row item;
        int in_has_row = 0;

        while (1) {
            cdb_value gvals[CDB_EXEC_MAX_GROUP_KEYS];
            int group_idx = -1;

            st = a->input->vtab->next(a->input, cur, &item, &in_has_row);
            if (st != CDB_OK)
                return st;
            if (!in_has_row)
                break;

            /* Set up evaluation context for current input row */
            cur->eval_ctx.entry_id = item.entry_id;
            cur->eval_ctx.score = (double)item.score;
            cur->eval_ctx.timestamp = item.timestamp;
            cur->eval_ctx.record_data = item.record_data;
            cur->eval_ctx.record_len = item.record_len;
            cur->eval_ctx.store_id = item.store_id;
            cdb_eval_ctx_set_custom_resolver(&cur->eval_ctx, row_field_resolver, (void *)&item);

            /* Evaluate group keys */
            for (g = 0; g < a->groups_count; g++) {
                size_t consumed = 0;
                st = cdb_eval_expr_wire(&cur->eval_ctx, a->group_wires[g], a->group_lens[g],
                                        &gvals[g], &consumed);
                if (st != CDB_OK)
                    return st;
            }

            /* Search for matching group */
            for (g = 0; g < a->n_groups; g++) {
                int match = 1;
                for (i = 0; i < a->groups_count; i++) {
                    int c_res = 0;
                    int is_null = 0;
                    if (cdb_eval_compare(&gvals[i], &a->groups[g].group_vals[i], &c_res, &is_null)
                            != CDB_OK
                        || is_null || c_res != 0) {
                        match = 0;
                        break;
                    }
                }
                if (match) {
                    group_idx = (int)g;
                    break;
                }
            }

            /* Create new group if not found */
            if (group_idx < 0) {
                if (a->n_groups >= a->max_groups) {
                    /* Host profile: a larger groups array; mcu: the limit */
                    cdb_exec_agg_group *grown;
                    if (a->max_groups > SIZE_MAX / 2 / sizeof *grown
                        || (grown = (cdb_exec_agg_group *)exec_grow(
                                cur, &a->group_blocks, 2 * a->max_groups * sizeof *grown))
                               == NULL)
                        return CDB_E_OUT_OF_BUDGET;
                    memcpy(grown, a->groups, a->n_groups * sizeof *grown);
                    if (a->group_blocks->next != NULL
                        && (uint8_t *)a->group_blocks->next + BLOCK_HEAD == (uint8_t *)a->groups)
                        exec_free_one(cur, &a->group_blocks, a->groups);
                    a->groups = grown;
                    a->max_groups *= 2;
                }

                group_idx = (int)a->n_groups++;
                memset(&a->groups[group_idx], 0, sizeof(cdb_exec_agg_group));
                for (i = 0; i < a->groups_count; i++) {
                    if ((st = pin_value(cur, &a->pool, &gvals[i])) != CDB_OK)
                        return st;
                    a->groups[group_idx].group_vals[i] = gvals[i];
                }
            }

            /* Update accumulators for group */
            for (i = 0; i < a->aggs_count; i++) {
                cdb_exec_agg_group *grp = &a->groups[group_idx];
                cdb_value aval;
                size_t consumed = 0;
                double dval = 0.0;

                st = cdb_eval_expr_wire(&cur->eval_ctx, a->aggs[i].arg_wire, a->aggs[i].arg_len,
                                        &aval, &consumed);
                if (st != CDB_OK)
                    return st;

                if (a->aggs[i].fn == CDB_AGG_COUNT) {
                    grp->count[i]++;
                    grp->has_val[i] = 1;
                    continue;
                }

                if (cdb_eval_is_null(&aval))
                    continue;

                if (aval.type == CDB_TYPE_INT)
                    dval = (double)aval.as.i64;
                else if (aval.type == CDB_TYPE_F64)
                    dval = aval.as.f64;
                else if (aval.type == CDB_TYPE_F32)
                    dval = (double)aval.as.f32;

                grp->count[i]++;
                grp->sum[i] += dval;
                grp->sumsq[i] += dval * dval; /* for STDDEV / VARIANCE */

                /* FIRST / LAST keep the non-null value itself (scan order), so
                 * pin a copy — but ONLY for those aggregates, so the common
                 * numeric aggregates do not pin a row each and exhaust the pool.
                 * FIRST pins on the first non-null row; LAST on every row. */
                if (a->aggs[i].fn == CDB_AGG_FIRST) {
                    if (!grp->has_val[i]) {
                        cdb_value lv = aval;
                        if ((st = pin_value(cur, &a->pool, &lv)) != CDB_OK)
                            return st;
                        grp->fl_val[i] = lv;
                    }
                } else if (a->aggs[i].fn == CDB_AGG_LAST) {
                    cdb_value lv = aval;
                    if ((st = pin_value(cur, &a->pool, &lv)) != CDB_OK)
                        return st;
                    grp->fl_val[i] = lv;
                }

                /* MIN and MAX keep a value across rows, so it is pinned;
                 * only when it changes, which keeps the pool small */
                if (!grp->has_val[i]) {
                    if ((st = pin_value(cur, &a->pool, &aval)) != CDB_OK)
                        return st;
                    grp->min_val[i] = aval;
                    grp->max_val[i] = aval;
                    grp->has_val[i] = 1;
                } else {
                    int c_res = 0;
                    int is_null = 0;
                    int lower =
                        cdb_eval_compare(&aval, &grp->min_val[i], &c_res, &is_null) == CDB_OK
                        && !is_null && c_res < 0;
                    int higher =
                        cdb_eval_compare(&aval, &grp->max_val[i], &c_res, &is_null) == CDB_OK
                        && !is_null && c_res > 0;
                    if (lower || higher) {
                        if ((st = pin_value(cur, &a->pool, &aval)) != CDB_OK)
                            return st;
                        if (lower)
                            grp->min_val[i] = aval;
                        if (higher)
                            grp->max_val[i] = aval;
                    }
                }
            }
        }
        a->is_buffered = 1;
        a->cur_idx = 0;
    }

    if (a->cur_idx < a->n_groups) {
        cdb_exec_agg_group *grp = &a->groups[a->cur_idx++];
        memset(out_row, 0, sizeof(*out_row));

        /* Add group keys to output */
        for (g = 0; g < a->groups_count && out_row->n_fields < CDB_EXEC_MAX_FIELDS; g++) {
            /* A key that is a plain field keeps the field's name, so
             * GROUP BY region yields "region"; any other is "group" */
            const uint8_t *gp = a->group_wires[g];
            cdb_query_expr gx;
            if (cdb_query_read_expr(&gp, a->group_wires[g] + a->group_lens[g], &gx) == CDB_OK
                && gx.tag == CDB_QUERY_EXPR_FIELD) {
                out_row->fields[out_row->n_fields].name = gx.as.field.path;
                out_row->fields[out_row->n_fields].name_len = gx.as.field.len;
            } else {
                out_row->fields[out_row->n_fields].name = "group";
                out_row->fields[out_row->n_fields].name_len = 5;
            }
            out_row->fields[out_row->n_fields].val = grp->group_vals[g];
            out_row->n_fields++;
        }

        /* Add aggregate outputs */
        for (i = 0; i < a->aggs_count && out_row->n_fields < CDB_EXEC_MAX_FIELDS; i++) {
            cdb_value res;
            memset(&res, 0, sizeof(res));

            switch (a->aggs[i].fn) {
            case CDB_AGG_COUNT: cdb_eval_make_int(&res, (int64_t)grp->count[i]); break;
            case CDB_AGG_SUM: cdb_eval_make_f64(&res, grp->sum[i]); break;
            case CDB_AGG_AVG:
                cdb_eval_make_f64(&res, (grp->count[i] > 0) ? (grp->sum[i] / (double)grp->count[i])
                                                            : 0.0);
                break;
            case CDB_AGG_MIN: res = grp->min_val[i]; break;
            case CDB_AGG_MAX: res = grp->max_val[i]; break;
            case CDB_AGG_FIRST:
            case CDB_AGG_LAST:
                if (grp->has_val[i])
                    res = grp->fl_val[i];
                else
                    cdb_eval_make_null(&res);
                break;
            case CDB_AGG_VARIANCE:
            case CDB_AGG_STDDEV: {
                /* Sample (n-1): NULL when fewer than two values. */
                uint64_t n = grp->count[i];
                if (n < 2) {
                    cdb_eval_make_null(&res);
                } else {
                    double mean = grp->sum[i] / (double)n;
                    double var = (grp->sumsq[i] - (double)n * mean * mean) / (double)(n - 1);
                    if (var < 0.0)
                        var = 0.0; /* guard tiny negative from rounding */
                    cdb_eval_make_f64(&res,
                                      a->aggs[i].fn == CDB_AGG_STDDEV ? cdb_math_sqrt(var) : var);
                }
                break;
            }
            default: cdb_eval_make_null(&res); break;
            }

            out_row->fields[out_row->n_fields].name = a->aggs[i].alias;
            out_row->fields[out_row->n_fields].name_len = a->aggs[i].alias_len;
            out_row->fields[out_row->n_fields].val = res;
            out_row->n_fields++;
        }

        *has_row = 1;
        return CDB_OK;
    }

    return CDB_OK;
}

static const cdb_exec_vtab aggregate_vtab = {aggregate_open, aggregate_next, aggregate_reset,
                                             aggregate_close};

/* --------------------------------------------------------------------------
 * Operator 0x0D: WINDOW
 * -------------------------------------------------------------------------- */
/* A single row that lands in more covering windows than this (a tiny step
 * against a huge size) is rejected rather than expanded unboundedly: a
 * crafted plan must not turn one input row into a denial of service
 * (#36 FR1; CWE-834/CWE-400). */
#define CDB_EXEC_MAX_WINDOWS_PER_ROW 65536u

typedef struct cdb_exec_window {
    cdb_exec_op base;
    cdb_exec_op *input;
    uint8_t type; /* 1=Tumbling, 2=Sliding, 3=Hopping */
    const char *time_field;
    size_t time_field_len;
    uint64_t size_ns;
    uint64_t step_ns;

    /* Effective hop between window starts: step_ns for sliding/hopping,
     * size_ns for tumbling (0 only when size_ns is 0). Resolved at open. */
    uint64_t step;

    /* A row that falls in several overlapping windows (sliding/hopping) is
     * held and emitted once per covering window, so each (row, window) pair
     * reaches the operator above (e.g. an Aggregate grouping on
     * $window_start). The held input stays valid because the input is not
     * advanced until all its windows are emitted. */
    cdb_exec_row cur_in;
    int have_in;
    int64_t cur_ts;
    int64_t cur_k;  /* next window index to emit for cur_in */
    int64_t last_k; /* last covering window index (inclusive) */
} cdb_exec_window;

/* floor(a / b) for b > 0, correct for negative a (C division truncates
 * toward zero, which is not floor for negative numerators). */
static int64_t window_floor_div(int64_t a, int64_t b)
{
    int64_t q = a / b;
    if ((a % b != 0) && ((a < 0) != (b < 0)))
        q--;
    return q;
}

/* The effective hop between window starts, honoring type and step_ns. */
static uint64_t window_effective_step(const cdb_exec_window *w)
{
    if ((w->type == 0x02u || w->type == 0x03u) && w->step_ns > 0)
        return w->step_ns; /* sliding / hopping */
    return w->size_ns;     /* tumbling (or degenerate size 0) */
}

/* Reads the row's window timestamp from the time_field, falling back to the
 * row's own timestamp. */
static int64_t window_extract_ts(cdb_exec_window *w, cdb_exec_row *row, cdb_exec_cursor *cur)
{
    if (w->time_field_len > 0) {
        cdb_value tval;
        int found = 0;
        if (cdb_exec_row_get_field(row, &cur->eval_ctx, w->time_field, w->time_field_len, &tval,
                                   &found)
                == CDB_OK
            && found && tval.type == CDB_TYPE_INT)
            return tval.as.i64;
    }
    return row->timestamp;
}

static cdb_status window_open(cdb_exec_op *op, cdb_exec_cursor *cur)
{
    cdb_exec_window *w = (cdb_exec_window *)op;
    w->have_in = 0;
    w->cur_k = 0;
    w->last_k = 0;
    w->step = window_effective_step(w);
    return w->input->vtab->open(w->input, cur);
}

static cdb_status window_reset(cdb_exec_op *op, cdb_exec_cursor *cur)
{
    cdb_exec_window *w = (cdb_exec_window *)op;
    w->have_in = 0;
    w->cur_k = 0;
    w->last_k = 0;
    w->step = window_effective_step(w);
    return w->input->vtab->reset(w->input, cur);
}

static void window_close(cdb_exec_op *op, cdb_exec_cursor *cur)
{
    cdb_exec_window *w = (cdb_exec_window *)op;
    w->input->vtab->close(w->input, cur);
}

static cdb_status window_next(cdb_exec_op *op, cdb_exec_cursor *cur, cdb_exec_row *out_row,
                              int *has_row)
{
    cdb_exec_window *w = (cdb_exec_window *)op;
    cdb_status st;
    int64_t win_start, win_end;

    *has_row = 0;

    /* Fetch and window-assign the next input row when the current one's
     * windows are exhausted. */
    if (!w->have_in) {
        int in_has = 0;
        st = w->input->vtab->next(w->input, cur, &w->cur_in, &in_has);
        if (st != CDB_OK || !in_has)
            return st;

        w->cur_ts = window_extract_ts(w, &w->cur_in, cur);

        if (w->size_ns == 0 || w->step == 0) {
            /* Degenerate: a single point window at the timestamp. */
            w->cur_k = 0;
            w->last_k = 0;
        } else {
            int64_t size = (int64_t)w->size_ns;
            int64_t step = (int64_t)w->step;
            /* A window with start = k*step covers ts iff k*step <= ts and
             * ts < k*step + size, i.e. k in (floor((ts-size)/step),
             * floor(ts/step)]. For tumbling (step == size) this collapses to
             * the single window floor(ts/size)*size, preserving the prior
             * tumbling behavior; for step < size it yields the overlapping
             * sliding/hopping windows (#36 FR1). */
            int64_t last_k = window_floor_div(w->cur_ts, step);
            int64_t first_k = window_floor_div(w->cur_ts - size, step) + 1;
            if (first_k > last_k)
                first_k = last_k; /* ts is always in at least its own window */
            if ((uint64_t)(last_k - first_k) >= CDB_EXEC_MAX_WINDOWS_PER_ROW)
                return CDB_E_OUT_OF_BUDGET;
            w->cur_k = first_k;
            w->last_k = last_k;
        }
        w->have_in = 1;
    }

    cdb_exec_row_copy(out_row, &w->cur_in);

    if (w->size_ns == 0 || w->step == 0) {
        win_start = w->cur_ts;
        win_end = w->cur_ts;
    } else {
        win_start = w->cur_k * (int64_t)w->step;
        win_end = win_start + (int64_t)w->size_ns;
    }

    /* Fail closed rather than silently dropping the window bounds (#36 FR5). */
    if (out_row->n_fields + 2 > CDB_EXEC_MAX_FIELDS)
        return CDB_E_OVERFLOW;

    out_row->fields[out_row->n_fields].name = "$window_start";
    out_row->fields[out_row->n_fields].name_len = 13;
    cdb_eval_make_int(&out_row->fields[out_row->n_fields].val, win_start);
    out_row->n_fields++;

    out_row->fields[out_row->n_fields].name = "$window_end";
    out_row->fields[out_row->n_fields].name_len = 11;
    cdb_eval_make_int(&out_row->fields[out_row->n_fields].val, win_end);
    out_row->n_fields++;

    w->cur_k++;
    if (w->cur_k > w->last_k)
        w->have_in = 0; /* advance to the next input row on the next call */

    *has_row = 1;
    return CDB_OK;
}

static const cdb_exec_vtab window_vtab = {window_open, window_next, window_reset, window_close};

/* --------------------------------------------------------------------------
 * Operator 0x0E: ASOF_JOIN
 * -------------------------------------------------------------------------- */
typedef struct cdb_exec_asof {
    cdb_exec_op base;
    uint8_t kind; /* 1=Backward, 2=Forward, 3=Nearest */
    uint64_t tolerance_ns;
    cdb_exec_op *left;
    cdb_exec_op *right;
    const uint8_t *left_time_wire;
    size_t left_time_len;
    const uint8_t *right_time_wire;
    size_t right_time_len;
    const uint8_t *match_cond_wire;
    size_t match_cond_len;

    /* The right input is materialized exactly once (its computed as-of time
     * stored in each buffered row's timestamp), so each left row is matched
     * against an in-memory buffer rather than re-executing the right pipeline:
     * right-subtree scans go from O(n*m) to O(m) (#36 FR2). */
    int right_buffered;
    cdb_exec_row **right_rows;
    size_t right_n;
    size_t right_max;
    cdb_exec_pool right_pool;
} cdb_exec_asof;

/* Number of right rows scanned by the most recent AsofJoin open. One pass
 * over the right pipeline fills the buffer, so this is m, not n*m. */
static uint64_t g_asof_right_scans = 0;

uint64_t cdb_exec_asof_right_scan_count(void)
{
    return g_asof_right_scans;
}

/* Binds the evaluation context and field resolver to a row. */
static void asof_bind_ctx(cdb_exec_cursor *cur, cdb_exec_row *row)
{
    cur->eval_ctx.entry_id = row->entry_id;
    cur->eval_ctx.score = (double)row->score;
    cur->eval_ctx.timestamp = row->timestamp;
    cur->eval_ctx.record_data = row->record_data;
    cur->eval_ctx.record_len = row->record_len;
    cur->eval_ctx.store_id = row->store_id;
    cdb_eval_ctx_set_custom_resolver(&cur->eval_ctx, row_field_resolver, (void *)row);
}

/* Materializes the whole right input once into the as-of buffer, storing the
 * computed right-side time in each buffered row's timestamp. */
static cdb_status asof_materialize_right(cdb_exec_asof *a, cdb_exec_cursor *cur)
{
    void *items = NULL;
    cdb_status st;

    g_asof_right_scans = 0;
    if ((st = carve_buffer(&cur->arena, sizeof(cdb_exec_row *), cur->max_buffered_rows, &items,
                           &a->right_max, &a->right_pool))
        != CDB_OK)
        return st;
    a->right_rows = (cdb_exec_row **)items;
    a->right_n = 0;

    for (;;) {
        cdb_exec_row rrow;
        int rhas = 0;
        int64_t t_right;

        st = a->right->vtab->next(a->right, cur, &rrow, &rhas);
        if (st != CDB_OK)
            return st;
        if (!rhas)
            break;
        g_asof_right_scans++;

        asof_bind_ctx(cur, &rrow);
        t_right = rrow.timestamp;
        if (a->right_time_wire != NULL && a->right_time_len > 0) {
            cdb_value tv;
            size_t consumed = 0;
            if (cdb_eval_expr_wire(&cur->eval_ctx, a->right_time_wire, a->right_time_len, &tv,
                                   &consumed)
                    == CDB_OK
                && tv.type == CDB_TYPE_INT)
                t_right = tv.as.i64;
        }
        rrow.timestamp = t_right; /* reuse the field to carry the as-of time */

        if (a->right_n >= a->right_max)
            return CDB_E_OUT_OF_BUDGET; /* fail closed: right can't be buffered */
        if ((st = store_row(cur, &a->right_pool, &rrow, &a->right_rows[a->right_n])) != CDB_OK)
            return st;
        a->right_n++;
    }

    a->right_buffered = 1;
    return CDB_OK;
}

static cdb_status asof_open(cdb_exec_op *op, cdb_exec_cursor *cur)
{
    cdb_exec_asof *a = (cdb_exec_asof *)op;
    cdb_status st;

    a->right_buffered = 0;
    a->right_rows = NULL;
    a->right_n = 0;
    a->right_max = 0;
    memset(&a->right_pool, 0, sizeof a->right_pool);

    /* The right input is materialized lazily on the first next (asof_next) so
     * that a test's mock scan, bound after open, is already in place. */
    if ((st = a->left->vtab->open(a->left, cur)) != CDB_OK)
        return st;
    return a->right->vtab->open(a->right, cur);
}

static cdb_status asof_reset(cdb_exec_op *op, cdb_exec_cursor *cur)
{
    cdb_exec_asof *a = (cdb_exec_asof *)op;
    /* The right buffer is a deterministic materialization; only the left
     * cursor restarts. */
    return a->left->vtab->reset(a->left, cur);
}

static void asof_close(cdb_exec_op *op, cdb_exec_cursor *cur)
{
    cdb_exec_asof *a = (cdb_exec_asof *)op;
    if (cur->db != NULL)
        exec_free_all(cur, &a->right_pool.blocks);
    a->left->vtab->close(a->left, cur);
    a->right->vtab->close(a->right, cur);
}

/* Evaluates the as-of match predicate over the combined left+right row.
 * An absent predicate matches. */
static cdb_status asof_match(cdb_exec_asof *a, cdb_exec_cursor *cur, const cdb_exec_row *left_row,
                             const cdb_exec_row *rr, int *matched)
{
    cdb_exec_row cand;
    size_t f;

    *matched = 1;
    if (a->match_cond_wire == NULL || a->match_cond_len == 0)
        return CDB_OK;

    cand = *left_row;
    cand.has_right = 1;
    cand.right_store_id = rr->store_id;
    cand.right_entry_id = rr->entry_id;
    cand.right_model = rr->model;
    cand.right_record_data = rr->record_data;
    cand.right_record_len = rr->record_len;
    for (f = 0; f < rr->n_fields && cand.n_fields < CDB_EXEC_MAX_FIELDS; f++)
        cand.fields[cand.n_fields++] = rr->fields[f];

    asof_bind_ctx(cur, &cand);
    return cdb_eval_predicate(&cur->eval_ctx, a->match_cond_wire, a->match_cond_len, matched);
}

static cdb_status asof_next(cdb_exec_op *op, cdb_exec_cursor *cur, cdb_exec_row *out_row,
                            int *has_row)
{
    cdb_exec_asof *a = (cdb_exec_asof *)op;
    cdb_exec_row left_row;
    int left_has = 0;
    cdb_status st;
    int64_t t_left;
    size_t i, best_idx = 0;
    int has_best = 0;
    int64_t best_diff = 0x7FFFFFFFFFFFFFFFLL;

    *has_row = 0;

    if (!a->right_buffered && (st = asof_materialize_right(a, cur)) != CDB_OK)
        return st;

    st = a->left->vtab->next(a->left, cur, &left_row, &left_has);
    if (st != CDB_OK || !left_has)
        return st;

    /* Evaluate left time */
    asof_bind_ctx(cur, &left_row);
    t_left = left_row.timestamp;
    if (a->left_time_wire != NULL && a->left_time_len > 0) {
        cdb_value tv;
        size_t consumed = 0;
        if (cdb_eval_expr_wire(&cur->eval_ctx, a->left_time_wire, a->left_time_len, &tv, &consumed)
                == CDB_OK
            && tv.type == CDB_TYPE_INT)
            t_left = tv.as.i64;
    }

    /* Scan the materialized right buffer (no right-pipeline re-execution). */
    for (i = 0; i < a->right_n; i++) {
        cdb_exec_row *rr = a->right_rows[i];
        int64_t t_right = rr->timestamp;
        int64_t diff = t_left - t_right;
        int64_t adiff;
        int matched = 0;

        /* Backward as-of: right point must be <= left point */
        if (a->kind == 1 && diff < 0)
            continue;
        /* Forward as-of: right point must be >= left point */
        if (a->kind == 2 && diff > 0)
            continue;

        adiff = diff < 0 ? -diff : diff;
        if (a->tolerance_ns > 0 && (uint64_t)adiff > a->tolerance_ns)
            continue;

        if ((st = asof_match(a, cur, &left_row, rr, &matched)) != CDB_OK)
            return st;
        if (!matched)
            continue;

        if (!has_best || adiff < best_diff) {
            has_best = 1;
            best_diff = adiff;
            best_idx = i;
        }
    }

    *out_row = left_row;
    if (has_best) {
        cdb_exec_row *rr = a->right_rows[best_idx];
        out_row->has_right = 1;
        out_row->right_store_id = rr->store_id;
        out_row->right_entry_id = rr->entry_id;
        out_row->right_model = rr->model;
        out_row->right_record_data = rr->record_data;
        out_row->right_record_len = rr->record_len;
        for (i = 0; i < rr->n_fields && out_row->n_fields < CDB_EXEC_MAX_FIELDS; i++)
            out_row->fields[out_row->n_fields++] = rr->fields[i];
    }

    *has_row = 1;
    return CDB_OK;
}

static const cdb_exec_vtab asof_vtab = {asof_open, asof_next, asof_reset, asof_close};

/* --------------------------------------------------------------------------
 * Operator 0x0F: UNNEST
 * -------------------------------------------------------------------------- */
typedef struct cdb_exec_unnest {
    cdb_exec_op base;
    cdb_exec_op *input;
    const char *item_alias;
    size_t item_alias_len;
    const char *index_alias;
    size_t index_alias_len;
    const uint8_t *array_wire;
    size_t array_len;

    cdb_exec_row cur_parent;
    int has_parent;
    cdb_value cur_array;
    size_t cur_elem_idx;
} cdb_exec_unnest;

static cdb_status unnest_open(cdb_exec_op *op, cdb_exec_cursor *cur)
{
    cdb_exec_unnest *u = (cdb_exec_unnest *)op;
    u->has_parent = 0;
    u->cur_elem_idx = 0;
    return u->input->vtab->open(u->input, cur);
}

static cdb_status unnest_reset(cdb_exec_op *op, cdb_exec_cursor *cur)
{
    cdb_exec_unnest *u = (cdb_exec_unnest *)op;
    u->has_parent = 0;
    u->cur_elem_idx = 0;
    return u->input->vtab->reset(u->input, cur);
}

static void unnest_close(cdb_exec_op *op, cdb_exec_cursor *cur)
{
    cdb_exec_unnest *u = (cdb_exec_unnest *)op;
    u->input->vtab->close(u->input, cur);
}

static cdb_status unnest_next(cdb_exec_op *op, cdb_exec_cursor *cur, cdb_exec_row *out_row,
                              int *has_row)
{
    cdb_exec_unnest *u = (cdb_exec_unnest *)op;
    cdb_status st;
    size_t consumed = 0;

    *has_row = 0;

    while (1) {
        if (!u->has_parent) {
            st = u->input->vtab->next(u->input, cur, &u->cur_parent, &u->has_parent);
            if (st != CDB_OK || !u->has_parent)
                return st;

            /* Eval array expression */
            cur->eval_ctx.entry_id = u->cur_parent.entry_id;
            cur->eval_ctx.score = (double)u->cur_parent.score;
            cur->eval_ctx.timestamp = u->cur_parent.timestamp;
            cur->eval_ctx.record_data = u->cur_parent.record_data;
            cur->eval_ctx.record_len = u->cur_parent.record_len;
            cur->eval_ctx.store_id = u->cur_parent.store_id;
            cdb_eval_ctx_set_custom_resolver(&cur->eval_ctx, row_field_resolver,
                                             (void *)&u->cur_parent);

            st = cdb_eval_expr_wire(&cur->eval_ctx, u->array_wire, u->array_len, &u->cur_array,
                                    &consumed);
            if (st != CDB_OK)
                return st;

            u->cur_elem_idx = 0;
        }

        /* If value is an array, iterate through its elements */
        if (u->cur_array.type == CDB_TYPE_ARRAY && u->cur_elem_idx < u->cur_array.as.array.count) {
            cdb_value_iter iter;
            cdb_value elem;
            int done = 0;
            size_t k;

            if (cdb_value_array_iter(&u->cur_array, cur->order, &iter) != CDB_OK) {
                u->has_parent = 0;
                continue;
            }

            for (k = 0; k <= u->cur_elem_idx; k++) {
                if (cdb_value_array_next(&iter, &elem, &done) != CDB_OK || done)
                    break;
            }

            if (done) {
                u->has_parent = 0;
                continue;
            }

            *out_row = u->cur_parent;

            /* Attach item alias */
            if (out_row->n_fields < CDB_EXEC_MAX_FIELDS) {
                out_row->fields[out_row->n_fields].name = u->item_alias;
                out_row->fields[out_row->n_fields].name_len = u->item_alias_len;
                out_row->fields[out_row->n_fields].val = elem;
                out_row->n_fields++;
            }

            /* Attach optional index alias */
            if (u->index_alias_len > 0 && out_row->n_fields < CDB_EXEC_MAX_FIELDS) {
                out_row->fields[out_row->n_fields].name = u->index_alias;
                out_row->fields[out_row->n_fields].name_len = u->index_alias_len;
                cdb_eval_make_int(&out_row->fields[out_row->n_fields].val,
                                  (int64_t)u->cur_elem_idx);
                out_row->n_fields++;
            }

            u->cur_elem_idx++;
            *has_row = 1;
            return CDB_OK;
        }

        /* Done with this parent row */
        u->has_parent = 0;
    }
}

static const cdb_exec_vtab unnest_vtab = {unnest_open, unnest_next, unnest_reset, unnest_close};

/* --------------------------------------------------------------------------
 * Shared helpers for the multi-model search / graph source operators
 * (TEXT_SEARCH, VECTOR_SEARCH, TRAVERSE). These drive the per-model engines
 * over the store resolved by the child Scan (spec 8.10, 6.4, 7).
 * -------------------------------------------------------------------------- */

/* The store ID resolved by the child Scan beneath op's input chain, or 0 when
 * there is no live store (a mock scan, or no database). Descends the single
 * input of the row-preserving wrappers; a Scan resolves its ID in scan_open,
 * which the operator's open has already run. */
static uint64_t exec_input_store_id(cdb_exec_op *op)
{
    while (op != NULL) {
        switch (op->tag) {
        case CDB_QUERY_NODE_SCAN: return ((cdb_exec_scan *)op)->store_id;
        case CDB_QUERY_NODE_FILTER: op = ((cdb_exec_filter *)op)->input; break;
        case CDB_QUERY_NODE_PROJECT: op = ((cdb_exec_project *)op)->input; break;
        case CDB_QUERY_NODE_LIMIT: op = ((cdb_exec_limit *)op)->input; break;
        case CDB_QUERY_NODE_SORT: op = ((cdb_exec_sort *)op)->input; break;
        default: return 0;
        }
    }
    return 0;
}

/* The catalog model of a resolved store, or 0 (CDB_MODEL_* is never 0 for a
 * real store). Read under the cursor's held lock. */
static uint32_t exec_store_model(cdb_exec_cursor *cur, uint64_t store_id)
{
    cdb_store_info info;
    if (cur->cat == NULL || store_id == 0)
        return 0;
    if (cdb_catalog_get_store(cur->cat, store_id, &info) != CDB_OK)
        return 0;
    return info.model;
}

/* Parses the near-vector expression (an EXPR_LITERAL holding an encoded vector
 * value, spec 14.6) into a bounded (value, len) the vector engine can search
 * with. near_wire..near_wire+near_len is the untrusted wire slice; only a
 * literal is accepted (fail closed on any other expression). CWE-125/787:
 * the length is taken from the literal header and bound-checked against the
 * slice, never read past it. */
static cdb_status exec_parse_near(const uint8_t *near_wire, size_t near_len, const uint8_t **val,
                                  size_t *val_len)
{
    uint64_t lit_len = 0;
    size_t vn = 0;
    const uint8_t *p = near_wire;
    const uint8_t *end;

    *val = NULL;
    *val_len = 0;
    if (near_wire == NULL || near_len < 1)
        return CDB_E_INVALID_ARG;
    end = near_wire + near_len;
    if (*p != CDB_QUERY_EXPR_LITERAL)
        return CDB_E_UNSUPPORTED;
    p++;
    if (cdb_varint_decode(p, (size_t)(end - p), &lit_len, &vn) != CDB_OK)
        return CDB_E_MALFORMED;
    p += vn;
    if (lit_len > (uint64_t)(end - p))
        return CDB_E_MALFORMED;
    *val = p;
    *val_len = (size_t)lit_len;
    return CDB_OK;
}

/* --------------------------------------------------------------------------
 * Operator 0x09: TRAVERSE — a bounded breadth-first walk of the link store
 * (cdb_link_list) from each input seed, honouring direction and max_hops,
 * with a global visited set for cycle termination (CWE-674) and shortest
 * (first-reached) $depth per node.
 * -------------------------------------------------------------------------- */

/* One discovered node: doubles as the visited set and the BFS queue. */
typedef struct cdb_exec_bfs_node {
    uint64_t store;
    uint64_t entry;
    uint64_t depth;
} cdb_exec_bfs_node;

typedef struct cdb_exec_traverse {
    cdb_exec_op base;
    cdb_exec_op *input;
    const char *link_type;
    size_t link_type_len;
    uint8_t dir; /* 1=Fwd, 2=Rev, 3=Both */
    uint64_t min_hops;
    uint64_t max_hops;

    cdb_exec_bfs_node *nodes; /* visited set + queue, from the cursor arena */
    size_t cap;               /* nodes capacity */
    size_t n_nodes;           /* discovered so far */
    size_t emit_idx;          /* streaming cursor over nodes[] */
    int built;                /* BFS completed */
} cdb_exec_traverse;

static cdb_status traverse_open(cdb_exec_op *op, cdb_exec_cursor *cur)
{
    cdb_exec_traverse *t = (cdb_exec_traverse *)op;
    t->nodes = NULL;
    t->cap = 0;
    t->n_nodes = 0;
    t->emit_idx = 0;
    t->built = 0;
    return t->input->vtab->open(t->input, cur);
}

static cdb_status traverse_reset(cdb_exec_op *op, cdb_exec_cursor *cur)
{
    cdb_exec_traverse *t = (cdb_exec_traverse *)op;
    t->n_nodes = 0;
    t->emit_idx = 0;
    t->built = 0;
    return t->input->vtab->reset(t->input, cur);
}

static void traverse_close(cdb_exec_op *op, cdb_exec_cursor *cur)
{
    cdb_exec_traverse *t = (cdb_exec_traverse *)op;
    t->input->vtab->close(t->input, cur);
}

/* Whether (store, entry) is already in the visited set. */
static int traverse_seen(const cdb_exec_traverse *t, uint64_t store, uint64_t entry)
{
    size_t i;
    for (i = 0; i < t->n_nodes; i++) {
        if (t->nodes[i].store == store && t->nodes[i].entry == entry)
            return 1;
    }
    return 0;
}

/* Appends an unseen node to the visited set / queue. CDB_E_OUT_OF_BUDGET when
 * the arena-backed set is full (bounds a huge or adversarial graph). */
static cdb_status traverse_discover(cdb_exec_traverse *t, uint64_t store, uint64_t entry,
                                    uint64_t depth)
{
    if (traverse_seen(t, store, entry))
        return CDB_OK;
    if (t->n_nodes >= t->cap)
        return CDB_E_OUT_OF_BUDGET;
    t->nodes[t->n_nodes].store = store;
    t->nodes[t->n_nodes].entry = entry;
    t->nodes[t->n_nodes].depth = depth;
    t->n_nodes++;
    return CDB_OK;
}

/* Expands one side (OUT or IN) of node, discovering each neighbour at depth+1.
 * Pages cdb_link_list; the neighbour is the far end of each link. */
static cdb_status traverse_expand_side(cdb_exec_traverse *t, cdb_exec_cursor *cur, uint64_t store,
                                       uint64_t entry, uint64_t depth, uint64_t type, int direction)
{
    cdb_link page[16];
    const cdb_link *after = NULL;
    cdb_ref self = cdb_ref_entry(store, entry);
    size_t got = 0;

    do {
        size_t i;
        cdb_status st = cdb_link_list(cur->db, self, direction, type, after, page,
                                      sizeof page / sizeof page[0], &got);
        if (st != CDB_OK)
            return st;
        for (i = 0; i < got; i++) {
            const cdb_ref *far = (direction == CDB_LINK_OUT) ? &page[i].target : &page[i].source;
            st = traverse_discover(t, far->store, far->entry, depth + 1);
            if (st != CDB_OK)
                return st;
        }
        if (got > 0)
            after = &page[got - 1];
    } while (got == sizeof page / sizeof page[0]);
    return CDB_OK;
}

/* Drains the input seeds and runs the BFS once, into t->nodes. */
static cdb_status traverse_build(cdb_exec_traverse *t, cdb_exec_cursor *cur)
{
    uint64_t type = 0;
    size_t head;
    cdb_status st;
    size_t avail;

    avail = (cur->arena.cap > cur->arena.used) ? (cur->arena.cap - cur->arena.used) : 0;
    t->cap = avail / sizeof(cdb_exec_bfs_node);
    if (t->cap > cur->max_buffered_rows)
        t->cap = cur->max_buffered_rows;
    if (t->cap < 1)
        return CDB_E_OUT_OF_BUDGET;
    t->nodes = (cdb_exec_bfs_node *)cdb_exec_arena_alloc(
        &cur->arena, sizeof(cdb_exec_bfs_node) * t->cap, sizeof(void *));
    if (t->nodes == NULL)
        return CDB_E_OUT_OF_BUDGET;

    /* A named link type that does not exist yields no edges (not an error):
     * only the seeds within [min_hops, max_hops] are reachable. type 0 walks
     * every type. */
    if (cur->db != NULL && t->link_type_len > 0) {
        int found = 0;
        st = cdb_link_find_type(cur->db, t->link_type, t->link_type_len, &type, &found);
        if (st != CDB_OK)
            return st;
        if (!found)
            type = 0, t->link_type_len = 0; /* no such type: seeds only */
    }

    /* Seed the frontier at depth 0 from the input stream. */
    for (;;) {
        cdb_exec_row seed;
        int has = 0;
        st = t->input->vtab->next(t->input, cur, &seed, &has);
        if (st != CDB_OK)
            return st;
        if (!has)
            break;
        st = traverse_discover(t, seed.store_id, seed.entry_id, 0);
        if (st != CDB_OK)
            return st;
    }

    /* BFS: expand each node whose depth is below max_hops. nodes[] grows as
     * neighbours are discovered; the visited check in traverse_discover makes
     * a cycle terminate. No expansion when there is no live link store. */
    for (head = 0; head < t->n_nodes; head++) {
        uint64_t store = t->nodes[head].store;
        uint64_t entry = t->nodes[head].entry;
        uint64_t depth = t->nodes[head].depth;
        if (cur->db == NULL || depth >= t->max_hops)
            continue;
        if (t->dir == CDB_TRAVERSE_FWD || t->dir == CDB_TRAVERSE_BOTH) {
            st = traverse_expand_side(t, cur, store, entry, depth, type, CDB_LINK_OUT);
            if (st != CDB_OK)
                return st;
        }
        if (t->dir == CDB_TRAVERSE_REV || t->dir == CDB_TRAVERSE_BOTH) {
            st = traverse_expand_side(t, cur, store, entry, depth, type, CDB_LINK_IN);
            if (st != CDB_OK)
                return st;
        }
    }
    t->built = 1;
    return CDB_OK;
}

static cdb_status traverse_next(cdb_exec_op *op, cdb_exec_cursor *cur, cdb_exec_row *out_row,
                                int *has_row)
{
    cdb_exec_traverse *t = (cdb_exec_traverse *)op;
    cdb_status st;

    *has_row = 0;
    if (!t->built) {
        st = traverse_build(t, cur);
        if (st != CDB_OK)
            return st;
    }

    /* Emit the reached nodes within the hop window, each at its shortest
     * (first-reached) depth. */
    while (t->emit_idx < t->n_nodes) {
        cdb_exec_bfs_node *node = &t->nodes[t->emit_idx++];
        if (node->depth < t->min_hops || node->depth > t->max_hops)
            continue;
        memset(out_row, 0, sizeof(*out_row));
        out_row->store_id = node->store;
        out_row->entry_id = node->entry;
        out_row->model = exec_store_model(cur, node->store);
        out_row->fields[0].name = "$depth";
        out_row->fields[0].name_len = 6;
        cdb_eval_make_int(&out_row->fields[0].val, (int64_t)node->depth);
        out_row->n_fields = 1;
        *has_row = 1;
        return CDB_OK;
    }
    return CDB_OK;
}

static const cdb_exec_vtab traverse_vtab = {traverse_open, traverse_next, traverse_reset,
                                            traverse_close};

/* --------------------------------------------------------------------------
 * Operator 0x0A: TEXT_SEARCH
 * -------------------------------------------------------------------------- */
typedef struct cdb_exec_text_search {
    cdb_exec_op base;
    cdb_exec_op *input;
    uint8_t mode;
    uint64_t limit;
    const char *query;
    size_t query_len;

    cdb_fts_hit *hits; /* ranked hits, from the cursor arena */
    size_t n_hits;
    size_t idx;      /* streaming cursor over hits[] */
    uint64_t store;  /* store resolved by the child Scan */
    int built;       /* BM25 search completed */
    int passthrough; /* no live store: forward input rows (mock path) */
    size_t yielded;  /* rows emitted (passthrough limit) */
} cdb_exec_text_search;

static cdb_status text_search_open(cdb_exec_op *op, cdb_exec_cursor *cur)
{
    cdb_exec_text_search *ts = (cdb_exec_text_search *)op;
    ts->hits = NULL;
    ts->n_hits = 0;
    ts->idx = 0;
    ts->store = 0;
    ts->built = 0;
    ts->passthrough = 0;
    ts->yielded = 0;
    return ts->input->vtab->open(ts->input, cur);
}

static cdb_status text_search_reset(cdb_exec_op *op, cdb_exec_cursor *cur)
{
    cdb_exec_text_search *ts = (cdb_exec_text_search *)op;
    ts->idx = 0;
    ts->built = 0;
    ts->passthrough = 0;
    ts->yielded = 0;
    return ts->input->vtab->reset(ts->input, cur);
}

static void text_search_close(cdb_exec_op *op, cdb_exec_cursor *cur)
{
    cdb_exec_text_search *ts = (cdb_exec_text_search *)op;
    ts->input->vtab->close(ts->input, cur);
}

/* Runs the BM25 search once over the resolved store (spec 8.10, 14.14), into
 * an arena cdb_fts_hit[]. A positive limit caps the search to its top-N; limit
 * 0 is unbounded (bounded here by the arena / max_buffered_rows). With no live
 * store (mock scan), falls back to forwarding input rows. */
static cdb_status text_search_build(cdb_exec_text_search *ts, cdb_exec_cursor *cur)
{
    size_t avail, cap, want;
    int mode;
    cdb_status st;

    ts->store = exec_input_store_id(ts->input);
    if (cur->db == NULL || ts->store == 0) {
        ts->passthrough = 1;
        ts->built = 1;
        return CDB_OK;
    }

    avail = (cur->arena.cap > cur->arena.used) ? (cur->arena.cap - cur->arena.used) : 0;
    cap = avail / sizeof(cdb_fts_hit);
    if (cap > cur->max_buffered_rows)
        cap = cur->max_buffered_rows;
    if (cap < 1)
        return CDB_E_OUT_OF_BUDGET;
    want = (ts->limit > 0 && ts->limit < (uint64_t)cap) ? (size_t)ts->limit : cap;

    ts->hits = (cdb_fts_hit *)cdb_exec_arena_alloc(&cur->arena, sizeof(cdb_fts_hit) * want,
                                                   sizeof(void *));
    if (ts->hits == NULL)
        return CDB_E_OUT_OF_BUDGET;

    mode = (ts->mode == CDB_QUERY_FTS_ALL) ? CDB_FTS_ALL : CDB_FTS_ANY;
    st = cdb_doc_search(cur->db, ts->store, ts->query, ts->query_len, mode, ts->hits, want,
                        &ts->n_hits);
    if (st != CDB_OK)
        return st;
    ts->built = 1;
    return CDB_OK;
}

static cdb_status text_search_next(cdb_exec_op *op, cdb_exec_cursor *cur, cdb_exec_row *out_row,
                                   int *has_row)
{
    cdb_exec_text_search *ts = (cdb_exec_text_search *)op;
    cdb_status st;

    *has_row = 0;
    if (!ts->built) {
        st = text_search_build(ts, cur);
        if (st != CDB_OK)
            return st;
    }

    if (ts->passthrough) {
        if (ts->limit > 0 && ts->yielded >= ts->limit)
            return CDB_OK;
        st = ts->input->vtab->next(ts->input, cur, out_row, has_row);
        if (st != CDB_OK || !*has_row)
            return st;
        ts->yielded++;
        return CDB_OK;
    }

    if (ts->idx < ts->n_hits) {
        const cdb_fts_hit *h = &ts->hits[ts->idx++];
        memset(out_row, 0, sizeof(*out_row));
        out_row->store_id = ts->store;
        out_row->entry_id = h->entry;
        out_row->model = exec_store_model(cur, ts->store);
        out_row->score = (float)h->score;
        *has_row = 1;
    }
    return CDB_OK;
}

static const cdb_exec_vtab text_search_vtab = {text_search_open, text_search_next,
                                               text_search_reset, text_search_close};

/* --------------------------------------------------------------------------
 * Operator 0x0B: VECTOR_SEARCH
 * -------------------------------------------------------------------------- */
typedef struct cdb_exec_vec_search {
    cdb_exec_op base;
    cdb_exec_op *input;
    const char *field;
    size_t field_len;
    uint64_t k;
    uint8_t metric;
    const uint8_t *near_wire;
    size_t near_len;

    cdb_vec_hit *hits; /* nearest hits, from the cursor arena */
    size_t n_hits;
    size_t idx;      /* streaming cursor over hits[] */
    uint64_t store;  /* store resolved by the child Scan */
    int built;       /* ANN search completed */
    int passthrough; /* no live store: forward input rows (mock path) */
    size_t yielded;  /* rows emitted (passthrough k cap) */
} cdb_exec_vec_search;

/* Maps the query metric override (spec 11.5) to the vector measure (spec 6.4). */
static unsigned vec_measure_of(uint8_t metric)
{
    switch (metric) {
    case CDB_QUERY_METRIC_EUCLIDEAN: return CDB_VEC_EUCLIDEAN;
    case CDB_QUERY_METRIC_COSINE: return CDB_VEC_COSINE;
    case CDB_QUERY_METRIC_DOT: return CDB_VEC_DOT;
    default: return CDB_VEC_BASE; /* DEFAULT: the collection's base measure */
    }
}

static cdb_status vec_search_open(cdb_exec_op *op, cdb_exec_cursor *cur)
{
    cdb_exec_vec_search *vs = (cdb_exec_vec_search *)op;
    vs->hits = NULL;
    vs->n_hits = 0;
    vs->idx = 0;
    vs->store = 0;
    vs->built = 0;
    vs->passthrough = 0;
    vs->yielded = 0;
    return vs->input->vtab->open(vs->input, cur);
}

static cdb_status vec_search_reset(cdb_exec_op *op, cdb_exec_cursor *cur)
{
    cdb_exec_vec_search *vs = (cdb_exec_vec_search *)op;
    vs->idx = 0;
    vs->built = 0;
    vs->passthrough = 0;
    vs->yielded = 0;
    return vs->input->vtab->reset(vs->input, cur);
}

static void vec_search_close(cdb_exec_op *op, cdb_exec_cursor *cur)
{
    cdb_exec_vec_search *vs = (cdb_exec_vec_search *)op;
    vs->input->vtab->close(vs->input, cur);
}

/* Runs the ANN search once over the resolved collection (spec 6.4), ranking by
 * the chosen metric, into an arena cdb_vec_hit[]. The query vector comes from
 * the bounded-decoded near literal. k 0 is unbounded (bounded here by the
 * arena / max_buffered_rows and CDB_VEC_MAX_K); k greater than the collection
 * returns all available. With no live store (mock scan), forwards input rows. */
static cdb_status vec_search_build(cdb_exec_vec_search *vs, cdb_exec_cursor *cur)
{
    size_t avail, cap, want;
    const uint8_t *qval = NULL;
    size_t qlen = 0;
    cdb_status st;

    vs->store = exec_input_store_id(vs->input);
    if (cur->db == NULL || vs->store == 0) {
        vs->passthrough = 1;
        vs->built = 1;
        return CDB_OK;
    }

    st = exec_parse_near(vs->near_wire, vs->near_len, &qval, &qlen);
    if (st != CDB_OK)
        return st;

    avail = (cur->arena.cap > cur->arena.used) ? (cur->arena.cap - cur->arena.used) : 0;
    cap = avail / sizeof(cdb_vec_hit);
    if (cap > cur->max_buffered_rows)
        cap = cur->max_buffered_rows;
    if (cap > CDB_VEC_MAX_K)
        cap = CDB_VEC_MAX_K;
    if (cap < 1)
        return CDB_E_OUT_OF_BUDGET;
    want = (vs->k > 0 && vs->k < (uint64_t)cap) ? (size_t)vs->k : cap;

    vs->hits = (cdb_vec_hit *)cdb_exec_arena_alloc(&cur->arena, sizeof(cdb_vec_hit) * want,
                                                   sizeof(void *));
    if (vs->hits == NULL)
        return CDB_E_OUT_OF_BUDGET;

    st = cdb_vec_search_mode(cur->db, vs->store, qval, qlen, vec_measure_of(vs->metric),
                             CDB_VEC_AUTO, vs->hits, want, &vs->n_hits);
    if (st != CDB_OK)
        return st;
    vs->built = 1;
    return CDB_OK;
}

static cdb_status vec_search_next(cdb_exec_op *op, cdb_exec_cursor *cur, cdb_exec_row *out_row,
                                  int *has_row)
{
    cdb_exec_vec_search *vs = (cdb_exec_vec_search *)op;
    cdb_status st;

    *has_row = 0;
    if (!vs->built) {
        st = vec_search_build(vs, cur);
        if (st != CDB_OK)
            return st;
    }

    if (vs->passthrough) {
        if (vs->k > 0 && vs->yielded >= vs->k)
            return CDB_OK;
        st = vs->input->vtab->next(vs->input, cur, out_row, has_row);
        if (st != CDB_OK || !*has_row)
            return st;
        vs->yielded++;
        return CDB_OK;
    }

    if (vs->idx < vs->n_hits) {
        const cdb_vec_hit *h = &vs->hits[vs->idx++];
        memset(out_row, 0, sizeof(*out_row));
        out_row->store_id = vs->store;
        out_row->entry_id = h->entry;
        out_row->model = exec_store_model(cur, vs->store);
        out_row->score = (float)h->distance;
        *has_row = 1;
    }
    return CDB_OK;
}

static const cdb_exec_vtab vec_search_vtab = {vec_search_open, vec_search_next, vec_search_reset,
                                              vec_search_close};

/* --------------------------------------------------------------------------
 * Operator 0x0C: HYBRID_RANK
 * -------------------------------------------------------------------------- */
typedef struct cdb_exec_hybrid {
    cdb_exec_op base;
    uint8_t fuse; /* 1 = RRF */
    size_t count;
    cdb_exec_op *branches[CDB_EXEC_MAX_BRANCHES];
    uint32_t weights[CDB_EXEC_MAX_BRANCHES];

    cdb_exec_row *fused_buf;
    size_t n_fused;
    size_t max_rows;
    size_t cur_idx;
    int is_buffered;
} cdb_exec_hybrid;

static cdb_status hybrid_open(cdb_exec_op *op, cdb_exec_cursor *cur)
{
    cdb_exec_hybrid *h = (cdb_exec_hybrid *)op;
    size_t row_size = sizeof(cdb_exec_row);
    size_t avail = (cur->arena.cap > cur->arena.used) ? (cur->arena.cap - cur->arena.used) : 0;
    size_t max_rows = avail / row_size;
    size_t b;

    if (max_rows > cur->max_buffered_rows)
        max_rows = cur->max_buffered_rows;
    if (max_rows < 1)
        return CDB_E_OUT_OF_BUDGET;

    h->n_fused = 0;
    h->cur_idx = 0;
    h->is_buffered = 0;
    h->max_rows = max_rows;
    h->fused_buf =
        (cdb_exec_row *)cdb_exec_arena_alloc(&cur->arena, row_size * max_rows, sizeof(void *));
    if (h->fused_buf == NULL)
        return CDB_E_OUT_OF_BUDGET;

    for (b = 0; b < h->count; b++) {
        cdb_status st = h->branches[b]->vtab->open(h->branches[b], cur);
        if (st != CDB_OK)
            return st;
    }
    return CDB_OK;
}

static cdb_status hybrid_reset(cdb_exec_op *op, cdb_exec_cursor *cur)
{
    cdb_exec_hybrid *h = (cdb_exec_hybrid *)op;
    (void)cur;
    h->cur_idx = 0;
    return CDB_OK;
}

static void hybrid_close(cdb_exec_op *op, cdb_exec_cursor *cur)
{
    cdb_exec_hybrid *h = (cdb_exec_hybrid *)op;
    size_t b;
    for (b = 0; b < h->count; b++) {
        h->branches[b]->vtab->close(h->branches[b], cur);
    }
}

static cdb_status hybrid_next(cdb_exec_op *op, cdb_exec_cursor *cur, cdb_exec_row *out_row,
                              int *has_row)
{
    cdb_exec_hybrid *h = (cdb_exec_hybrid *)op;
    size_t b;

    *has_row = 0;

    if (!h->is_buffered) {
        for (b = 0; b < h->count; b++) {
            cdb_exec_row item;
            int in_has = 0;
            uint32_t rank = 0;
            float weight = (float)h->weights[b] / 1000.0f;
            if (weight <= 0.0f)
                weight = 1.0f;

            while (1) {
                size_t c;
                int found = 0;
                cdb_status st = h->branches[b]->vtab->next(h->branches[b], cur, &item, &in_has);
                if (st != CDB_OK)
                    return st;
                if (!in_has)
                    break;

                rank++;

                /* Check if entry_id already present */
                for (c = 0; c < h->n_fused; c++) {
                    if (h->fused_buf[c].entry_id == item.entry_id
                        && h->fused_buf[c].store_id == item.store_id) {
                        /* Add RRF score: weight / (60 + rank) */
                        h->fused_buf[c].score += weight / (60.0f + (float)rank);
                        found = 1;
                        break;
                    }
                }

                if (!found) {
                    if (h->n_fused >= h->max_rows)
                        return CDB_E_OUT_OF_BUDGET;
                    item.score = weight / (60.0f + (float)rank);
                    h->fused_buf[h->n_fused++] = item;
                }
            }
        }

        /* Sort fused candidates by score descending */
        if (h->n_fused > 1) {
            size_t i, j;
            for (i = 1; i < h->n_fused; i++) {
                cdb_exec_row key = h->fused_buf[i];
                j = i;
                while (j > 0 && h->fused_buf[j - 1].score < key.score) {
                    h->fused_buf[j] = h->fused_buf[j - 1];
                    j--;
                }
                h->fused_buf[j] = key;
            }
        }

        h->is_buffered = 1;
        h->cur_idx = 0;
    }

    if (h->cur_idx < h->n_fused) {
        *out_row = h->fused_buf[h->cur_idx++];
        *has_row = 1;
        return CDB_OK;
    }

    return CDB_OK;
}

static const cdb_exec_vtab hybrid_vtab = {hybrid_open, hybrid_next, hybrid_reset, hybrid_close};

/* --------------------------------------------------------------------------
 * Recursive Plan Tree Builder
 * -------------------------------------------------------------------------- */
/* Depth-bounded exec-tree builder (CWE-674). This is the second recursive
 * descent over the wire, run after cdb_query_validate; `depth` bounds it as
 * defense in depth. `depth` is a size_t only ever reached via `depth + 1` on the
 * `depth < CDB_QUERY_MAX_DEPTH` branch, so it never exceeds the cap and cannot
 * overflow (rule_0024 / CWE-190). */
static cdb_status build_exec_tree(cdb_exec_cursor *cur, const uint8_t **p, const uint8_t *end,
                                  cdb_exec_op **out_op, size_t depth)
{
    cdb_query_node node;
    cdb_status st;
    const uint8_t *node_start = *p;

    if (depth >= CDB_QUERY_MAX_DEPTH)
        return CDB_E_DEPTH;
    if (cur == NULL || p == NULL || *p >= end || out_op == NULL)
        return CDB_E_INVALID_ARG;

    st = cdb_query_read_node(p, end, &node);
    if (st != CDB_OK)
        return st;

    switch (node.tag) {
    case CDB_QUERY_NODE_SCAN: {
        cdb_exec_scan *op = (cdb_exec_scan *)cdb_exec_arena_alloc(
            &cur->arena, sizeof(cdb_exec_scan), sizeof(void *));
        if (op == NULL)
            return CDB_E_OUT_OF_BUDGET;
        op->base.vtab = &scan_vtab;
        op->base.tag = CDB_QUERY_NODE_SCAN;
        op->store_name = node.as.scan.name;
        op->store_name_len = node.as.scan.name_len;
        /* Taken here, before any pipeline breaker above it claims the rest
         * of the arena when it opens. A larger record fails the scan with
         * CDB_E_BUFFER_TOO_SMALL rather than being cut short. */
        if (cur->db != NULL) {
            op->rec_cap = CDB_EXEC_SCAN_RECORD_PAGES * cur->db->pager.page_size;
            op->rec_buf = (uint8_t *)cdb_exec_arena_alloc(&cur->arena, op->rec_cap, sizeof(void *));
            if (op->rec_buf == NULL)
                return CDB_E_OUT_OF_BUDGET;
            /* Time-series / link enumeration cursor (#52), kept off the budget
             * of the other models by living here, not inline on the op. */
            op->mc = (cdb_scan_model_cursor *)cdb_exec_arena_alloc(
                &cur->arena, sizeof(cdb_scan_model_cursor), sizeof(void *));
            if (op->mc == NULL)
                return CDB_E_OUT_OF_BUDGET;
        }
        *out_op = &op->base;
        return CDB_OK;
    }

    case CDB_QUERY_NODE_FILTER: {
        cdb_exec_filter *op = (cdb_exec_filter *)cdb_exec_arena_alloc(
            &cur->arena, sizeof(cdb_exec_filter), sizeof(void *));
        if (op == NULL)
            return CDB_E_OUT_OF_BUDGET;
        op->base.vtab = &filter_vtab;
        op->base.tag = CDB_QUERY_NODE_FILTER;
        op->pred_wire = node.as.filter.pred_wire;
        op->pred_len = (size_t)(end - node.as.filter.pred_wire);
        st = build_exec_tree(cur, &node.as.filter.input_wire, end, &op->input, depth + 1);
        if (st != CDB_OK)
            return st;
        *out_op = &op->base;
        return CDB_OK;
    }

    case CDB_QUERY_NODE_PROJECT: {
        size_t i;
        const uint8_t *cur_wire;
        cdb_exec_project *op = (cdb_exec_project *)cdb_exec_arena_alloc(
            &cur->arena, sizeof(cdb_exec_project), sizeof(void *));
        if (op == NULL)
            return CDB_E_OUT_OF_BUDGET;
        op->base.vtab = &project_vtab;
        op->base.tag = CDB_QUERY_NODE_PROJECT;
        op->passthrough = (uint8_t)node.as.project.passthrough;
        op->count = node.as.project.count;
        /* More output columns than a row can hold is a fail-closed error, not
         * a silent truncation of the plan's outputs (#36 FR5). */
        if (op->count > CDB_EXEC_MAX_FIELDS)
            return CDB_E_OVERFLOW;
        st = build_exec_tree(cur, &node.as.project.input_wire, end, &op->input, depth + 1);
        if (st != CDB_OK)
            return st;

        cur_wire = node.as.project.outputs_wire;
        for (i = 0; i < op->count && i < CDB_EXEC_MAX_FIELDS; i++) {
            uint64_t alen = 0;
            size_t vlen = 0;
            const uint8_t *expr_wire;
            if (cdb_varint_decode(cur_wire, (size_t)(end - cur_wire), &alen, &vlen) != CDB_OK)
                return CDB_E_MALFORMED;
            cur_wire += vlen;
            if (cur_wire + alen > end)
                return CDB_E_MALFORMED;
            op->cols[i].alias = (const char *)cur_wire;
            op->cols[i].alias_len = (size_t)alen;
            cur_wire += alen;
            expr_wire = cur_wire;
            st = cdb_query_skip_expr(&cur_wire, end);
            if (st != CDB_OK)
                return st;
            op->cols[i].expr_wire = expr_wire;
            op->cols[i].expr_len = (size_t)(cur_wire - expr_wire);
        }
        *out_op = &op->base;
        return CDB_OK;
    }

    case CDB_QUERY_NODE_LIMIT: {
        cdb_exec_limit *op = (cdb_exec_limit *)cdb_exec_arena_alloc(
            &cur->arena, sizeof(cdb_exec_limit), sizeof(void *));
        if (op == NULL)
            return CDB_E_OUT_OF_BUDGET;
        op->base.vtab = &limit_vtab;
        op->base.tag = CDB_QUERY_NODE_LIMIT;
        op->count = node.as.limit.count;
        op->offset = node.as.limit.offset;
        st = build_exec_tree(cur, &node.as.limit.input_wire, end, &op->input, depth + 1);
        if (st != CDB_OK)
            return st;
        /* A Sort below (through Projects, which keep every row) need only
         * hold the rows this Limit can reach: top-N */
        if (op->count > 0 && op->offset <= UINT64_MAX - op->count) {
            cdb_exec_op *below = op->input;
            while (below->tag == CDB_QUERY_NODE_PROJECT)
                below = ((cdb_exec_project *)below)->input;
            if (below->tag == CDB_QUERY_NODE_SORT)
                ((cdb_exec_sort *)below)->keep = op->offset + op->count;
        }
        *out_op = &op->base;
        return CDB_OK;
    }

    case CDB_QUERY_NODE_UNION: {
        size_t i;
        const uint8_t *cur_wire;
        cdb_exec_union *op = (cdb_exec_union *)cdb_exec_arena_alloc(
            &cur->arena, sizeof(cdb_exec_union), sizeof(void *));
        if (op == NULL)
            return CDB_E_OUT_OF_BUDGET;
        op->base.vtab = &union_vtab;
        op->base.tag = CDB_QUERY_NODE_UNION;
        op->count = node.as.union_node.count;

        cur_wire = node.as.union_node.branches_wire;
        for (i = 0; i < op->count && i < CDB_EXEC_MAX_BRANCHES; i++) {
            st = build_exec_tree(cur, &cur_wire, end, &op->branches[i], depth + 1);
            if (st != CDB_OK)
                return st;
        }
        *out_op = &op->base;
        return CDB_OK;
    }

    case CDB_QUERY_NODE_JOIN: {
        cdb_exec_join *op = (cdb_exec_join *)cdb_exec_arena_alloc(
            &cur->arena, sizeof(cdb_exec_join), sizeof(void *));
        if (op == NULL)
            return CDB_E_OUT_OF_BUDGET;
        op->base.vtab = &join_vtab;
        op->base.tag = CDB_QUERY_NODE_JOIN;
        op->kind = node.as.join.kind;
        op->cond_wire = node.as.join.cond_wire;
        op->cond_len = (size_t)(end - node.as.join.cond_wire);
        st = build_exec_tree(cur, &node.as.join.left_wire, end, &op->left, depth + 1);
        if (st != CDB_OK)
            return st;
        st = build_exec_tree(cur, &node.as.join.right_wire, end, &op->right, depth + 1);
        if (st != CDB_OK)
            return st;
        *out_op = &op->base;
        return CDB_OK;
    }

    case CDB_QUERY_NODE_SORT: {
        size_t i;
        const uint8_t *cur_wire;
        cdb_exec_sort *op = (cdb_exec_sort *)cdb_exec_arena_alloc(
            &cur->arena, sizeof(cdb_exec_sort), sizeof(void *));
        if (op == NULL)
            return CDB_E_OUT_OF_BUDGET;
        op->base.vtab = &sort_vtab;
        op->base.tag = CDB_QUERY_NODE_SORT;
        op->count = node.as.sort.count;
        st = build_exec_tree(cur, &node.as.sort.input_wire, end, &op->input, depth + 1);
        if (st != CDB_OK)
            return st;

        cur_wire = node.as.sort.keys_wire;
        for (i = 0; i < op->count && i < CDB_EXEC_MAX_SORT_KEYS; i++) {
            const uint8_t *k_start = cur_wire;
            st = cdb_query_skip_expr(&cur_wire, end);
            if (st != CDB_OK)
                return st;
            op->keys[i].expr_wire = k_start;
            op->keys[i].expr_len = (size_t)(cur_wire - k_start);
            if (cur_wire + 2 > end)
                return CDB_E_TRUNCATED;
            op->keys[i].dir = *cur_wire++;
            op->keys[i].nulls = *cur_wire++;
        }
        *out_op = &op->base;
        return CDB_OK;
    }

    case CDB_QUERY_NODE_AGGREGATE: {
        size_t i;
        const uint8_t *cur_wire;
        cdb_exec_aggregate *op = (cdb_exec_aggregate *)cdb_exec_arena_alloc(
            &cur->arena, sizeof(cdb_exec_aggregate), sizeof(void *));
        if (op == NULL)
            return CDB_E_OUT_OF_BUDGET;
        op->base.vtab = &aggregate_vtab;
        op->base.tag = CDB_QUERY_NODE_AGGREGATE;
        op->groups_count = node.as.aggregate.n_groups;
        op->aggs_count = node.as.aggregate.n_aggs;
        /* Fail closed rather than silently ignoring group keys / aggregates
         * beyond the fixed caps (#36 FR5). */
        if (op->groups_count > CDB_EXEC_MAX_GROUP_KEYS || op->aggs_count > CDB_EXEC_MAX_AGGS)
            return CDB_E_OVERFLOW;
        st = build_exec_tree(cur, &node.as.aggregate.input_wire, end, &op->input, depth + 1);
        if (st != CDB_OK)
            return st;

        cur_wire = node.as.aggregate.groups_wire;
        for (i = 0; i < op->groups_count && i < CDB_EXEC_MAX_GROUP_KEYS; i++) {
            const uint8_t *g_start = cur_wire;
            st = cdb_query_skip_expr(&cur_wire, end);
            if (st != CDB_OK)
                return st;
            op->group_wires[i] = g_start;
            op->group_lens[i] = (size_t)(cur_wire - g_start);
        }

        cur_wire = node.as.aggregate.aggs_wire;
        for (i = 0; i < op->aggs_count && i < CDB_EXEC_MAX_AGGS; i++) {
            uint64_t alen = 0;
            size_t vlen = 0;
            const uint8_t *arg_start;
            if (cdb_varint_decode(cur_wire, (size_t)(end - cur_wire), &alen, &vlen) != CDB_OK)
                return CDB_E_MALFORMED;
            cur_wire += vlen;
            if (cur_wire + alen > end)
                return CDB_E_MALFORMED;
            op->aggs[i].alias = (const char *)cur_wire;
            op->aggs[i].alias_len = (size_t)alen;
            cur_wire += alen;
            if (cur_wire >= end)
                return CDB_E_TRUNCATED;
            op->aggs[i].fn = *cur_wire++;
            arg_start = cur_wire;
            st = cdb_query_skip_expr(&cur_wire, end);
            if (st != CDB_OK)
                return st;
            op->aggs[i].arg_wire = arg_start;
            op->aggs[i].arg_len = (size_t)(cur_wire - arg_start);
        }
        *out_op = &op->base;
        return CDB_OK;
    }

    case CDB_QUERY_NODE_WINDOW: {
        cdb_exec_window *op = (cdb_exec_window *)cdb_exec_arena_alloc(
            &cur->arena, sizeof(cdb_exec_window), sizeof(void *));
        if (op == NULL)
            return CDB_E_OUT_OF_BUDGET;
        op->base.vtab = &window_vtab;
        op->base.tag = CDB_QUERY_NODE_WINDOW;
        op->type = node.as.window.type;
        op->time_field = node.as.window.time_field;
        op->time_field_len = node.as.window.time_field_len;
        op->size_ns = node.as.window.size_ns;
        op->step_ns = node.as.window.step_ns;
        st = build_exec_tree(cur, &node.as.window.input_wire, end, &op->input, depth + 1);
        if (st != CDB_OK)
            return st;
        *out_op = &op->base;
        return CDB_OK;
    }

    case CDB_QUERY_NODE_ASOF_JOIN: {
        cdb_exec_asof *op = (cdb_exec_asof *)cdb_exec_arena_alloc(
            &cur->arena, sizeof(cdb_exec_asof), sizeof(void *));
        if (op == NULL)
            return CDB_E_OUT_OF_BUDGET;
        op->base.vtab = &asof_vtab;
        op->base.tag = CDB_QUERY_NODE_ASOF_JOIN;
        op->kind = node.as.asof_join.kind;
        op->tolerance_ns = node.as.asof_join.tolerance_ns;
        op->left_time_wire = node.as.asof_join.left_time_wire;
        op->left_time_len = (size_t)(end - node.as.asof_join.left_time_wire);
        op->right_time_wire = node.as.asof_join.right_time_wire;
        op->right_time_len = (size_t)(end - node.as.asof_join.right_time_wire);
        op->match_cond_wire = node.as.asof_join.match_cond_wire;
        op->match_cond_len = (size_t)(end - node.as.asof_join.match_cond_wire);
        st = build_exec_tree(cur, &node.as.asof_join.left_wire, end, &op->left, depth + 1);
        if (st != CDB_OK)
            return st;
        st = build_exec_tree(cur, &node.as.asof_join.right_wire, end, &op->right, depth + 1);
        if (st != CDB_OK)
            return st;
        *out_op = &op->base;
        return CDB_OK;
    }

    case CDB_QUERY_NODE_UNNEST: {
        cdb_exec_unnest *op = (cdb_exec_unnest *)cdb_exec_arena_alloc(
            &cur->arena, sizeof(cdb_exec_unnest), sizeof(void *));
        if (op == NULL)
            return CDB_E_OUT_OF_BUDGET;
        op->base.vtab = &unnest_vtab;
        op->base.tag = CDB_QUERY_NODE_UNNEST;
        op->item_alias = node.as.unnest.item_alias;
        op->item_alias_len = node.as.unnest.item_alias_len;
        op->index_alias = node.as.unnest.index_alias;
        op->index_alias_len = node.as.unnest.index_alias_len;
        op->array_wire = node.as.unnest.array_expr_wire;
        op->array_len = (size_t)(end - node.as.unnest.array_expr_wire);
        st = build_exec_tree(cur, &node.as.unnest.input_wire, end, &op->input, depth + 1);
        if (st != CDB_OK)
            return st;
        *out_op = &op->base;
        return CDB_OK;
    }

    case CDB_QUERY_NODE_TRAVERSE: {
        cdb_exec_traverse *op = (cdb_exec_traverse *)cdb_exec_arena_alloc(
            &cur->arena, sizeof(cdb_exec_traverse), sizeof(void *));
        if (op == NULL)
            return CDB_E_OUT_OF_BUDGET;
        op->base.vtab = &traverse_vtab;
        op->base.tag = CDB_QUERY_NODE_TRAVERSE;
        op->link_type = node.as.traverse.link_type;
        op->link_type_len = node.as.traverse.link_type_len;
        op->dir = node.as.traverse.dir;
        op->min_hops = node.as.traverse.min_hops;
        op->max_hops = node.as.traverse.max_hops;
        st = build_exec_tree(cur, &node.as.traverse.input_wire, end, &op->input, depth + 1);
        if (st != CDB_OK)
            return st;
        *out_op = &op->base;
        return CDB_OK;
    }

    case CDB_QUERY_NODE_TEXT_SEARCH: {
        cdb_exec_text_search *op = (cdb_exec_text_search *)cdb_exec_arena_alloc(
            &cur->arena, sizeof(cdb_exec_text_search), sizeof(void *));
        if (op == NULL)
            return CDB_E_OUT_OF_BUDGET;
        op->base.vtab = &text_search_vtab;
        op->base.tag = CDB_QUERY_NODE_TEXT_SEARCH;
        op->mode = node.as.text_search.mode;
        op->limit = node.as.text_search.limit;
        op->query = node.as.text_search.query;
        op->query_len = node.as.text_search.query_len;
        st = build_exec_tree(cur, &node.as.text_search.input_wire, end, &op->input, depth + 1);
        if (st != CDB_OK)
            return st;
        *out_op = &op->base;
        return CDB_OK;
    }

    case CDB_QUERY_NODE_VECTOR_SEARCH: {
        cdb_exec_vec_search *op = (cdb_exec_vec_search *)cdb_exec_arena_alloc(
            &cur->arena, sizeof(cdb_exec_vec_search), sizeof(void *));
        if (op == NULL)
            return CDB_E_OUT_OF_BUDGET;
        op->base.vtab = &vec_search_vtab;
        op->base.tag = CDB_QUERY_NODE_VECTOR_SEARCH;
        op->field = node.as.vector_search.field;
        op->field_len = node.as.vector_search.field_len;
        op->k = node.as.vector_search.k;
        op->metric = node.as.vector_search.metric;
        op->near_wire = node.as.vector_search.near_wire;
        op->near_len = (size_t)(end - node.as.vector_search.near_wire);
        st = build_exec_tree(cur, &node.as.vector_search.input_wire, end, &op->input, depth + 1);
        if (st != CDB_OK)
            return st;
        *out_op = &op->base;
        return CDB_OK;
    }

    case CDB_QUERY_NODE_HYBRID_RANK: {
        size_t i;
        const uint8_t *cur_wire;
        cdb_exec_hybrid *op = (cdb_exec_hybrid *)cdb_exec_arena_alloc(
            &cur->arena, sizeof(cdb_exec_hybrid), sizeof(void *));
        if (op == NULL)
            return CDB_E_OUT_OF_BUDGET;
        op->base.vtab = &hybrid_vtab;
        op->base.tag = CDB_QUERY_NODE_HYBRID_RANK;
        op->fuse = node.as.hybrid_rank.fuse;
        op->count = node.as.hybrid_rank.count;

        cur_wire = node.as.hybrid_rank.branches_wire;
        for (i = 0; i < op->count && i < CDB_EXEC_MAX_BRANCHES; i++) {
            uint64_t w_val = 0;
            size_t w_len = 0;
            st = build_exec_tree(cur, &cur_wire, end, &op->branches[i], depth + 1);
            if (st != CDB_OK)
                return st;
            if (cdb_varint_decode(cur_wire, (size_t)(end - cur_wire), &w_val, &w_len) != CDB_OK)
                return CDB_E_MALFORMED;
            cur_wire += w_len;
            op->weights[i] = (uint32_t)w_val;
        }
        *out_op = &op->base;
        return CDB_OK;
    }

    default: (void)node_start; return CDB_E_UNSUPPORTED;
    }
}

static cdb_status exec_open_in(cdb_exec_cursor *cur, cdb_db *db, const uint8_t *wire, size_t len,
                               const cdb_eval_param *params, size_t n_params, uint8_t *scratch,
                               size_t scratch_cap);

cdb_status cdb_exec_open(cdb_exec_cursor *cur, cdb_db *db, const uint8_t *wire, size_t len,
                         const cdb_eval_param *params, size_t n_params, uint8_t *scratch,
                         size_t scratch_cap)
{
    cdb_status s;
    cdb_db_lock(db);
    s = exec_open_in(cur, db, wire, len, params, n_params, scratch, scratch_cap);
    cdb_db_unlock(db);
    return s;
}

static cdb_status exec_open_in(cdb_exec_cursor *cur, cdb_db *db, const uint8_t *wire, size_t len,
                               const cdb_eval_param *params, size_t n_params, uint8_t *scratch,
                               size_t scratch_cap)
{
    size_t root_offset = 0;
    const uint8_t *p;
    const uint8_t *end;
    cdb_status st;

    if (cur == NULL || wire == NULL || scratch == NULL || scratch_cap == 0)
        return CDB_E_INVALID_ARG;

    memset(cur, 0, sizeof(*cur));
    cur->db = db;
    if (db != NULL) {
        cur->cat = &db->catalog;
        cur->order = db->pager.order;
    } else {
        cur->order = CDB_ORDER_LITTLE;
    }

    cur->params = params;
    cur->n_params = n_params;
    cur->arena.buf = scratch;
    cur->arena.cap = scratch_cap;
    cur->arena.used = 0;
    cur->max_buffered_rows = CDB_EXEC_DEFAULT_BUFFERED_ROWS;
#ifdef CDB_PROFILE_HOST
    /* Pipeline breakers and scan buffers may grow past the arena, up to the
     * query memory budget (spec 17.4); max_buffered_rows then only sizes
     * their first array */
    if (db != NULL)
        cur->mem_budget = db->cfg.query_mem != 0 ? db->cfg.query_mem : CDB_QUERY_MEM_DEFAULT;
#endif

    /* Initialize evaluation context */
    cdb_eval_ctx_init(&cur->eval_ctx, cur->order, cur->cat, 0);
    cdb_eval_ctx_set_params(&cur->eval_ctx, params, n_params);
    cdb_eval_ctx_set_scratch(&cur->eval_ctx, cur->eval_scratch, sizeof(cur->eval_scratch));

    /* Validate header and find root plan node */
    st = cdb_query_validate(wire, len, &root_offset);
    if (st != CDB_OK)
        return st;

    p = wire + root_offset;
    end = wire + len;

    st = build_exec_tree(cur, &p, end, &cur->root_op, 0);
    if (st != CDB_OK)
        return st;

    st = cur->root_op->vtab->open(cur->root_op, cur);
    if (st != CDB_OK)
        return st;

    cur->is_open = 1;
    return CDB_OK;
}

/* next, reset and close take the lock of the cursor's database for their
 * whole run, so no worker task runs inside one step (spec 5.9.6). */
cdb_status cdb_exec_next(cdb_exec_cursor *cur, cdb_exec_row *row, int *has_row)
{
    cdb_status s;
    if (cur == NULL || !cur->is_open || cur->root_op == NULL || row == NULL || has_row == NULL)
        return CDB_E_INVALID_ARG;

    cdb_db_lock(cur->db);
    cdb_eval_ctx_reset_scratch(&cur->eval_ctx);
    s = cur->root_op->vtab->next(cur->root_op, cur, row, has_row);
    cdb_db_unlock(cur->db);
    return s;
}

cdb_status cdb_exec_reset(cdb_exec_cursor *cur)
{
    cdb_status s;
    if (cur == NULL || !cur->is_open || cur->root_op == NULL)
        return CDB_E_INVALID_ARG;

    cdb_db_lock(cur->db);
    cdb_eval_ctx_reset_scratch(&cur->eval_ctx);
    s = cur->root_op->vtab->reset(cur->root_op, cur);
    cdb_db_unlock(cur->db);
    return s;
}

cdb_status cdb_exec_close(cdb_exec_cursor *cur)
{
    cdb_db *db;
    if (cur == NULL || !cur->is_open)
        return CDB_OK;

    db = cur->db; /* captured: closing may clear it */
    cdb_db_lock(db);
    if (cur->root_op != NULL) {
        cur->root_op->vtab->close(cur->root_op, cur);
    }
    if (cur->db != NULL)
        exec_free_all(cur, &cur->blocks);
    cur->is_open = 0;
    cdb_db_unlock(db);
    return CDB_OK;
}

static int set_mock_scan_recursive(cdb_exec_op *op, const char *name, size_t name_len,
                                   const cdb_exec_row *rows, size_t n_rows)
{
    if (op == NULL)
        return 0;
    if (op->tag == CDB_QUERY_NODE_SCAN) {
        cdb_exec_scan *s = (cdb_exec_scan *)op;
        if (s->store_name_len == name_len && memcmp(s->store_name, name, name_len) == 0) {
            s->mock_rows = rows;
            s->n_mock_rows = n_rows;
            s->mock_idx = 0;
            return 1;
        }
        return 0;
    }
    if (op->tag == CDB_QUERY_NODE_FILTER) {
        return set_mock_scan_recursive(((cdb_exec_filter *)op)->input, name, name_len, rows,
                                       n_rows);
    }
    if (op->tag == CDB_QUERY_NODE_PROJECT) {
        return set_mock_scan_recursive(((cdb_exec_project *)op)->input, name, name_len, rows,
                                       n_rows);
    }
    if (op->tag == CDB_QUERY_NODE_LIMIT) {
        return set_mock_scan_recursive(((cdb_exec_limit *)op)->input, name, name_len, rows, n_rows);
    }
    if (op->tag == CDB_QUERY_NODE_SORT) {
        return set_mock_scan_recursive(((cdb_exec_sort *)op)->input, name, name_len, rows, n_rows);
    }
    if (op->tag == CDB_QUERY_NODE_AGGREGATE) {
        return set_mock_scan_recursive(((cdb_exec_aggregate *)op)->input, name, name_len, rows,
                                       n_rows);
    }
    if (op->tag == CDB_QUERY_NODE_WINDOW) {
        return set_mock_scan_recursive(((cdb_exec_window *)op)->input, name, name_len, rows,
                                       n_rows);
    }
    if (op->tag == CDB_QUERY_NODE_UNNEST) {
        return set_mock_scan_recursive(((cdb_exec_unnest *)op)->input, name, name_len, rows,
                                       n_rows);
    }
    if (op->tag == CDB_QUERY_NODE_TRAVERSE) {
        return set_mock_scan_recursive(((cdb_exec_traverse *)op)->input, name, name_len, rows,
                                       n_rows);
    }
    if (op->tag == CDB_QUERY_NODE_TEXT_SEARCH) {
        return set_mock_scan_recursive(((cdb_exec_text_search *)op)->input, name, name_len, rows,
                                       n_rows);
    }
    if (op->tag == CDB_QUERY_NODE_VECTOR_SEARCH) {
        return set_mock_scan_recursive(((cdb_exec_vec_search *)op)->input, name, name_len, rows,
                                       n_rows);
    }
    if (op->tag == CDB_QUERY_NODE_JOIN) {
        int r1 = set_mock_scan_recursive(((cdb_exec_join *)op)->left, name, name_len, rows, n_rows);
        int r2 =
            set_mock_scan_recursive(((cdb_exec_join *)op)->right, name, name_len, rows, n_rows);
        return r1 || r2;
    }
    if (op->tag == CDB_QUERY_NODE_ASOF_JOIN) {
        int r1 = set_mock_scan_recursive(((cdb_exec_asof *)op)->left, name, name_len, rows, n_rows);
        int r2 =
            set_mock_scan_recursive(((cdb_exec_asof *)op)->right, name, name_len, rows, n_rows);
        return r1 || r2;
    }
    if (op->tag == CDB_QUERY_NODE_UNION) {
        cdb_exec_union *u = (cdb_exec_union *)op;
        size_t i;
        int any = 0;
        for (i = 0; i < u->count; i++) {
            if (set_mock_scan_recursive(u->branches[i], name, name_len, rows, n_rows))
                any = 1;
        }
        return any;
    }
    if (op->tag == CDB_QUERY_NODE_HYBRID_RANK) {
        cdb_exec_hybrid *h = (cdb_exec_hybrid *)op;
        size_t i;
        int any = 0;
        for (i = 0; i < h->count; i++) {
            if (set_mock_scan_recursive(h->branches[i], name, name_len, rows, n_rows))
                any = 1;
        }
        return any;
    }
    return 0;
}

cdb_status cdb_exec_set_mock_scan(cdb_exec_cursor *cur, const char *store_name, size_t name_len,
                                  const cdb_exec_row *rows, size_t n_rows)
{
    if (cur == NULL || !cur->is_open || cur->root_op == NULL || store_name == NULL)
        return CDB_E_INVALID_ARG;
    if (set_mock_scan_recursive(cur->root_op, store_name, name_len, rows, n_rows))
        return CDB_OK;
    return CDB_E_NOT_FOUND;
}
