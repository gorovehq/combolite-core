/* Branch-coverage harness for the CMBQL wire codec in cdb_query.c.
 *
 * The encoders' success + buffer-too-small branches are already covered by
 * test_wire_writer_edge.c, and test_query.c exercises a handful of read/validate
 * paths. This file targets what remains in cdb_query.c:
 *   - every writer argument-validation (CDB_E_INVALID_ARG) branch;
 *   - cdb_query_read_node / cdb_query_skip_node for every node tag, including the
 *     five test_query.c omits (sort, union, aggregate, text_search,
 *     vector_search) and all per-node semantic-reject branches;
 *   - cdb_query_read_expr / cdb_query_skip_expr for every expression tag
 *     (param-named, unary, binary, call) plus the embedded-value validate branch;
 *   - the long `if (s != CDB_OK) return s;` truncation chains, swept by
 *     validating/reading every byte-length prefix of a full valid plan.
 * Pure codec, no DB. Spec 11.1/11.10/14.19. */
#include "unity.h"
#include "cdb_query.h"

#include <string.h>

void setUp(void) {}
void tearDown(void) {}

/* 6-byte CMBQ header: magic 'C''M''B''Q', version 1, flags 0. */
#define HDR CDB_QUERY_MAGIC_0, CDB_QUERY_MAGIC_1, CDB_QUERY_MAGIC_2, CDB_QUERY_MAGIC_3, \
            CDB_QUERY_VERSION_1, 0x00u

static uint8_t abig[1024];

/* Encodes a valid int64 cdb_value literal; returns its byte length. */
static size_t make_int_literal(uint8_t *buf, size_t cap, int64_t val)
{
    cdb_value_writer vw;
    cdb_value_writer_init(&vw, buf, cap, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_value_write_int(&vw, val));
    return cdb_value_writer_len(&vw);
}

/* ------------------------------------------------------------- writer argument validation
 * Every cdb_query_write_* early CDB_E_INVALID_ARG guard. Distinct from
 * test_wire_writer_edge.c (success / buffer-too-small) and test_query.c. */

/* Re-inits an ample writer `w_`, then asserts the encoder fails closed. */
#define WERR(call)                                                   \
    do {                                                             \
        cdb_query_writer w_;                                         \
        cdb_query_writer_init(&w_, abig, sizeof abig);              \
        TEST_ASSERT_EQUAL_INT_MESSAGE(CDB_E_INVALID_ARG, (call), #call); \
    } while (0)

static void test_writer_arg_validation(void)
{
    WERR(cdb_query_write_scan(&w_, NULL, 3));                 /* name NULL, len != 0 */
    WERR(cdb_query_write_project_output(&w_, NULL, 2));       /* alias NULL, len != 0 */
    WERR(cdb_query_write_join(&w_, 0x7Fu));                   /* bad join kind */
    WERR(cdb_query_write_sort(&w_, 0));                       /* zero keys */
    WERR(cdb_query_write_sort_key_suffix(&w_, 0xFFu, CDB_NULLS_FIRST)); /* bad dir */
    WERR(cdb_query_write_sort_key_suffix(&w_, CDB_SORT_ASC, 0xFFu));    /* bad nulls */
    WERR(cdb_query_write_union(&w_, 0));                      /* zero branches */
    WERR(cdb_query_write_aggregate(&w_, 0, 0));               /* both zero */
    WERR(cdb_query_write_aggregate_output(&w_, "a", 1, 0));           /* fn < COUNT */
    WERR(cdb_query_write_aggregate_output(&w_, "a", 1, CDB_AGG__HIGHEST + 1u)); /* fn above the range */
    WERR(cdb_query_write_traverse(&w_, "l", 1, 0xFFu, 0, 1)); /* bad dir */
    WERR(cdb_query_write_traverse(&w_, "l", 1, CDB_TRAVERSE_FWD, 5, 2)); /* max < min */
    WERR(cdb_query_write_text_search(&w_, 0xFFu, 1, "q", 1, 0));   /* bad mode */
    WERR(cdb_query_write_vector_search(&w_, "v", 1, 1, 0x7Fu));    /* bad metric */
    WERR(cdb_query_write_hybrid_rank(&w_, 0xFFu, 1));             /* bad fuse */
    WERR(cdb_query_write_hybrid_rank(&w_, CDB_FUSE_RRF, 0));      /* zero branches */
    WERR(cdb_query_write_window(&w_, 0xFFu, "t", 1, 1, 1));       /* bad window type */
    WERR(cdb_query_write_asof_join(&w_, 0xFFu, 1));              /* bad asof kind */
    WERR(cdb_query_write_unnest(&w_, NULL, 1, "j", 1));          /* item NULL */
    WERR(cdb_query_write_unnest(&w_, "i", 0, "j", 1));          /* item len 0 */
    WERR(cdb_query_write_expr_literal(&w_, NULL, 3));           /* bytes NULL, len != 0 */
    WERR(cdb_query_write_expr_field(&w_, NULL, 3));             /* path NULL, len != 0 */
    WERR(cdb_query_write_expr_param_named(&w_, NULL, 1));       /* name NULL */
    WERR(cdb_query_write_expr_param_named(&w_, "n", 0));        /* name len 0 */
    WERR(cdb_query_write_expr_unary(&w_, 0xFFu));              /* bad unary op */
    WERR(cdb_query_write_expr_binary(&w_, 0xFFu));             /* bad binary op */
}

/* ------------------------------------------------------------- valid plans, one per node tag
 * Builds a minimal valid plan rooted at each operator so cdb_query_validate (via
 * skip_node) and cdb_query_read_node exercise every tag's success path. The
 * unusual variants (passthrough=1, LEFT_OUTER join, TRAVERSE_BOTH with
 * max==min, SLIDING window, ASOF_NEAREST, a valid literal in a predicate) pick
 * branches test_query.c leaves cold. */

typedef struct {
    uint8_t buf[256];
    size_t len;
    uint8_t root_tag;
} plan_t;

#define FIN(p, w)                                                  \
    do {                                                           \
        TEST_ASSERT_EQUAL_INT_MESSAGE(CDB_OK, (w).error, "build"); \
        (p)->len = cdb_query_writer_len(&(w));                     \
    } while (0)

static void build_plans(plan_t *plans, size_t *out_n)
{
    uint8_t litbuf[32];
    size_t litlen = make_int_literal(litbuf, sizeof litbuf, 42);
    size_t n = 0;
    cdb_query_writer w;
    plan_t *p;

    /* SCAN */
    p = &plans[n]; p->root_tag = CDB_QUERY_NODE_SCAN;
    cdb_query_writer_init(&w, p->buf, sizeof p->buf);
    cdb_query_writer_begin(&w);
    cdb_query_write_scan(&w, "s", 1);
    FIN(p, w); n++;

    /* FILTER(Scan, Binary(EQ, Field, Literal(valid value))) */
    p = &plans[n]; p->root_tag = CDB_QUERY_NODE_FILTER;
    cdb_query_writer_init(&w, p->buf, sizeof p->buf);
    cdb_query_writer_begin(&w);
    cdb_query_write_filter(&w);
    cdb_query_write_scan(&w, "s", 1);
    cdb_query_write_expr_binary(&w, CDB_BIN_EQ);
    cdb_query_write_expr_field(&w, "age", 3);
    cdb_query_write_expr_literal(&w, litbuf, litlen);
    FIN(p, w); n++;

    /* PROJECT(passthrough=1, 1 out) */
    p = &plans[n]; p->root_tag = CDB_QUERY_NODE_PROJECT;
    cdb_query_writer_init(&w, p->buf, sizeof p->buf);
    cdb_query_writer_begin(&w);
    cdb_query_write_project(&w, 1, 1);
    cdb_query_write_scan(&w, "s", 1);
    cdb_query_write_project_output(&w, "a", 1);
    cdb_query_write_expr_field(&w, "f", 1);
    FIN(p, w); n++;

    /* JOIN(LEFT_OUTER, Scan, Scan, Binary(EQ, Field, Field)) */
    p = &plans[n]; p->root_tag = CDB_QUERY_NODE_JOIN;
    cdb_query_writer_init(&w, p->buf, sizeof p->buf);
    cdb_query_writer_begin(&w);
    cdb_query_write_join(&w, CDB_JOIN_LEFT_OUTER);
    cdb_query_write_scan(&w, "l", 1);
    cdb_query_write_scan(&w, "r", 1);
    cdb_query_write_expr_binary(&w, CDB_BIN_EQ);
    cdb_query_write_expr_field(&w, "a", 1);
    cdb_query_write_expr_field(&w, "b", 1);
    FIN(p, w); n++;

    /* SORT(2 keys: ASC/NULLS_FIRST, DESC/NULLS_LAST) */
    p = &plans[n]; p->root_tag = CDB_QUERY_NODE_SORT;
    cdb_query_writer_init(&w, p->buf, sizeof p->buf);
    cdb_query_writer_begin(&w);
    cdb_query_write_sort(&w, 2);
    cdb_query_write_scan(&w, "s", 1);
    cdb_query_write_expr_field(&w, "f1", 2);
    cdb_query_write_sort_key_suffix(&w, CDB_SORT_ASC, CDB_NULLS_FIRST);
    cdb_query_write_expr_field(&w, "f2", 2);
    cdb_query_write_sort_key_suffix(&w, CDB_SORT_DESC, CDB_NULLS_LAST);
    FIN(p, w); n++;

    /* LIMIT(10, 5) */
    p = &plans[n]; p->root_tag = CDB_QUERY_NODE_LIMIT;
    cdb_query_writer_init(&w, p->buf, sizeof p->buf);
    cdb_query_writer_begin(&w);
    cdb_query_write_limit(&w, 10, 5);
    cdb_query_write_scan(&w, "s", 1);
    FIN(p, w); n++;

    /* UNION(2 branches) */
    p = &plans[n]; p->root_tag = CDB_QUERY_NODE_UNION;
    cdb_query_writer_init(&w, p->buf, sizeof p->buf);
    cdb_query_writer_begin(&w);
    cdb_query_write_union(&w, 2);
    cdb_query_write_scan(&w, "a", 1);
    cdb_query_write_scan(&w, "b", 1);
    FIN(p, w); n++;

    /* AGGREGATE(1 group, 1 agg: SUM) */
    p = &plans[n]; p->root_tag = CDB_QUERY_NODE_AGGREGATE;
    cdb_query_writer_init(&w, p->buf, sizeof p->buf);
    cdb_query_writer_begin(&w);
    cdb_query_write_aggregate(&w, 1, 1);
    cdb_query_write_scan(&w, "s", 1);
    cdb_query_write_expr_field(&w, "g", 1);      /* group expr */
    cdb_query_write_aggregate_output(&w, "c", 1, CDB_AGG_SUM);
    cdb_query_write_expr_field(&w, "v", 1);      /* agg input expr */
    FIN(p, w); n++;

    /* TRAVERSE(BOTH, min==max==0) */
    p = &plans[n]; p->root_tag = CDB_QUERY_NODE_TRAVERSE;
    cdb_query_writer_init(&w, p->buf, sizeof p->buf);
    cdb_query_writer_begin(&w);
    cdb_query_write_traverse(&w, "lt", 2, CDB_TRAVERSE_BOTH, 0, 0);
    cdb_query_write_scan(&w, "s", 1);
    FIN(p, w); n++;

    /* TEXT_SEARCH(ALL, 2 fields) */
    p = &plans[n]; p->root_tag = CDB_QUERY_NODE_TEXT_SEARCH;
    cdb_query_writer_init(&w, p->buf, sizeof p->buf);
    cdb_query_writer_begin(&w);
    cdb_query_write_text_search(&w, CDB_QUERY_FTS_ALL, 50, "q", 1, 2);
    cdb_query_write_scan(&w, "s", 1);
    cdb_query_write_field_name(&w, "b", 1);
    cdb_query_write_field_name(&w, "c", 1);
    FIN(p, w); n++;

    /* VECTOR_SEARCH(EUCLIDEAN, near = Param[0]) */
    p = &plans[n]; p->root_tag = CDB_QUERY_NODE_VECTOR_SEARCH;
    cdb_query_writer_init(&w, p->buf, sizeof p->buf);
    cdb_query_writer_begin(&w);
    cdb_query_write_vector_search(&w, "v", 1, 5, CDB_QUERY_METRIC_EUCLIDEAN);
    cdb_query_write_scan(&w, "s", 1);
    cdb_query_write_expr_param_index(&w, 0);
    FIN(p, w); n++;

    /* HYBRID_RANK(RRF, 2 scan branches + weights) */
    p = &plans[n]; p->root_tag = CDB_QUERY_NODE_HYBRID_RANK;
    cdb_query_writer_init(&w, p->buf, sizeof p->buf);
    cdb_query_writer_begin(&w);
    cdb_query_write_hybrid_rank(&w, CDB_FUSE_RRF, 2);
    cdb_query_write_scan(&w, "a", 1);
    cdb_query_write_branch_weight(&w, 1000);
    cdb_query_write_scan(&w, "b", 1);
    cdb_query_write_branch_weight(&w, 2000);
    FIN(p, w); n++;

    /* WINDOW(SLIDING) */
    p = &plans[n]; p->root_tag = CDB_QUERY_NODE_WINDOW;
    cdb_query_writer_init(&w, p->buf, sizeof p->buf);
    cdb_query_writer_begin(&w);
    cdb_query_write_window(&w, CDB_WINDOW_SLIDING, "ts", 2, 1000, 100);
    cdb_query_write_scan(&w, "s", 1);
    FIN(p, w); n++;

    /* ASOF_JOIN(NEAREST) */
    p = &plans[n]; p->root_tag = CDB_QUERY_NODE_ASOF_JOIN;
    cdb_query_writer_init(&w, p->buf, sizeof p->buf);
    cdb_query_writer_begin(&w);
    cdb_query_write_asof_join(&w, CDB_ASOF_NEAREST, 1000000000ULL);
    cdb_query_write_scan(&w, "l", 1);
    cdb_query_write_scan(&w, "r", 1);
    cdb_query_write_expr_field(&w, "lt", 2);   /* left_time */
    cdb_query_write_expr_field(&w, "rt", 2);   /* right_time */
    cdb_query_write_expr_binary(&w, CDB_BIN_EQ); /* match_cond */
    cdb_query_write_expr_field(&w, "a", 1);
    cdb_query_write_expr_field(&w, "b", 1);
    FIN(p, w); n++;

    /* UNNEST(item, idx, array = Field) */
    p = &plans[n]; p->root_tag = CDB_QUERY_NODE_UNNEST;
    cdb_query_writer_init(&w, p->buf, sizeof p->buf);
    cdb_query_writer_begin(&w);
    cdb_query_write_unnest(&w, "i", 1, "j", 1);
    cdb_query_write_scan(&w, "s", 1);
    cdb_query_write_expr_field(&w, "arr", 3);
    FIN(p, w); n++;

    *out_n = n;
}

/* Validate (skip_node) + read root for every node tag: the success side. */
static void test_validate_and_read_all_node_tags(void)
{
    static plan_t plans[16];
    size_t n, i;
    build_plans(plans, &n);
    TEST_ASSERT_EQUAL_size_t(15, n);

    for (i = 0; i < n; i++) {
        size_t off = 0;
        const uint8_t *p = plans[i].buf + CDB_QUERY_HEADER_SIZE;
        const uint8_t *end = plans[i].buf + plans[i].len;
        cdb_query_node node;

        TEST_ASSERT_EQUAL_INT_MESSAGE(CDB_OK,
            cdb_query_validate(plans[i].buf, plans[i].len, &off),
            "valid plan should validate");
        TEST_ASSERT_EQUAL_size_t(CDB_QUERY_HEADER_SIZE, off);
        TEST_ASSERT_EQUAL_INT_MESSAGE(CDB_OK, cdb_query_read_node(&p, end, &node),
            "valid plan root should read");
        TEST_ASSERT_EQUAL_UINT8(plans[i].root_tag, node.tag);
    }
}

/* Deep field asserts + child navigation for the tags test_query.c never reads. */
static void test_read_untested_node_fields(void)
{
    static plan_t plans[16];
    size_t n, i;
    const uint8_t *end;
    cdb_query_node node, child;
    const uint8_t *p;
    cdb_query_expr e;
    build_plans(plans, &n);

    for (i = 0; i < n; i++) {
        end = plans[i].buf + plans[i].len;
        p = plans[i].buf + CDB_QUERY_HEADER_SIZE;
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_read_node(&p, end, &node));

        switch (node.tag) {
        case CDB_QUERY_NODE_SORT:
            TEST_ASSERT_EQUAL_size_t(2, node.as.sort.count);
            p = node.as.sort.keys_wire;             /* first key expr */
            TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_read_expr(&p, end, &e));
            TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_EXPR_FIELD, e.tag);
            break;
        case CDB_QUERY_NODE_UNION:
            TEST_ASSERT_EQUAL_size_t(2, node.as.union_node.count);
            p = node.as.union_node.branches_wire;
            TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_read_node(&p, end, &child));
            TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_NODE_SCAN, child.tag);
            TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_read_node(&p, end, &child));
            TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_NODE_SCAN, child.tag);
            break;
        case CDB_QUERY_NODE_AGGREGATE:
            TEST_ASSERT_EQUAL_size_t(1, node.as.aggregate.n_groups);
            TEST_ASSERT_EQUAL_size_t(1, node.as.aggregate.n_aggs);
            p = node.as.aggregate.groups_wire;
            TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_read_expr(&p, end, &e));
            TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_EXPR_FIELD, e.tag);
            break;
        case CDB_QUERY_NODE_TEXT_SEARCH:
            TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_FTS_ALL, node.as.text_search.mode);
            TEST_ASSERT_EQUAL_UINT64(50, node.as.text_search.limit);
            TEST_ASSERT_EQUAL_size_t(1, node.as.text_search.query_len);
            TEST_ASSERT_EQUAL_size_t(2, node.as.text_search.n_fields);
            p = node.as.text_search.input_wire;
            TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_read_node(&p, end, &child));
            TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_NODE_SCAN, child.tag);
            break;
        case CDB_QUERY_NODE_VECTOR_SEARCH:
            TEST_ASSERT_EQUAL_size_t(1, node.as.vector_search.field_len);
            TEST_ASSERT_EQUAL_UINT64(5, node.as.vector_search.k);
            TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_METRIC_EUCLIDEAN, node.as.vector_search.metric);
            p = node.as.vector_search.near_wire;
            TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_read_expr(&p, end, &e));
            TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_EXPR_PARAM, e.tag);
            TEST_ASSERT_EQUAL_UINT8(CDB_PARAM_INDEX, e.as.param.kind);
            break;
        default:
            break;
        }
    }
}

/* Truncating a valid plan at every length < full must fail both the walker
 * (validate/skip_node) and the direct reader, exercising the error-propagation
 * branch of each sequential field read. */
static void test_truncation_sweeps(void)
{
    static plan_t plans[16];
    size_t n, i, L;
    build_plans(plans, &n);

    for (i = 0; i < n; i++) {
        for (L = CDB_QUERY_HEADER_SIZE; L < plans[i].len; L++) {
            size_t off = 0;
            const uint8_t *p = plans[i].buf + CDB_QUERY_HEADER_SIZE;
            cdb_query_node node;
            TEST_ASSERT_TRUE_MESSAGE(
                cdb_query_validate(plans[i].buf, L, &off) != CDB_OK,
                "validate must reject a truncated plan");
            TEST_ASSERT_TRUE_MESSAGE(
                cdb_query_read_node(&p, plans[i].buf + L, &node) != CDB_OK,
                "read_node must reject a truncated node");
        }
    }
}

/* ------------------------------------------------------------- node semantic rejects
 * Hand-built wire that is well-formed up to a field whose value is out of range,
 * so both skip_node (via validate) and read_node hit the reject. */

static void expect_node_reject(const uint8_t *wire, size_t len, const char *what)
{
    size_t off = 0;
    const uint8_t *p = wire + CDB_QUERY_HEADER_SIZE;
    cdb_query_node node;
    TEST_ASSERT_EQUAL_INT_MESSAGE(CDB_E_INVALID_ARG,
        cdb_query_validate(wire, len, &off), what);
    TEST_ASSERT_EQUAL_INT_MESSAGE(CDB_E_INVALID_ARG,
        cdb_query_read_node(&p, wire + len, &node), what);
}

static void test_node_semantic_rejects(void)
{
    /* unknown node tag */
    { static const uint8_t b[] = {HDR, 0xEEu};
      expect_node_reject(b, sizeof b, "unknown node tag"); }
    /* PROJECT passthrough > 1 */
    { static const uint8_t b[] = {HDR, CDB_QUERY_NODE_PROJECT, 0x02u};
      expect_node_reject(b, sizeof b, "project passthrough>1"); }
    /* JOIN bad kind */
    { static const uint8_t b[] = {HDR, CDB_QUERY_NODE_JOIN, 0xFFu};
      expect_node_reject(b, sizeof b, "join bad kind"); }
    /* SORT count == 0 */
    { static const uint8_t b[] = {HDR, CDB_QUERY_NODE_SORT, 0x00u};
      expect_node_reject(b, sizeof b, "sort count 0"); }
    /* SORT bad dir (count 1, scan "s", field key, dir 0xFF, nulls) */
    { static const uint8_t b[] = {HDR, CDB_QUERY_NODE_SORT, 0x01u,
          CDB_QUERY_NODE_SCAN, 0x01u, 's',
          CDB_QUERY_EXPR_FIELD, 0x01u, 'f', 0xFFu, CDB_NULLS_FIRST};
      expect_node_reject(b, sizeof b, "sort bad dir"); }
    /* SORT bad nulls (dir ASC ok, nulls 0xFF) */
    { static const uint8_t b[] = {HDR, CDB_QUERY_NODE_SORT, 0x01u,
          CDB_QUERY_NODE_SCAN, 0x01u, 's',
          CDB_QUERY_EXPR_FIELD, 0x01u, 'f', CDB_SORT_ASC, 0xFFu};
      expect_node_reject(b, sizeof b, "sort bad nulls"); }
    /* UNION count == 0 */
    { static const uint8_t b[] = {HDR, CDB_QUERY_NODE_UNION, 0x00u};
      expect_node_reject(b, sizeof b, "union count 0"); }
    /* AGGREGATE both counts 0 */
    { static const uint8_t b[] = {HDR, CDB_QUERY_NODE_AGGREGATE, 0x00u, 0x00u};
      expect_node_reject(b, sizeof b, "aggregate both zero"); }
    /* AGGREGATE bad fn (0 groups, 1 agg, scan, alias "a", fn 0xFF, expr field) */
    { static const uint8_t b[] = {HDR, CDB_QUERY_NODE_AGGREGATE, 0x00u, 0x01u,
          CDB_QUERY_NODE_SCAN, 0x01u, 's',
          0x01u, 'a', 0xFFu, CDB_QUERY_EXPR_FIELD, 0x01u, 'v'};
      expect_node_reject(b, sizeof b, "aggregate bad fn"); }
    /* TRAVERSE bad dir (link "l", dir 0xFF) */
    { static const uint8_t b[] = {HDR, CDB_QUERY_NODE_TRAVERSE, 0x01u, 'l', 0xFFu};
      expect_node_reject(b, sizeof b, "traverse bad dir"); }
    /* TRAVERSE max < min (dir FWD, min 5, max 2, scan) */
    { static const uint8_t b[] = {HDR, CDB_QUERY_NODE_TRAVERSE, 0x01u, 'l',
          CDB_TRAVERSE_FWD, 0x05u, 0x02u, CDB_QUERY_NODE_SCAN, 0x01u, 's'};
      expect_node_reject(b, sizeof b, "traverse max<min"); }
    /* TEXT_SEARCH bad mode */
    { static const uint8_t b[] = {HDR, CDB_QUERY_NODE_TEXT_SEARCH, 0xFFu};
      expect_node_reject(b, sizeof b, "text_search bad mode"); }
    /* VECTOR_SEARCH bad metric (field "v", k 1, metric 0xFF) */
    { static const uint8_t b[] = {HDR, CDB_QUERY_NODE_VECTOR_SEARCH, 0x01u, 'v',
          0x01u, 0xFFu};
      expect_node_reject(b, sizeof b, "vector_search bad metric"); }
    /* HYBRID_RANK bad fuse */
    { static const uint8_t b[] = {HDR, CDB_QUERY_NODE_HYBRID_RANK, 0xFFu};
      expect_node_reject(b, sizeof b, "hybrid bad fuse"); }
    /* HYBRID_RANK count == 0 (fuse RRF, count 0) */
    { static const uint8_t b[] = {HDR, CDB_QUERY_NODE_HYBRID_RANK, CDB_FUSE_RRF, 0x00u};
      expect_node_reject(b, sizeof b, "hybrid count 0"); }
    /* WINDOW bad type */
    { static const uint8_t b[] = {HDR, CDB_QUERY_NODE_WINDOW, 0xFFu};
      expect_node_reject(b, sizeof b, "window bad type"); }
    /* ASOF_JOIN bad kind */
    { static const uint8_t b[] = {HDR, CDB_QUERY_NODE_ASOF_JOIN, 0xFFu};
      expect_node_reject(b, sizeof b, "asof bad kind"); }
    /* UNNEST item_len == 0 */
    { static const uint8_t b[] = {HDR, CDB_QUERY_NODE_UNNEST, 0x00u};
      expect_node_reject(b, sizeof b, "unnest item len 0"); }
}

/* ------------------------------------------------------------- expression paths
 * read_expr / skip_expr take (p, end) directly, so expressions are tested as
 * raw bytes with no query header. */

static void test_read_and_skip_all_expr_tags(void)
{
    uint8_t buf[64];
    uint8_t litbuf[32];
    size_t litlen = make_int_literal(litbuf, sizeof litbuf, 7);
    cdb_query_writer w;
    const uint8_t *p, *end;
    cdb_query_expr e;
    size_t len;

    /* LITERAL (valid embedded value): read_expr + skip_expr value-validate OK */
    cdb_query_writer_init(&w, buf, sizeof buf);
    cdb_query_write_expr_literal(&w, litbuf, litlen);
    len = cdb_query_writer_len(&w);
    p = buf; end = buf + len;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_read_expr(&p, end, &e));
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_EXPR_LITERAL, e.tag);
    TEST_ASSERT_EQUAL_size_t(litlen, e.as.literal.len);
    p = buf;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_skip_expr(&p, end));

    /* FIELD */
    cdb_query_writer_init(&w, buf, sizeof buf);
    cdb_query_write_expr_field(&w, "a\x1f" "b", 3);
    len = cdb_query_writer_len(&w);
    p = buf; end = buf + len;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_read_expr(&p, end, &e));
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_EXPR_FIELD, e.tag);
    TEST_ASSERT_EQUAL_size_t(3, e.as.field.len);
    p = buf;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_skip_expr(&p, end));

    /* PARAM index */
    cdb_query_writer_init(&w, buf, sizeof buf);
    cdb_query_write_expr_param_index(&w, 9);
    len = cdb_query_writer_len(&w);
    p = buf; end = buf + len;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_read_expr(&p, end, &e));
    TEST_ASSERT_EQUAL_UINT8(CDB_PARAM_INDEX, e.as.param.kind);
    TEST_ASSERT_EQUAL_UINT32(9, e.as.param.index);
    p = buf;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_skip_expr(&p, end));

    /* PARAM named */
    cdb_query_writer_init(&w, buf, sizeof buf);
    cdb_query_write_expr_param_named(&w, "lim", 3);
    len = cdb_query_writer_len(&w);
    p = buf; end = buf + len;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_read_expr(&p, end, &e));
    TEST_ASSERT_EQUAL_UINT8(CDB_PARAM_NAMED, e.as.param.kind);
    TEST_ASSERT_EQUAL_size_t(3, e.as.param.name_len);
    p = buf;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_skip_expr(&p, end));

    /* UNARY(IS_NULL, operand = Field) */
    cdb_query_writer_init(&w, buf, sizeof buf);
    cdb_query_write_expr_unary(&w, CDB_UNARY_IS_NULL);
    cdb_query_write_expr_field(&w, "x", 1);
    len = cdb_query_writer_len(&w);
    p = buf; end = buf + len;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_read_expr(&p, end, &e));
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_EXPR_UNARY, e.tag);
    TEST_ASSERT_EQUAL_UINT8(CDB_UNARY_IS_NULL, e.as.unary.op);
    TEST_ASSERT_NOT_NULL(e.as.unary.operand_wire);
    p = buf;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_skip_expr(&p, end));

    /* BINARY(LIKE, Field, Field) */
    cdb_query_writer_init(&w, buf, sizeof buf);
    cdb_query_write_expr_binary(&w, CDB_BIN_LIKE);
    cdb_query_write_expr_field(&w, "x", 1);
    cdb_query_write_expr_field(&w, "y", 1);
    len = cdb_query_writer_len(&w);
    p = buf; end = buf + len;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_read_expr(&p, end, &e));
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_EXPR_BINARY, e.tag);
    TEST_ASSERT_EQUAL_UINT8(CDB_BIN_LIKE, e.as.binary.op);
    TEST_ASSERT_NOT_NULL(e.as.binary.left_wire);
    TEST_ASSERT_NOT_NULL(e.as.binary.right_wire);
    p = buf;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_skip_expr(&p, end));

    /* CALL(fn, 2 args) */
    cdb_query_writer_init(&w, buf, sizeof buf);
    cdb_query_write_expr_call(&w, CDB_FN_HYPOT, 2);
    cdb_query_write_expr_field(&w, "x", 1);
    cdb_query_write_expr_field(&w, "y", 1);
    len = cdb_query_writer_len(&w);
    p = buf; end = buf + len;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_read_expr(&p, end, &e));
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_EXPR_CALL, e.tag);
    TEST_ASSERT_EQUAL_UINT16(CDB_FN_HYPOT, e.as.call.fn_id);
    TEST_ASSERT_EQUAL_UINT16(2, e.as.call.n_args);
    p = buf;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_skip_expr(&p, end));

    /* CALL(fn, 0 args): loop body never runs */
    cdb_query_writer_init(&w, buf, sizeof buf);
    cdb_query_write_expr_call(&w, CDB_FN_SIN, 0);
    len = cdb_query_writer_len(&w);
    p = buf; end = buf + len;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_read_expr(&p, end, &e));
    TEST_ASSERT_EQUAL_UINT16(0, e.as.call.n_args);
    p = buf;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_skip_expr(&p, end));
}

/* read_expr + skip_expr should match on every rejectable expression. */
static void expect_expr_reject(const uint8_t *buf, size_t len, const char *what)
{
    const uint8_t *p = buf;
    cdb_query_expr e;
    TEST_ASSERT_EQUAL_INT_MESSAGE(CDB_E_INVALID_ARG,
        cdb_query_read_expr(&p, buf + len, &e), what);
    p = buf;
    TEST_ASSERT_EQUAL_INT_MESSAGE(CDB_E_INVALID_ARG,
        cdb_query_skip_expr(&p, buf + len), what);
}

static void test_expr_semantic_rejects(void)
{
    /* empty (*p >= end) */
    { static const uint8_t b[] = {0x00u};
      const uint8_t *p = b; cdb_query_expr e;
      TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_query_read_expr(&p, b, &e)); /* end == p */
      p = b;
      TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_query_skip_expr(&p, b)); }
    /* unknown expr tag */
    { static const uint8_t b[] = {0xAAu};
      expect_expr_reject(b, sizeof b, "unknown expr tag"); }
    /* PARAM bad kind */
    { static const uint8_t b[] = {CDB_QUERY_EXPR_PARAM, 0xFFu};
      expect_expr_reject(b, sizeof b, "param bad kind"); }
    /* UNARY bad op */
    { static const uint8_t b[] = {CDB_QUERY_EXPR_UNARY, 0xFFu};
      expect_expr_reject(b, sizeof b, "unary bad op"); }
    /* BINARY bad op */
    { static const uint8_t b[] = {CDB_QUERY_EXPR_BINARY, 0xFFu};
      expect_expr_reject(b, sizeof b, "binary bad op"); }
    /* LITERAL length exceeds buffer */
    { static const uint8_t b[] = {CDB_QUERY_EXPR_LITERAL, 0x05u, 0x01u};
      expect_expr_reject(b, sizeof b, "literal truncated"); }
    /* CALL n_args=1 but no arg bytes */
    { static const uint8_t b[] = {CDB_QUERY_EXPR_CALL, 0x01u, 0x01u};
      expect_expr_reject(b, sizeof b, "call missing arg"); }
    /* UNARY recursion: operand literal claims 5 bytes, buffer has none */
    { static const uint8_t b[] = {CDB_QUERY_EXPR_UNARY, CDB_UNARY_NOT,
          CDB_QUERY_EXPR_LITERAL, 0x05u};
      expect_expr_reject(b, sizeof b, "unary operand truncated"); }
    /* BINARY recursion: left Field OK, right Field claims 5 bytes with none */
    { static const uint8_t b[] = {CDB_QUERY_EXPR_BINARY, CDB_BIN_EQ,
          CDB_QUERY_EXPR_FIELD, 0x01u, 'a',
          CDB_QUERY_EXPR_FIELD, 0x05u};
      expect_expr_reject(b, sizeof b, "binary right truncated"); }
}

/* The literal value-validate branch: read_expr accepts raw bytes (no value
 * check), but skip_expr rejects an embedded blob that is not a canonical
 * cdb_value in either byte order. */
static void test_literal_value_validation(void)
{
    static const uint8_t bad[] = {CDB_QUERY_EXPR_LITERAL, 0x01u, 0xFFu};
    const uint8_t *p = bad;
    const uint8_t *end = bad + sizeof bad;
    cdb_query_expr e;

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_query_read_expr(&p, end, &e)); /* no value check */
    TEST_ASSERT_EQUAL_UINT8(CDB_QUERY_EXPR_LITERAL, e.tag);
    TEST_ASSERT_EQUAL_size_t(1, e.as.literal.len);

    p = bad;
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_query_skip_expr(&p, end)); /* value check fails */
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_writer_arg_validation);
    RUN_TEST(test_validate_and_read_all_node_tags);
    RUN_TEST(test_read_untested_node_fields);
    RUN_TEST(test_truncation_sweeps);
    RUN_TEST(test_node_semantic_rejects);
    RUN_TEST(test_read_and_skip_all_expr_tags);
    RUN_TEST(test_expr_semantic_rejects);
    RUN_TEST(test_literal_value_validation);
    return UNITY_END();
}
