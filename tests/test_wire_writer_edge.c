/* Coverage for the CMBQL wire encoders in cdb_query.c and cdb_proc.c. The query
 * plan writers (cdb_query_write_*) and the proc bytecode emitters
 * (cdb_proc_write_*) each have two under-tested branches: the success append and
 * the buffer-too-small error propagation from w_byte/w_str/w_b. This drives every
 * encoder once on an ample buffer (success) and once on a zero/short buffer
 * (fail-closed -> CDB_E_BUFFER_TOO_SMALL), plus the NULL-argument guards and the
 * proc writer's own too-small-buffer init guard. Pure encoders, no DB. Spec 19
 * (query wire) + spec 21 (proc bytecode). */
#include "unity.h"
#include "cdb_query.h"
#include "cdb_proc.h"

#include <string.h>

static uint8_t big[8192];
static uint8_t tiny[16];

void setUp(void) {}
void tearDown(void) {}

#define QOK(call)  TEST_ASSERT_EQUAL_INT_MESSAGE(CDB_OK, (call), #call)
/* re-init a zero-capacity writer, then the encoder must fail closed */
#define QERR(expr)                                   \
    do {                                             \
        cdb_query_writer w_;                         \
        cdb_query_writer_init(&w_, tiny, 0);         \
        TEST_ASSERT_EQUAL_INT_MESSAGE(CDB_E_BUFFER_TOO_SMALL, (expr), #expr); \
    } while (0)

static void test_query_writers_success(void)
{
    static const uint8_t lit[] = {0x01, 0x02, 0x03};
    cdb_query_writer w;
    cdb_query_writer_init(&w, big, sizeof big);

    QOK(cdb_query_write_scan(&w, "store", 5));
    QOK(cdb_query_write_filter(&w));
    QOK(cdb_query_write_project(&w, 0, 1));
    QOK(cdb_query_write_project_output(&w, "a", 1));
    QOK(cdb_query_write_join(&w, CDB_JOIN_INNER));
    QOK(cdb_query_write_sort(&w, 1));
    QOK(cdb_query_write_sort_key_suffix(&w, CDB_SORT_ASC, CDB_NULLS_FIRST));
    QOK(cdb_query_write_limit(&w, 10, 0));
    QOK(cdb_query_write_union(&w, 2));
    QOK(cdb_query_write_aggregate(&w, 1, 1));
    QOK(cdb_query_write_aggregate_output(&w, "c", 1, CDB_AGG_COUNT));
    QOK(cdb_query_write_traverse(&w, "lt", 2, CDB_TRAVERSE_FWD, 1, 3));
    QOK(cdb_query_write_text_search(&w, CDB_QUERY_FTS_ANY, 10, "q", 1, 1));
    QOK(cdb_query_write_field_name(&w, "f", 1));
    QOK(cdb_query_write_vector_search(&w, "v", 1, 5, CDB_QUERY_METRIC_DOT));
    QOK(cdb_query_write_hybrid_rank(&w, CDB_FUSE_RRF, 2));
    QOK(cdb_query_write_branch_weight(&w, 1));
    QOK(cdb_query_write_window(&w, CDB_WINDOW_TUMBLING, "t", 1, 1000, 100));
    QOK(cdb_query_write_asof_join(&w, CDB_ASOF_BACKWARD, 100));
    QOK(cdb_query_write_unnest(&w, "i", 1, "j", 1));
    QOK(cdb_query_write_expr_literal(&w, lit, sizeof lit));
    QOK(cdb_query_write_expr_field(&w, "p", 1));
    QOK(cdb_query_write_expr_param_index(&w, 0));
    QOK(cdb_query_write_expr_param_named(&w, "n", 1));
    QOK(cdb_query_write_expr_unary(&w, CDB_UNARY_NOT));
    QOK(cdb_query_write_expr_binary(&w, CDB_BIN_AND));
    QOK(cdb_query_write_expr_call(&w, 0, 0));

    TEST_ASSERT_TRUE(cdb_query_writer_len(&w) > 0);
}

static void test_query_writers_buffer_too_small(void)
{
    static const uint8_t lit[] = {0x01};
    QERR(cdb_query_write_scan(&w_, "store", 5));
    QERR(cdb_query_write_filter(&w_));
    QERR(cdb_query_write_project(&w_, 0, 1));
    QERR(cdb_query_write_project_output(&w_, "a", 1));
    QERR(cdb_query_write_join(&w_, CDB_JOIN_INNER));
    QERR(cdb_query_write_sort(&w_, 1));
    QERR(cdb_query_write_sort_key_suffix(&w_, CDB_SORT_ASC, CDB_NULLS_FIRST));
    QERR(cdb_query_write_limit(&w_, 10, 0));
    QERR(cdb_query_write_union(&w_, 2));
    QERR(cdb_query_write_aggregate(&w_, 1, 1));
    QERR(cdb_query_write_aggregate_output(&w_, "c", 1, CDB_AGG_COUNT));
    QERR(cdb_query_write_traverse(&w_, "lt", 2, CDB_TRAVERSE_FWD, 1, 3));
    QERR(cdb_query_write_text_search(&w_, CDB_QUERY_FTS_ANY, 10, "q", 1, 1));
    QERR(cdb_query_write_field_name(&w_, "f", 1));
    QERR(cdb_query_write_vector_search(&w_, "v", 1, 5, CDB_QUERY_METRIC_DOT));
    QERR(cdb_query_write_hybrid_rank(&w_, CDB_FUSE_RRF, 2));
    QERR(cdb_query_write_branch_weight(&w_, 1));
    QERR(cdb_query_write_window(&w_, CDB_WINDOW_TUMBLING, "t", 1, 1000, 100));
    QERR(cdb_query_write_asof_join(&w_, CDB_ASOF_BACKWARD, 100));
    QERR(cdb_query_write_unnest(&w_, "i", 1, "j", 1));
    QERR(cdb_query_write_expr_literal(&w_, lit, sizeof lit));
    QERR(cdb_query_write_expr_field(&w_, "p", 1));
    QERR(cdb_query_write_expr_param_index(&w_, 0));
    QERR(cdb_query_write_expr_param_named(&w_, "n", 1));
    QERR(cdb_query_write_expr_unary(&w_, CDB_UNARY_NOT));
    QERR(cdb_query_write_expr_binary(&w_, CDB_BIN_AND));
    QERR(cdb_query_write_expr_call(&w_, 0, 0));
}

static void test_query_writer_null_guards(void)
{
    cdb_query_writer w;
    cdb_query_writer_init(&w, big, sizeof big);
    /* store_name NULL with non-zero len is an invalid argument */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_query_write_scan(&w, NULL, 5));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_query_write_join(&w, 0xFF)); /* invalid join kind */
}

static void test_proc_emitters_success(void)
{
    static const uint8_t cst[] = {0x00};
    static const uint8_t args[] = {0x01, 0x02};
    static const uint8_t wire[] = {0x10, 0x20, 0x30};
    cdb_proc_writer w;
    cdb_proc_writer_init(&w, big, sizeof big, 8, 2);

    QOK(cdb_proc_write_load_const(&w, 0, cst, sizeof cst));
    QOK(cdb_proc_write_load_param(&w, 1, 0));
    QOK(cdb_proc_write_move(&w, 2, 1));
    QOK(cdb_proc_write_jump(&w, 2));
    QOK(cdb_proc_write_jump_if_true(&w, 0, 1));
    QOK(cdb_proc_write_jump_if_false(&w, 0, 1));
    QOK(cdb_proc_write_call_math(&w, 3, 0, 2, args));
    QOK(cdb_proc_write_call_mutation(&w, 4, 0, 0, 1, 2));
    QOK(cdb_proc_write_call_mutation_ex(&w, 4, 0, 2, args));
    QOK(cdb_proc_write_open_cursor(&w, 0, wire, sizeof wire));
    QOK(cdb_proc_write_cursor_next(&w, 5, 6, 0));
    QOK(cdb_proc_write_cursor_close(&w, 0));
    QOK(cdb_proc_write_savepoint(&w, 1));
    QOK(cdb_proc_write_rollback_to(&w, 1));
    QOK(cdb_proc_write_release_sp(&w, 1));
    QOK(cdb_proc_write_return(&w, 0));
    QOK(cdb_proc_write_halt(&w));
    QOK(cdb_proc_writer_finish(&w));

    TEST_ASSERT_TRUE(cdb_proc_writer_len(&w) > 0);
}

static void test_proc_emitters_buffer_too_small(void)
{
    static const uint8_t cst[] = {0x00};
    cdb_proc_writer w;
    /* init OK (>= header+1) but no room for any instruction body */
    cdb_proc_writer_init(&w, big, 9, 2, 1);
    /* the first emitter overflows and must fail closed */
    TEST_ASSERT_EQUAL_INT(CDB_E_BUFFER_TOO_SMALL, cdb_proc_write_load_const(&w, 0, cst, sizeof cst));
}

static void test_proc_writer_init_too_small(void)
{
    cdb_proc_writer w;
    /* cap below the fixed header is rejected at init; a later emit still errors */
    cdb_proc_writer_init(&w, big, 4, 1, 0);
    TEST_ASSERT_EQUAL_INT(CDB_E_BUFFER_TOO_SMALL, cdb_proc_write_halt(&w));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_query_writers_success);
    RUN_TEST(test_query_writers_buffer_too_small);
    RUN_TEST(test_query_writer_null_guards);
    RUN_TEST(test_proc_emitters_success);
    RUN_TEST(test_proc_emitters_buffer_too_small);
    RUN_TEST(test_proc_writer_init_too_small);
    return UNITY_END();
}
