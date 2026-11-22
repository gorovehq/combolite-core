/* combolite-core #35 (sub-feature B) — QA edge/abuse for the real trigger
 * dispatch + proc registry. Complements tests/test_trigger.c (fires/marshal/
 * depth/proc-error). Registry-only and hermetic: exercises the matching,
 * resource-bound, and fail-closed behaviour of cdb_trigger_dispatch /
 * cdb_trigger_register_proc without needing a live database.
 *
 * Focus:
 *   - event-mask and store matching (only the right event on the right store
 *     fires; non-matching dispatch is a clean no-op, not a silent error);
 *   - multiple triggers on one store all fire (dispatch counts each);
 *   - proc registry limits: table full, bytecode too large, bad args, and
 *     in-place replacement by name;
 *   - a custom per-trigger max_depth boundary (fires below, budgets at limit);
 *   - total_dispatched accounting. */
#include "unity.h"
#include "cdb_trigger.h"
#include "cdb_db.h"
#include "cdb_proc.h"
#include "cdb_eval.h"
#include "combolite/cdb_value.h"
#include <string.h>

void setUp(void) {}
void tearDown(void) {}

/* R0 = const int; RETURN R0. */
static size_t build_const_proc(uint8_t *bc, size_t cap, int64_t v)
{
    uint8_t lit[16];
    cdb_value_writer vw;
    cdb_proc_writer w;
    size_t lit_len;
    cdb_value_writer_init(&vw, lit, sizeof lit, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_write_int(&vw, v);
    lit_len = cdb_value_writer_len(&vw);
    cdb_proc_writer_init(&w, bc, cap, 4, 2);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_proc_write_load_const(&w, 0, lit, lit_len));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_proc_write_return(&w, 0));
    return cdb_proc_writer_len(&w);
}

/* A trigger armed for INSERT does not fire on UPDATE/DELETE, and a clean
 * non-match returns CDB_OK (no silent error, no proc run). */
static void test_event_mask_only_matching_fires(void)
{
    cdb_trigger_registry reg;
    uint8_t bc[64];
    size_t bclen;
    cdb_trigger_registry_init(&reg, NULL, 1000);

    bclen = build_const_proc(bc, sizeof bc, 5);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_trigger_register_proc(&reg, "p", 1, bc, bclen));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_trigger_register(&reg, "t", 1, 42, CDB_TRIGGER_AFTER_INSERT,
                                                       "p", 1, 8));

    /* Wrong event -> clean no-op. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_trigger_dispatch(&reg, NULL, 42, CDB_TRIGGER_AFTER_UPDATE,
                                                       NULL, NULL, 0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_trigger_dispatch(&reg, NULL, 42, CDB_TRIGGER_AFTER_DELETE,
                                                       NULL, NULL, 0));
    TEST_ASSERT_EQUAL_INT(0, reg.last_proc_ran);
    TEST_ASSERT_EQUAL_UINT64(0, reg.total_dispatched);

    /* Wrong store -> clean no-op. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_trigger_dispatch(&reg, NULL, 99, CDB_TRIGGER_AFTER_INSERT,
                                                       NULL, NULL, 0));
    TEST_ASSERT_EQUAL_INT(0, reg.last_proc_ran);

    /* Right store + event -> fires. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_trigger_dispatch(&reg, NULL, 42, CDB_TRIGGER_AFTER_INSERT,
                                                       NULL, NULL, 0));
    TEST_ASSERT_EQUAL_INT(1, reg.last_proc_ran);
    TEST_ASSERT_EQUAL_UINT64(1, reg.total_dispatched);
}

/* A trigger armed for INSERT|UPDATE fires on either member of the mask. */
static void test_multi_event_mask(void)
{
    cdb_trigger_registry reg;
    uint8_t bc[64];
    size_t bclen;
    cdb_trigger_registry_init(&reg, NULL, 1000);

    bclen = build_const_proc(bc, sizeof bc, 1);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_trigger_register_proc(&reg, "p", 1, bc, bclen));
    TEST_ASSERT_EQUAL_INT(CDB_OK,
                          cdb_trigger_register(&reg, "t", 1, 7,
                                               CDB_TRIGGER_AFTER_INSERT | CDB_TRIGGER_AFTER_UPDATE,
                                               "p", 1, 8));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_trigger_dispatch(&reg, NULL, 7, CDB_TRIGGER_AFTER_INSERT,
                                                       NULL, NULL, 0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_trigger_dispatch(&reg, NULL, 7, CDB_TRIGGER_AFTER_UPDATE,
                                                       NULL, NULL, 0));
    TEST_ASSERT_EQUAL_UINT64(2, reg.total_dispatched);
    /* But not on DELETE. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_trigger_dispatch(&reg, NULL, 7, CDB_TRIGGER_AFTER_DELETE,
                                                       NULL, NULL, 0));
    TEST_ASSERT_EQUAL_UINT64(2, reg.total_dispatched);
}

/* Two triggers on one store+event both fire on a single dispatch. */
static void test_two_triggers_same_store_both_fire(void)
{
    cdb_trigger_registry reg;
    uint8_t bc1[64], bc2[64];
    size_t l1, l2;
    cdb_trigger_registry_init(&reg, NULL, 1000);

    l1 = build_const_proc(bc1, sizeof bc1, 11);
    l2 = build_const_proc(bc2, sizeof bc2, 22);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_trigger_register_proc(&reg, "a", 1, bc1, l1));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_trigger_register_proc(&reg, "b", 1, bc2, l2));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_trigger_register(&reg, "t1", 2, 300,
                                                       CDB_TRIGGER_AFTER_INSERT, "a", 1, 8));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_trigger_register(&reg, "t2", 2, 300,
                                                       CDB_TRIGGER_AFTER_INSERT, "b", 1, 8));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_trigger_dispatch(&reg, NULL, 300, CDB_TRIGGER_AFTER_INSERT,
                                                       NULL, NULL, 0));
    /* Both triggers ran: the counter advanced by two in one dispatch call. */
    TEST_ASSERT_EQUAL_UINT64(2, reg.total_dispatched);
    TEST_ASSERT_EQUAL_INT(1, reg.last_proc_ran);
}

/* A per-trigger custom max_depth governs the fail-closed boundary. */
static void test_custom_max_depth_boundary(void)
{
    cdb_trigger_registry reg;
    uint8_t bc[64];
    size_t bclen;
    cdb_trigger_registry_init(&reg, NULL, 1000);

    bclen = build_const_proc(bc, sizeof bc, 1);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_trigger_register_proc(&reg, "p", 1, bc, bclen));
    /* max_depth = 3 */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_trigger_register(&reg, "t", 1, 1, CDB_TRIGGER_AFTER_INSERT,
                                                       "p", 1, 3));

    /* Below the limit fires. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_trigger_dispatch(&reg, NULL, 1, CDB_TRIGGER_AFTER_INSERT,
                                                       NULL, NULL, 2));
    /* At the limit fails closed before executing the proc. */
    TEST_ASSERT_EQUAL_INT(CDB_E_OUT_OF_BUDGET,
                          cdb_trigger_dispatch(&reg, NULL, 1, CDB_TRIGGER_AFTER_INSERT, NULL, NULL,
                                               3));
    TEST_ASSERT_EQUAL_INT(CDB_E_OUT_OF_BUDGET,
                          cdb_trigger_dispatch(&reg, NULL, 1, CDB_TRIGGER_AFTER_INSERT, NULL, NULL,
                                               4));
}

/* register_proc argument validation. */
static void test_register_proc_bad_args(void)
{
    cdb_trigger_registry reg;
    uint8_t bc[16];
    size_t bclen;
    cdb_trigger_registry_init(&reg, NULL, 1000);
    bclen = build_const_proc(bc, sizeof bc, 1);

    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
                          cdb_trigger_register_proc(&reg, NULL, 1, bc, bclen));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
                          cdb_trigger_register_proc(&reg, "p", 0, bc, bclen));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
                          cdb_trigger_register_proc(&reg, "p", 1, NULL, bclen));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
                          cdb_trigger_register_proc(&reg, "p", 1, bc, 0));
}

/* Bytecode larger than the inline cap is rejected (no-heap bound). */
static void test_register_proc_bytecode_too_large(void)
{
    cdb_trigger_registry reg;
    static uint8_t big[CDB_TRIGGER_PROC_BYTECODE_CAP + 1];
    cdb_trigger_registry_init(&reg, NULL, 1000);
    memset(big, 0, sizeof big);
    TEST_ASSERT_EQUAL_INT(CDB_E_BUFFER_TOO_SMALL,
                          cdb_trigger_register_proc(&reg, "p", 1, big, sizeof big));
}

/* The proc table is bounded; the (CDB_TRIGGER_MAX_PROCS+1)-th distinct proc
 * fails closed rather than overflowing. */
static void test_register_proc_table_full(void)
{
    cdb_trigger_registry reg;
    uint8_t bc[32];
    size_t bclen;
    char name[8];
    unsigned i;
    cdb_trigger_registry_init(&reg, NULL, 1000);
    bclen = build_const_proc(bc, sizeof bc, 1);

    for (i = 0; i < CDB_TRIGGER_MAX_PROCS; i++) {
        name[0] = (char)('a' + i);
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_trigger_register_proc(&reg, name, 1, bc, bclen));
    }
    name[0] = 'z';
    TEST_ASSERT_EQUAL_INT(CDB_E_BUFFER_TOO_SMALL,
                          cdb_trigger_register_proc(&reg, name, 1, bc, bclen));
}

/* Re-registering a proc under an existing name replaces its bytecode in place
 * (does not consume another table slot) and the new behaviour takes effect. */
static void test_register_proc_replace_in_place(void)
{
    cdb_trigger_registry reg;
    uint8_t bc[64];
    size_t bclen;
    cdb_trigger_registry_init(&reg, NULL, 1000);

    bclen = build_const_proc(bc, sizeof bc, 100);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_trigger_register_proc(&reg, "p", 1, bc, bclen));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_trigger_register(&reg, "t", 1, 1, CDB_TRIGGER_AFTER_INSERT,
                                                       "p", 1, 8));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_trigger_dispatch(&reg, NULL, 1, CDB_TRIGGER_AFTER_INSERT,
                                                       NULL, NULL, 0));
    TEST_ASSERT_EQUAL_INT64(100, reg.last_proc_ret.as.i64);

    /* Replace: same name, new constant. */
    bclen = build_const_proc(bc, sizeof bc, 200);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_trigger_register_proc(&reg, "p", 1, bc, bclen));
    TEST_ASSERT_EQUAL_UINT(1, reg.n_procs); /* still a single slot */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_trigger_dispatch(&reg, NULL, 1, CDB_TRIGGER_AFTER_INSERT,
                                                       NULL, NULL, 0));
    TEST_ASSERT_EQUAL_INT64(200, reg.last_proc_ret.as.i64);
}

/* The trigger table is bounded; the (CDB_MAX_TRIGGERS+1)-th fails closed. */
static void test_trigger_table_full(void)
{
    cdb_trigger_registry reg;
    char name[16];
    unsigned i;
    int w;
    cdb_trigger_registry_init(&reg, NULL, 1000);

    for (i = 0; i < CDB_MAX_TRIGGERS; i++) {
        w = snprintf(name, sizeof name, "t%u", i);
        TEST_ASSERT_TRUE(w > 0);
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_trigger_register(&reg, name, (size_t)w, 1,
                                                           CDB_TRIGGER_AFTER_INSERT, "p", 1, 8));
    }
    w = snprintf(name, sizeof name, "over");
    TEST_ASSERT_EQUAL_INT(CDB_E_BUFFER_TOO_SMALL,
                          cdb_trigger_register(&reg, name, (size_t)w, 1, CDB_TRIGGER_AFTER_INSERT,
                                               "p", 1, 8));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_event_mask_only_matching_fires);
    RUN_TEST(test_multi_event_mask);
    RUN_TEST(test_two_triggers_same_store_both_fire);
    RUN_TEST(test_custom_max_depth_boundary);
    RUN_TEST(test_register_proc_bad_args);
    RUN_TEST(test_register_proc_bytecode_too_large);
    RUN_TEST(test_register_proc_table_full);
    RUN_TEST(test_register_proc_replace_in_place);
    RUN_TEST(test_trigger_table_full);
    return UNITY_END();
}
