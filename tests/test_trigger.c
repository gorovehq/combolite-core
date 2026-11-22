/* Event triggers (spec 11.6, 11.9) — registry, and #35: real dispatch that
 * actually executes the registered procedure (marshalling old/new row values,
 * honouring the depth/cascade limit, fail-closed on error).
 *
 * The dispatch tests are red -> green against the pre-#35 code: cdb_trigger_dispatch
 * used to (void)-discard db/old/new and only bump a counter, so last_proc_ran was
 * never set and no procedure ran. These assert the procedure actually executed. */
#include "unity.h"
#include "cdb_trigger.h"
#include "cdb_db.h"
#include "cdb_proc.h"
#include "cdb_eval.h"
#include "combolite/cdb_value.h"
#include <string.h>

void setUp(void) {}
void tearDown(void) {}

/* Encode an integer cdb_value literal for LOAD_CONST. */
static size_t make_int_literal(uint8_t *buf, size_t cap, int64_t v)
{
    cdb_value_writer vw;
    cdb_value_writer_init(&vw, buf, cap, CDB_ORDER_LITTLE, CDB_DECIMAL_COMPACT);
    cdb_value_write_int(&vw, v);
    return cdb_value_writer_len(&vw);
}

/* Build a proc that returns a constant int: R0 = const; RETURN R0. */
static size_t build_const_proc(uint8_t *bc, size_t cap, int64_t v)
{
    uint8_t lit[16];
    size_t lit_len = make_int_literal(lit, sizeof lit, v);
    cdb_proc_writer w;
    cdb_proc_writer_init(&w, bc, cap, 4, 2);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_proc_write_load_const(&w, 0, lit, lit_len));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_proc_write_return(&w, 0));
    return cdb_proc_writer_len(&w);
}

/* Build a proc that echoes a parameter: R0 = param[idx]; RETURN R0. */
static size_t build_echo_param_proc(uint8_t *bc, size_t cap, uint8_t idx)
{
    cdb_proc_writer w;
    cdb_proc_writer_init(&w, bc, cap, 4, 2);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_proc_write_load_param(&w, 0, idx));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_proc_write_return(&w, 0));
    return cdb_proc_writer_len(&w);
}

/* Build a proc that errors at runtime (CALL_MATH with too few args). */
static size_t build_error_proc(uint8_t *bc, size_t cap)
{
    uint8_t args[1] = {0};
    cdb_proc_writer w;
    cdb_proc_writer_init(&w, bc, cap, 4, 2);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_proc_write_call_math(&w, 1, CDB_FN_HAVERSINE, 1, args));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_proc_write_return(&w, 1));
    return cdb_proc_writer_len(&w);
}

static void test_trigger_register_and_unregister(void)
{
    cdb_trigger_registry reg;
    cdb_trigger_registry_init(&reg, NULL, 50);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_trigger_register(&reg, "trg_books", 9, 101,
                                                       CDB_TRIGGER_AFTER_INSERT, "audit_fn", 8, 8));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_trigger_register(&reg, "trg_users", 9, 102,
                                                       CDB_TRIGGER_AFTER_UPDATE, "notify_fn", 9, 5));

    /* Duplicate registration */
    TEST_ASSERT_EQUAL_INT(CDB_E_EXISTS, cdb_trigger_register(&reg, "trg_books", 9, 101,
                                                             CDB_TRIGGER_AFTER_INSERT, "other_fn",
                                                             8, 8));

    /* Unregister */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_trigger_unregister(&reg, "trg_books", 9));
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_trigger_unregister(&reg, "trg_books", 9));
    TEST_ASSERT_EQUAL_UINT(1, reg.n_triggers);
}

/* #35: a dispatched trigger actually runs its registered procedure (red->green:
 * last_proc_ran was never set by the old no-op dispatch). */
static void test_trigger_fires_registered_proc(void)
{
    cdb_trigger_registry reg;
    uint8_t bc[128];
    size_t bclen;
    cdb_trigger_registry_init(&reg, NULL, 100);

    bclen = build_const_proc(bc, sizeof bc, 42);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_trigger_register_proc(&reg, "audit_fn", 8, bc, bclen));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_trigger_register(&reg, "trg", 3, 101,
                                                       CDB_TRIGGER_AFTER_INSERT, "audit_fn", 8, 8));

    TEST_ASSERT_EQUAL_INT(0, reg.last_proc_ran);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_trigger_dispatch(&reg, NULL, 101, CDB_TRIGGER_AFTER_INSERT,
                                                       NULL, NULL, 0));
    /* The procedure actually executed and returned 42. */
    TEST_ASSERT_EQUAL_INT(1, reg.last_proc_ran);
    TEST_ASSERT_EQUAL_INT(CDB_TYPE_INT, reg.last_proc_ret.type);
    TEST_ASSERT_EQUAL_INT64(42, reg.last_proc_ret.as.i64);
    TEST_ASSERT_EQUAL_UINT64(1, reg.total_dispatched);
}

/* #35 (AC6): old/new row values are marshalled into the procedure's params. */
static void test_trigger_marshals_old_new(void)
{
    cdb_trigger_registry reg;
    uint8_t bc[128];
    size_t bclen;
    cdb_value oldv, newv;
    cdb_trigger_registry_init(&reg, NULL, 100);

    /* param[1] is the new value; echo it back. */
    bclen = build_echo_param_proc(bc, sizeof bc, 1);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_trigger_register_proc(&reg, "p", 1, bc, bclen));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_trigger_register(&reg, "t", 1, 7,
                                                       CDB_TRIGGER_AFTER_UPDATE, "p", 1, 8));

    cdb_eval_make_int(&oldv, 100);
    cdb_eval_make_int(&newv, 200);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_trigger_dispatch(&reg, NULL, 7, CDB_TRIGGER_AFTER_UPDATE,
                                                       &oldv, &newv, 0));
    TEST_ASSERT_EQUAL_INT(1, reg.last_proc_ran);
    TEST_ASSERT_EQUAL_INT64(200, reg.last_proc_ret.as.i64); /* saw the NEW value */

    /* param[0] is the old value. */
    bclen = build_echo_param_proc(bc, sizeof bc, 0);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_trigger_register_proc(&reg, "p", 1, bc, bclen));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_trigger_dispatch(&reg, NULL, 7, CDB_TRIGGER_AFTER_UPDATE,
                                                       &oldv, &newv, 0));
    TEST_ASSERT_EQUAL_INT64(100, reg.last_proc_ret.as.i64); /* saw the OLD value */
}

/* #35 (AC7): the per-trigger depth/cascade limit stops dispatch before exec. */
static void test_trigger_depth_limit_protection(void)
{
    cdb_trigger_registry reg;
    uint8_t bc[128];
    size_t bclen;
    cdb_trigger_registry_init(&reg, NULL, 100);

    bclen = build_const_proc(bc, sizeof bc, 1);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_trigger_register_proc(&reg, "proc_step", 9, bc, bclen));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_trigger_register(&reg, "deep_trg", 8, 201,
                                                       CDB_TRIGGER_AFTER_INSERT, "proc_step", 9, 8));

    /* Depths within budget run the proc. */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_trigger_dispatch(&reg, NULL, 201, CDB_TRIGGER_AFTER_INSERT,
                                                       NULL, NULL, 0));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_trigger_dispatch(&reg, NULL, 201, CDB_TRIGGER_AFTER_INSERT,
                                                       NULL, NULL, 7));

    /* Depth at/above the limit (8) fails closed before executing the proc. */
    TEST_ASSERT_EQUAL_INT(CDB_E_OUT_OF_BUDGET, cdb_trigger_dispatch(&reg, NULL, 201,
                                                                    CDB_TRIGGER_AFTER_INSERT, NULL,
                                                                    NULL, 8));
    TEST_ASSERT_EQUAL_INT(CDB_E_OUT_OF_BUDGET, cdb_trigger_dispatch(&reg, NULL, 201,
                                                                    CDB_TRIGGER_AFTER_INSERT, NULL,
                                                                    NULL, 10));
}

/* #35 (FR-B4/AC8): a trigger procedure error is surfaced, not swallowed. */
static void test_trigger_proc_error_fail_closed(void)
{
    cdb_trigger_registry reg;
    uint8_t bc[128];
    size_t bclen;
    cdb_trigger_registry_init(&reg, NULL, 100);

    bclen = build_error_proc(bc, sizeof bc);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_trigger_register_proc(&reg, "bad", 3, bc, bclen));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_trigger_register(&reg, "t", 1, 5,
                                                       CDB_TRIGGER_AFTER_DELETE, "bad", 3, 8));

    /* The procedure's runtime error propagates as the dispatch status. */
    TEST_ASSERT_EQUAL_INT(CDB_E_MALFORMED, cdb_trigger_dispatch(&reg, NULL, 5,
                                                                CDB_TRIGGER_AFTER_DELETE, NULL,
                                                                NULL, 0));
}

/* #35: a trigger naming an unregistered procedure fails closed (not silently
 * skipped), so a misconfiguration cannot pass unnoticed. */
static void test_trigger_missing_proc_fail_closed(void)
{
    cdb_trigger_registry reg;
    cdb_trigger_registry_init(&reg, NULL, 100);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_trigger_register(&reg, "t", 1, 9,
                                                       CDB_TRIGGER_AFTER_INSERT, "ghost", 5, 8));
    TEST_ASSERT_EQUAL_INT(CDB_E_NOT_FOUND, cdb_trigger_dispatch(&reg, NULL, 9,
                                                                CDB_TRIGGER_AFTER_INSERT, NULL,
                                                                NULL, 0));
}

static void test_trigger_cascade_warning(void)
{
    cdb_trigger_registry reg;
    uint8_t bc[128];
    size_t bclen;
    cdb_trigger_registry_init(&reg, NULL, 5); /* threshold = 5 */

    bclen = build_const_proc(bc, sizeof bc, 1);
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_trigger_register_proc(&reg, "log_fn", 6, bc, bclen));
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_trigger_register(&reg, "casc_trg", 8, 301,
                                                       CDB_TRIGGER_AFTER_INSERT, "log_fn", 6, 8));

    TEST_ASSERT_EQUAL_INT(0, reg.cascade_warning_issued);
    for (int i = 0; i < 4; i++) {
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_trigger_dispatch(&reg, NULL, 301,
                                                           CDB_TRIGGER_AFTER_INSERT, NULL, NULL, 0));
    }
    TEST_ASSERT_EQUAL_INT(0, reg.cascade_warning_issued);

    /* 5th dispatch hits threshold */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_trigger_dispatch(&reg, NULL, 301, CDB_TRIGGER_AFTER_INSERT,
                                                       NULL, NULL, 0));
    TEST_ASSERT_EQUAL_INT(1, reg.cascade_warning_issued);
}

static void dummy_maintenance_task(cdb_db *db, void *arg)
{
    (void)db;
    int *counter = (int *)arg;
    (*counter)++;
}

static void test_scheduled_maintenance_tick(void)
{
    cdb_trigger_registry reg;
    int task_runs = 0;
    cdb_trigger_registry_init(&reg, NULL, 100);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_schedule_register(&reg, "maint_cleanup", 13, 1000,
                                                        dummy_maintenance_task, &task_runs));

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_schedule_tick(&reg, NULL, 500));
    TEST_ASSERT_EQUAL_INT(0, task_runs);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_schedule_tick(&reg, NULL, 1200));
    TEST_ASSERT_EQUAL_INT(1, task_runs);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_schedule_tick(&reg, NULL, 1600));
    TEST_ASSERT_EQUAL_INT(1, task_runs);

    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_schedule_tick(&reg, NULL, 2300));
    TEST_ASSERT_EQUAL_INT(2, task_runs);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_trigger_register_and_unregister);
    RUN_TEST(test_trigger_fires_registered_proc);
    RUN_TEST(test_trigger_marshals_old_new);
    RUN_TEST(test_trigger_depth_limit_protection);
    RUN_TEST(test_trigger_proc_error_fail_closed);
    RUN_TEST(test_trigger_missing_proc_fail_closed);
    RUN_TEST(test_trigger_cascade_warning);
    RUN_TEST(test_scheduled_maintenance_tick);
    return UNITY_END();
}
