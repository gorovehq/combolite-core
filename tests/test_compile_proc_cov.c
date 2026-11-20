/* Branch-coverage set for cdb_compile_proc (agent-authored, increment 3 of the
 * #18 coverage ratchet). Complements tests/test_compile_coverage.c (the SQL-form
 * happy-path statement matrix) by driving the *alternate* syntax forms and
 * error/edge branches it leaves cold: the function-call forms of the mutation
 * statements (compact()/reclaim()/reconcile()/set_peer()/sync()/check_rotation()/
 * check_perm()/rotate()/create_enclave()/open_enclave()/register_principal()/
 * grant_role()/drop_*()/create_*()/add_schema()/append()/prune()/set_retention()/
 * apply_retention()/free_blob()/update()/delete()/insert()/vec_insert()), the SQL
 * forms of LINK / REINFORCE / UNLINK, the PEER and SET PEER / SET RETENTION
 * variants, RETURN of a literal, and the SAVEPOINT / ROLLBACK / RELEASE
 * statements. Plus explicit malformed-statement rejections with a populated
 * cdb_compile_error. Compile-only (no DB); hermetic; every value initialised at
 * declaration; abuse paths pass bad input and assert the returned status without
 * dereferencing a maybe-null result. Spec 21. */
#include "unity.h"
#include "cdb_compiler.h"
#include <string.h>

void setUp(void) {}
void tearDown(void) {}

/* Compiles the procedure script; asserts success and non-empty bytecode. */
static void ok(const char *p)
{
    uint8_t bc[4096];
    size_t n = 0;
    cdb_compile_error e;
    cdb_status s;
    memset(&e, 0, sizeof e);
    s = cdb_compile_proc(p, strlen(p), NULL, bc, sizeof bc, &n, &e);
    TEST_ASSERT_EQUAL_INT_MESSAGE(CDB_OK, s, p);
    TEST_ASSERT_TRUE_MESSAGE(n > 0, p);
}

/* Compiles the script; asserts a typed rejection with a populated message. */
static void reject(const char *p)
{
    uint8_t bc[4096];
    size_t n = 0;
    cdb_compile_error e;
    cdb_status s;
    memset(&e, 0, sizeof e);
    s = cdb_compile_proc(p, strlen(p), NULL, bc, sizeof bc, &n, &e);
    TEST_ASSERT_NOT_EQUAL_INT_MESSAGE(CDB_OK, s, p);
    TEST_ASSERT_TRUE_MESSAGE(strlen(e.msg) > 0, p);
}

static void test_return_and_savepoints(void)
{
    ok("RETURN 99;");
    ok("RETURN \"hi\";");
    ok("SAVEPOINT sp;");
    ok("ROLLBACK TO sp;");
    ok("RELEASE SAVEPOINT sp;");
}

static void test_maintenance_function_forms(void)
{
    ok("compact(10);");
    ok("reclaim();");
    ok("reconcile();");
    ok("PEER 5;");
    ok("SET PEER 7;");
    ok("set_peer(3);");
    ok("SET RETENTION TIMESERIES \"m\" SERIES 1 AGE 10;");
    ok("sync IMPORT \"s\";");
    ok("sync(\"s\");");
    ok("check_rotation();");
    ok("check_perm(1, 2, 3);");
    ok("CHECK PERM 1 SCOPE 2 PERMS 4;");
    ok("rotate(1, 2, \"env://k\");");
    ok("rotate_key(0, 0, \"env://k\");");
}

static void test_admin_function_forms(void)
{
    ok("create_enclave(1, \"env://k\");");
    ok("open_enclave(1, \"env://k\");");
    ok("register_principal(1, 1, \"ab\");");
    ok("grant_role(1, 2, 3, 4);");
    ok("drop_trigger(\"t\");");
    ok("drop_store(\"s\");");
    ok("create_trigger(\"t\", 1, 1, \"f\", 4);");
    ok("create_link_type(\"l\", 1, 1, 2);");
    ok("create_store(\"s\", 1);");
    ok("add_schema(\"s\", \"{}\");");
}

static void test_timeseries_and_blob_forms(void)
{
    ok("append(\"m\", 1, 1000, 42.5);");
    ok("prune(\"m\", 1, 500);");
    ok("set_retention(\"m\", 1, 3600);");
    ok("apply_retention(\"m\", 1, 5000);");
    ok("downsample(1, 1, 1, 2, 60, 0, 1000);");
    ok("free_blob(1, 5, 1, 1024);");
}

static void test_link_sql_forms(void)
{
    ok("LINK 1 FROM 10:100 TO 20:200 WEIGHT 1.5 TIME 5;");
    ok("REINFORCE LINK 1 FROM 10:100 TO 20:200;");
    ok("UNLINK 1 FROM 10:100 TO 20:200;");
    ok("unlink(type: 1, from: [10, 100], to: [20, 200]);");
}

static void test_crud_function_forms(void)
{
    ok("insert(\"s\", \"{}\", \"k\");");
    ok("table_insert(\"s\", \"{}\", \"k\");");
    ok("vec_insert(\"s\", \"k\", \"[1,2]\");");
    ok("update(\"s\", 1, \"{}\");");
    ok("PATCH \"s\" 1 WITH \"{}\";");
    ok("REPLACE \"s\" 1 WITH \"{}\";");
    ok("DELETE FROM \"s\" 1;");
    ok("delete(\"s\", 1);");
    ok("PROCEDURE foo($a INT, $b STRING) BEGIN LET $x = 1; RETURN $x; END;");
}

static void test_rejections(void)
{
    /* NULL / zero-capacity argument guards. */
    {
        uint8_t bc[64];
        size_t n = 0;
        cdb_compile_error e;
        memset(&e, 0, sizeof e);
        TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
            cdb_compile_proc(NULL, 0, NULL, bc, sizeof bc, &n, &e));
        TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
            cdb_compile_proc("RECLAIM;", 8, NULL, NULL, 10, &n, &e));
        TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG,
            cdb_compile_proc("RECLAIM;", 8, NULL, bc, 0, &n, &e));
    }
    /* Malformed / unterminated / unrecognized statements fail closed. */
    reject("LET $x = ;");
    reject("yield 5;");
    reject("@@@ bad;");
    reject("UPDATE \"s\" 1 WITH \"{}\";");
    reject("CREATE STORE \"x\" MODEL notamodel;");
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_return_and_savepoints);
    RUN_TEST(test_maintenance_function_forms);
    RUN_TEST(test_admin_function_forms);
    RUN_TEST(test_timeseries_and_blob_forms);
    RUN_TEST(test_link_sql_forms);
    RUN_TEST(test_crud_function_forms);
    RUN_TEST(test_rejections);
    return UNITY_END();
}
