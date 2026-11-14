/* Compile-coverage matrix: compile valid CMBQL statement variants with optional-
 * clause combinations (trigger timing/events/MAX DEPTH, link cardinalities +
 * ENFORCED/INVERSE, every store model, auth/maintenance/key statements,
 * BEGIN/COMMIT, LET/RETURN) that the single-example suites don't exercise. Drives
 * cdb_compiler parse branches + cdb_proc bytecode emitters. Compile-only (no DB).
 * Spec 19/21. */
#include "unity.h"
#include "cdb_compiler.h"
#include <string.h>

void setUp(void) {}
void tearDown(void) {}

static void ok(const char *q)
{
    uint8_t bc[4096]; size_t n = 0; cdb_compile_error e;
    memset(&e, 0, sizeof e);
    TEST_ASSERT_EQUAL_INT_MESSAGE(CDB_OK, cdb_compile_proc(q, strlen(q), NULL, bc, sizeof bc, &n, &e), q);
}

static void test_statement_variants_compile(void)
{
    ok("CREATE STORE \"a\" MODEL document;");
    ok("CREATE STORE \"a\" MODEL table;");
    ok("CREATE STORE \"a\" MODEL vector;");
    ok("CREATE STORE \"a\" MODEL timeseries;");
    ok("CREATE STORE \"a\" MODEL link;");
    ok("CREATE STORE \"a\" MODEL graph;");
    ok("CREATE LINK TYPE \"l\" CARDINALITY 1:1 ENFORCED;");
    ok("CREATE LINK TYPE \"l\" CARDINALITY 1:N;");
    ok("CREATE LINK TYPE \"l\" CARDINALITY N:M ENFORCED;");
    ok("CREATE LINK TYPE \"l\" CARDINALITY 1:N ENFORCED INVERSE 2;");
    ok("CREATE TRIGGER t ON 1 BEFORE INSERT EXECUTE \"f\";");
    ok("CREATE TRIGGER t ON 1 AFTER UPDATE EXECUTE \"f\";");
    ok("CREATE TRIGGER t ON 1 AFTER DELETE EXECUTE \"f\";");
    ok("CREATE TRIGGER t ON 1 AFTER INSERT EXECUTE \"f\" MAX DEPTH 4;");
    ok("CREATE TRIGGER t ON 1 INSTEAD OF INSERT EXECUTE \"f\";");
    ok("GRANT ROLE 1 TO 2 SCOPE 3 PERMS 1;");
    ok("GRANT ROLE 2 TO 3 SCOPE 0 PERMS 15;");
    ok("ROTATE MASTER KEY \"env://k\";");
    ok("ROTATE ENCLAVE 1 KEY \"env://k\";");
    ok("CHECK ROTATION;");
    ok("CHECK PERM 1 SCOPE 2 PERMS 4;");
    ok("COMPACT MAX 10;");
    ok("COMPACT MAX 1000;");
    ok("RECLAIM;");
    ok("RECONCILE;");
    ok("DROP STORE \"a\";");
    ok("DROP TRIGGER t;");
    ok("ADD SCHEMA \"a\" \"{}\";");
    ok("SET RETENTION TIMESERIES \"m\" SERIES 1 AGE 3600;");
    ok("APPLY RETENTION TIMESERIES \"m\" SERIES 1 TIME 5000;");
    ok("FREE BLOB 1 PAGE 5 COUNT 1 LEN 1024;");
    ok("OPEN ENCLAVE 1 KEY \"env://k\";");
    ok("REGISTER PRINCIPAL 1 TENANT 1 PUBKEY \"ab\";");
    ok("APPEND INTO TIMESERIES \"m\" SERIES 1 TIME 1000 VALUE 42.5;");
    ok("PRUNE TIMESERIES \"m\" SERIES 1 BEFORE 500;");
    ok("BEGIN; INSERT INTO \"a\" (\"{}\", \"k\"); COMMIT;");
    ok("LET $x = 5; RETURN $x;");
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_statement_variants_compile);
    return UNITY_END();
}
