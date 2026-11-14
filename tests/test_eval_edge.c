/* Edge/negative coverage for the cdb_eval public value API that the wire-driven
 * test_eval.c does not reach directly: the NULL-guard (fail-closed) branch of
 * every context setter, ctx_set_vector (both branches), the make_* constructors
 * (incl. NULL out), is_null / is_truthy across every value type, and
 * cdb_eval_compare across all type pairings (numeric INT/F64/F32 mixes, bool,
 * string incl. prefix + length tiebreak + empty, binary, NULL operands, and the
 * type-mismatch fallthrough) plus its invalid-argument branch. These are the
 * negative/abuse-path tests the ruleset requires (master Sec 4). */
#include "unity.h"
#include "cdb_eval.h"
#include "combolite/cdb_value.h"

#include <string.h>

void setUp(void) {}
void tearDown(void) {}

static cdb_value mk_str(const char *s)
{
    cdb_value v;
    memset(&v, 0, sizeof v);
    v.type = CDB_TYPE_STRING;
    v.payload = (const uint8_t *)s;
    v.payload_len = strlen(s);
    return v;
}

static cdb_value mk_bin(const uint8_t *b, size_t n)
{
    cdb_value v;
    memset(&v, 0, sizeof v);
    v.type = CDB_TYPE_BINARY;
    v.payload = b;
    v.payload_len = n;
    return v;
}

static cdb_value mk_f32(float f)
{
    cdb_value v;
    memset(&v, 0, sizeof v);
    v.type = CDB_TYPE_F32;
    v.as.f32 = f;
    return v;
}

/* Every ctx setter has a leading `if (ctx == NULL) return;` — hitting it with a
 * NULL ctx covers that fail-closed branch (and must not crash). */
static void test_ctx_setters_null_guard(void)
{
    cdb_value v;
    cdb_eval_make_int(&v, 1);
    cdb_eval_ctx_set_scratch(NULL, NULL, 0);
    cdb_eval_ctx_reset_scratch(NULL);
    cdb_eval_ctx_set_params(NULL, NULL, 0);
    cdb_eval_ctx_set_record(NULL, NULL, 0);
    cdb_eval_ctx_set_entry_id(NULL, 0);
    cdb_eval_ctx_set_score(NULL, 0.0);
    cdb_eval_ctx_set_timestamp(NULL, 0, CDB_TS_SECONDS);
    cdb_eval_ctx_set_vector(NULL, &v);
    cdb_eval_ctx_set_budget(NULL, 0);
    cdb_eval_ctx_set_custom_resolver(NULL, NULL, NULL);
    TEST_PASS(); /* reaching here without a crash is the assertion */
}

/* ctx_set_vector: the vec!=NULL branch and the vec==NULL branch, on a real ctx. */
static void test_ctx_set_vector_both_branches(void)
{
    cdb_eval_ctx ctx;
    cdb_value vec;
    cdb_eval_ctx_init(&ctx, CDB_ORDER_LITTLE, NULL, 0);
    cdb_eval_make_f64(&vec, 3.5);
    cdb_eval_ctx_set_vector(&ctx, &vec); /* has_vector = 1 */
    cdb_eval_ctx_set_vector(&ctx, NULL); /* has_vector = 0 */
    TEST_PASS();
}

static void test_make_and_classify(void)
{
    cdb_value n, b, i, d;
    /* NULL out must be a safe no-op for each constructor */
    cdb_eval_make_null(NULL);
    cdb_eval_make_bool(NULL, 1);
    cdb_eval_make_int(NULL, 1);
    cdb_eval_make_f64(NULL, 1.0);

    cdb_eval_make_null(&n);
    cdb_eval_make_bool(&b, 1);
    cdb_eval_make_int(&i, 7);
    cdb_eval_make_f64(&d, 2.5);

    TEST_ASSERT_TRUE(cdb_eval_is_null(&n));
    TEST_ASSERT_TRUE(cdb_eval_is_null(NULL));     /* NULL -> null */
    TEST_ASSERT_FALSE(cdb_eval_is_null(&i));

    /* is_truthy across every arm of the switch */
    TEST_ASSERT_FALSE(cdb_eval_is_truthy(NULL));
    TEST_ASSERT_TRUE(cdb_eval_is_truthy(&b));
    cdb_eval_make_bool(&b, 0);
    TEST_ASSERT_FALSE(cdb_eval_is_truthy(&b));
    TEST_ASSERT_TRUE(cdb_eval_is_truthy(&i));
    TEST_ASSERT_TRUE(cdb_eval_is_truthy(&d));
    TEST_ASSERT_FALSE(cdb_eval_is_truthy(&n)); /* NULL type -> default arm */
    {
        cdb_value f = mk_f32(1.0f);
        cdb_value s = mk_str("x");
        cdb_value emptys = mk_str("");
        cdb_value bin = mk_bin((const uint8_t *)"\x01", 1);
        TEST_ASSERT_TRUE(cdb_eval_is_truthy(&f));
        TEST_ASSERT_TRUE(cdb_eval_is_truthy(&s));
        TEST_ASSERT_FALSE(cdb_eval_is_truthy(&emptys));
        TEST_ASSERT_TRUE(cdb_eval_is_truthy(&bin));
    }
}

static void cmp_ok(const cdb_value *l, const cdb_value *r, int expect_sign)
{
    int cmp = 99, is_null = 99;
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_eval_compare(l, r, &cmp, &is_null));
    TEST_ASSERT_EQUAL_INT(0, is_null);
    if (expect_sign < 0)
        TEST_ASSERT_TRUE(cmp < 0);
    else if (expect_sign > 0)
        TEST_ASSERT_TRUE(cmp > 0);
    else
        TEST_ASSERT_EQUAL_INT(0, cmp);
}

static void test_compare_all_pairings(void)
{
    cdb_value i1, i2, d1, d2, b0, b1, nul;
    int cmp = 0, is_null = 0;

    cdb_eval_make_int(&i1, 1);
    cdb_eval_make_int(&i2, 2);
    cdb_eval_make_f64(&d1, 1.5);
    cdb_eval_make_f64(&d2, 1.5);
    cdb_eval_make_bool(&b0, 0);
    cdb_eval_make_bool(&b1, 1);
    cdb_eval_make_null(&nul);

    /* invalid-argument branch */
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_eval_compare(NULL, &i1, &cmp, &is_null));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_eval_compare(&i1, NULL, &cmp, &is_null));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_eval_compare(&i1, &i2, NULL, &is_null));
    TEST_ASSERT_EQUAL_INT(CDB_E_INVALID_ARG, cdb_eval_compare(&i1, &i2, &cmp, NULL));

    /* NULL operand -> is_null set, cmp 0 */
    TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_eval_compare(&nul, &i1, &cmp, &is_null));
    TEST_ASSERT_EQUAL_INT(1, is_null);

    /* INT/INT all three orderings */
    cmp_ok(&i1, &i2, -1);
    cmp_ok(&i2, &i1, 1);
    cmp_ok(&i1, &i1, 0);

    /* mixed numeric (INT vs F64), F64/F64 equal, F32 path */
    cmp_ok(&i1, &d1, -1);  /* 1 < 1.5 */
    cmp_ok(&d2, &i2, -1);  /* 1.5 < 2 */
    cmp_ok(&d1, &d2, 0);
    {
        cdb_value f1 = mk_f32(1.0f), f2 = mk_f32(2.0f);
        cmp_ok(&f1, &f2, -1);
        cmp_ok(&f2, &d1, 1); /* 2.0 > 1.5 */
    }

    /* bool/bool */
    cmp_ok(&b0, &b1, -1);
    cmp_ok(&b1, &b0, 1);
    cmp_ok(&b1, &b1, 0);

    /* string/string: content, prefix-is-shorter tiebreak, equal, empty */
    {
        cdb_value a = mk_str("apple"), b = mk_str("banana");
        cdb_value ab = mk_str("ab"), abc = mk_str("abc");
        cdb_value e1 = mk_str(""), e2 = mk_str("");
        cmp_ok(&a, &b, -1);
        cmp_ok(&ab, &abc, -1); /* prefix shorter -> less */
        cmp_ok(&abc, &ab, 1);
        cmp_ok(&a, &a, 0);
        cmp_ok(&e1, &e2, 0);   /* both empty */
    }

    /* binary/binary */
    {
        cdb_value x = mk_bin((const uint8_t *)"\x01\x02", 2);
        cdb_value y = mk_bin((const uint8_t *)"\x01\x03", 2);
        cmp_ok(&x, &y, -1);
        cmp_ok(&x, &x, 0);
    }

    /* type-mismatch fallthrough (string vs int): defined, non-crashing result */
    {
        cdb_value s = mk_str("z");
        TEST_ASSERT_EQUAL_INT(CDB_OK, cdb_eval_compare(&s, &i1, &cmp, &is_null));
    }
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_ctx_setters_null_guard);
    RUN_TEST(test_ctx_set_vector_both_branches);
    RUN_TEST(test_make_and_classify);
    RUN_TEST(test_compare_all_pairings);
    return UNITY_END();
}
