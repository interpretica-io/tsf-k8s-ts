/** @file
 * @brief Test Suite
 *
 * Test Suite prologue.
 *
 * Copyright (C) 2026 Interpretica Unipessoal Lda
 *
 * @author Maxim Menshikov <maxim.menshikov@interpretica.io>
 */

#define TE_TEST_NAME    "prologue"

#include "te_config.h"
#include "tapi_test.h"

int
main(int argc, char **argv)
{
    TEST_START;

    TEST_STEP("Initialize test suite");
    /* Nothing to set up at the suite level: each group brings up and
     * tears down its own Kubernetes cluster. */

    TEST_SUCCESS;

cleanup:

    TEST_END;
}
