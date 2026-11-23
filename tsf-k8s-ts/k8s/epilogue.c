/** @file
 * @brief Kubernetes group epilogue: tear the cluster(s) down.
 *
 * Copyright (C) 2026 Interpretica Unipessoal Lda
 */

#define TE_TEST_NAME    "k8s/epilogue"

#include "te_config.h"
#include "tapi_test.h"
#include "tsapi_k8s_ts.h"

int
main(int argc, char **argv)
{
    tsapi_k8s_ts s = {0};

    TEST_START;

    TEST_STEP("Open a session to the agent");
    CHECK_RC(tsapi_k8s_ts_init(&s, "pco_k8s_epilogue"));

    TEST_STEP("Tear the Kubernetes clusters down");
    /* The throwaway open-kubelet cluster too, in case a test that brought
     * it up did not get to its own cleanup. */
    tsapi_k8s_ts_k3s_insecure_kubelet_down(&s);
    tsapi_k8s_ts_k3s_down(&s);

    TEST_SUCCESS;

cleanup:
    tsapi_k8s_ts_fini(&s);
    TEST_END;
}
