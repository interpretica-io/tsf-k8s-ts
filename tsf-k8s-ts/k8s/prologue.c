/** @file
 * @brief Kubernetes group prologue: bring a single-node k3s cluster up.
 *
 * The cluster is the secure baseline: a stock k3s with the API server's
 * anonymous authentication enabled (the upstream Kubernetes default), so
 * an unauthenticated request reaches RBAC and is denied there rather than
 * refused outright - which is the posture the audits examine. The kubelet
 * keeps its secure default. Individual tests apply their own reversible
 * misconfiguration for the known-bad control.
 *
 * Copyright (C) 2026 Interpretica Unipessoal Lda
 */

#define TE_TEST_NAME    "k8s/prologue"

#include "te_config.h"
#include "tapi_test.h"
#include "tsapi_k8s_ts.h"

int
main(int argc, char **argv)
{
    tsapi_k8s_ts s = {0};

    TEST_START;

    TEST_STEP("Open a session to the agent");
    CHECK_RC(tsapi_k8s_ts_init(&s, "pco_k8s_prologue"));

    TEST_STEP("Bring a single-node k3s cluster up in Docker");
    rc = tsapi_k8s_ts_k3s_up(&s);
    if (TE_RC_GET_ERROR(rc) == TE_ENOENT)
        TEST_SKIP("Kubernetes is not available (no Docker, or k3s would "
                  "not come up)");
    CHECK_RC(rc);

    TEST_SUCCESS;

cleanup:
    tsapi_k8s_ts_fini(&s);
    TEST_END;
}
