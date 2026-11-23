/** @file
 * @brief Kubernetes group: RBAC posture for anonymous principals
 *
 * SECURITY. The previous test reads endpoints over HTTP; this one asks the
 * API server's own authorizer what @c system:anonymous is allowed to do,
 * with @c kubectl @c auth @c can-i @c --as. It is the authoritative view of
 * the grant, independent of which endpoints happen to exist, and it catches
 * a dangerous permission before anything exercises it. A sound cluster
 * answers "no" to every dangerous verb/resource pair for an anonymous
 * caller.
 *
 * The audit runs a fixed list of dangerous checks and records a finding for
 * each one answered "yes". The gate fails on HIGH.
 *
 * @c profile selects the posture, as in @ref k8s/anon_api:
 * - @c baseline - anonymous is allowed none of them, the audit passes;
 * - @c open - this test binds @c cluster-admin to @c system:anonymous (the
 *   known-bad control, reverted in cleanup), every check answers "yes" and
 *   the audit fails. The TRC records that failure as expected.
 *
 * Authorized use only.
 *
 * Copyright (C) 2026 Interpretica Unipessoal Lda
 */

#define TE_TEST_NAME    "k8s/rbac"

#include "te_config.h"
#include <stdlib.h>
#include <string.h>
#include "tapi_test.h"
#include "te_string.h"
#include "te_mi_log.h"

#include "tapi_cybersec.h"
#include "tsapi_k8s_ts.h"

#define ANON_ADMIN_CRB  "tsf-rbac-anon-admin"

/** One "can the anonymous user do this?" check. */
typedef struct rbac_check {
    const char             *cani;      /**< kubectl auth can-i arguments. */
    const char             *check;     /**< Stable finding id if allowed. */
    tapi_cybersec_severity  severity;  /**< Severity if allowed. */
    const char             *what;      /**< Human description. */
} rbac_check;

static const rbac_check checks[] = {
    { "'*' '*'",
      "k8s.rbac-anon-all",        TAPI_CYBERSEC_SEV_CRITICAL,
      "anything on anything (cluster-admin)" },
    { "get secrets -A",
      "k8s.rbac-anon-get-secrets", TAPI_CYBERSEC_SEV_CRITICAL,
      "read Secrets in every namespace" },
    { "create pods -A",
      "k8s.rbac-anon-create-pods", TAPI_CYBERSEC_SEV_HIGH,
      "create pods (code execution on a node)" },
    { "create clusterrolebindings",
      "k8s.rbac-anon-create-crb", TAPI_CYBERSEC_SEV_HIGH,
      "create ClusterRoleBindings (privilege escalation)" },
    { "'*' nodes/proxy",
      "k8s.rbac-anon-node-proxy",  TAPI_CYBERSEC_SEV_HIGH,
      "reach the kubelet through the node proxy" },
    { "impersonate users",
      "k8s.rbac-anon-impersonate", TAPI_CYBERSEC_SEV_HIGH,
      "impersonate any user" },
};

/** Ask the authorizer one question; @p allowed is set to "can anonymous?". */
static te_errno
can_anon(tsapi_k8s_ts *s, const char *cani, bool *allowed)
{
    te_string cmd = TE_STRING_INIT;
    te_string out = TE_STRING_INIT;
    te_errno rc;

    *allowed = false;
    /* --quiet would suppress the word; we want to read "yes"/"no". The
     * exit status also encodes it, but reading stdout keeps us independent
     * of how the shell wrapper reports a non-zero kubectl. */
    te_string_append(&cmd, "auth can-i %s --as=system:anonymous", cani);
    rc = tsapi_k8s_ts_kubectl(s, cmd.ptr, 60000, &out, NULL);
    te_string_free(&cmd);
    if (rc == 0 && out.ptr != NULL && strncmp(out.ptr, "yes", 3) == 0)
        *allowed = true;
    te_string_free(&out);
    return rc;
}

int
main(int argc, char **argv)
{
    tsapi_k8s_ts s = {0};
    tapi_cybersec_report report;
    te_string verdict = TE_STRING_INIT;
    te_mi_logger *logger = NULL;
    const char *profile;
    bool open_posture;
    bool crb_applied = false;
    bool report_ready = false;
    unsigned int allowed_count = 0;
    size_t i;

    TEST_START;
    TEST_GET_STRING_PARAM(profile);
    open_posture = (strcmp(profile, "open") == 0);

    TEST_STEP("Open a session to the agent");
    CHECK_RC(tsapi_k8s_ts_init(&s, "pco_k8s_rbac"));

    TEST_STEP("Check kubectl can reach the cluster");
    {
        int status = -1;

        CHECK_RC(tsapi_k8s_ts_kubectl(&s, "version --output=yaml",
                                      60000, NULL, &status));
        if (status != 0)
            TEST_SKIP("kubectl cannot reach the cluster");
    }

    if (open_posture)
    {
        int status = -1;

        TEST_STEP("Known-bad control: bind cluster-admin to system:anonymous");
        CHECK_RC(tsapi_k8s_ts_kubectl(&s,
            "create clusterrolebinding " ANON_ADMIN_CRB
            " --clusterrole=cluster-admin --user=system:anonymous",
            60000, NULL, &status));
        if (status != 0)
            TEST_VERDICT("could not apply the anonymous cluster-admin binding");
        crb_applied = true;
        tsapi_k8s_ts_sh(&s, "sleep 2", 5000, NULL, NULL);
    }

    TEST_STEP("Ask the authorizer each dangerous question for system:anonymous");
    tapi_cybersec_report_init(&report);
    report_ready = true;
    CHECK_RC(te_mi_logger_meas_create("k8s-rbac", &logger));
    te_mi_logger_add_meas_key(logger, NULL, "profile", "%s", profile);
    te_mi_logger_add_meas_key(logger, NULL, "principal", "%s",
                              "system:anonymous");

    for (i = 0; i < TE_ARRAY_LEN(checks); i++)
    {
        const rbac_check *c = &checks[i];
        bool allowed = false;

        CHECK_RC(can_anon(&s, c->cani, &allowed));
        RING("can-i %s --as=system:anonymous -> %s", c->cani,
             allowed ? "YES" : "no");

        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                              "allowed", TE_MI_MEAS_AGGR_SINGLE,
                              allowed ? 1.0 : 0.0, TE_MI_MEAS_MULTIPLIER_PLAIN);

        if (allowed)
        {
            allowed_count++;
            tapi_cybersec_report_add(&report, c->severity, c->check, c->cani,
                "RBAC allows system:anonymous to %s", c->what);
        }
    }

    TEST_STEP("Chart: allowed (1) / denied (0) per dangerous action");
    te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                          "allowed_total", TE_MI_MEAS_AGGR_SINGLE,
                          (double)allowed_count, TE_MI_MEAS_MULTIPLIER_PLAIN);
    te_mi_logger_add_meas_view(logger, NULL, TE_MI_MEAS_VIEW_LINE_GRAPH,
                               "rbac", "Anonymous RBAC: allowed per action");
    te_mi_logger_meas_graph_axis_add_name(logger, NULL,
                               TE_MI_MEAS_VIEW_LINE_GRAPH, "rbac",
                               TE_MI_GRAPH_AXIS_X, TE_MI_GRAPH_AUTO_SEQNO);
    te_mi_logger_meas_graph_axis_add_name(logger, NULL,
                               TE_MI_MEAS_VIEW_LINE_GRAPH, "rbac",
                               TE_MI_GRAPH_AXIS_Y, "allowed");
    te_mi_logger_destroy(logger);
    logger = NULL;

    tapi_cybersec_report_log(&report);

    TEST_STEP("Gate: fail on anything at least HIGH");
    if (tapi_cybersec_report_verdict(&report, TAPI_CYBERSEC_SEV_HIGH, &verdict))
        TEST_VERDICT("%s", verdict.ptr);

    TEST_SUCCESS;

cleanup:
    if (logger != NULL)
        te_mi_logger_destroy(logger);
    if (crb_applied)
        tsapi_k8s_ts_kubectl(&s,
            "delete clusterrolebinding " ANON_ADMIN_CRB " --ignore-not-found",
            60000, NULL, NULL);
    te_string_free(&verdict);
    if (report_ready)
        tapi_cybersec_report_free(&report);
    tsapi_k8s_ts_fini(&s);
    TEST_END;
}
