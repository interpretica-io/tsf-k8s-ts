/** @file
 * @brief Kubernetes group: anonymous kubelet access
 *
 * SECURITY. Every node runs a kubelet whose HTTPS API on :10250 serves,
 * among other things, @c /pods (the full spec of every pod on the node,
 * environment variables and mounted secret names included), @c /runningpods
 * and @c /metrics, and @c /exec and @c /run, which run a command inside a
 * container. A kubelet left with @c anonymous-auth=true and
 * @c authorization-mode=AlwaysAllow serves all of that to any peer that can
 * reach the port - a direct path to the node's workloads and, through
 * @c /run, to code execution. The secure default is @c anonymous-auth=false,
 * which answers an unauthenticated request with 401.
 *
 * The audit reads a fixed set of kubelet endpoints with no credentials and
 * records a finding for each one served (200). The gate fails on HIGH.
 *
 * @c profile selects the kubelet under test:
 * - @c baseline - the prologue's cluster, whose kubelet keeps the secure
 *   default; every endpoint is rejected (401) and the audit passes;
 * - @c open - this test brings up a throwaway cluster whose kubelet has
 *   anonymous auth on (the known-bad control, torn down in cleanup); the
 *   endpoints are served and the audit fails. The TRC records that failure
 *   as expected.
 *
 * Authorized use only.
 *
 * Copyright (C) 2026 Interpretica Unipessoal Lda
 */

#define TE_TEST_NAME    "k8s/anon_kubelet"

#include "te_config.h"
#include <stdlib.h>
#include <string.h>
#include "tapi_test.h"
#include "te_string.h"
#include "te_mi_log.h"

#include "tapi_cybersec.h"
#include "tsapi_k8s_ts.h"

typedef struct kendpoint {
    const char             *path;
    const char             *check;
    tapi_cybersec_severity  severity;
    const char             *what;
} kendpoint;

static const kendpoint endpoints[] = {
    { "/pods",
      "k8s.kubelet-anon-pods",    TAPI_CYBERSEC_SEV_CRITICAL,
      "every pod spec on the node (env, secret mounts)" },
    { "/runningpods/",
      "k8s.kubelet-anon-running", TAPI_CYBERSEC_SEV_HIGH,
      "the running pods on the node" },
    { "/stats/summary",
      "k8s.kubelet-anon-stats",   TAPI_CYBERSEC_SEV_HIGH,
      "per-container resource stats (names, namespaces, volumes)" },
    { "/configz",
      "k8s.kubelet-anon-configz", TAPI_CYBERSEC_SEV_HIGH,
      "the kubelet's own configuration" },
    { "/metrics",
      "k8s.kubelet-anon-metrics", TAPI_CYBERSEC_SEV_MEDIUM,
      "node and workload metrics" },
    { "/metrics/cadvisor",
      "k8s.kubelet-anon-cadvisor", TAPI_CYBERSEC_SEV_MEDIUM,
      "cAdvisor container metrics" },
};

int
main(int argc, char **argv)
{
    tsapi_k8s_ts s = {0};
    tapi_cybersec_report report;
    te_string verdict = TE_STRING_INIT;
    te_mi_logger *logger = NULL;
    const char *profile;
    const char *base;
    bool open_posture;
    bool ins_up = false;
    bool report_ready = false;
    unsigned int served = 0;
    size_t i;

    TEST_START;
    TEST_GET_STRING_PARAM(profile);
    open_posture = (strcmp(profile, "open") == 0);

    TEST_STEP("Open a session to the agent");
    CHECK_RC(tsapi_k8s_ts_init(&s, "pco_k8s_kubelet"));

    if (open_posture)
    {
        TEST_STEP("Known-bad control: bring up a cluster with an open kubelet");
        rc = tsapi_k8s_ts_k3s_insecure_kubelet_up(&s);
        if (TE_RC_GET_ERROR(rc) == TE_ENOENT)
            TEST_SKIP("Could not bring up the open-kubelet control cluster");
        CHECK_RC(rc);
        ins_up = true;
        base = tsapi_k8s_ts_kubelet_ins_url();
    }
    else
    {
        base = tsapi_k8s_ts_kubelet_url();
    }

    TEST_STEP("Check the kubelet port answers at all");
    {
        long code = 0;
        te_string url = TE_STRING_INIT;

        te_string_append(&url, "%s/healthz", base);
        CHECK_RC(tsapi_k8s_ts_http_code(&s, url.ptr, &code));
        te_string_free(&url);
        if (code == 0)
            TEST_SKIP("The kubelet at %s did not answer", base);
    }

    TEST_STEP("Read each kubelet endpoint with no credentials");
    tapi_cybersec_report_init(&report);
    report_ready = true;
    CHECK_RC(te_mi_logger_meas_create("k8s-anon-kubelet", &logger));
    te_mi_logger_add_meas_key(logger, NULL, "profile", "%s", profile);
    te_mi_logger_add_meas_key(logger, NULL, "kubelet", "%s", base);

    for (i = 0; i < TE_ARRAY_LEN(endpoints); i++)
    {
        const kendpoint *e = &endpoints[i];
        te_string url = TE_STRING_INIT;
        long code = 0;

        te_string_append(&url, "%s%s", base, e->path);
        CHECK_RC(tsapi_k8s_ts_http_code(&s, url.ptr, &code));
        te_string_free(&url);

        RING("anonymous GET %s -> HTTP %ld (%s)", e->path, code, e->what);

        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                              "http_code", TE_MI_MEAS_AGGR_SINGLE,
                              (double)code, TE_MI_MEAS_MULTIPLIER_PLAIN);

        if (code == 200)
        {
            served++;
            tapi_cybersec_report_add(&report, e->severity, e->check, e->path,
                "anonymous GET served %s (HTTP 200)", e->what);
        }
    }

    TEST_STEP("Chart: HTTP status code per kubelet endpoint");
    te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                          "served", TE_MI_MEAS_AGGR_SINGLE,
                          (double)served, TE_MI_MEAS_MULTIPLIER_PLAIN);
    te_mi_logger_add_meas_view(logger, NULL, TE_MI_MEAS_VIEW_LINE_GRAPH,
                               "codes", "Anonymous HTTP status per kubelet endpoint");
    te_mi_logger_meas_graph_axis_add_name(logger, NULL,
                               TE_MI_MEAS_VIEW_LINE_GRAPH, "codes",
                               TE_MI_GRAPH_AXIS_X, TE_MI_GRAPH_AUTO_SEQNO);
    te_mi_logger_meas_graph_axis_add_name(logger, NULL,
                               TE_MI_MEAS_VIEW_LINE_GRAPH, "codes",
                               TE_MI_GRAPH_AXIS_Y, "http_code");
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
    if (ins_up)
        tsapi_k8s_ts_k3s_insecure_kubelet_down(&s);
    te_string_free(&verdict);
    if (report_ready)
        tapi_cybersec_report_free(&report);
    tsapi_k8s_ts_fini(&s);
    TEST_END;
}
