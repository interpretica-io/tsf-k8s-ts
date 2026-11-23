/** @file
 * @brief Kubernetes group: anonymous API server telemetry
 *
 * SECURITY. The API server exposes @c /metrics (Prometheus telemetry) and a
 * handful of health endpoints. @c /metrics is not public: it is served only
 * to a principal RBAC allows (@c system:monitoring and the like), because it
 * leaks the cluster's internals - object counts by kind and namespace,
 * request latencies and error rates, admission and audit activity, the
 * build version. A cluster that serves @c /metrics to an anonymous peer has
 * handed over a detailed map of itself. The health endpoints
 * (@c /healthz, @c /livez, @c /readyz) are public by design and recorded
 * only as INFO.
 *
 * The audit reads these with no credentials; a served @c /metrics (200) is
 * the HIGH finding. The gate fails on HIGH.
 *
 * @c profile selects the posture, as in @ref k8s/anon_api:
 * - @c baseline - @c /metrics is denied (403), the audit passes;
 * - @c open - binding @c cluster-admin to @c system:anonymous (the known-bad
 *   control, reverted in cleanup) makes @c /metrics served; the audit fails.
 *   The TRC records that failure as expected.
 *
 * Authorized use only.
 *
 * Copyright (C) 2026 Interpretica Unipessoal Lda
 */

#define TE_TEST_NAME    "k8s/anon_metrics"

#include "te_config.h"
#include <stdlib.h>
#include <string.h>
#include "tapi_test.h"
#include "te_string.h"
#include "te_mi_log.h"

#include "tapi_cybersec.h"
#include "tsapi_k8s_ts.h"

#define ANON_ADMIN_CRB  "tsf-metrics-anon-admin"

typedef struct endpoint {
    const char             *path;
    const char             *check;
    tapi_cybersec_severity  severity;
    const char             *what;
} endpoint;

static const endpoint endpoints[] = {
    { "/healthz",
      "k8s.metrics-anon-healthz", TAPI_CYBERSEC_SEV_INFO,
      "health endpoint (public info)" },
    { "/readyz",
      "k8s.metrics-anon-readyz",  TAPI_CYBERSEC_SEV_INFO,
      "readiness endpoint (public info)" },
    { "/metrics",
      "k8s.anon-metrics",         TAPI_CYBERSEC_SEV_HIGH,
      "the API server's Prometheus telemetry" },
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
    bool crb_applied = false;
    bool report_ready = false;
    size_t i;

    TEST_START;
    TEST_GET_STRING_PARAM(profile);
    open_posture = (strcmp(profile, "open") == 0);

    TEST_STEP("Open a session to the agent");
    CHECK_RC(tsapi_k8s_ts_init(&s, "pco_k8s_metrics"));
    base = tsapi_k8s_ts_api_url();

    TEST_STEP("Check the API server answers at all");
    {
        long code = 0;
        te_string url = TE_STRING_INIT;

        te_string_append(&url, "%s/healthz", base);
        CHECK_RC(tsapi_k8s_ts_http_code(&s, url.ptr, &code));
        te_string_free(&url);
        if (code == 0)
            TEST_SKIP("The API server at %s did not answer", base);
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

    TEST_STEP("Read the telemetry and health endpoints with no credentials");
    tapi_cybersec_report_init(&report);
    report_ready = true;
    CHECK_RC(te_mi_logger_meas_create("k8s-anon-metrics", &logger));
    te_mi_logger_add_meas_key(logger, NULL, "profile", "%s", profile);

    for (i = 0; i < TE_ARRAY_LEN(endpoints); i++)
    {
        const endpoint *e = &endpoints[i];
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
            tapi_cybersec_report_add(&report, e->severity, e->check, e->path,
                "anonymous GET served %s (HTTP 200)", e->what);
    }

    TEST_STEP("Chart: HTTP status code per endpoint");
    te_mi_logger_add_meas_view(logger, NULL, TE_MI_MEAS_VIEW_LINE_GRAPH,
                               "codes", "Anonymous HTTP status: health and /metrics");
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
