/** @file
 * @brief Kubernetes group: anonymous API server access
 *
 * SECURITY. A Kubernetes API server with anonymous authentication enabled
 * (the upstream default) hands an unauthenticated request the identity
 * @c system:anonymous in the group @c system:unauthenticated, and then
 * RBAC decides. On a sound cluster RBAC grants that identity only a few
 * public info endpoints (@c /version, @c /healthz), so a read of secrets,
 * pods, namespaces or the RBAC bindings is denied (HTTP 403). A single
 * over-broad binding - the classic one grants @c cluster-admin to
 * @c system:anonymous - turns the same requests into 200s that serve the
 * cluster's contents to anyone who can reach the port.
 *
 * The audit reads a fixed set of endpoints with no credentials and records
 * a finding for each sensitive one that is served (200). @c /version being
 * served is normal and recorded only as INFO. The gate fails on HIGH.
 *
 * @c profile selects the posture:
 * - @c baseline - the cluster as the prologue left it; every sensitive
 *   endpoint is denied, the audit passes;
 * - @c open - this test first binds @c cluster-admin to @c system:anonymous
 *   (the known-bad control, reverted in cleanup); the sensitive endpoints
 *   are served and the audit fails. The TRC records that failure as
 *   expected, with the stable verdict below.
 *
 * Authorized use only: it reads a cluster the suite brought up.
 *
 * Copyright (C) 2026 Interpretica Unipessoal Lda
 */

#define TE_TEST_NAME    "k8s/anon_api"

#include "te_config.h"
#include <stdlib.h>
#include "tapi_test.h"
#include "te_string.h"
#include "te_mi_log.h"

#include "tapi_cybersec.h"
#include "tsapi_k8s_ts.h"

/** The ClusterRoleBinding this test owns for the open-posture control. */
#define ANON_ADMIN_CRB  "tsf-anon-api-admin"

/** One endpoint the audit probes with no credentials. */
typedef struct endpoint {
    const char             *path;      /**< Path under the API base URL. */
    const char             *check;     /**< Stable finding id if served. */
    tapi_cybersec_severity  severity;  /**< Severity if served (200). */
    const char             *what;      /**< Human description for the log. */
} endpoint;

/*
 * INFO for the public version endpoint (served on every cluster, a mild
 * disclosure); HIGH/CRITICAL for the ones that must never be anonymous.
 */
static const endpoint endpoints[] = {
    { "/version",
      "k8s.anon-version",         TAPI_CYBERSEC_SEV_INFO,
      "server version (public info)" },
    { "/api",
      "k8s.anon-api-discovery",   TAPI_CYBERSEC_SEV_LOW,
      "API discovery" },
    { "/api/v1/namespaces",
      "k8s.anon-list-namespaces", TAPI_CYBERSEC_SEV_HIGH,
      "namespace inventory" },
    { "/api/v1/pods",
      "k8s.anon-list-pods",       TAPI_CYBERSEC_SEV_HIGH,
      "pod inventory across the cluster" },
    { "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
      "k8s.anon-read-rbac",       TAPI_CYBERSEC_SEV_HIGH,
      "the cluster's RBAC bindings" },
    { "/api/v1/secrets",
      "k8s.anon-read-secrets",    TAPI_CYBERSEC_SEV_CRITICAL,
      "every Secret in the cluster" },
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
    unsigned int served_sensitive = 0;
    size_t i;

    TEST_START;
    TEST_GET_STRING_PARAM(profile);
    open_posture = (strcmp(profile, "open") == 0);

    TEST_STEP("Open a session to the agent");
    CHECK_RC(tsapi_k8s_ts_init(&s, "pco_k8s_anon_api"));
    base = tsapi_k8s_ts_api_url();

    TEST_STEP("Check the API server answers at all");
    {
        long code = 0;
        te_string url = TE_STRING_INIT;

        te_string_append(&url, "%s/version", base);
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
        /* RBAC caches briefly; give the binding a moment to take effect. */
        tsapi_k8s_ts_sh(&s, "sleep 2", 5000, NULL, NULL);
    }

    TEST_STEP("Read each endpoint with no credentials and record findings");
    tapi_cybersec_report_init(&report);
    report_ready = true;
    CHECK_RC(te_mi_logger_meas_create("k8s-anon-api", &logger));
    te_mi_logger_add_meas_key(logger, NULL, "profile", "%s", profile);
    te_mi_logger_add_meas_key(logger, NULL, "api", "%s", base);

    for (i = 0; i < TE_ARRAY_LEN(endpoints); i++)
    {
        const endpoint *e = &endpoints[i];
        te_string url = TE_STRING_INIT;
        long code = 0;

        te_string_append(&url, "%s%s", base, e->path);
        CHECK_RC(tsapi_k8s_ts_http_code(&s, url.ptr, &code));
        te_string_free(&url);

        RING("anonymous GET %s -> HTTP %ld (%s)", e->path, code, e->what);

        /* Chart the status code for this endpoint. */
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                              "http_code", TE_MI_MEAS_AGGR_SINGLE,
                              (double)code, TE_MI_MEAS_MULTIPLIER_PLAIN);

        /* 200 means the endpoint served its body to an anonymous peer. */
        if (code == 200)
        {
            tapi_cybersec_report_add(&report, e->severity, e->check, e->path,
                "anonymous GET served %s (HTTP 200)", e->what);
            if (e->severity >= TAPI_CYBERSEC_SEV_HIGH)
                served_sensitive++;
        }
    }

    TEST_STEP("Chart: HTTP status code per endpoint, and the exposure count");
    te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                          "served_sensitive", TE_MI_MEAS_AGGR_SINGLE,
                          (double)served_sensitive, TE_MI_MEAS_MULTIPLIER_PLAIN);
    te_mi_logger_add_meas_view(logger, NULL, TE_MI_MEAS_VIEW_LINE_GRAPH,
                               "codes", "Anonymous HTTP status per API endpoint");
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
