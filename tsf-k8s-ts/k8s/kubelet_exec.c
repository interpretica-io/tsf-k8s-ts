/** @file
 * @brief Kubernetes group: command execution through an open kubelet
 *
 * SECURITY. The worst of an open kubelet is not disclosure but execution:
 * @c POST @c /run/<namespace>/<pod>/<container> runs a command inside a
 * container on the node and returns its output. On a kubelet that answers
 * unauthenticated requests (@c anonymous-auth=true,
 * @c authorization-mode=AlwaysAllow) this is remote code execution against
 * every workload on the node, reachable by anyone who can open the port.
 *
 * The audit picks a running pod on the node and asks its kubelet to run a
 * command, with no credentials. The security-relevant fact is whether the
 * kubelet @b authorizes the exec: a secure kubelet refuses with 401; an
 * open one accepts it (and runs it, or at least tries to - a 200, or a 500
 * from inside the container, both mean the request was authorized). So any
 * answer that is neither 401 nor 403 is the finding.
 *
 * @c profile selects the kubelet under test, as in @ref k8s/anon_kubelet:
 * - @c baseline - the prologue cluster's secure kubelet refuses (401), the
 *   audit passes;
 * - @c open - a throwaway cluster whose kubelet runs with anonymous auth on
 *   (the known-bad control, torn down in cleanup); the exec is authorized
 *   and the audit fails (CRITICAL). The TRC records that failure as
 *   expected.
 *
 * Authorized use only.
 *
 * Copyright (C) 2026 Interpretica Unipessoal Lda
 */

#define TE_TEST_NAME    "k8s/kubelet_exec"

#include "te_config.h"
#include <stdlib.h>
#include <string.h>
#include "tapi_test.h"
#include "te_string.h"
#include "te_mi_log.h"

#include "tapi_cybersec.h"
#include "tsapi_k8s_ts.h"

/** Find a Running pod in kube-system and its first container. */
static te_errno
find_running_pod(tsapi_k8s_ts *s, const char *ct, te_string *pod,
                 te_string *container)
{
    te_string out = TE_STRING_INIT;
    te_string args = TE_STRING_INIT;
    char *sp;
    int i;
    te_errno rc = 0;

    /* Retry: pods take a few seconds to reach Running after the API is up. */
    for (i = 0; i < 60; i++)
    {
        te_string_reset(&out);
        te_string_reset(&args);
        te_string_append(&args,
            "get pods -n kube-system "
            "-o jsonpath='{range .items[*]}{.metadata.name}{\" \"}"
            "{.status.phase}{\" \"}{.spec.containers[0].name}{\"\\n\"}{end}' "
            "2>/dev/null | awk '$2==\"Running\"{print $1\" \"$3; exit}'");
        rc = tsapi_k8s_ts_kubectl_ct(s, ct, args.ptr, 30000, &out, NULL);
        if (rc == 0 && out.ptr != NULL && (sp = strchr(out.ptr, ' ')) != NULL)
        {
            te_string_append(pod, "%.*s", (int)(sp - out.ptr), out.ptr);
            te_string_append(container, "%s", sp + 1);
            break;
        }
        tsapi_k8s_ts_sh(s, "sleep 2", 5000, NULL, NULL);
    }

    te_string_free(&out);
    te_string_free(&args);
    return rc;
}

int
main(int argc, char **argv)
{
    tsapi_k8s_ts s = {0};
    tapi_cybersec_report report;
    te_string verdict = TE_STRING_INIT;
    te_string pod = TE_STRING_INIT;
    te_string container = TE_STRING_INIT;
    te_mi_logger *logger = NULL;
    const char *profile;
    const char *base;
    const char *ct;
    bool open_posture;
    bool ins_up = false;
    bool report_ready = false;
    long code = 0;

    TEST_START;
    TEST_GET_STRING_PARAM(profile);
    open_posture = (strcmp(profile, "open") == 0);

    TEST_STEP("Open a session to the agent");
    CHECK_RC(tsapi_k8s_ts_init(&s, "pco_k8s_kubelet_exec"));

    if (open_posture)
    {
        TEST_STEP("Known-bad control: bring up a cluster with an open kubelet");
        rc = tsapi_k8s_ts_k3s_insecure_kubelet_up(&s);
        if (TE_RC_GET_ERROR(rc) == TE_ENOENT)
            TEST_SKIP("Could not bring up the open-kubelet control cluster");
        CHECK_RC(rc);
        ins_up = true;
        base = tsapi_k8s_ts_kubelet_ins_url();
        ct = TSAPI_K8S_K3S_INS_CT;
    }
    else
    {
        base = tsapi_k8s_ts_kubelet_url();
        ct = TSAPI_K8S_K3S_CT;
    }

    TEST_STEP("Find a running pod on the node");
    CHECK_RC(find_running_pod(&s, ct, &pod, &container));
    if (pod.ptr == NULL || pod.len == 0)
        TEST_SKIP("No running pod found to target");
    RING("target: kube-system/%s container %s", pod.ptr, container.ptr);

    TEST_STEP("Ask the kubelet to run a command, with no credentials");
    tapi_cybersec_report_init(&report);
    report_ready = true;
    CHECK_RC(te_mi_logger_meas_create("k8s-kubelet-exec", &logger));
    te_mi_logger_add_meas_key(logger, NULL, "profile", "%s", profile);
    te_mi_logger_add_meas_key(logger, NULL, "kubelet", "%s", base);

    {
        te_string url = TE_STRING_INIT;

        te_string_append(&url, "%s/run/kube-system/%s/%s", base, pod.ptr,
                         container.ptr);
        CHECK_RC(tsapi_k8s_ts_http_post_code(&s, url.ptr, "cmd=id", &code));
        te_string_free(&url);
    }
    RING("anonymous POST /run/... -> HTTP %ld", code);
    te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                          "http_code", TE_MI_MEAS_AGGR_SINGLE,
                          (double)code, TE_MI_MEAS_MULTIPLIER_PLAIN);

    if (code == 0)
        TEST_SKIP("The kubelet at %s did not answer", base);

    /* 401/403 = the kubelet refused (secure). Anything else = it authorized
     * the exec and ran (or attempted) the command. */
    if (code != 401 && code != 403)
        tapi_cybersec_report_add(&report, TAPI_CYBERSEC_SEV_CRITICAL,
            "k8s.kubelet-anon-exec", "/run",
            "the kubelet authorized an unauthenticated exec (HTTP %ld)", code);

    TEST_STEP("Chart: the /run status code");
    te_mi_logger_add_meas_view(logger, NULL, TE_MI_MEAS_VIEW_LINE_GRAPH,
                               "code", "Anonymous kubelet /run HTTP status");
    te_mi_logger_meas_graph_axis_add_name(logger, NULL,
                               TE_MI_MEAS_VIEW_LINE_GRAPH, "code",
                               TE_MI_GRAPH_AXIS_X, TE_MI_GRAPH_AUTO_SEQNO);
    te_mi_logger_meas_graph_axis_add_name(logger, NULL,
                               TE_MI_MEAS_VIEW_LINE_GRAPH, "code",
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
    te_string_free(&pod);
    te_string_free(&container);
    te_string_free(&verdict);
    if (report_ready)
        tapi_cybersec_report_free(&report);
    tsapi_k8s_ts_fini(&s);
    TEST_END;
}
