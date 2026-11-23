/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief tsf-k8s-ts suite helpers
 *
 * @author Maxim Menshikov <maxim.menshikov@interpretica.io>
 */

#define TE_LGR_USER "TSAPI K8S TS"

#include "te_config.h"

#include <stdlib.h>
#include <string.h>

#include "logger_api.h"
#include "te_str.h"
#include "te_string.h"
#include "tapi_job_opt.h"
#include "tapi_job_factory_rpc.h"

#include "tapi_devtool_run.h"

#include "tsapi_k8s_ts.h"

/** The k3s image, env-overridable. */
#define K8S_IMAGE_DEFAULT       "rancher/k3s:v1.31.5-k3s1"

/** An environment value, or a default when it is unset or empty. */
static const char *
env_or(const char *name, const char *dflt)
{
    const char *v = getenv(name);

    return (v != NULL && v[0] != '\0') ? v : dflt;
}

/* See description in tsapi_k8s_ts.h */
const char *
tsapi_k8s_ts_api_url(void)
{
    return env_or("TSF_K8S_API_URL", "https://127.0.0.1:16443");
}

/* See description in tsapi_k8s_ts.h */
const char *
tsapi_k8s_ts_kubelet_url(void)
{
    return env_or("TSF_K8S_KUBELET_URL", "https://127.0.0.1:10250");
}

/* See description in tsapi_k8s_ts.h */
const char *
tsapi_k8s_ts_kubelet_ins_url(void)
{
    return env_or("TSF_K8S_KUBELET_INS_URL", "https://127.0.0.1:10251");
}

/* ---- session ---- */

/* See description in tsapi_k8s_ts.h */
te_errno
tsapi_k8s_ts_init(tsapi_k8s_ts *s, const char *name)
{
    te_errno rc;

    memset(s, 0, sizeof(*s));
    s->ta = TSAPI_K8S_TA;

    rc = rcf_rpc_server_create(s->ta, name, &s->pco);
    if (rc != 0)
    {
        ERROR("Cannot create the RPC server '%s' on %s: %r", name, s->ta, rc);
        return rc;
    }

    rc = tapi_job_factory_rpc_create(s->pco, &s->factory);
    if (rc != 0)
    {
        ERROR("Cannot create a job factory on %s: %r", s->ta, rc);
        rcf_rpc_server_destroy(s->pco);
        s->pco = NULL;
        return rc;
    }

    return 0;
}

/* See description in tsapi_k8s_ts.h */
void
tsapi_k8s_ts_fini(tsapi_k8s_ts *s)
{
    if (s->factory != NULL)
    {
        tapi_job_factory_destroy(s->factory);
        s->factory = NULL;
    }
    if (s->pco != NULL)
    {
        rcf_rpc_server_destroy(s->pco);
        s->pco = NULL;
    }
}

/* ---- the command runner ---- */

/** Arguments of a command, as a plain vector of strings. */
typedef struct k8s_cmd_opt {
    size_t n_args;
    const char **args;
} k8s_cmd_opt;

static const tapi_job_opt_bind k8s_cmd_binds[] = TAPI_JOB_OPT_SET(
    TAPI_JOB_OPT_ARRAY_PTR(k8s_cmd_opt, n_args, args,
        TAPI_JOB_OPT_CONTENT(TAPI_JOB_OPT_STRING, NULL, false))
);

/* See description in tsapi_k8s_ts.h */
te_errno
tsapi_k8s_ts_sh(tsapi_k8s_ts *s, const char *cmd, int timeout_ms,
                te_string *out, int *status)
{
    const char *args[] = { "-c", cmd };
    k8s_cmd_opt opt = { .n_args = TE_ARRAY_LEN(args), .args = args };
    tapi_devtool_run run = TAPI_DEVTOOL_RUN_INIT;
    tapi_devtool_output output;
    te_errno rc;

    if (status != NULL)
        *status = -1;

    rc = tapi_devtool_run_init(&run, s->factory, "sh", "sh", k8s_cmd_binds,
                               &opt, NULL);
    if (rc != 0)
        return rc;

    rc = tapi_devtool_run_start(&run);
    if (rc == 0)
        rc = tapi_devtool_run_wait(&run, timeout_ms);

    if (rc == 0)
    {
        tapi_devtool_run_get_output(&run, &output);
        if (out != NULL && output.out != NULL)
        {
            size_t len = strlen(output.out);

            while (len > 0 && (output.out[len - 1] == '\n' ||
                               output.out[len - 1] == '\r'))
                len--;
            te_string_append_buf(out, output.out, len);
        }
        if (status != NULL)
            *status = (output.status.type == TAPI_JOB_STATUS_EXITED) ?
                      output.status.value : -1;
    }

    tapi_devtool_run_fini(&run);

    return rc;
}

/* See description in tsapi_k8s_ts.h */
bool
tsapi_k8s_ts_docker_ok(tsapi_k8s_ts *s)
{
    int status = -1;

    if (tsapi_k8s_ts_sh(s, "docker version >/dev/null 2>&1", 30000, NULL,
                        &status) != 0)
        return false;

    return status == 0;
}

/* See description in tsapi_k8s_ts.h */
te_errno
tsapi_k8s_ts_http_code(tsapi_k8s_ts *s, const char *url, long *code)
{
    te_string cmd = TE_STRING_INIT;
    te_string out = TE_STRING_INIT;
    int status = -1;
    te_errno rc;

    if (code != NULL)
        *code = 0;

    /* -k: the cluster certificate is self-signed. --max-time bounds a
     * server that accepts the connection but never answers. */
    te_string_append(&cmd,
        "curl -sk -o /dev/null --max-time 15 -w '%%{http_code}' '%s'", url);
    rc = tsapi_k8s_ts_sh(s, cmd.ptr, 30000, &out, &status);
    te_string_free(&cmd);

    if (rc == 0 && code != NULL && out.ptr != NULL)
        *code = strtol(out.ptr, NULL, 10);

    te_string_free(&out);
    return rc;
}

/* See description in tsapi_k8s_ts.h */
te_errno
tsapi_k8s_ts_http_post_code(tsapi_k8s_ts *s, const char *url,
                            const char *body, long *code)
{
    te_string cmd = TE_STRING_INIT;
    te_string out = TE_STRING_INIT;
    int status = -1;
    te_errno rc;

    if (code != NULL)
        *code = 0;

    te_string_append(&cmd,
        "curl -sk -o /dev/null --max-time 20 -w '%%{http_code}' -X POST ");
    if (body != NULL && body[0] != '\0')
        te_string_append(&cmd, "--data '%s' ", body);
    te_string_append(&cmd, "'%s'", url);

    rc = tsapi_k8s_ts_sh(s, cmd.ptr, 40000, &out, &status);
    te_string_free(&cmd);

    if (rc == 0 && code != NULL && out.ptr != NULL)
        *code = strtol(out.ptr, NULL, 10);

    te_string_free(&out);
    return rc;
}

/* ---- kubectl ---- */

/* See description in tsapi_k8s_ts.h */
te_errno
tsapi_k8s_ts_kubectl_ct(tsapi_k8s_ts *s, const char *ct, const char *args,
                        int timeout_ms, te_string *out, int *status)
{
    te_string cmd = TE_STRING_INIT;
    te_errno rc;

    te_string_append(&cmd, "docker exec %s kubectl %s", ct, args);
    rc = tsapi_k8s_ts_sh(s, cmd.ptr, timeout_ms, out, status);
    te_string_free(&cmd);

    return rc;
}

/* See description in tsapi_k8s_ts.h */
te_errno
tsapi_k8s_ts_kubectl(tsapi_k8s_ts *s, const char *args, int timeout_ms,
                     te_string *out, int *status)
{
    return tsapi_k8s_ts_kubectl_ct(s, TSAPI_K8S_K3S_CT, args, timeout_ms,
                                   out, status);
}

/* ---- the clusters ---- */

/** Bring one k3s container up and wait for its API to answer /readyz. */
static te_errno
k3s_up(tsapi_k8s_ts *s, const char *ct, const char *ports,
       const char *extra_args)
{
    const char *image = env_or("TSF_K8S_IMAGE", K8S_IMAGE_DEFAULT);
    te_string cmd = TE_STRING_INIT;
    int status = -1;
    te_errno rc;
    int i;

    if (!tsapi_k8s_ts_docker_ok(s))
        return TE_RC(TE_TAPI, TE_ENOENT);

    RING("Bringing k3s container '%s' up (image %s)", ct, image);

    te_string_append(&cmd,
        "set -e; "
        "docker rm -f %s >/dev/null 2>&1 || true; "
        "docker run -d --name %s --privileged %s %s server "
        "--tls-san 127.0.0.1 --disable traefik --disable metrics-server %s "
        ">/dev/null",
        ct, ct, ports, image, extra_args);
    rc = tsapi_k8s_ts_sh(s, cmd.ptr, 300000, NULL, &status);
    te_string_free(&cmd);
    if (rc != 0 || status != 0)
    {
        WARN("k3s container '%s' would not start (rc %r, exit %d); skipping",
             ct, rc, status);
        return TE_RC(TE_TAPI, TE_ENOENT);
    }

    /* Wait for the API server to report readiness. */
    for (i = 0; i < 90; i++)
    {
        te_string probe = TE_STRING_INIT;
        te_string out = TE_STRING_INIT;
        int st = -1;

        te_string_append(&probe,
            "docker exec %s kubectl get --raw=/readyz 2>/dev/null", ct);
        tsapi_k8s_ts_sh(s, probe.ptr, 20000, &out, &st);
        te_string_free(&probe);
        if (st == 0 && out.ptr != NULL && strstr(out.ptr, "ok") != NULL)
        {
            te_string_free(&out);
            RING("k3s container '%s' is ready after ~%d s", ct, i);
            return 0;
        }
        te_string_free(&out);
        tsapi_k8s_ts_sh(s, "sleep 1", 5000, NULL, NULL);
    }

    WARN("k3s container '%s' did not become ready in time; skipping", ct);
    return TE_RC(TE_TAPI, TE_ETIMEDOUT);
}

/* See description in tsapi_k8s_ts.h */
te_errno
tsapi_k8s_ts_k3s_up(tsapi_k8s_ts *s)
{
    te_errno rc = k3s_up(s, TSAPI_K8S_K3S_CT,
                         "-p 16443:6443 -p 10250:10250",
                         "--kube-apiserver-arg=anonymous-auth=true");

    if (TE_RC_GET_ERROR(rc) == TE_ETIMEDOUT)
    {
        tsapi_k8s_ts_k3s_down(s);
        rc = TE_RC(TE_TAPI, TE_ENOENT);
    }
    return rc;
}

/* See description in tsapi_k8s_ts.h */
void
tsapi_k8s_ts_k3s_down(tsapi_k8s_ts *s)
{
    tsapi_k8s_ts_sh(s, "docker rm -f " TSAPI_K8S_K3S_CT " >/dev/null 2>&1",
                    60000, NULL, NULL);
}

/* See description in tsapi_k8s_ts.h */
te_errno
tsapi_k8s_ts_k3s_insecure_kubelet_up(tsapi_k8s_ts *s)
{
    te_errno rc = k3s_up(s, TSAPI_K8S_K3S_INS_CT,
                         "-p 16444:6443 -p 10251:10250",
                         "--kubelet-arg=anonymous-auth=true "
                         "--kubelet-arg=authorization-mode=AlwaysAllow");

    if (TE_RC_GET_ERROR(rc) == TE_ETIMEDOUT)
    {
        tsapi_k8s_ts_k3s_insecure_kubelet_down(s);
        rc = TE_RC(TE_TAPI, TE_ENOENT);
    }
    return rc;
}

/* See description in tsapi_k8s_ts.h */
void
tsapi_k8s_ts_k3s_insecure_kubelet_down(tsapi_k8s_ts *s)
{
    tsapi_k8s_ts_sh(s, "docker rm -f " TSAPI_K8S_K3S_INS_CT " >/dev/null 2>&1",
                    60000, NULL, NULL);
}
