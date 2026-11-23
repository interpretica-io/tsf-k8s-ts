/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief tsf-k8s-ts suite helpers
 *
 * Every group needs the same things: an agent with a job factory (to run
 * docker, curl and kubectl), a way to bring a Kubernetes cluster up in
 * Docker and tear it down, a way to drive kubectl against it as the
 * cluster administrator, and a way to make an unauthenticated HTTP(S)
 * request and read back the status code. The cluster is a single-node
 * k3s; the tests talk to its API server and kubelet exactly as an
 * unauthenticated network peer would.
 *
 * @author Maxim Menshikov <maxim.menshikov@interpretica.io>
 */

#ifndef __TSAPI_K8S_TS_H__
#define __TSAPI_K8S_TS_H__

#include "rcf_rpc.h"
#include "te_errno.h"
#include "te_string.h"
#include "tapi_job.h"

#ifdef __cplusplus
extern "C" {
#endif

/** The agent this suite works on. */
#define TSAPI_K8S_TA            "Agt_A"

/** Docker container of the main (secure-baseline) k3s cluster. */
#define TSAPI_K8S_K3S_CT        "tsf-k3s"

/** Docker container of the throwaway cluster with an open kubelet. */
#define TSAPI_K8S_K3S_INS_CT    "tsf-k3s-ins"

/** A session: the agent, an RPC server on it, and a job factory. */
typedef struct tsapi_k8s_ts {
    const char *ta;              /**< Agent name. */
    rcf_rpc_server *pco;         /**< RPC server on it. */
    tapi_job_factory_t *factory; /**< Job factory over @a pco. */
} tsapi_k8s_ts;

/**
 * Open a session: an RPC server on the agent and a job factory over it.
 *
 * @param[out] s     Session.
 * @param[in]  name  Name for the RPC server, unique within the test.
 *
 * @return Status code.
 */
extern te_errno tsapi_k8s_ts_init(tsapi_k8s_ts *s, const char *name);

/**
 * Close a session.
 *
 * @param s   Session.
 */
extern void tsapi_k8s_ts_fini(tsapi_k8s_ts *s);

/**
 * Run @c "sh -c <cmd>" on the agent, wait and capture its stdout.
 *
 * @param[in]  s          Session.
 * @param[in]  cmd        Shell command line.
 * @param[in]  timeout_ms Timeout, ms.
 * @param[out] out        Stdout, trimmed of a trailing newline (may be
 *                        @c NULL).
 * @param[out] status     Exit status, or -1 (may be @c NULL).
 *
 * @return Status code of running the shell, not of the command.
 */
extern te_errno tsapi_k8s_ts_sh(tsapi_k8s_ts *s, const char *cmd,
                                int timeout_ms, te_string *out, int *status);

/**
 * Whether Docker is usable on the agent (@c "docker version" exits 0).
 *
 * @param s   Session.
 *
 * @return @c true if Docker works.
 */
extern bool tsapi_k8s_ts_docker_ok(tsapi_k8s_ts *s);

/**
 * The API server base URL (no trailing slash), env-overridable with
 * @c TSF_K8S_API_URL.
 *
 * @return A static string, e.g. @c "https://127.0.0.1:16443".
 */
extern const char *tsapi_k8s_ts_api_url(void);

/**
 * The kubelet base URL of the secure cluster, env-overridable with
 * @c TSF_K8S_KUBELET_URL.
 *
 * @return A static string, e.g. @c "https://127.0.0.1:10250".
 */
extern const char *tsapi_k8s_ts_kubelet_url(void);

/**
 * The kubelet base URL of the throwaway open-kubelet cluster,
 * env-overridable with @c TSF_K8S_KUBELET_INS_URL.
 *
 * @return A static string, e.g. @c "https://127.0.0.1:10251".
 */
extern const char *tsapi_k8s_ts_kubelet_ins_url(void);

/**
 * Bring a single-node k3s cluster up in Docker and wait for its API to be
 * ready. The API server runs with @c anonymous-auth=true (the upstream
 * Kubernetes default): an unauthenticated request is evaluated by RBAC
 * and denied, rather than refused outright, which is what the audits
 * look at. The kubelet keeps its secure default (anonymous auth off).
 *
 * @param s   Session.
 *
 * @return Status code.
 * @retval 0           The cluster is up and the API answers @c /readyz.
 * @retval TE_ENOENT   Docker is absent or the cluster would not come up -
 *                     the caller should skip.
 */
extern te_errno tsapi_k8s_ts_k3s_up(tsapi_k8s_ts *s);

/**
 * Tear the main k3s cluster down. Idempotent.
 *
 * @param s   Session.
 */
extern void tsapi_k8s_ts_k3s_down(tsapi_k8s_ts *s);

/**
 * Bring a throwaway single-node k3s cluster up with an intentionally open
 * kubelet (@c anonymous-auth=true, @c authorization-mode=AlwaysAllow) on a
 * separate port. This is the known-bad control for the kubelet audit: a
 * real kubelet that answers unauthenticated requests.
 *
 * @param s   Session.
 *
 * @return Status code.
 * @retval 0           The cluster is up.
 * @retval TE_ENOENT   Docker is absent or the cluster would not come up.
 */
extern te_errno tsapi_k8s_ts_k3s_insecure_kubelet_up(tsapi_k8s_ts *s);

/**
 * Tear the throwaway open-kubelet cluster down. Idempotent.
 *
 * @param s   Session.
 */
extern void tsapi_k8s_ts_k3s_insecure_kubelet_down(tsapi_k8s_ts *s);

/**
 * Run @c kubectl inside the main k3s container, as the cluster
 * administrator (it uses the in-container admin kubeconfig).
 *
 * @param[in]  s          Session.
 * @param[in]  args       Arguments after @c kubectl, as one shell string.
 * @param[in]  timeout_ms Timeout, ms.
 * @param[out] out        Stdout, trimmed (may be @c NULL).
 * @param[out] status     kubectl exit status, or -1 (may be @c NULL).
 *
 * @return Status code of running the command.
 */
extern te_errno tsapi_k8s_ts_kubectl(tsapi_k8s_ts *s, const char *args,
                                     int timeout_ms, te_string *out,
                                     int *status);

/**
 * Make an unauthenticated HTTPS @c GET of @p url from the agent with
 * @c curl (TLS verification off: the cluster is self-signed) and read back
 * the HTTP status code.
 *
 * @param[in]  s     Session.
 * @param[in]  url   Full URL.
 * @param[out] code  HTTP status code, or 0 if the server did not answer.
 *
 * @return Status code of running curl.
 */
extern te_errno tsapi_k8s_ts_http_code(tsapi_k8s_ts *s, const char *url,
                                       long *code);

/**
 * Make an unauthenticated HTTPS @c POST of @p url from the agent with
 * @c curl (TLS verification off) sending @p body, and read back the HTTP
 * status code.
 *
 * @param[in]  s     Session.
 * @param[in]  url   Full URL.
 * @param[in]  body  Request body (a short ASCII string), or @c NULL.
 * @param[out] code  HTTP status code, or 0 if the server did not answer.
 *
 * @return Status code of running curl.
 */
extern te_errno tsapi_k8s_ts_http_post_code(tsapi_k8s_ts *s, const char *url,
                                            const char *body, long *code);

/**
 * Run @c kubectl inside a named k3s container (@ref TSAPI_K8S_K3S_CT or
 * @ref TSAPI_K8S_K3S_INS_CT), as its cluster administrator.
 *
 * @param[in]  s          Session.
 * @param[in]  ct         Container name.
 * @param[in]  args       Arguments after @c kubectl, as one shell string.
 * @param[in]  timeout_ms Timeout, ms.
 * @param[out] out        Stdout, trimmed (may be @c NULL).
 * @param[out] status     kubectl exit status, or -1 (may be @c NULL).
 *
 * @return Status code of running the command.
 */
extern te_errno tsapi_k8s_ts_kubectl_ct(tsapi_k8s_ts *s, const char *ct,
                                        const char *args, int timeout_ms,
                                        te_string *out, int *status);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TSAPI_K8S_TS_H__ */
