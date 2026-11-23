# tsf-k8s-ts

A Test Environment suite that audits a single-node Kubernetes cluster
(k3s, brought up in Docker on the agent it runs on) the way an
unauthenticated network peer would see it. Findings are collected through
[tsf-cybersec](https://github.com/interpretica-io/tsf-cybersec); the gate
fails on any finding ≥ HIGH.

| Test | What it checks |
|---|---|
| `anon_api` | anonymous reads of the API server — `/version`, `/api`, namespaces, pods, the RBAC bindings and Secrets — must be denied (403), not served (200) |
| `rbac` | the authorizer (`kubectl auth can-i --as=system:anonymous`) must grant `system:anonymous` none of the dangerous verb/resource pairs (`* *`, get secrets, create pods, create ClusterRoleBindings, node proxy, impersonate) |
| `anon_kubelet` | the kubelet must reject unauthenticated reads of `/pods`, `/runningpods` and `/metrics` (401) |

Each audit runs twice, selected by the `profile` argument:

- `baseline` — the secure cluster as the group prologue left it; the audit
  passes;
- `open` — a **reversible known-bad control** that makes the finding fire:
  `anon_api`/`rbac` bind `cluster-admin` to `system:anonymous` (reverted in
  cleanup); `anon_kubelet` brings up a throwaway cluster whose kubelet has
  anonymous auth on (torn down in cleanup). The audit fails, and
  `conf/trc.xml` records that failure as expected.

Every numeric test emits a native TE MI line-graph (anonymous HTTP status,
or the allowed/denied answer, per endpoint), so the HTML log draws the
posture.

## Authorized use only

The suite brings up its own cluster and reads it. If you point it at an
existing cluster (`TSF_K8S_API_URL`, `TSF_K8S_KUBELET_URL`), point it only
at one you own or are engaged to test.

## Running it

```bash
./scripts/run.sh guess --cfg=localhost      # native; or prefix 'docker'
```

Needs `test-environment` as a sibling, and Docker on the agent host (it
pulls `rancher/k3s`). The Builder resolves the tsf-devtool → tsf-kernel →
tsf-cybersec chain from `conf/external.yml`. With no Docker the group skips
cleanly, so a bare run is green.

Environment overrides: `TSF_K8S_IMAGE` (k3s image), `TSF_K8S_API_URL`,
`TSF_K8S_KUBELET_URL`, `TSF_K8S_KUBELET_INS_URL`.

## Status

Verified by building and running natively on a Linux host with Docker: the
`baseline` profiles pass and the `open` controls fail with the verdicts the
TRC records, so the run reports the expected pattern.
