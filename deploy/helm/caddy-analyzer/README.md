# caddy-analyzer Helm chart

This chart runs the CLI in `tail --detect` mode and reads JSON-lines Caddy
access logs from a read-only mounted volume. It does not create a Service,
ServiceAccount, RBAC rules, or an HTTP endpoint.

## Install

The default `emptyDir` is intentionally safe but contains no logs. Point the
chart at a PVC containing the logs:

```sh
helm upgrade --install caddy-analyzer ./deploy/helm/caddy-analyzer \
  --set logVolume.existingClaim=caddy-logs
```

For a local single-node demo, a host path can be used explicitly:

```sh
helm upgrade --install caddy-analyzer ./deploy/helm/caddy-analyzer \
  --set logVolume.hostPath=/var/log/caddy
```

The generated `caddy-analyzer.json` defaults to `/logs/access.log`. Override
it with `--set config.source=/logs/caddy_access.log` when needed.

## Probes and permissions

The image is a CLI and exposes no health or metrics endpoint. The optional
liveness probe only checks that PID 1 is alive; it does not assert that a log
file exists or that analysis is progressing. Readiness is intentionally not
claimed. Disable it with `--set livenessProbe.enabled=false` if the workload
is managed by an external supervisor.

The pod runs as non-root with all Linux capabilities dropped, a read-only root
filesystem, and no service-account token. Docker socket mounting is disabled
by default. `--set dockerSocket.enabled=true` is an explicit opt-in and gives
the pod control over the configured Docker daemon; use only for a trusted
local demo and review the resulting hostPath policy first.
