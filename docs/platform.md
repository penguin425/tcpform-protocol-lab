# tcpform platform features

The visualizer server can now be run as a persistent team service:

```sh
tcpform serve --bind 127.0.0.1:8080 --db tcpform.sqlite \
  --workers 4 --retention-days 30 --auth-config auth.json
```

`auth.json` is an array of `{ "name", "token_sha256", "role" }`. Roles are
`viewer`, `runner`, and `admin`. Mutating authenticated requests require both
`Authorization: Bearer …` and `X-Tcpform-CSRF: 1`. The service applies a
per-identity rate limit and records mutations in `audit_log`.

The stable API is described by `GET /api/openapi.json`. Versioned routes cover
jobs, run history, baselines, annotations, failure corpus and expiring shares.
Queued jobs survive a process restart and support cancellation and retry.
Prometheus text metrics are available to administrators at `GET /metrics`.

Additional CI commands are grouped under `tcpform platform`:

- `openapi-import`, `protobuf-import`, `proto-export`, and `wireshark`
- `schema-check` for backwards compatibility
- `k8s-job` for an Indexed Kubernetes Job manifest
- `html-report` and `sarif` for portable/PR reporting
- `netem` for validated Linux `tc netem` apply and cleanup arguments

The Rust API in `tcpform::platform` additionally exposes deterministic worker
result aggregation, nanosecond monotonic clocks, structured timing spans,
trace stepping/breakpoints/rewind, Ed25519 plugin verification and report
formatters. Failed visualization documents are fingerprinted in SQLite, so
duplicates increase an occurrence count instead of creating unbounded copies.
