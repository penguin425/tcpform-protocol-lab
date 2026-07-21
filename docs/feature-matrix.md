# Expansion feature matrix

This file is the completion checklist for the “implement every proposed
addition” goal. A checked item must have implementation and automated evidence;
categories marked partial are not considered complete.

## Operational expansion 1–10

- [x] Reproduction bundle v3 records the effective random seed, invocation and
  environment; all metadata is integrity-protected and CLI/browser compatible
- [x] Explicit `from_state` / `to_state` transitions are enforced per role and
  included in manifests and state-machine diagnostics
- [x] Deterministic DNS/refusal/TLS setup failures, link disconnect, delay
  spikes, dynamic bandwidth, NAT rewriting, MTU black holes and port exhaustion,
  in addition to loss, duplication, corruption and jitter
- [x] Seeded property-case generation, boundary values, browser execution and
  asynchronous failing-input shrinking
- [x] Baseline approval, tolerance profiles, multi-trace comparison, packet and
  timing regression reports, plus two-endpoint differential execution
- [x] PCAP import to raw-header DSL, capture/trace alignment, tshark filters and
  Lua dissector generation and directional TCP stream reassembly
- [x] DSL version markers and idempotent migration, variable-use and
  dependency-cycle diagnostics, contextual completion, cross-file navigation
  and refactoring
- [x] Trace annotations, standalone HTML report and print/PDF workflow, alongside
  SVG/PNG/Mermaid exports and large-trace virtualization
- [x] Runtime, trace, inbox, payload, retry, loop and plugin output/time limits;
  bundle path/integrity checks, secret anonymization and TLS expiry/cipher/ALPN
  auditing
- [x] Versioned, process-isolated JSON-RPC plugin API for custom actions,
  matchers, decoders and reports

Plugin invocation:

```text
tcpform plugin plugin.json matcher custom input.json
```

The plugin manifest declares `protocol_version = "1.0"` (as JSON), its command,
timeout/output limits and named capabilities. Each invocation receives one
JSON-RPC request and must return one response with the same id.

Plugins can also be invoked from a protocol. Results may publish variables,
decoded fields, matcher outcomes and report data:

```text
step "custom_check" {
  role = "client"
  action = "plugin"
  plugin {
    manifest = "plugins/custom.json"
    kind = "matcher"
    name = "valid_header"
    input = { value = "${captured_header}" }
  }
}
```

Maintenance and TLS audit commands:

```text
tcpform migrate --check protocol.tcpf
tcpform migrate --write protocol.tcpf
tcpform tls-audit --cert server.pem --warn-days 30
tcpform tls-audit --connect example.com:443 --server-name example.com
tcpform differential --left 127.0.0.1:8001 --right 127.0.0.1:8002 \
  --role client protocol.tcpf protocol_name
```

## Trace analysis

- [x] Saved queries and query history
- [x] Field/operator completion and positioned pipeline errors
- [x] Boolean filtering, time ranges through numeric predicates, sort/limit
- [x] Context events around matches
- [x] count/sum/avg/min/max/P50/P90/P95/P99 with grouping
- [x] CSV and JSON exports
- [x] Web Worker execution and bounded DOM rendering for large traces
- [x] Reusable virtual-window model and virtualized query result rendering
- [x] Apply virtual rendering to trace, query, diff and capture event lists

## Trace diff

- [x] LCS alignment, first divergence, added/removed/changed filtering data
- [x] Timestamp tolerance and volatile-field exclusions
- [x] Decoded-header and byte-level hex differences
- [x] JSON and standalone HTML reports
- [x] Multi-trace comparison API
- [x] Left/right selectors for current and case traces
- [x] Baseline approval and persisted comparison profiles
- [x] Include execution-history and arbitrary imported traces in both selectors

## State machine

- [x] Layered role-lane layout and trace-linked nodes
- [x] Transition diagnostics, cycle/blocking/terminal checks
- [x] Node and edge coverage model
- [x] Mermaid and Graphviz output
- [x] Interactive pan/zoom and SVG/PNG state export

## Fault generation and exploration

- [x] Loss, delay, jitter, bandwidth, MTU, reorder, duplicate, corrupt variants
- [x] Deterministic seeds and generated DSL
- [x] Configurable concurrent grid runner, progress and cancellation API
- [x] Minimal failure reduction, boundary search and confidence interval APIs
- [x] Burst loss and step/Nth/flag-scoped faults in the runtime engine
- [x] General structured and decoded raw-header equality predicate scopes
- [x] Browser heatmap, pause/resume/stop and minimal-result-to-DSL workflow

## DSL, formatter and language tooling

- [x] Step/role rename, module extraction and unused-step analysis APIs
- [x] CLI/browser formatter and basic stdio LSP
- [x] Inline module, protocol/case/module rename, cross-file preview and undo/redo
- [x] Formatter stdin/range/config/indent/alignment modes
- [x] LSP hover/references/symbols/semantic tokens/actions/format/inlay hints
- [x] Minimal VS Code extension package
- [x] Formatter explicit inline-block expansion and browser range selection UI
- [x] Cross-file import definitions and context-sensitive LSP completion

## Wireshark, bundles and anonymization

- [x] IPv4/IPv6/TCP/UDP/frame display filters and mappings
- [x] Versioned bundle with imported source collection and browser opening
- [x] Stable IPv4/MAC, secret and length-preserving hex masking
- [x] tshark commands, stream extraction and generated Lua dissectors
- [x] Bundle capture/case/config/diagnostic hashes, migration and CLI replay
- [x] IPv6/hostname/URL/email/JWT/DSL masking, configurable rules and audit report

## Regression and CI

- [x] Success/P95/coverage/retry thresholds and non-zero CLI result
- [x] CI smoke invocation
- [x] Config file, protocol/case profiles, stored baselines and tolerances
- [x] Packet changes, flaky detection and repeated stability runs
- [x] Markdown/JUnit/GitHub annotation and PR summary outputs

## UI platform

- [x] Tabs, resizable panels, command palette and keyboard shortcuts
- [x] URL state, undo/redo and persistent workspace state
- [x] Light theme and Japanese/English localization
- [x] Accessibility labels/focus controls, mobile layout and crash recovery

## Local productivity additions

- [x] Scriptable/interactive trace debugger with breakpoints, watches and rewind
- [x] Editable PCAP field boundaries with server-side DSL validation
- [x] Runnable OpenAPI/Protobuf cases and deterministic CLI property generation
- [x] DSL semantic compatibility report with CI exit status
- [x] Raw performance samples and statistical latency significance gate
- [x] Retention/capacity preview and explicitly confirmed pruning UI
- [x] Reproducibly built browser WebAssembly simulator for the portable subset
- [x] Terminal run inspector, import-aware watch mode, and one-role TCP/UDP mock server
- [x] HAR and bounded live-capture import, deterministic budgeted fault campaigns
- [x] Read-only Git regression bisection and configurable DSL lint policy
- [x] Guided local tutorial, VS Code Test Explorer, and portable execution report

## Live transports

- [x] TCP/UDP/TLS/raw sockets and framing already available
- [x] Simulation jitter, bandwidth shaping and MTU enforcement
- [x] Stream half-close, UDP reuse/multicast/broadcast and IPv4/IPv6 live endpoints
- [x] TCP/TLS proxy and certificate-authorized MITM mode
- [x] Unix domain sockets and mTLS/ALPN/SNI
- [x] WebSocket and QUIC transports
- [x] External process orchestration, namespaces and automatic capture lifecycle
