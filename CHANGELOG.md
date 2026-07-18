# Changelog

All notable changes to tcpform are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- Distribute container releases across native AMD64 and ARM64 runners, reuse
  architecture-scoped BuildKit caches, and mirror completed manifests to
  Docker Hub without rebuilding them under QEMU.

## [0.7.0] - 2026-07-19

### Added

- Define bidirectional dynamic message schemas with length, repetition,
  conditions, enums, bit fields, nested regions, checksums, compression, and
  authenticated encryption.
- Run bounded, state-aware robustness campaigns with deterministic mutation,
  novelty retention, crash artifacts, and delta-debugged reproducers.
- Import normative specification requirements and trace them to protocol tests
  and conformance results.
- Explore finite protocol state spaces, check invariants, and report deadlocks
  with counterexample traces.
- Plan multi-node, multi-role topologies with remote placement, links,
  dependencies, namespaces, and capture points.
- Correlate eBPF network events with protocol traces and export OpenTelemetry
  spans in OTLP JSON form.
- Exchange annotated TTCN-3 protocol flows and import fixed-layout ASN.1
  definitions with explicit encoding limitations.
- Benchmark protocols using bounded real-clock workers, latency percentiles,
  throughput, jitter, deadlines, JSON baselines, and CI regression gates.

## [0.6.0] - 2026-07-17

### Added

- Infer TCP session roles, protocol states, repeated-payload fields, and header
  schemas when generating DSL from PCAP or PCAPNG captures.
- Import fixed-layout Kaitai Struct schemas into tcpform header schemas with
  explicit warnings for unsupported dynamic constructs.
- Export field-aware Wireshark Lua dissectors and Scapy packet definitions.
- Generate boofuzz harnesses and AFLNet seed corpora from declarative protocol
  flows.
- Import and export supported packetdrill packet scripts.
- Produce requirement-level protocol conformance reports for external targets
  in JSON, Markdown, and JUnit formats.
- Test two or more implementations and report pairwise observable differences
  as an interoperability compatibility matrix.

## [0.5.2] - 2026-07-16

### Fixed

- Include `platform-ui.js` in the dashboard image so initialization can load
  sample manifests instead of stalling.

## [0.5.1] - 2026-07-15

### Changed

- Updated the Docker publishing actions to their Node.js 24-based major
  versions.

## [0.5.0] - 2026-07-15

### Added

- Added signed multi-platform CLI and dashboard container publishing to GHCR,
  with optional Docker Hub mirroring, SBOMs, provenance, and a published-image
  Compose lab.

### Changed

- Run the published CLI image as UID/GID 10001 by default and require raw labs
  to opt into root startup and narrowly scoped capabilities explicitly.

## [0.4.1] - 2026-07-15

### Changed

- Replaced third-party product and configuration-language comparisons with
  vendor-neutral descriptions of tcpform's declarative, block-oriented DSL.

## [0.4.0] - 2026-07-15

### Changed

- Raised the minimum supported Rust version from 1.88 to 1.97 and updated the
  digest-pinned Docker builder image accordingly.
- Updated `rusqlite` from 0.39.0 to 0.40.1 and the release artifact download
  action from v7 to v8.

## [0.3.1] - 2026-07-15

### Security

- Update the dashboard to the digest-pinned nginx 1.31.2 Alpine 3.23 slim image
  and enable weekly Dependabot updates for Docker base images.

## [0.3.0] - 2026-07-15

### Added

- External template registry search, pinned Git retrieval, trusted-owner policy,
  SHA256 and Ed25519 verification, deterministic caching, and lock files.
- Git-friendly local snapshot creation, checking, and explicit updates with
  packet, header, state-machine, result, latency, and Visualizer data.
- `tcpform import-pcap` generation of starter DSL and smoke cases from classic
  PCAP or PCAPNG TCP/UDP captures, including sessions, roles, headers, payloads,
  and packet timing.
- Full VS Code workflow with richer syntax highlighting, LSP-backed editing,
  format on save, protocol run/test CodeLens, an embedded Visualizer, and
  automatic DSL v2 schema generation.
- `tcpform doctor` project and host diagnostics with human-readable and JSON
  output for raw sockets, Docker, formatter configuration, imports, plugin
  signatures, and GitHub Actions.
- Dependency-free Bash and Zsh completion generation through
  `tcpform completion`.

## [0.2.0] - 2026-07-15

### Added

- Project scaffolding with `tcpform init`, five built-in protocol templates,
  formatter configuration, smoke cases, and GitHub Actions CI.
- Pull-request differential reports for success rate, P95 latency, packets,
  headers, state-machine changes, and newly failing cases.
- Explicit DSL version metadata, deprecation diagnostics, automatic migration,
  and a machine-readable JSON Schema.
- Automated signed-tag releases with native archives and SHA256 checksums.
- Contribution, security, conduct, issue, and pull request guidance for the OSS
  community.

## [0.1.1] - 2026-07-15

### Changed

- Added cross-platform CI for Rust stable and Rust 1.88 on Linux, macOS, and
  Windows, with aggregate required checks.
- Updated `quick-xml` to 0.41, `tungstenite` to 0.30, and `sha2` to 0.11.
- Adapted digest formatting for `sha2` 0.11.

### Fixed

- Stabilized retransmission, browser E2E, and cross-platform integration tests.
- Handled platform-specific socket closure behavior.

## [0.1.0] - 2026-07-15

### Added

- Initial public release of the declarative protocol DSL, simulation engine,
  live transports, raw packet workflows, browser visualizer, test cases, fault
  injection, PCAP output, LSP, formatter, bundles, plugins, and CI tooling.

[Unreleased]: https://github.com/penguin425/tcpform-protocol-lab/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/penguin425/tcpform-protocol-lab/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/penguin425/tcpform-protocol-lab/compare/v0.5.2...v0.6.0
[0.5.2]: https://github.com/penguin425/tcpform-protocol-lab/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/penguin425/tcpform-protocol-lab/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/penguin425/tcpform-protocol-lab/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/penguin425/tcpform-protocol-lab/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/penguin425/tcpform-protocol-lab/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/penguin425/tcpform-protocol-lab/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/penguin425/tcpform-protocol-lab/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/penguin425/tcpform-protocol-lab/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/penguin425/tcpform-protocol-lab/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/penguin425/tcpform-protocol-lab/releases/tag/v0.1.0
