# Changelog

All notable changes to tcpform are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/penguin425/tcpform-protocol-lab/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/penguin425/tcpform-protocol-lab/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/penguin425/tcpform-protocol-lab/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/penguin425/tcpform-protocol-lab/releases/tag/v0.1.0
