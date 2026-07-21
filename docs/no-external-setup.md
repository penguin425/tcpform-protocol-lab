# No-external-setup implementation audit

This audit maps the 20 follow-up ideas to implementation evidence. “External
setup” means an account, publishing credential, hosted registry, organization
configuration, database server, or distributed compute environment that must
exist outside this repository.

| # | Capability | Result and evidence |
|---|---|---|
| 1 | Publish the VS Code extension | Excluded: marketplace publisher account and token are required. The extension package remains buildable locally. |
| 2 | crates.io distribution | Excluded: crates.io ownership and publishing token are required. |
| 3 | Homebrew/Scoop/Winget | Excluded: external package repositories and maintainer credentials are required. |
| 4 | DSL debugger | Implemented: `tcpform debug` supports step, continue, rewind, inspect, breakpoints, watches, an interactive REPL, and command files. |
| 5 | Manual PCAP field boundaries | Implemented: capture review fields can be added, removed, renamed, moved, resized, typed, validated by Rust, and regenerated into runnable DSL. |
| 6 | Wireshark round trip | Already implemented: PCAP import, trace alignment, display filters, tshark commands, stream extraction, and Lua dissector export. Installing Wireshark is optional. |
| 7 | OpenAPI/Protobuf test generation | Implemented: imports generate request/receive pairs and runnable tagged cases. |
| 8 | DSL compatibility | Implemented: `tcpform platform dsl-compat` reports removed steps/schemas/fields and role, action, dependency, and wire-layout changes with a CI failure status. |
| 9 | Protocol coverage | Already implemented: step, branch, failed-path, node, edge, case, and requirements coverage are available in the dashboard and reports. |
| 10 | Property-based tests | Implemented locally and in-browser: `platform property-cases` and the workbench use deterministic seeds, boundaries, execution, and shrinking. |
| 11 | Regression cases from failures | Already implemented: deduplicated failure corpus entries can be promoted and revalidated as background jobs with their source bundle and protocol. |
| 12 | Load/endurance testing | Local portion already implemented through bounded iterations, warmup, parallel jobs, deadlines, throughput and latency gates. Distributed execution is excluded because it requires compute infrastructure. |
| 13 | Statistical latency regression | Implemented: performance reports retain raw latency samples and baseline comparison calculates a two-sided significance value; `--max-p-value` gates CI. |
| 14 | GitHub Checks annotations | Already implemented as portable workflow annotations, SARIF, Markdown, and JUnit. Publishing them requires GitHub and is therefore not a new local prerequisite. |
| 15 | Organization authentication | Excluded: organization identity-provider configuration is required. Existing local bearer-role configuration remains available. |
| 16 | PostgreSQL/multi-server | Excluded: an external database and deployment topology are required. |
| 17 | Retention/capacity UI | Implemented: authenticated preview reports database bytes and expired rows per table; pruning requires an explicit confirmation. |
| 18 | Official plugin/template registry | Excluded: registry hosting, trust ownership, and signing operations are required. Local signed and pinned registries remain supported. |
| 19 | Secret masking | Already implemented: stable address replacement, secret/JWT/URL/email/hostname masking, length-preserving hex masking, custom rules, and an audit report. |
| 20 | Browser WebAssembly simulator | Implemented: a dependency-free committed WASM engine executes the portable DSL subset without a server, reports unsupported steps, and is reproducibly rebuilt in CI. |

The excluded items are intentionally not represented as complete. They should
be reconsidered only after the required external ownership or infrastructure
has been selected.
