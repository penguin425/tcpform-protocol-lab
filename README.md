# tcpform

Compose protocol primitives — `send`, `recv`, `ack`, `wait`, `close` — into
**new protocols** using a **declarative protocol DSL**, then **simulate**
them and inspect the message timeline.

You describe a protocol as ordered, composable steps (with flags, sequence
numbers, ack numbers, payloads, timers and cross-step dependencies); `tcpform`
builds a dependency graph, validates it, and runs both endpoints against an
in-memory or real TCP/UDP transport, printing a trace of every segment exchanged.

> Declare the *shape* of a protocol conversation, validate its dependency
> graph, then run both endpoints against simulated or real transports.

## Build & run

Prebuilt archives for Linux, macOS, and Windows are attached to each
[GitHub Release](https://github.com/penguin425/tcpform-protocol-lab/releases).
Verify a downloaded archive against `SHA256SUMS` before extracting it.

Release containers are published separately for the CLI and Visualizer:

```sh
docker pull ghcr.io/penguin425/tcpform:latest
docker pull ghcr.io/penguin425/tcpform-dashboard:latest
docker run --rm ghcr.io/penguin425/tcpform:latest \
  list /scenarios/raw_docker_udp.tcpf
```

The CLI image runs as UID/GID 10001 by default. Raw packet access is available
through [`compose.published.yml`](compose.published.yml), which explicitly
starts as root with only `NET_RAW`, `SETUID`, and `SETGID`, then instructs
tcpform to drop permanently to UID/GID 10001 before executing the scenario.

```sh
cargo build --release
./target/release/tcpform <command> ...
```

Maintainers create a release by updating the package version in `Cargo.toml`
and `Cargo.lock`, merging that change, and pushing a matching signed tag such
as `v0.1.2`. The release workflow builds native archives, publishes checksums,
and creates or updates the GitHub Release. To additionally publish to crates.io,
set the repository variable `PUBLISH_CRATE` to `true` and add the
`CARGO_REGISTRY_TOKEN` Actions secret.

## Start a protocol project

Create a ready-to-run project from a built-in template. Available templates are
`tcp-handshake`, `dns`, `http`, `websocket`, and `tls`.

```sh
tcpform template list
tcpform init my-protocol --template websocket
cd my-protocol
tcpform validate protocol.tcpf
tcpform test protocol.tcpf
```

The generated project includes a versioned DSL file, smoke case, formatter
configuration, README, and GitHub Actions workflow. On pull requests, CI posts
or updates one differential report covering success rate, P95 latency, packet
and header changes, state-machine changes, and newly failing cases.

DSL documents should declare `tcpform { dsl_version = 2 }`. Older documents
continue to load with deprecation warnings and can be upgraded in place:

```sh
tcpform migrate --check protocol.tcpf
tcpform migrate --write protocol.tcpf
tcpform schema dsl --output tcpform-dsl.schema.json
```

For custom CI, create snapshots for the base and current revisions and compare
them with `tcpform ci-report base.json current.json --markdown report.md`.

## CLI

```text
tcpform validate <file>                # parse + validate every protocol
tcpform init demo --template websocket # scaffold a protocol project and CI
tcpform template list                  # list built-in protocol templates
tcpform template search mqtt           # search the configured external registry
tcpform template add owner/mqtt        # verify, cache, and lock an external template
tcpform schema dsl                     # print the machine-readable DSL schema
tcpform snapshot protocol.tcpf         # create/check protocol.tcpf.snapshot.json
tcpform snapshot --check protocol.tcpf # fail when behavior differs from Git
tcpform snapshot --update protocol.tcpf # accept current behavior as baseline
tcpform ci-snapshot --output result.json <file> [protocol]
tcpform ci-report base.json result.json --markdown report.md
tcpform doctor [--json] [project-directory] # diagnose host and project setup
tcpform completion bash               # generate Bash completion
tcpform completion zsh                # generate Zsh completion
tcpform import-pcap capture.pcapng --protocol captured --output captured.tcpf \
  --analysis captured.inference.json
tcpform list <file>                    # list protocols, steps, roles
tcpform plan   <file> <protocol>       # show the resolved topological order
tcpform run    <file> <protocol>       # simulate and print the event timeline
tcpform run --json --diagram <file> <protocol> # output modes can be combined
tcpform visualize --output ./visual <file> <protocol>
tcpform run --pcap out.pcap --pcapng out.pcapng <file> <protocol>
tcpform run --live [--udp] --bind 127.0.0.1:0 <file> <protocol>
tcpform run --external --role client --connect host:port <file> <protocol>
tcpform run --external --udp --role client --connect host:port <file> <protocol>
tcpform run --raw --interface eth0 --role client <file> <protocol>
tcpform run --external --tls --role client --connect host:port \
  --server-name example.com [--ca ca.pem] <file> <protocol>
tcpform run --external --websocket --role client --connect ws://host/path <file> <protocol>
tcpform run --external --quic --role client --connect host:port \
  --server-name example.com --alpn my-protocol <file> <protocol>
tcpform run --external --unix --role client --connect /tmp/service.sock <file> <protocol>
./scripts/docker-raw-test.sh          # isolated two-container raw packet lab
./scripts/docker-visual-lab.sh up     # run lab and open the browser dashboard
tcpform test --jobs 8 --tag smoke <file> [protocol]
tcpform test --case 'valid|retry' --shard 1/4 --junit report.xml <file>
tcpform fmt [--check|--write] [--indent 4] [--align] <file...>
tcpform fmt --stdin [--config .tcpformfmt.json]
tcpform lsp                           # Language Server Protocol over stdio
tcpform generate-faults --output faults <file>
tcpform explore <file> <protocol>     # loss/delay/seed matrix + minimal failure
tcpform bundle --output repro.tcpfbundle <file> <protocol>
tcpform replay-bundle repro.tcpfbundle
tcpform anonymize input.json shared.json
tcpform gate metrics.json --min-success-rate 1 --max-p95-us 50000
tcpform orchestrate scenario.json [--dry-run]
tcpform proxy --listen 127.0.0.1:8443 --upstream service:443 \
  --tls-cert proxy.pem --tls-key proxy-key.pem --tls-upstream \
  --ca upstream-ca.pem --server-name service
```

`tcpform doctor` checks the tcpform and DSL versions, raw-socket permissions,
Docker Engine and Compose v2, `.tcpformfmt.json`, every `.tcpf` import graph,
plugin signatures in `.tcpform/plugins.lock.json`, and GitHub Actions setup.
Warnings describe optional capabilities; invalid configuration or broken
imports produce a non-zero exit status. Use `--json` for CI or editor tooling.

Install generated shell completions with one of the following:

```sh
# Bash
tcpform completion bash > ~/.local/share/bash-completion/completions/tcpform

# Zsh (ensure ~/.zfunc is in fpath)
tcpform completion zsh > ~/.zfunc/_tcpform
```

`tcpform import-pcap` accepts classic PCAP and PCAPNG captures with Ethernet or
raw-IP link types. It groups IPv4/IPv6 TCP and UDP packets into sessions,
identifies the TCP initiator, infers per-role handshake/data/closing states, and
uses repeated same-direction payloads to propose fixed and variable field
boundaries as `header_schema` blocks. It also generates endpoint/header
comments, timing delays, payload hex, send/receive steps, and a smoke case.
`--analysis` writes the session states, inferred fields, confidence scores, and
sample values as JSON for review or downstream tooling. Treat all inferred DSL
and field boundaries as hypotheses: captures may be incomplete and may contain
credentials or other sensitive payloads.

`tcpform snapshot` stores packets, decoded headers, state transitions, case
success rates, P95 latency, and the complete Visualizer manifest in readable
JSON. Commit the generated `*.snapshot.json` file to Git and use `--check` in
CI. Running without a mode creates a missing snapshot and checks an existing
one; `--update` explicitly replaces it. Runtime latency has a 1000 µs default
tolerance, configurable with `--latency-tolerance-us`, while protocol structure
and packet data are compared exactly. Use `--output` to choose another path.

External templates use `.tcpform/template-registry.json` as an explicit trust
policy. Each entry names a trusted owner, semantic version, full 40-character
Git commit, repository path, template path, SHA256, Ed25519 signature, and
public key. For example:

```json
{
  "schema_version": "1.0",
  "trusted_owners": ["owner"],
  "templates": [{
    "name": "owner/mqtt",
    "version": "1.0.0",
    "repository": "https://github.com/owner/mqtt.git",
    "revision": "0123456789abcdef0123456789abcdef01234567",
    "path": "tcpform/template.tcpf",
    "sha256": "<64 hexadecimal characters>",
    "signature_hex": "<Ed25519 signature over the exact template bytes>",
    "public_key_hex": "<Ed25519 public key>"
  }]
}
```

Run `tcpform template search mqtt`, then `tcpform template add owner/mqtt`.
The add command clones only for verification, checks out the pinned commit,
verifies the digest and signature, caches the exact bytes, and writes
`.tcpform/templates.lock.json`. Afterwards,
`tcpform init broker-test --template owner/mqtt` works from the verified cache.
Commit the registry, lock file, and `.tcpform/templates/` cache so CI and other
contributors use the same reviewed bytes without a mutable network lookup.
Changing the registry is a trust-policy change and should receive code-owner
review. Use `--registry <file>` for a non-default index.

The formatter discovers `.tcpformfmt.json` or accepts an explicit `--config`.
Supported keys are `indent_width`, `align_attributes`, and
`preserve_inline_blocks`. The LSP provides diagnostics, completion,
definitions, references, rename, hover, document/workspace symbols, semantic
tokens, formatting, code actions, and inlay hints. The VS Code extension in
`editors/vscode` adds syntax highlighting, format-on-save defaults, protocol
run/test CodeLens, an embedded Visualizer webview, and automatic local DSL v2
JSON Schema generation. Configure `tcpform.executable` when the binary is not
on `PATH`; run `npm install` before packaging or launching the extension host.

The browser visualizer includes a Protocol workbench for boolean trace queries,
LCS-aligned trace/header/payload diffs, generated fault variants, state-machine
diagnostics, rename/unused-step refactoring, DSL formatting, Wireshark display
filters, condition exploration, portable repro bundles, anonymized exports, and
regression gates. A `.tcpfbundle` is versioned JSON containing the root and
imported DSL sources, manifest, traces, and environment metadata; it can be
opened with the same **Open files** control.

Trace queries support parentheses and `and`, `or`, `not`, with `=`, `!=`,
`>`, `>=`, `<`, `<=`, `contains`, and `matches`. Event fields such as `role`,
`step`, `action`, `status`, `duration_us`, and decoded header paths are
available, for example:

```text
role = "client" and duration_us > 10 and headers.ipv4.ttl < 64
```

Example (data-driven testing):

```sh
$ tcpform test examples/dns_cases.tcpf
Testing protocol `dns_lookup` — 4 cases
#    case                 expect   actual   result detail
1    valid_a_record       pass     pass     PASS
2    valid_aaaa_record    pass     pass     PASS
3    nxdomain             pass     pass     PASS
4    servfail             pass     pass     PASS

Testing protocol `dns_lookup` — 1 cases
#    case                 expect   actual   result detail
1    rcode_mismatch       fail     fail     PASS

5/5 cases passed
```

Example:

```sh
$ tcpform run examples/tcp_handshake.tcpf tcp_handshake
#    role     step           act    ok   detail
1    client   syn            send   ok   send -> server flags=SYN seq=1000 ack=0
2    server   recv_syn       recv   ok   recv <- client flags=SYN seq=1000 ack=0
3    server   syn_ack        send   ok   send -> client flags=SYN,ACK seq=5000 ack=1001
4    client   recv_syn_ack   recv   ok   recv <- server flags=SYN,ACK seq=5000 ack=1001
5    client   ack            send   ok   send -> server flags=ACK seq=1001 ack=5001
6    server   recv_ack       recv   ok   recv <- client flags=ACK seq=1001 ack=5001

result: ok (6 events)
```

## The DSL

A `.tcpf` file contains `protocol` blocks; each contains `step` blocks.

```text
protocol "tcp_handshake" {
  description = "TCP three-way handshake"

  step "syn" {
    role   = "client"
    action = "send"
    segment { flags = ["SYN"] seq = 1000 }
  }

  step "recv_syn" {
    role   = "server"
    action = "recv"
    expect { flags = ["SYN"] }
  }

  step "syn_ack" {
    role       = "server"
    action     = "send"
    depends_on = ["recv_syn"]
    segment    { flags = ["SYN", "ACK"] seq = 5000 ack = 1001 }
  }

  step "ack" {
    role       = "client"
    action     = "send"
    depends_on = ["recv_syn_ack"]
    segment    { flags = ["ACK"] ack = 5001 }
  }

  step "recv_syn_ack" {
    role       = "client"
    action     = "recv"
    depends_on = ["syn"]
    expect     { flags = ["SYN", "ACK"] }
  }
}
```

### Step attributes

| attribute     | type           | meaning                                              |
|---------------|----------------|------------------------------------------------------|
| `role`        | string         | which endpoint performs the step                     |
| `action`      | string         | see the action table below                           |
| `depends_on`  | array<string>  | steps that must complete first (cross-role sync)     |
| `to`          | string         | destination role for outbound actions (auto if 2 roles) |
| `mode`        | string         | `open`: `"active"` (connect) or `"passive"` (listen) |
| `message`     | string         | free-text note emitted by `log` steps                |
| `retransmit`  | number         | on `recv` timeout, resend the role's last outbound step up to N times |
| `when`        | bool/string    | run only when the bool or interpolated `${var}` is true |
| `retry`       | number         | retry this step N times after an execution failure     |
| `on_timeout`  | bool           | restrict `retry` to timeout failures                   |
| `retry_on`    | array<string>  | retry selected typed failures (`timeout`, `transport`, etc.) |
| `retry_delay` | duration       | delay before the first retry                           |
| `retry_max_delay` | duration   | cap for exponential retry delay                        |
| `retry_backoff` | number       | delay multiplier, at least 1.0                         |
| `retry_jitter` | number        | deterministic jitter fraction from 0.0 through 1.0     |
| `loop`        | number         | execute the step N times (`0` records a skip)          |

### Actions

| action               | aliases          | meaning                                                        |
|----------------------|------------------|----------------------------------------------------------------|
| `send`               |                  | transmit a segment                                             |
| `send_raw`           |                  | construct and transmit an IP or Ethernet packet                |
| `recv`               |                  | wait for and consume a matching inbound segment                |
| `recv_raw`           |                  | decode/reassemble and match an inbound raw packet               |
| `ack`                |                  | send a positive ACK (auto-computes ack# from last recv)        |
| `nack`               |                  | send a negative ACK (references the rejected seq)              |
| `wait`               |                  | sleep for `timer.timeout`                                      |
| `open`               | `connect`,`listen`| record a connection start (`listen` ⇒ passive mode)          |
| `close`              |                  | graceful close (no segment emitted)                            |
| `reset`              | `abort`          | send an RST and mark the role aborted (`assert { aborted=true }`) |
| `drop`               |                  | consume & discard a matching inbound segment (loss injection)  |
| `duplicate`          | `dup`            | send the same segment twice (duplicate injection)              |
| `corrupt`            |                  | flip `segment.flip` in a raw hex payload and transmit it        |
| `assert`             | `check`          | verify role state; fails the run on mismatch                   |
| `set`                |                  | write local variables readable by later `assert`               |
| `log`                | `mark`           | emit a trace marker with `message`                             |

> **Reordering** is not a primitive: declare two `recv` steps in the order you
> want them satisfied — the matcher scans the inbox and leaves non-matching
> segments for later recvs, so out-of-order arrival is handled naturally.

### `segment { ... }` (for outbound actions)

`flags` (array), `seq` (number), `ack` (number), `payload` (string),
`hex` (string — raw binary payload, see below),
`payload_len` (number), `window` (number — flow-control advertisement),
`stream` (number — multiplexing id, QUIC/HTTP2),
`delay` (duration string — extra delivery latency for this segment),
`flip` (number — zero-based, MSB-first bit index used by `corrupt`),
`fields` (object — structured key/value fields, see below). If `seq` is
omitted, the role's auto-advancing sequence number is used. For `ack`, if
`ack` is omitted it is computed as
`last_received_seq + max(1, last_received_payload_len)`. For `nack`, `ack`
defaults to `last_received_seq` (the rejected sequence). When `hex` is set,
it takes precedence over `payload`.

### `expect { ... }` (for `recv` / `drop`)

`flags` (array — **subset** match, so `["SYN"]` matches `["SYN","ACK"]`),
`payload` (string — exact match), `hex` (string — exact binary match),
`hex_contains` (string — binary substring match),
`from` (string — source role filter),
`window` (number — must equal the segment's advertised window),
`stream` (number — must equal the segment's stream id),
`fields` (object — per-field matchers, see below),
`capture { field = "var" }` (nested block — capture fields into variables).

### Structured message fields

Segments carry a `fields` object of key/value pairs alongside the raw
`payload`. This lets you model structured wire messages (DNS records, HTTP
headers, gRPC metadata) and test individual fields without full-message
equality:

```text
# send with structured fields
segment { flags = ["DNS"] fields = { id = 4242 name = "example.com" qtype = 1 } }

# recv: partial field match — only named fields are checked
expect { flags = ["DNS"] fields = { qtype = 1 name = "example.com" } }
```

Field match operators (in `expect.fields`):

| syntax | meaning |
|---|---|
| `key = value` | exact equality (number, string, bool) |
| `key = { hex = "aabb" }` | exact binary equality (bytes) |
| `key = { hex_contains = "aabb" }` | binary substring match (bytes) |
| `key = { contains = "str" }` | string contains substring |
| `key = { not_equal = value }` | value is not equal |
| `key = { prefix = "str" }` | string starts with prefix |
| `key = { suffix = "str" }` | string ends with suffix |
| `key = { regex = "pattern" }` | string matches a regular expression |
| `key = { min = N }` | number ≥ N |
| `key = { max = N }` | number ≤ N |
| `key = { min = N max = M }` | number in range [N, M] |

### Binary messages (hex)

Segments can carry raw binary payloads via `hex = "..."`. Hex strings accept
an optional `0x` prefix and embedded whitespace (so `"45 00 00 3c"` is valid).
`hex` takes precedence over `payload` when both are set:

```text
# send a binary payload
segment { flags = ["DNS"] hex = "1234 0100 0001 0000 0000 0000 07 6578616d706c65 03 636f6d 00" }

# recv: exact binary match
expect { flags = ["DNS"] hex = "1234 0100 0001 0000 0000 0000 07 6578616d706c65 03 636f6d 00" }

# recv: binary substring match (checks the payload contains these bytes)
expect { flags = ["DNS"] hex_contains = "6578616d706c65" }
```

Binary field values use `fields = { key = { hex = "aabb" } }`. Captured binary
fields can be interpolated back into `hex` payloads via `${var}`:

```text
# field with binary value
segment { flags = ["DNS"] fields = { id = { hex = "1234" } } }

# capture the binary id, then echo it in a hex payload
expect { flags = ["DNS"] capture { id = "txn_id" } }
# ...
segment { flags = ["DNS"] hex = "${txn_id} 8180 0001" }
```

`assert { "recv_field:id" = { hex = "1234" } }` verifies received binary
fields. The `last_recv_hex` assert key provides the last received raw payload
as `Value::Bytes`.

### Raw Ethernet/IP/TCP/UDP headers

`send_raw` constructs complete packets and `recv_raw` decodes, matches, and
captures dotted header fields. Checksums and lengths default to automatic
values; explicit values and `"invalid"` intentionally produce malformed test
packets. IPv4/IPv6 fragmentation is enabled with a step-level `mtu`.

```text
protocol "raw_syn" {
  raw_tcp_stateful = true

  step "syn" {
    role = "client" action = "send_raw" to = "server" mtu = 1500
    ethernet {
      source = "02:00:00:00:00:01"
      destination = "02:00:00:00:00:02"
      vlan_id = 7
    }
    ipv4 {
      source = "192.0.2.10" destination = "198.51.100.20"
      ttl = 32 id = 1234 dont_fragment = true
    }
    tcp {
      source_port = 40000 destination_port = 443 seq = 1000
      flags = ["SYN", "ECE"] window = 32000
      options = [{ mss = 1460 }, "nop", { window_scale = 7 }]
    }
  }

  step "receive" {
    role = "server" action = "recv_raw"
    expect {
      fields = {
        "ipv4.ttl" = 32
        "tcp.destination_port" = 443
        "transport.checksum_valid" = true
      }
      capture { "tcp.seq" = "peer_seq" }
    }
  }
}
```

IPv4 fields include DSCP/ECN, ID, DF/MF/offset, TTL, protocol, options, IHL,
total length, and checksum. IPv6 includes traffic class, flow label, next
header, hop limit, payload length, and fragment fields. TCP supports every
wire flag plus MSS, window scale, SACK, timestamps, unknown options, data
offset, and checksum. UDP supports ports, length, and checksum. Ethernet
supports source/destination MAC, EtherType, and 802.1Q VLAN fields.

Linux can transmit and receive the exact Ethernet bytes with:

```sh
sudo setcap cap_net_raw+ep ./target/release/tcpform  # optional alternative to root
tcpform run --raw --interface eth0 --role client scenario.tcpf raw_syn
```

Raw mode is Linux-only and requires root or `CAP_NET_RAW`. Promiscuous capture
is opt-in (`--promiscuous`); outgoing copies are ignored unless
`--receive-outgoing` is set. Crafted TCP is blocked unless
`--allow-host-tcp` is explicitly supplied, because the host kernel may emit
competing RST/ACK packets. Use an isolated network namespace or an unassigned
source address. `raw_tcp_stateful = true` validates handshake/teardown order;
leave it false when intentionally fuzzing invalid TCP transitions.
For a supervisor/container that must start as root, `--drop-uid <id>` and
`--drop-gid <id>` open and configure AF_PACKET first, clear supplementary
groups, then irreversibly switch the whole process before worker threads or DSL
steps start. Both options are required together.

### Isolated Docker communication lab

The repository includes a two-node Docker lab that exercises the real
AF_PACKET backend without granting privileges to the host process:

```sh
./scripts/docker-raw-test.sh
```

The script builds the multi-stage [Dockerfile](Dockerfile), starts `raw-client`
and `raw-server` on the internal-only network in
[`compose.raw-test.yml`](compose.raw-test.yml), waits for both bounded test
programs, verifies their exit statuses, and checks that both PCAP files contain
packet records. Captures are written to:

```text
target/docker-raw/udp-client.pcap
target/docker-raw/udp-server.pcap
target/docker-raw/tcp-client.pcap
target/docker-raw/tcp-server.pcap
```

The first test exchanges complete Ethernet/IPv4/UDP frames using fixed
lab-only MAC/IP addresses. The server and client independently validate MAC
addresses, IPv4 DSCP/ECN/TTL, UDP ports, application bytes, and both IP and
UDP checksums. The second test performs a state-validated raw TCP three-way
handshake followed by bidirectional PSH/ACK data, including TCP options,
sequence/acknowledgment numbers, flags, and checksums. Because the ports are
not opened by the kernel TCP stack, incidental kernel RST frames can occur;
the raw matchers filter that noise while validating the crafted exchange. The DSLs
are [`raw_docker_udp.tcpf`](examples/docker/raw_docker_udp.tcpf) and
[`raw_docker_tcp.tcpf`](examples/docker/raw_docker_tcp.tcpf).

Security properties of the lab:

- the Compose network is `internal: true` and has no external connectivity;
- containers start with only `CAP_NET_RAW`, `CAP_SETUID`, and `CAP_SETGID`, open
  AF_PACKET, then immediately clear supplementary groups and drop to
  UID/GID 10001 before any DSL step; PCAP ownership verifies the transition;
- `no-new-privileges` is enabled; neither `privileged` nor host networking is
  used;
- receive timers bound both success and failure paths, and cleanup runs even
  when a peer fails.

Docker Engine with the Compose v2 plugin is required. The `docker-raw` CI job
runs the visual lab, probes its HTML/JSON endpoints, and uploads traces and
captures for diagnosis.

After container packages have been published for a release, run the same lab
without compiling Rust locally:

```sh
docker compose -f compose.published.yml --profile visual up
```

Maintainers publish `linux/amd64` and `linux/arm64` images to GHCR from signed
release tags. The images include SBOM and provenance attestations and are
signed with Sigstore keyless signing. If the `DOCKERHUB_USERNAME` and
`DOCKERHUB_TOKEN` repository secrets are configured, the workflow mirrors the
same tags to the `tcpform` and `tcpform-dashboard` Docker Hub repositories.

### Visual Docker communication monitor

Run both communication scenarios and keep a browser dashboard running:

```sh
./scripts/docker-visual-lab.sh up
```

Then open [http://127.0.0.1:8088](http://127.0.0.1:8088). The dashboard shows:

- virtual client/server nodes with their IP and MAC addresses;
- PASS/FAIL state for each endpoint;
- animated packet direction over the virtual link;
- UDP/TCP switching and replay controls;
- a causally ordered packet timeline with steps, flags, SEQ/ACK, byte counts,
  and raw wire hex;
- total transmitted frames and wire bytes.

The scenario selector also includes **Error: recv timeout**. It
intentionally drops a request, retries the receive once, fails with a typed
timeout, and leaves assertion/response steps unexecuted so every failure-flow
state can be inspected without editing a template.

Client and server use independent monotonic clocks, so the UI does not merge
events by timestamp alone. It pairs identical transmitted/received
`wire_hex` frames and combines those edges with each role's local ordering,
then performs a topological ordering before animation.

Use another host port when 8088 is occupied:

```sh
TCPFORM_DASHBOARD_PORT=9090 ./scripts/docker-visual-lab.sh up
```

Inspect or stop the lab with:

```sh
./scripts/docker-visual-lab.sh status
./scripts/docker-visual-lab.sh down
```

The dashboard runs as the nginx non-root user with a read-only filesystem, no
Linux capabilities, and `no-new-privileges`. Trace JSON is served read-only
from `target/docker-raw/` and refreshed automatically.

### Generic protocol visualizer

Generate a visualization directory from any valid `.tcpf` protocol, including
imported and module protocols:

```sh
tcpform visualize --output ./visual examples/advanced_actions.tcpf advanced_actions
cd visual
python3 -m http.server 8080
```

Open `http://127.0.0.1:8080`. The generated `manifest.json` drives the UI; the
HTML has no fixed role names or two-node assumption. It renders every role as
a lane, resolved explicit and implicit dependencies as arrows, raw
Ethernet/IP/TCP/UDP header values, `when` branches and case variables, retry /
loop / retransmit policies, and fault actions such as `drop`, `corrupt`,
`duplicate`, `reset`, and `nack`. By default the protocol is simulated and
`trace.json` is replayable on the plan. Use `--no-run` for a plan-only view.
The role interaction flow also renders receive timeouts as failed inbound
arrows, assertion/runtime failures as red role-local nodes, `when=false` as
skipped nodes, and all steps left after an early stop as grey unexecuted nodes.
The trace document's typed failure and error message are shown above the flow.

For another UI or externally collected traces, emit only the model with:

```sh
tcpform plan --json-file manifest.json <file> <protocol>
```

Set `trace_files` in the manifest to any number of tcpform trace JSON files.
The Docker raw lab uses this to combine independently captured role traces.

For direct browser loading of a `.tcpf`, start the local-only analysis server:

```sh
tcpform serve --bind 127.0.0.1:8080
```

Open `http://127.0.0.1:8080`, choose **Open files** for one or more related DSL
files, or **Open .tcpf folder** for a directory tree. Relative `import` paths,
aliases, `only` filters, and import-cycle checks use the uploaded in-memory
bundle; files are not copied to disk. Uploads are parsed and executed locally
with a 16 MiB request limit and a 128-file limit.

The visualizer additionally supports case selection and side-by-side case
comparison, planned-versus-executed state, clickable failure root-cause
details, decoded raw packet headers and planned/wire diffs, PCAP frame numbers,
role/action/state/text filters, retry folding, role collapsing, event limits,
zoom and a minimap. Sequence views can be exported as SVG, PNG, or Mermaid.
The integrated DSL editor automatically reparses after edits, selects and
highlights the source line on parser/model errors, and reruns valid changes.
Playback has pause, previous/next event, seek, and 0.25x–4x speed controls.
Playback can use either a fixed 650 ms interval or the actual differences
between trace `timestamp_us` values (long gaps are capped at five seconds).
The time-axis view highlights waits, retries, and failures. Breakpoints can
stop on a named step, any failure, retry/retransmit, or a decoded header
path/value.
Classic PCAP and PCAPNG captures can be imported and matched to trace events by
wire bytes. The capture frame number and exact/contained/missing result appear
in both the alignment view and packet inspector. Captures can also generate a
reviewable DSL template: Ethernet/IPv4/TCP/UDP packets become dependent
`send_raw`/`recv_raw` pairs, while unknown link formats retain exact hex in
ordinary send/receive pairs.

The packet lab links hex, ASCII, individual bits, standard header fields, and
custom `header_schema` fields. Editable MAC, IPv4, TCP, and UDP values update
the wire hex and DSL segment immediately; IPv4 and transport checksums are
recalculated. Up to 50 execution snapshots
per browser are kept in local storage; new failures, resolved failures, event
count, and duration changes are classified as regressions or improvements.
Aggregate run count, success rate, mean/P95 duration, retry count, and loss
indicators are shown beside case/branch/failed-path coverage.

**Start live run** streams events from the engine as Server-Sent Events rather
than waiting for the run to finish. Simulation and actual TCP/UDP socket modes
are available. Linux raw mode accepts a local role and interface and retains
the same `CAP_NET_RAW`, host-TCP, and interface safety checks as the CLI.

The editor provides action-aware attribute suggestions plus role and step-name
completion. Static diagnostics flag unknown actions/dependencies and
attributes not permitted by the selected action before server-side parsing.
The visual lab catalog includes timeout, assertion, corrupt mismatch, total
transport loss/retransmit exhaustion, invalid TCP state, resource limit, and
unknown-dependency validation, and retry-recovery demonstrations.

Proprietary application headers can be decoded without changing tcpform code:

```text
header_schema "acme" {
  offset = 0
  endian = "big"
  fields = {
    version = { offset=0 length=1 bit_offset=4 bits=4 format="uint" }
    code    = { offset=1 length=1 format="hex" }
    label   = { offset=2 length=2 format="ascii" }
  }
}
```

`offset` and `length` are byte based. `bit_offset` is counted from the least
significant bit; `bits` selects up to 64 bits. Supported formats are `uint`,
`hex`, `ascii`, and `ipv4`. See `examples/custom_header_schema.tcpf`.

### Capture and `${var}` interpolation

`expect { capture { id = "txn_id" } }` saves the received `id` field into the
role's variable `txn_id`. Later `send` steps can interpolate it:

```text
segment { flags = ["DNS"] fields = { id = "${txn_id}" rdata = "1.2.3.4" } }
```

If a field value is exactly `"${var}"`, the variable's typed value is
substituted directly (a Number stays a Number, Bytes stays Bytes). Mixed
strings like `"id=${var}"` are stringified (Bytes variables render as hex).
`assert { txn_id = 4242 }` verifies captured variables.

### `timer { ... }`

`timeout` (e.g. `"100ms"`, `"2s"`) — for `recv`/`drop`, how long to wait;
for `wait`, how long to sleep. On a `recv`, `retransmit` (number) retries by
resending the role's most recent `send`/`ack`/`nack`/`duplicate` step. It can
also be specified as a step-level attribute. Automatic sequence numbers are
reused rather than advanced by a retry.

### `transport { ... }`

An optional protocol-level block injects faults into every outbound segment:

```text
transport {
  loss_rate = 0.10
  delay     = "50ms"
  reorder   = true
  seed      = 42
}
```

`loss_rate` is a probability from `0.0` to `1.0`; `delay` is added to any
`segment.delay`; `reorder` inserts queued messages at pseudo-random positions.
Set `seed` to a non-zero integer to replay the same loss and reorder choices.

### Conditional and repeated execution

`when` must resolve to a boolean. A false step is recorded as skipped and is
still considered complete for dependency purposes, which makes it useful with
`cases`:

```text
step "maybe_drop" {
  role = "server" action = "drop" when = "${drop_first}"
  expect { flags = ["DATA"] }
}
```

`retry = N` retries a failed step up to N additional times. Set
`on_timeout = true` as shorthand for `retry_on = ["timeout"]`, or select from
`timeout`, `transport`, `assertion`, `validation`, `resource_limit`, `panic`,
and `runtime`. Backoff is controlled by `retry_delay`, `retry_max_delay`,
`retry_backoff`, and `retry_jitter`. `loop = N` repeats each successful
execution N times. `retransmit` remains specialized for a timed-out `recv`:
it resends the role's immutable last-outbound snapshot.

### Imports and modules

Imports are recursive, relative to the importing file, deduplicated per import
configuration, and checked for cycles. `as` namespaces an import and `only`
selects protocols and case suites; the same file can be instantiated under
multiple aliases:

```text
import "shared/tcp.tcpf"
import "shared/http.tcpf" { as = "v1" only = ["request"] }
import "shared/http.tcpf" { as = "v2" only = ["request"] }
```

Modules provide namespaces. Nested names are joined with dots, so this defines
`network.tcp.handshake`:

```text
module "network" {
  module "tcp" {
    protocol "handshake" { ... }
  }
}
```

### Time, safety limits, and diagnostics

Use `clock = "virtual"` on a protocol for fast, reproducible timer tests.
Waits, retry backoff, transport delay, and receive timeouts advance the virtual
clock without sleeping for their declared duration. Real time is the default.

```text
protocol "bounded" {
  clock = "virtual"
  limits {
    max_inbox       = 10000
    max_trace       = 100000
    max_payload     = 16777216
    max_loop        = 10000
    max_retry       = 1000
    connect_timeout = "10s"
  }
  # steps ...
}
```

Limits apply to simulated and live transports, including background readers.
Parser, schema, and dependency-graph failures include source path, line, and
column when loaded from a file. Runtime and case JSON use typed failure names
and preserve assertion expected/actual values plus the failure trace.

### JSON, diagrams, PCAP, and live sockets

- `run --json` emits `{status,error,events}` and `test --json` emits case results.
- `run --diagram` emits Mermaid `sequenceDiagram` text.
- `run --pcap` and `run --pcapng` write timestamped synthetic Ethernet/IPv4
  TCP or UDP packets with the traced wire payload. TLS captures contain DSL
  application bytes, not encrypted TLS records.
- Raw trace events are written to PCAP/PCAPNG byte-for-byte, preserving crafted
  headers, invalid checksums, VLAN tags, options, and fragments. IP-only raw
  captures use the DLT_RAW link type; Ethernet raw captures use DLT_EN10MB.
- `run --live --bind ...` uses actual loopback TCP sockets; add `--udp` for UDP.
  Live mode requires exactly two roles and preserves flags, raw bytes, stream
  IDs, and recursively structured fields on the wire.
- `run --external --role ... --connect host:port` executes one role against an
  external peer; use `--listen` to accept instead. TCP/TLS framing choices are
  `raw`, `length-prefix`, `line`, `delimiter:<text>`, and `fixed:<bytes>`.
  Raw TCP keeps byte-stream semantics and does not promise one DSL message per
  read. `--udp` exchanges one payload per datagram. `--tls` verifies system
  roots plus optional `--ca`; clients use `--server-name`, while listeners
  require `--tls-cert` and `--tls-key`.
- External UDP supports IPv4/IPv6, broadcast, `SO_REUSEADDR`, multicast group
  membership, interface selection, and multicast TTL. TCP, TLS, and Unix
  streams perform a write half-close when a DSL `close` step runs.
- `--unix` connects to Unix domain sockets. `--websocket` performs a real HTTP
  Upgrade and supports text/binary frames, origin, subprotocol negotiation,
  ping/pong, and close. `--quic` uses a certificate-validated QUIC connection,
  ALPN, mTLS credentials, bidirectional streams, and length-preserved messages.
- TLS clients can present `--tls-cert`/`--tls-key`; listeners can require a
  client certificate with `--require-client-cert --ca ...`. Repeat `--alpn`
  to advertise protocols; `--server-name` controls SNI and verification.
- `proxy` provides explicit certificate-authorized TLS termination and
  re-encryption, optional upstream mTLS, ALPN, and application-byte JSONL
  capture. It never generates or installs trust certificates implicitly.
- `orchestrate` starts declared external processes, optionally under Linux
  network namespaces, manages timeout/cleanup, and owns tcpdump capture from
  start through shutdown.

### `set { ... }` and `assert { ... }`

`set { key = value ... }` stores arbitrary values in the role's local
variable map. `assert { key = value ... }` checks each key against role
state and **fails the run** on any mismatch. Built-in keys:

| key               | type    | meaning                                  |
|-------------------|---------|------------------------------------------|
| `send_count`      | number  | segments emitted on the wire             |
| `recv_count`      | number  | segments consumed by `recv`              |
| `next_seq`        | number  | next auto sequence number                |
| `last_recv_seq`   | number  | seq of last received segment             |
| `last_recv_ack`   | number  | ack of last received segment             |
| `last_recv_from`  | string  | sender of last received segment          |
| `last_recv_window`| number  | window of last received segment          |
| `last_sent_seq`   | number  | seq of last sent segment                 |
| `last_sent_ack`   | number  | ack of last sent segment                 |
| `last_sent_to`    | string  | destination of last sent segment         |
| `last_sent_window`| number  | window of last sent segment              |
| `aborted`         | bool    | whether `reset` was called               |
| `recv_flags`      | array   | subset-match against last recv flags     |
| `sent_flags`      | array   | subset-match against last sent flags     |
| `recv_field:name` | any     | a structured field from the last recv    |
| `last_recv_hex`   | bytes   | last received raw payload (from `hex`)  |
| *(user var)*      | any     | any key written by `set` or `capture`    |

Both `segment { ... }` (nested block) and `segment = { ... }` (object
attribute) forms are accepted by the block-oriented configuration syntax.
Quoted string keys (`"my-key" = 1`) are supported in objects and blocks.

## Data-driven testing (`cases`)

A `cases` block runs the same protocol multiple times with different inputs,
checking each run's outcome and per-role final state as a data-driven test
matrix — one protocol definition, many parameterized test cases.

```text
protocol "dns_lookup" {
  step "query"  { role = "client" action = "send" segment { fields = { name = "${qname}" } } }
  step "rquery" { role = "server" action = "recv" expect { flags = ["DNS"] } }
  step "response" { role = "server" action = "send" depends_on = ["rquery"]
    segment { fields = { rcode = "${resp_rcode}" } } }
  step "rresponse" { role = "client" action = "recv" depends_on = ["query"]
    expect { fields = { rcode = "${expect_rcode}" } } }
}

cases "dns_lookup" {
  case "valid" {
    tags = ["smoke", "positive"]
    vars { qname = "example.com" resp_rcode = 0 expect_rcode = 0 }
    assert_client { recv_count = 1 }
  }
  case "nxdomain" {
    vars { qname = "no.test" resp_rcode = 3 expect_rcode = 3 }
  }
}

# Negative test: server sends rcode=3 but client expects 0 → run fails
cases "dns_lookup" {
  case "mismatch" {
    vars { qname = "bad.test" resp_rcode = 3 expect_rcode = 0 }
    expect = "fail"
  }
}
```

### `case` attributes

| attribute | meaning |
|---|---|
| `vars { key = value }` | initial variables injected into every role (used via `${var}`) |
| `tags = ["smoke", ...]` | labels used to select CI/test subsets |
| `expect = "pass"` | the run should succeed (default) |
| `expect = "fail"` | the run should fail — **negative test** (timeout/error expected) |
| `assert_<role> { ... }` | per-role post-run assertions (same keys as `assert` steps) |

Multiple `cases` blocks can target the same protocol. Run with
`tcpform test <file> [protocol]`.

### Scaling case suites in CI

- `--jobs N` executes independent cases concurrently while keeping results in
  declaration order.
- `--case REGEX` selects case names using a compiled regular expression.
- One or more `--tag TAG` options select cases carrying any requested tag.
- `--shard I/N` selects a stable, 1-based shard after name/tag filtering. Run
  `1/N` through `N/N` to cover every selected case exactly once.
- `--junit report.xml` writes JUnit XML with typed failure details, assertion
  expected/actual values, elapsed virtual/real time, and the trace in
  `system-out`. It can be combined with human or `--json` output.

Machine-readable JSON includes a `"schema_version":"1.0"` field; existing leading
fields (`status` for runs and `passed`/`failed` for case suites) remain stable.

## How ordering works

Two kinds of edges form the execution graph:

1. **Implicit** — steps of the *same role* run in **declaration order**.
2. **Explicit** — `depends_on = [...]` adds cross-role edges.

So to **adjust the order**, either reorder a role's steps or edit
`depends_on`. `tcpform plan` shows the resulting topological order, and the
engine refuses to run graphs with cycles or unknown references.
## Examples

`examples/` contains ready-to-run protocol templates across the stack.
Run any with `tcpform run examples/<file>.tcpf <protocol>`.

**Transport & reliability**

| file | protocol | demonstrates |
|---|---|---|
| `tcp_handshake.tcpf` | `tcp_handshake` | 3-way handshake (send/recv/ack) |
| `tcp_teardown.tcpf` | `tcp_teardown` | 4-way FIN/ACK teardown, auto ack# |
| `tcp_data_transfer.tcpf` | `tcp_data_transfer` | cumulative ACK data transfer |
| `tcp_reset.tcpf` | `tcp_reset` | abortive RST close, `aborted` assert |
| `tcp_syn_retransmit.tcpf` | `tcp_syn_retransmit` | SYN loss (`drop`) + retransmit |
| `retransmit_transport.tcpf` | `retransmit_transport` | automatic timeout retransmit + transport/segment delay |
| `advanced_actions.tcpf` | `advanced_actions` | corrupt, retry, loop, regex/prefix/suffix matching |
| `conditional_cases.tcpf` | `conditional_delivery` | case-driven `when` fault injection |
| `imported_module.tcpf` | `shared.echo` | relative import + module namespace |
| `stop_and_wait.tcpf` | `stop_and_wait` | stop-and-wait ARQ |
| `sliding_window.tcpf` | `sliding_window` | 3-frame sliding window, pipelined |
| `go_back_n.tcpf` | `go_back_n` | Go-Back-N with loss + retransmission |
| `sctp_handshake.tcpf` | `sctp_handshake` | SCTP 4-way (INIT/INIT-ACK/COOKIE) |
| `udp.tcpf` | `udp_request_response` | connectionless UDP |
| `icmp_ping.tcpf` | `icmp_ping` | ICMP echo request/reply (L3) |

**Web & RPC**

| file | protocol | demonstrates |
|---|---|---|
| `http1_0.tcpf` | `http1_0` | HTTP/1.0 single request then close |
| `http1_1_keepalive.tcpf` | `http1_1_keepalive` | HTTP/1.1 keep-alive, two requests |
| `http2_grpc.tcpf` | `http2_grpc` | HTTP/2 multiplexed streams |
| `grpc_server_streaming.tcpf` | `grpc_server_streaming` | server-streaming RPC |
| `websocket.tcpf` | `websocket` | WS upgrade, ping/pong, close |

**Application — request/response**

| file | protocol | demonstrates |
|---|---|---|
| `dns.tcpf` | `dns` | DNS query/response with id matching |
| `redis.tcpf` | `redis` | Redis RESP command/response |
| `ntp.tcpf` | `ntp` | NTP time sync, `log` checkpoint |

**Application — connection-oriented**

| file | protocol | demonstrates |
|---|---|---|
| `mqtt.tcpf` | `mqtt` | MQTT connect/publish/subscribe/ping/disconnect |
| `smtp.tcpf` | `smtp` | SMTP EHLO/MAIL/RCPT/DATA/QUIT |
| `pop3.tcpf` | `pop3` | POP3 login/stat/list/retr/quit |
| `imap.tcpf` | `imap` | IMAP tagged commands, login/select/fetch |
| `ftp.tcpf` | `ftp` | FTP control + PASV data connection |
| `ssh.tcpf` | `ssh` | SSH version exchange + KEXINIT |
| `bittorrent.tcpf` | `bittorrent` | peer-wire handshake/bitfield/interested/unchoke |
| `sip_call.tcpf` | `sip_call` | SIP INVITE/trying/ringing/ok/ack/bye |
| `dhcp_dora.tcpf` | `dhcp_dora` | DHCP Discover/Offer/Request/Ack, `set` lease |

**Security, routing & P2P**

| file | protocol | demonstrates |
|---|---|---|
| `tls13.tcpf` | `tls13` | TLS 1.3 1-RTT handshake + app data |
| `quic.tcpf` | `quic` | QUIC handshake + interleaved 1-RTT streams |
| `stun.tcpf` | `stun` | STUN binding, reflexive address `set`/`assert` |
| `nat_hole_punch.tcpf` | `nat_hole_punch` | UDP simultaneous open, symmetric peers |
| `bgp.tcpf` | `bgp` | BGP open/keepalive/update |

**Showcase**

| file | protocol | demonstrates |
|---|---|---|
| `custom.tcpf` | `ping_pong` | wait, to, from, payload matching |
| `rich.tcpf` | `rich_primitives` | all primitives in one protocol |
| `structured_messages.tcpf` | `structured_messages` | structured fields, capture, `${var}` interpolation, field operators |
| `binary_hex.tcpf` | `binary_hex` | binary payloads via `hex`, `hex_contains`, binary fields, capture+interpolate |
| `dns_cases.tcpf` | `dns_lookup` | data-driven `cases` table (positive + negative tests, per-role asserts) |

## Inventing a new protocol

Add a new `protocol` block (or a new file). For example, a request/response
with a timed gap (`examples/custom.tcpf`):

```text
protocol "ping_pong" {
  step "ping"      { role="client" action="send" to="server" segment { flags=["PING"] payload="hello" } }
  step "recv_ping" { role="server" action="recv" expect { flags=["PING"] from="client" } }
  step "think"     { role="server" action="wait" depends_on=["recv_ping"] timer { timeout="50ms" } }
  step "pong"      { role="server" action="send" depends_on=["think"] to="client" segment { flags=["PONG"] payload="world" } }
  step "recv_pong" { role="client" action="recv" depends_on=["ping"] expect { flags=["PONG"] from="server" } }
}
```

## Architecture

| module          | responsibility                                             |
|-----------------|------------------------------------------------------------|
| `value.rs`      | typed DSL values                                           |
| `ast.rs`        | generic block-oriented syntax tree                          |
| `parser.rs`     | hand-rolled lexer + recursive-descent parser (no deps)     |
| `loader.rs`     | recursive relative imports and cycle detection              |
| `model.rs`      | interpret AST → `Protocol` / `Step` / `Segment` / `Expect` |
| `graph.rs`      | dependency DAG, reference + cycle validation, topo sort    |
| `primitives.rs` | wire `Message` + `Expect` matching                         |
| `transport.rs`  | bounded fault transport plus live TCP/UDP/TLS and framing    |
| `engine.rs`     | multi-threaded roles and bounded parallel case execution     |
| `output.rs`     | versioned JSON, JUnit, Mermaid, PCAP/PCAPNG formatters        |
| `main.rs`       | CLI (`validate` / `list` / `plan` / `run` / `test`)        |

Runtime dependencies provide compiled lightweight regex matching, JSON
serialization, PEM handling, TLS, and public root certificates.

## Tests

```sh
cargo test
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
```

Includes parsing, planning (cycle / unknown-dep detection), duration parsing,
end-to-end simulation of the handshake, teardown, ping/pong, and rich-primitives
examples, plus focused tests for every action (drop, duplicate, nack, reset,
assert/set, window, stream, open/listen, log, corrupt), conditional execution,
retry/loop, imports/modules, JSON/JUnit/diagram/PCAP/PCAPNG output, live TCP/UDP/TLS, automatic
retransmission, latency injection, probabilistic loss, seeding, and reordering.
Case tests cover tag/regex filtering, stable sharding, and ordered parallel
execution.
Property tests exercise parser robustness, hex round trips, durations, and
concurrent inbox delivery, including arbitrary packet decoder inputs. `fuzz/` contains `cargo-fuzz` targets for the DSL
and hex decoder. CI runs the test suite on Linux/macOS/Windows with stable and
MSRV Rust, plus formatting, Clippy, coverage, dependency updates, and fuzz smoke.

## Community

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) before
opening a pull request and follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) in
project spaces. Report vulnerabilities privately as described in
[SECURITY.md](SECURITY.md). User-visible changes are tracked in
[CHANGELOG.md](CHANGELOG.md).

## Operational notes

- Live mode models both roles in one process over a real loopback socket; it is
  intended for socket-level testing of tcpform's full message envelope.
- External mode (`run --external --role client --connect host:port ...`) executes one
  role against a third-party TCP endpoint using raw `segment.payload` or
  `segment.hex` bytes. Add `--listen` before the address to accept a connection.
  TCP is a byte stream, so one read may not correspond to one application
  message; DSL expectations should use payloads appropriate to the peer.
- PCAP output uses synthetic Ethernet/IPv4/TCP or UDP records. Role names map
  to stable addresses and ports; sequence, acknowledgment, flags, timestamps,
  and application bytes come from outbound trace events.
- AF_PACKET raw mode is intentionally privilege-gated and does not alter host
  firewall, routing, or namespace configuration. Run it only on interfaces and
  networks you are authorized to test.
