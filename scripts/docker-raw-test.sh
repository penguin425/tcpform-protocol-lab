#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ARTIFACTS=${TCPFORM_ARTIFACTS:-"$ROOT/target/docker-raw"}
COMPOSE_FILE="$ROOT/compose.raw-test.yml"

if ! command -v docker >/dev/null 2>&1; then
  echo "error: Docker with the Compose plugin is required" >&2
  exit 127
fi
if ! docker compose version >/dev/null 2>&1; then
  echo "error: the Docker Compose plugin is required" >&2
  exit 127
fi

mkdir -p "$ARTIFACTS"
chmod a+rwx "$ARTIFACTS"
rm -f \
  "$ARTIFACTS/udp-client.pcap" "$ARTIFACTS/udp-server.pcap" \
  "$ARTIFACTS/tcp-client.pcap" "$ARTIFACTS/tcp-server.pcap" \
  "$ARTIFACTS/udp-client.json" "$ARTIFACTS/udp-server.json" \
  "$ARTIFACTS/tcp-client.json" "$ARTIFACTS/tcp-server.json"
rm -f "$ARTIFACTS/error-trace.json" "$ARTIFACTS/error-manifest.json"
rm -f "$ARTIFACTS"/demo-*.json
export TCPFORM_ARTIFACTS="$ARTIFACTS"

cleanup() {
  docker compose -f "$COMPOSE_FILE" down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

run_case() (
  case_name=$1
  export TCPFORM_SCENARIO="/scenarios/raw_docker_${case_name}.tcpf"
  export TCPFORM_PROTOCOL="docker_raw_${case_name}"
  export TCPFORM_CLIENT_PCAP="/artifacts/${case_name}-client.pcap"
  export TCPFORM_SERVER_PCAP="/artifacts/${case_name}-server.pcap"
  export TCPFORM_CLIENT_JSON="/artifacts/${case_name}-client.json"
  export TCPFORM_SERVER_JSON="/artifacts/${case_name}-server.json"

  docker compose -f "$COMPOSE_FILE" up -d --build --force-recreate

  client_id=$(docker compose -f "$COMPOSE_FILE" ps --all -q raw-client)
  server_id=$(docker compose -f "$COMPOSE_FILE" ps --all -q raw-server)
  if [ -z "$client_id" ] || [ -z "$server_id" ]; then
    docker compose -f "$COMPOSE_FILE" logs --no-color >&2
    echo "error: $case_name raw test containers were not created" >&2
    exit 1
  fi

  # Both DSL programs have bounded receive timers, so this wait also covers
  # failure paths without leaving an indefinitely running container.
  docker wait "$client_id" "$server_id" >/dev/null
  docker compose -f "$COMPOSE_FILE" logs --no-color

  client_status=$(docker inspect --format '{{.State.ExitCode}}' "$client_id")
  server_status=$(docker inspect --format '{{.State.ExitCode}}' "$server_id")
  if [ "$client_status" -ne 0 ] || [ "$server_status" -ne 0 ]; then
    echo "error: Docker $case_name peers failed (client=$client_status server=$server_status)" >&2
    exit 1
  fi

  client_capture="$ARTIFACTS/${case_name}-client.pcap"
  server_capture="$ARTIFACTS/${case_name}-server.pcap"
  test -s "$client_capture"
  test -s "$server_capture"
  test -s "$ARTIFACTS/${case_name}-client.json"
  test -s "$ARTIFACTS/${case_name}-server.json"

  # A classic PCAP global header is 24 bytes and each successful sender writes
  # at least one packet record (16-byte header plus an Ethernet frame).
  client_size=$(wc -c <"$client_capture")
  server_size=$(wc -c <"$server_capture")
  minimum_size=54
  if [ "$case_name" = tcp ]; then
    # TCP must contain multiple outbound records (SYN/ACK/data), not merely a
    # single frame that happened to be captured before a later failure.
    minimum_size=150
  fi
  if [ "$client_size" -le "$minimum_size" ] || [ "$server_size" -le "$minimum_size" ]; then
    echo "error: Docker $case_name captures do not contain Ethernet packet records" >&2
    exit 1
  fi
  client_owner=$(stat -c '%u:%g' "$client_capture")
  server_owner=$(stat -c '%u:%g' "$server_capture")
  if [ "$client_owner" != 10001:10001 ] || [ "$server_owner" != 10001:10001 ]; then
    echo "error: tcpform did not drop privileges before writing captures (client=$client_owner server=$server_owner)" >&2
    exit 1
  fi

  echo "Docker raw $case_name communication test passed"
  echo "  client capture: $client_capture ($client_size bytes)"
  echo "  server capture: $server_capture ($server_size bytes)"
  echo "  runtime credentials: 10001:10001"
)

run_case udp
run_case tcp

# Publish the declarative plans alongside the traces. The dashboard discovers
# both scenarios through this catalog; no role names or topology are embedded
# in the UI.
cargo run --quiet -- plan --json-file "$ARTIFACTS/udp-manifest.json" \
  "$ROOT/examples/docker/raw_docker_udp.tcpf" docker_raw_udp
cargo run --quiet -- plan --json-file "$ARTIFACTS/tcp-manifest.json" \
  "$ROOT/examples/docker/raw_docker_tcp.tcpf" docker_raw_tcp
cargo run --quiet -- plan --json-file "$ARTIFACTS/error-manifest.json" \
  "$ROOT/examples/docker/error_flow.tcpf" docker_error_flow
if cargo run --quiet -- run --json-file "$ARTIFACTS/error-trace.json" \
  "$ROOT/examples/docker/error_flow.tcpf" docker_error_flow >/dev/null 2>&1; then
  echo "error: visualizer error demo unexpectedly succeeded" >&2
  exit 1
fi
test -s "$ARTIFACTS/error-trace.json"
sed 's/"trace_files": \[\]/"trace_files": ["udp-client.json", "udp-server.json"]/' \
  "$ARTIFACTS/udp-manifest.json" > "$ARTIFACTS/udp-manifest.tmp"
mv "$ARTIFACTS/udp-manifest.tmp" "$ARTIFACTS/udp-manifest.json"
sed 's/"trace_files": \[\]/"trace_files": ["tcp-client.json", "tcp-server.json"]/' \
  "$ARTIFACTS/tcp-manifest.json" > "$ARTIFACTS/tcp-manifest.tmp"
mv "$ARTIFACTS/tcp-manifest.tmp" "$ARTIFACTS/tcp-manifest.json"
sed 's/"trace_files": \[\]/"trace_files": ["error-trace.json"]/' \
  "$ARTIFACTS/error-manifest.json" > "$ARTIFACTS/error-manifest.tmp"
mv "$ARTIFACTS/error-manifest.tmp" "$ARTIFACTS/error-manifest.json"

generate_demo() {
  demo_id=$1
  demo_file=$2
  demo_protocol=$3
  expected=$4
  cargo run --quiet -- plan --json-file "$ARTIFACTS/demo-$demo_id-manifest.json" \
    "$demo_file" "$demo_protocol"
  if cargo run --quiet -- run --json-file "$ARTIFACTS/demo-$demo_id-trace.json" \
    "$demo_file" "$demo_protocol" >/dev/null 2>&1; then
    actual=pass
  else
    actual=fail
  fi
  if [ "$actual" != "$expected" ]; then
    echo "error: visualizer demo $demo_id expected $expected but got $actual" >&2
    exit 1
  fi
  sed "s/\"trace_files\": \[\]/\"trace_files\": [\"demo-$demo_id-trace.json\"]/" \
    "$ARTIFACTS/demo-$demo_id-manifest.json" > "$ARTIFACTS/demo-$demo_id-manifest.tmp"
  mv "$ARTIFACTS/demo-$demo_id-manifest.tmp" "$ARTIFACTS/demo-$demo_id-manifest.json"
}

generate_demo assertion "$ROOT/examples/docker/error_scenarios.tcpf" error_assertion fail
generate_demo corrupt "$ROOT/examples/docker/error_scenarios.tcpf" error_corrupt_mismatch fail
generate_demo loss "$ROOT/examples/docker/error_scenarios.tcpf" error_transport_loss fail
generate_demo tcp-state "$ROOT/examples/docker/error_scenarios.tcpf" error_tcp_state fail
generate_demo resource "$ROOT/examples/docker/error_scenarios.tcpf" error_resource_limit fail
generate_demo recovery "$ROOT/examples/retransmit_transport.tcpf" retransmit_transport pass

# A dependency error cannot produce a normal engine plan, so retain the
# rejected source as a selectable validation artifact with its typed error.
printf '%s\n' '{"schema_version":"1.0","protocol":{"name":"error_dependency","description":"Intentional unknown dependency validation error"},"roles":["client","server"],"steps":[{"index":0,"name":"cannot_start","role":"client","action":"send","to":"server","depends_on":["missing_handshake"],"explicit_depends_on":["missing_handshake"],"description":null,"when":null,"retry":0,"loop":1,"retransmit":0,"retry_policy":{"on_timeout":false,"retry_on":[],"initial_delay_ms":0,"max_delay_ms":60000,"backoff":1,"jitter":0},"timer":null,"segment":{"flags":["DATA"]},"expect":null,"headers":null,"source":"examples/docker/error_dependency.tcpf","line":3}],"cases":[],"trace_files":["demo-dependency-trace.json"],"transport":null}' > "$ARTIFACTS/demo-dependency-manifest.json"
printf '%s\n' '{"status":"fail","schema_version":"1.0","failure_kind":"validation","error":"step `cannot_start` depends on unknown step `missing_handshake`","events":[{"index":0,"timestamp_us":0,"role":"client","step":"cannot_start","action":"send","ok":false,"detail":"plan validation failed: unknown dependency `missing_handshake`","flags":["DATA"],"seq":null,"ack":null,"peer":"server","pcap_frame":null,"wire_hex":"","network":"tcp"}]}' > "$ARTIFACTS/demo-dependency-trace.json"

printf '%s\n' '{"scenarios":[{"name":"UDP raw lab","manifest":"data/udp-manifest.json"},{"name":"TCP raw lab","manifest":"data/tcp-manifest.json"},{"name":"Error: recv timeout","manifest":"data/error-manifest.json"},{"name":"Error: assertion failure","manifest":"data/demo-assertion-manifest.json"},{"name":"Error: corrupt mismatch","manifest":"data/demo-corrupt-manifest.json"},{"name":"Error: retransmit limit / loss","manifest":"data/demo-loss-manifest.json"},{"name":"Error: invalid TCP state","manifest":"data/demo-tcp-state-manifest.json"},{"name":"Error: resource limit","manifest":"data/demo-resource-manifest.json"},{"name":"Error: unknown dependency","manifest":"data/demo-dependency-manifest.json"},{"name":"Recovery: retry succeeds","manifest":"data/demo-recovery-manifest.json"}]}' \
  > "$ARTIFACTS/catalog.json"
