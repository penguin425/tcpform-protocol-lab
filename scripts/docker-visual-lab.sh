#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
COMPOSE_FILE="$ROOT/compose.raw-test.yml"
ARTIFACTS=${TCPFORM_ARTIFACTS:-"$ROOT/target/docker-raw"}
PORT=${TCPFORM_DASHBOARD_PORT:-8088}
ACTION=${1:-up}
export TCPFORM_ARTIFACTS="$ARTIFACTS" TCPFORM_DASHBOARD_PORT="$PORT"

require_docker() {
  command -v docker >/dev/null 2>&1 || {
    echo "error: Docker with the Compose plugin is required" >&2
    exit 127
  }
  docker compose version >/dev/null 2>&1 || {
    echo "error: the Docker Compose plugin is required" >&2
    exit 127
  }
}

require_docker
case "$ACTION" in
  up|start)
    "$ROOT/scripts/docker-raw-test.sh"
    docker compose -f "$COMPOSE_FILE" --profile visual up -d --build dashboard
    url="http://127.0.0.1:$PORT"
    attempts=0
    until curl --fail --silent --show-error "$url/" >/dev/null 2>&1; do
      attempts=$((attempts + 1))
      if [ "$attempts" -ge 30 ]; then
        docker compose -f "$COMPOSE_FILE" --profile visual logs --no-color dashboard >&2
        echo "error: dashboard did not become ready at $url" >&2
        exit 1
      fi
      sleep 1
    done
    echo "tcpform visual lab is ready: $url"
    echo "Stop it with: $0 down"
    ;;
  down|stop)
    docker compose -f "$COMPOSE_FILE" --profile visual down --volumes --remove-orphans
    ;;
  status)
    docker compose -f "$COMPOSE_FILE" --profile visual ps --all
    ;;
  *)
    echo "usage: $0 [up|down|status]" >&2
    exit 2
    ;;
esac
