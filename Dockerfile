# syntax=docker/dockerfile:1
FROM rust:1.97-bookworm@sha256:77fac8b98f9f46062bb680b6d25d5bcaabfc400143952ebc572e924bcbedc3fa AS builder
WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY dashboard ./dashboard
RUN cargo build --locked --release

FROM debian:bookworm-slim AS runtime
RUN groupadd --gid 10001 tcpform && useradd --uid 10001 --gid tcpform --no-create-home --home-dir /nonexistent tcpform
COPY --from=builder /build/target/release/tcpform /usr/local/bin/tcpform
COPY examples/docker /scenarios

# Compose starts with the three capabilities needed to open AF_PACKET and
# irreversibly switch to UID/GID 10001. tcpform performs that switch before
# starting any transport worker or executing a DSL step.
USER tcpform:tcpform
ENTRYPOINT ["/usr/local/bin/tcpform"]

FROM nginx:1.31.2-alpine3.23-slim@sha256:dd722b8ee8794f3c273bfaf8b5351b0652a68ccd73c17e5f0d029857a58f25ef AS dashboard
COPY dashboard/nginx.conf /etc/nginx/conf.d/default.conf
COPY dashboard/index.html /usr/share/nginx/html/index.html
COPY dashboard/order.js /usr/share/nginx/html/order.js
COPY dashboard/flow.js /usr/share/nginx/html/flow.js
COPY dashboard/packet-view.js /usr/share/nginx/html/packet-view.js
COPY dashboard/analysis-tools.js /usr/share/nginx/html/analysis-tools.js
COPY dashboard/advanced-tools.js /usr/share/nginx/html/advanced-tools.js
COPY dashboard/workbench-tools.js /usr/share/nginx/html/workbench-tools.js
COPY dashboard/workbench-worker.js /usr/share/nginx/html/workbench-worker.js
COPY dashboard/wasm-engine.js /usr/share/nginx/html/wasm-engine.js
COPY dashboard/tcpform-engine.wasm /usr/share/nginx/html/tcpform-engine.wasm
COPY dashboard/platform-ui.js /usr/share/nginx/html/platform-ui.js
USER nginx:nginx
ENTRYPOINT ["nginx", "-g", "daemon off;"]
