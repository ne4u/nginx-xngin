# xngin test image: nginx + module + both agents + harness
FROM debian:bookworm-slim AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential curl ca-certificates libpcre2-dev zlib1g-dev \
    golang-go cargo python3 python3-pip && rm -rf /var/lib/apt/lists/*

ARG NGINX_VERSION=1.31.8
WORKDIR /build
RUN curl -fsSL https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz \
    | tar xz

COPY module/ /xngin/module/
RUN cd nginx-${NGINX_VERSION} \
    && ./configure --add-dynamic-module=/xngin/module \
       --with-http_ssl_module \
    && make -j"$(nproc)" && make install

COPY agents/ /xngin/agents/
RUN cd /xngin/agents/go && go build -o /usr/local/bin/edge-guard ./cmd/edge-guard
RUN cd /xngin/agents/rust && cargo build --release --example mini_waf \
    && cp target/release/examples/mini_waf /usr/local/bin/

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcre2-8-0 zlib1g python3 openssl && rm -rf /var/lib/apt/lists/*
COPY --from=build /usr/local/nginx /usr/local/nginx
COPY --from=build /build/nginx-*/objs/ngx_http_xngin_module.so /usr/local/nginx/modules/
COPY --from=build /usr/local/bin/edge-guard /usr/local/bin/edge-guard
COPY --from=build /usr/local/bin/mini_waf /usr/local/bin/mini_waf
COPY test/ /xngin/test/
ENV PATH=/usr/local/nginx/sbin:$PATH
WORKDIR /xngin
CMD ["bash", "-c", "edge-guard -listen unix:/run/edge-guard.sock & \
     mini_waf --listen unix:/run/mini-waf.sock & \
     nginx -g 'daemon off;'"]
