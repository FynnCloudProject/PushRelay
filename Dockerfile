# syntax=docker/dockerfile:1

FROM swift:6.2-noble AS build
ARG BUILDPLATFORM
ARG TARGETPLATFORM

WORKDIR /build

COPY ./Package.* ./
RUN --mount=type=cache,target=/build/.build,id=push-relay-build-${TARGETPLATFORM},sharing=locked \
    --mount=type=cache,target=/root/.cache/org.swift.swiftpm,id=push-relay-spm-${TARGETPLATFORM},sharing=locked \
    swift package resolve

COPY ./Sources ./Sources
COPY ./Resources ./Resources
COPY ./Tests ./Tests

RUN --mount=type=cache,target=/build/.build,id=push-relay-build-${TARGETPLATFORM},sharing=locked \
    --mount=type=cache,target=/root/.cache/org.swift.swiftpm,id=push-relay-spm-${TARGETPLATFORM},sharing=locked \
    JOBS=$([ "$BUILDPLATFORM" != "$TARGETPLATFORM" ] && echo 4 || nproc) \
    && swift build -c release \
        --product PushRelay \
        --static-swift-stdlib \
        -j "$JOBS" \
        -Xswiftc -gnone \
    && mkdir -p /staging \
    && cp ".build/release/PushRelay" /staging/PushRelay \
    && cp -R ./Resources /staging/Resources

FROM debian:trixie-slim

RUN export DEBIAN_FRONTEND=noninteractive \
    && apt-get -q update \
    && apt-get -q install -y --no-install-recommends \
        ca-certificates \
        tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --user-group --create-home --system --skel /dev/null --home-dir /app vapor

WORKDIR /app
COPY --from=build --chown=vapor:vapor /staging /app
RUN chmod -R a-w ./Resources

USER vapor:vapor
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/bin/bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/${PORT:-8080} && printf 'GET /health HTTP/1.0\\r\\nHost: localhost\\r\\n\\r\\n' >&3 && grep -q '200 OK' <&3"]

ENTRYPOINT ["./PushRelay"]
CMD ["serve", "--env", "production", "--hostname", "0.0.0.0", "--port", "8080"]
