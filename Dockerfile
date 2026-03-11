FROM alpine:3.20

LABEL org.opencontainers.image.source="https://github.com/yix/wg-busy"

RUN apk add --no-cache \
    wireguard-tools \
    iptables \
    ip6tables \
    iproute2 \
    && rm -rf /var/cache/apk/*

WORKDIR /app

ARG TARGETARCH
COPY bin/wg-busy-${TARGETARCH} /app/wg-busy

RUN mkdir -p /app/data /etc/wireguard

VOLUME /app/data
VOLUME /etc/wireguard

EXPOSE 8080
EXPOSE 51820/udp

ENTRYPOINT ["/app/wg-busy"]
CMD ["-listen", ":8080", "-config", "/app/data/config.yaml", "-wg-config", "/etc/wireguard/wg0.conf"]
