FROM alpine:3.20

LABEL org.opencontainers.image.source="https://github.com/yix/wg-busy"

# Alpine dropped the zerotier-one package after 3.17, so the musl-built binary
# comes from the multi-arch zyclonite image. libc6-compat/libstdc++ are its
# runtime dependencies.
RUN apk add --no-cache \
    wireguard-tools \
    iptables \
    ip6tables \
    iproute2 \
    libc6-compat \
    libstdc++ \
    && rm -rf /var/cache/apk/*

COPY --from=zyclonite/zerotier:1.14.2 /usr/sbin/zerotier-one /usr/sbin/zerotier-one
RUN ln -s zerotier-one /usr/sbin/zerotier-cli \
    && ln -s zerotier-one /usr/sbin/zerotier-idtool

WORKDIR /app

ARG TARGETARCH
COPY bin/wg-busy-${TARGETARCH} /app/wg-busy

RUN mkdir -p /app/data/zerotier /etc/wireguard

VOLUME /app/data
VOLUME /etc/wireguard

EXPOSE 1179/tcp
EXPOSE 8080
EXPOSE 51820/udp
EXPOSE 9993/udp

ENTRYPOINT ["/app/wg-busy"]
CMD ["-listen", ":8080", "-config", "/app/data/config.yaml", "-wg-config", "/etc/wireguard/wg0.conf", "-zt-data", "/app/data/zerotier"]
