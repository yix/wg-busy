FROM golang:1.23-alpine AS builder

RUN apk add --no-cache git make

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN make build

FROM alpine:3.20

RUN apk add --no-cache \
    wireguard-tools \
    iptables \
    ip6tables \
    iproute2 \
    && rm -rf /var/cache/apk/*

WORKDIR /app

COPY --from=builder /src/bin/wg-busy /app/wg-busy

RUN mkdir -p /app/data /etc/wireguard

VOLUME /app/data
VOLUME /etc/wireguard

EXPOSE 8080
EXPOSE 51820/udp

ENTRYPOINT ["/app/wg-busy"]
CMD ["-listen", ":8080", "-config", "/app/data/config.yaml", "-wg-config", "/etc/wireguard/wg0.conf"]
