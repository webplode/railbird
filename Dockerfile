FROM golang:1.26.5-alpine3.24@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux \
    go build -trimpath -ldflags='-s -w' -o /out/railbird . \
    && mkdir -p /out/rootfs/var/lib/railbird/netbird \
    && chmod 0755 /out/rootfs/var /out/rootfs/var/lib /out/rootfs/var/lib/railbird \
    && chmod 0700 /out/rootfs/var/lib/railbird/netbird \
    && chown 65532:65532 /out/rootfs/var/lib/railbird/netbird

FROM scratch

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/rootfs/ /
COPY --from=build --chown=65532:65532 --chmod=0555 /out/railbird /railbird

USER 65532:65532

ENTRYPOINT ["/railbird"]
