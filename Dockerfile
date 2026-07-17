FROM golang:1.26-alpine AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux \
    go build -trimpath -ldflags='-s -w' -o /out/railbird .

FROM alpine:3.22.0
RUN apk add --no-cache ca-certificates iputils bind-tools
COPY --from=build /out/railbird /railbird
ENV NB_STATE_DIR=/tmp/netbird-embed
ENTRYPOINT ["/railbird"]
