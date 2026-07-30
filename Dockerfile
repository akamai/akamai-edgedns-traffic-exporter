# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.26.5 AS builder

ARG ARCH
ARG OS

RUN apt-get update && apt-get install -y make git ca-certificates

WORKDIR /app
COPY . .

RUN CGO_ENABLED=0 GOOS=${OS} GOARCH=${ARCH} make build

FROM busybox:latest AS app
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/akamai-edgedns-traffic-exporter /bin/akamai-edgedns-traffic-exporter

EXPOSE 9801
ENTRYPOINT ["/bin/akamai-edgedns-traffic-exporter"]