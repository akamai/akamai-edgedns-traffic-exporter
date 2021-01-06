FROM golang:1.14 as builder
WORKDIR /go/src/github.com/akamai/akamai-edgedns-traffic-exporter
COPY . .
RUN make build

FROM quay.io/prometheus/busybox:latest AS app

COPY --from=builder /go/src/github.com/akamai/akamai-edgedns-traffic-exporter/akamai-edgedns-traffic-exporter /bin/akamai-edgedns-traffic-exporter

EXPOSE 9801
ENTRYPOINT ["/bin/akamai-edgedns-traffic-exporter"]
