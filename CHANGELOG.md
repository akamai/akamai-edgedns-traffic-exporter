## 0.3.0 / 2026-07
* Upgraded the exporter to use Akamai Edgegrid v13
* Updated Go version to 1.26.5
* Upgraded the exporter to use latest Prometheus Go libraries
* Updated Prometheus dependencies (client_golang v1.23.2, common v0.69.0)
* Updated golang.org/x dependencies (net v0.56.0, sys v0.46.0)
* Updated project license file

## 0.2.0 / 2026-02
* Upgraded the plugin to use Akamai Edgegrid v12
* Upgraded the plugin to use latest Prometheus Go libraries
* Added support for the latest Akamai Reporting API -- [authoritative-dns-traffic-by-time](https://techdocs.akamai.com/reporting/v1/reference/authoritative-dns-traffic-by-time)
* Added the --edgedns.use-legacy-api flag to allow users to use the [Edge DNS Traffic Reporting API v1](https://techdocs.akamai.com/developer/pdfs/edge-dns-traffic-reporting-api-v1.pdf)
* Added support for darwin/arm64


## 0.1.0 / 2021-01-31

Initial release.

* [FEATURE] Prometheus exporter for monitoring Akamai Edge DNS traffic metrics
