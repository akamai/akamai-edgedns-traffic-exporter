# akamai-edgedns-traffic-exporter

Prometheus exporter exposing Akamai Edge DNS [Traffic Report](https://developer.akamai.com/api/cloud_security/edge_dns_traffic_reporting/v1.html) status as `up` metrics.

## Getting Started

### Akamai Open Edgegrid Authentication 

This exporter calls the Akamai Edge DNS Traffic Report API utilizing the Akamai OpenEdgegrid authentication credentials.

Credentials can be provided to the exporter via exporter command line, environment variables or indirectly via a file reference in the exporter configuration. Command line and configuration file information is detailed later in this document. Auth credentials are specified in environment variables as follows:

| Environment Variable | Description |
| -------------------- | ----------- |
| AKAMAI_HOST | Akamai Edgegrid API server |
| AKAMAI_ACCESS_TOKEN | Akamai Edgegrid API access token |
| AKAMAI_CLIENT_TOKEN |Akamai Edgegrid API client token |
| AKAMAI_CLIENT_SECRET |Akamai Edgegrid API client secret |

Credential locations are searched in the following priority order.
1. Command line
2. Environment
3.

[Akamai API Authentication](https://developer.akamai.com/getting-started/edgegrid) provides an overview and further information pertaining to the generation of auth credentials for API based applications and tools.

### Prerequisites

To run this project, you will need a [working Go environment](https://golang.org/doc/install).

### Installing

```bash
go get -u github.com/akamai/akamai-edgedns-traffic-exporter
```

## Building

Build the sources with

```bash
make build
```

## Run the binary

```bash
./akamai-edgedns-traffic-exporter
```

The exporter requires Akamai Open Edgegrid credentials to configure the Edge DNS API connection.

Credentials may be provided as:
1. Command line args
2. Environment variables 
3. .edgerc file and section (specified in config)

## Command line arguments

Use -h or --help flag to list available options.

```
./akamai-edgedns-traffic-exporter --help
usage: akamai-edgedns-traffic-exporter [<flags>]

Flags:
      -h, --help Show context-sensitive help (also try --help-long and --help-man).
      --config.file="edgedns.yml"
                 Edge DNS Traffic exporter configuration file. Default: ./edgedns.yml
      --web.listen-address=":9999"
                 The address to listen on for HTTP requests.
      --edgedns.ignore-timestamps
                 Flag to ignore original timestamp when saving metrics. Default: true
      --edgedns.edgegrid-host=EDGEDNS.EDGEGRID-HOST
                 The Akamai Edgegrid host auth credential.
      --edgedns.edgegrid-client-secret=EDGEDNS.EDGEGRID-CLIENT-SECRET
                 The Akamai Edgegrid client_secret credential.
      --edgedns.edgegrid-client-token=EDGEDNS.EDGEGRID-CLIENT-TOKEN
                 The Akamai Edgegrid client_token credential.
      --edgedns.edgegrid-access-token=EDGEDNS.EDGEGRID-ACCESS-TOKEN
                 The Akamai Edgegrid access_token credential.
      --version  Show application version.
```

## Example invocations

`Invoke exporter providing configuration file path`

```bash
./akamai-edgedns-traffic-exporter --config.file=/home/example/edgedns.yml
```

`Invoke exporter providing configuration file path and Edgegrid auth credentials`

```bash
./akamai-edgedns-traffic-exporter --config.file="/home/example/edgedns.yml" akamai-edgedns-traffic-exporter --config.file ./edgedns_example_config.yaml --edgedns.edgegrid-host akab-abcdefghijklmnop-01234567890aaaaa.luna.akamaiapis.net --edgedns.edgegrid-access-token example_provided_access_token --edgedns.edgegrid-client-token example_provided_client_token --edgedns.edgegrid-client-secret example_provided_client_secret
```

`Invoke exporter providing configuration file path and instructing to include timestamp in metrics`

```bash
./akamai-edgedns-traffic-exporter --config.file=/home/example/edgedns.yml --no-edgedns.ignore-timestamps
```

By default, the exporter optional config file is expected in the current working directory, `./edgedns.yml`.

Use -h or --help flag to list available options.

## Testing

### Running unit tests

```bash
make test
```

## Configuration

Configuration is usually done in `./edgedns.yml`.

An example can be found in
[./edgedns_traffic_example_config.yaml](https://github.com/akamai/akamai-edgedns-traffic-exporter/blob/master/edgedns_traffic_example_config.yaml).


| Configuration element | Description |
| zones | (Required) Akamai Edge DNS zones to collect traffic metrics from |
| edgerc_path | (Optional) Accessible path to Edgegrid credentials file, e.g /home/test/.edgerc |
| edgerc_section | (Optional) Section in Edgegrid credentials file containing credentials |
| summary_window | (Optional) Rolling window for summary and metric data in mins, hours, days. Default: 1 day |

## Docker image

A docker image can be built by executing the following comand::

```bash
make docker
```

The resulting image is named `/akamai/akamai-edgedns-traffic-exporter-linux-amd64:<git-branch>`.

TODO :: NEEDS WORK!!!!

The image exposes port xxxx and expects an optional config in `./edgedns.yml`.
To configure it, you must pass the environment variables, and you can bind-mount a config from your host:

```bash
docker run -p 9613:9613 -v /path/on/host/config/config.yml:/opt/azure-health-exporter/config/config.yml -e AZURE_SUBSCRIPTION_ID="my_subscription_id" -e AZURE_TENANT_ID="my_tenant_id" -e AZURE_CLIENT_ID="my_client_id" -e AZURE_CLIENT_SECRET="my_client_secret" fxinnovation/azure-health-exporter:<git-branch>
```

## Exposed metrics

Metric | Description
------ | -----------
edgedns_traffic_dns_hits_per_interval | Number of DNS hits per 5 minute interval (per zone)
edgedns_traffic_nxd_hits_per_interval | Number of NXD hits per 5 minute interval (per zone) 
edgedns_traffic_dns_hits_per_interval_summary_count | Summary count of DNS Hit 5 minute intervals (per zone) 
edgedns_traffic_dns_hits_per_interval_summary_sum | Summary aggregation of DNS Hit 5 minute interval hits (per zone)
edgedns_traffic_nxd_hits_per_interval_summary_count | Summary count of NXD Hit 5 minute intervals (per zone)
edgedns_traffic_nxd_hits_per_interval_summary_sum | Summary aggregation of NXD Hit 5 minute interval hits (per zone)

Example:

TODO :: FIX UP

```
# HELP azure_resource_health_availability_up Resource health availability that relies on signals from different Azure services to assess whether a resource is healthy
# TYPE azure_resource_health_availability_up gauge
azure_resource_health_availability_up{resource_group="my_group",resource_name="my_name",resource_type="Microsoft.Storage/storageAccounts",subscription_id="xxx"} 1
# HELP azure_tag_info Tags of the Azure resource
# TYPE azure_tag_info gauge
azure_tag_info{resource_group="my_group",resource_name="my_name",resource_type="Microsoft.Storage/storageAccounts",subscription_id="xxx",tag_monitoring="enabled"} 1
# HELP azure_resource_health_ratelimit_remaining_requests Azure subscription scoped Resource Health requests remaining (based on X-Ms-Ratelimit-Remaining-Subscription-Resource-Requests header)
# TYPE azure_resource_health_ratelimit_remaining_requests gauge
azure_resource_health_ratelimit_remaining_requests{subscription_id="xxx"} 98
```

## Alerting on Traffic Metrics

...

## Contributing

TBD

## License

Apache License 2.0, see [LICENSE](https://github.com/akamai/akamai-edgedns-traffic-exporter/blob/master/LICENSE).
