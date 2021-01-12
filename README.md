# akamai-edgedns-traffic-exporter

The Edge DNS Prometheus Traffic Exporter Technical Preview publishes Akamai Edge DNS [Traffic Report](https://developer.akamai.com/api/cloud_security/edge_dns_traffic_reporting/v1.html) data as metrics. With Edge DNS metrics, Prometheus can track DNS query and NXDOMAIN traffic and trigger alerts such as NXDOMAIN spikes that exceed a thresh hold, e.g. 10x a rolling average, and might be indicative of DNS abuse or an attack.

## Getting started

1. Install and build the Edge DNS exporter.
2. Configure and start the Edge DNS Exporter to generate metrics for Prometheus.
3. Update the Prometheus configuration to include the Edge DNS exporter. Restart Prometheus.
4. Validate that the exporter target is live and metrics are available in Prometheus.

## Prerequisites

* Prometheus environment with an active Alertmanager.
* [Go environment](https://golang.org/doc/install).
* Valid Akamai API client with authorization to use the Edge DNS Traffic Reporting API. [Akamai API Authentication](https://developer.akamai.com/getting-started/edgegrid) provides an overview and information to generate of authorization credentials to use the API.

## Install

```bash
go get -u github.com/akamai/akamai-edgedns-traffic-exporter
```

## Build

### Docker image

```bash
make docker
```

The resulting image has a name of `/akamai/akamai-edgedns-traffic-exporter-linux-amd64:<git-branch>`, has an endpoint of `/bin/akamai-edgedns-traffic-exporter`, and uses port `9801`.

### Binary executable

```bash
make build
```

#### Test

```bash
make test
```

## Configuration

The exporter requires Akamai Open Edgegrid credentials to configure the Edge DNS API connection and can get credentials using one of the following mechanisms:

1. An `.edgerc` file and section set with the exporter configuration file.
2. Environment variables.
3. Command line arguments.

### Exporter configuration

Configuration is usually done in file in the working directory (e.g. `./edgedns.yml`) containing the following settings.

Configuration element | Description
--------------------- | -----------
zones | (Required) List of Akamai Edge DNS zones to collect traffic metrics from
edgerc_path | (Optional) Accessible path to Edgegrid credentials file, e.g /home/test/.edgerc
edgerc_section | (Optional) Section in Edgegrid credentials file containing credentials
summary_window | (Optional) Rolling window for summary and metric data in [m]ins, [h]ours, or [d]ays. Default: 1 day
timestamp_label | (Optional) Creates time series with traffic timestamp as label. Default: false
traffic_timestamp | (Optional) Create time series with traffic timestamp. Default: false

#### Example exporter configuration

An example can be found in
[edgedns_traffic_example_config.yml](https://github.com/akamai/akamai-edgedns-traffic-exporter/blob/master/edgedns_traffic_example_config.yml). This configuration file contains settings as follows.

```
zones:
  - example.zone
  - another-example.zone

edgerc_path: /home/testuser/.edgerc

edgerc_section: default

summary_window: 8h

timestamp_label: false          # Creates time series with traffic timestamp as label

traffic_timestamp: false        # Create time series with traffic timestamp
```

#### Environment variables 

Instead of using `.edgerc` workflow, authentication credentials can be set with environment variables as follows.

| Environment Variable | Description |
| -------------------- | ----------- |
| AKAMAI_HOST | Akamai Edgegrid API server |
| AKAMAI_ACCESS_TOKEN | Akamai Edgegrid API access token |
| AKAMAI_CLIENT_TOKEN |Akamai Edgegrid API client token |
| AKAMAI_CLIENT_SECRET |Akamai Edgegrid API client secret |

### Prometheus configuration

Prometheus target configuration is minimal. As the following fragment shows, settings include a static configuration pointing to the exporter, the scrape interval and the scrape timeout. Other useful settings include definition for Alerts and Rules.

```
global:
  scrape_interval: 15s
  scrape_timeout: 15s

scrape_configs:
  - job_name: 'edgedns'
    static_configs:
      - targets: ['docker.for.mac.localhost:9801']

alerting:
  alertmanagers:
  - static_configs:
    - targets:
      - alertmanager:9093

rule_files:
  - 'example_edgedns_traffic_alerts.rules'
```

## Run the exporter

### Using the binary

```bash
./akamai-edgedns-traffic-exporter
```

In the log, the exporter will publish a series of INFO messages to show normal operation. Look for the `Beginning to serve on address:` message to learn its port.

```
INFO[0000] Config file: edgedns_traffic_example_config.yaml  source="main.go:328"
INFO[0000] Starting Edge DNS Traffic exporter(version=0.1.0, branch=master, revision=84667d49203590616cd6d1b07d75715eaff31392)  source="main.go:333"
INFO[0000] Build context(go=go1.15.6, user=jgilbert@bos-mp8o3, date=20210106-15:40:18)  source="main.go:334"
INFO[0000] akamai_edgedns_traffic_exporter config loaded  source="main.go:450"
INFO[0000] Edge DNS Traffic exporter start time: 2021-01-07 09:45:33.538348 +0000 UTC  source="main.go:390"
INFO[0000] Beginning to serve on address :9801           source="main.go:422"
```

NOTE: running the exporter without the appropriate settings to access the Edge DNS Traffic Reporting API will only publish build info like below. To validate, visit the exporter's metrics view with a browser using local host and the exporter's port known from one of the INFO startup messages (e.g. http://localhost:9801/metrics).

```
# HELP akamai_edgedns_traffic_exporter_build_info A metric with a constant '1' value labeled by version, revision, branch, and goversion from which akamai_edgedns_traffic_exporter was built.
# TYPE akamai_edgedns_traffic_exporter_build_info gauge
akamai_edgedns_traffic_exporter_build_info{branch="master",goversion="go1.15.6",revision="84667d49203590616cd6d1b07d75715eaff31392",version="0.1.0"} 1
```

#### Command line arguments

Use -h or --help flag to list available options.

```
./akamai-edgedns-traffic-exporter --help
usage: akamai-edgedns-traffic-exporter [<flags>]

Flags:
      -h, --help          Show context-sensitive help (also try --help-long and --help-man).
      --config.file="edgedns.yml"
                          Edge DNS Traffic exporter configuration file. Default: ./edgedns.yml
      --web.listen-address=":9801"
                          The address to listen on for HTTP requests.
      --edgedns.edgegrid-host=EDGEDNS.EDGEGRID-HOST
                          The Akamai Edgegrid host auth credential.
      --edgedns.edgegrid-client-secret=EDGEDNS.EDGEGRID-CLIENT-SECRET
                          The Akamai Edgegrid client_secret credential.
      --edgedns.edgegrid-client-token=EDGEDNS.EDGEGRID-CLIENT-TOKEN
                          The Akamai Edgegrid client_token credential.
      --edgedns.edgegrid-access-token=EDGEDNS.EDGEGRID-ACCESS-TOKEN
                          The Akamai Edgegrid access_token credential.
      --log.level="info"  Only log messages with the given severity or above. Valid levels: [debug, info, warn, error,
                          fatal]
      --log.format="logger:stderr"  
                          Set the log target and format. Example: "logger:syslog?appname=bob&local=7" or
                          "logger:stdout?json=true"
      --version           Show application version.
```

Note: By default, the exporter expects the configuration file to exist in the current working directory (e.g. `./edgedns.yml`).

#### Example invocations

`Invoke exporter with a configuration file path`

```bash
./akamai-edgedns-traffic-exporter --config.file=edgedns_example_config.yml
```

`Invoke exporter with a configuration file path and Edgegrid authentication credentials`

```bash
./akamai-edgedns-traffic-exporter --config.file=edgedns_example_config.yml --edgedns.edgegrid-host akab-abcdefghijklmnop-01234567890aaaaa.luna.akamaiapis.net --edgedns.edgegrid-access-token example_provided_access_token --edgedns.edgegrid-client-token example_provided_client_token --edgedns.edgegrid-client-secret example_provided_client_secret
```

### Using the Docker container

The following example command instantiates the exporter container by specifying the working directory and providing volume arguments for the `.edgerc` and Prometheus configuration files. Note that the container `.edgerc` path will be the same as the setting path in the exporter configuration file.

```bash
docker run --rm -i -p 9801:9801 --workdir="/tmp" -v /home/testuser/akamai-edgedns-traffic-exporter/edgedns.yml:/tmp/edgedns.yml -v /home/testuser/.edgerc:/tmp/.edgerc akamai/akamai-edgedns-traffic-exporter-linux-amd64:master
```

The following, second example instantiates the exporter container by specifying the working directory, providing a bind mount to the configuration file in the work directory and providing the API authorization crendentials via environment variables.

```bash
$ docker run --rm -i -p 9801:9801 --workdir="/tmp" --mount type=bind,src=/home/testuser/akamai-edgedns_traffic-exporter/edgedns.yml,dst=/tmp/edgedns.yml --mount type=bind,src=/home/testuser/.edgerc,dst="/tmp/.edgerc" -e AKAMAI_HOST="akab-zzzzzzzzzzz-wwwwwwwwww.luna.akamaiapis.net" -e AKAMAI_ACCESS_TOKEN="akab-abcdefghijk-1234567890xx" -e AKAMAI_CLIENT_TOKEN="akab-bbbbbbbbbbbb-ccccccccccccccc" -e AKAMAI_CLIENT_SECRET="abcdefGHIJKLMNopqrstuv1234567890" akamai/akamai-edgedns-traffic-exporter-linux-amd64:master
```

## Metrics

The Edge DNS Exporter pulls DNS query and NXD traffic activity data and makes it available to Prometheus with the below metrics. The API provides traffic data in sequential 5 minute intervals that can lag in time. The exporter mitigates this timing by creating metrics for past datapoints (e.g. 3 hours ago) as current datapoints with increasing timestamp order. Living in the present, Prometheus might also have timing issues by expecting API data for each scrape transaction. Edge DNS may not have a datapoint available for Prometheus for each scraping interval. In this scenario, gaps can exist in the Prometheus Graph.

Distinct gauge time series are created for DNS and NXD Hits per interval; with zone used as a label. Distinct summary time series are created for DNS and NXD Hits per interval per zone as well; also applying zone name as a label and bound by the summary_window configuration value. _sum and _count metrics represent the summary aggregation metrics.

Metric | Description
------ | -----------
edgedns_traffic_dns_hits_per_interval | Number of DNS hits per 5 minute interval per zone
edgedns_traffic_nxd_hits_per_interval | Number of NXD hits per 5 minute interval per zone 
edgedns_traffic_dns_hits_per_interval_summary_count | Summary count of DNS Hit 5 minute intervals per zone
edgedns_traffic_dns_hits_per_interval_summary_sum | Summary aggregation of DNS Hit 5 minute interval hits per zone
edgedns_traffic_nxd_hits_per_interval_summary_count | Summary count of NXD Hit 5 minute intervals per zone
edgedns_traffic_nxd_hits_per_interval_summary_sum | Summary aggregation of NXD Hit 5 minute interval hits per zone

### Advanced Operation

Prometheus' default TLDB storage bounds the timestamp window that it will accept for newly created time series metrics (~2-3 hours). As such, the exporter (by default) records traffic data in the time order received, however, the metric time stamp is the current time when the time series is created.  

The exporter provides advanced configuration options that enable the inclusion of the traffic data timestamp as a time series label and/or create the time series metric with the traffic data timestamp. Enabling one or both options may be useful and valuable if traffic data returned is timestamped accordingly, a time series database supporting broader time ranges is configured  or the timestamp of the collected traffic data interval is needed.

#### `timestamp_label` Behavior Notes

Adding a timestamp label to each metric time series has the side effect of creating a distinct series for each label/timestamp combination. When retreiving metrics, it is recommended to use only the zone label in the query expression. The legend displayed when viewing graphs through the Prometheus portal will contain all generated series; 288 per day. Other viewing applications, e.g. Grafana, will allow graph customization and reduced screen clutter. 

The table tab in the Prometheus portal may provide a more manageable means to view metrics with a timestamp label. For example by only retrieving the last 5 minutes of collected metrics: `edgedns_traffic_nxd_hits_per_interval{zone="example.com"}[5m]`

#### `traffic_timestamp` Behavior Notes

Prometheus will not persist traffic metrics with a timestamp outside of the current time series database collection window. The Prometheus log will note a warning, e.g. 

```
level=warn ts=2021-01-12T18:56:49.492Z caller=scrape.go:1378 component="scrape manager" scrape_pool=edgedns_zone target=http://localhost:9801/metrics msg="Error on ingesting samples that are too old or are too far into the future" num_dropped=2
```

and continue to collect future metric data. The dropped data will not be available for further viewing, analysis or alerting

### View the metrics using the exporter webserver

To glimpse Edge DNS Traffic metric activity in the exporter, visit the exporter's metrics web page with a browser using local host and the exporter's port known from one of the INFO startup messages (e.g. http://localhost:9801/metrics). The web page will present exporter status and metrics as follows.

```
# HELP akamai_edgedns_traffic_exporter_build_info A metric with a constant '1' value labeled by version, revision, branch, and goversion from which akamai_edgedns_traffic_exporter was built.
# TYPE akamai_edgedns_traffic_exporter_build_info gauge
akamai_edgedns_traffic_exporter_build_info{branch="master",goversion="go1.15.6",revision="84667d49203590616cd6d1b07d75715eaff31392",version="0.1.0"} 1
# HELP edgedns_traffic_dns_hits_per_interval Number of DNS hits per 5 minute interval (per zone)
# TYPE edgedns_traffic_dns_hits_per_interval gauge
edgedns_traffic_dns_hits_per_interval{zone="edgedns.zone"} 75
# HELP edgedns_traffic_dns_hits_per_interval_summary Number of DNS hits per 5 minute interval (per zone)
# TYPE edgedns_traffic_dns_hits_per_interval_summary summary
edgedns_traffic_dns_hits_per_interval_summary_sum{zone="edgedns.zone"} 158
edgedns_traffic_dns_hits_per_interval_summary_count{zone="edgedns.zone"} 2
# HELP edgedns_traffic_nxd_hits_per_interval Number of NXD hits per 5 minute interval (per zone)
# TYPE edgedns_traffic_nxd_hits_per_interval gauge
edgedns_traffic_nxd_hits_per_interval{zone="edgedns.zone"} 11
# HELP edgedns_traffic_nxd_hits_per_interval_summary Number of NXDomain hits per 5 minute interval (per zone)
# TYPE edgedns_traffic_nxd_hits_per_interval_summary summary
edgedns_traffic_nxd_hits_per_interval_summary_sum{zone="edgedns.zone"} 15
edgedns_traffic_nxd_hits_per_interval_summary_count{zone="edgedns.zone"} 2
```

### View the metrics using the prometheus webserver

To view the metrics in Prometheus, visit Graph and Execute a query expression for one of the metrics. As an example, the following image shows the graph for `edgedns_traffic_nxd_hits_per_interval_summary_sum`.

![Prometheus](/static/prometheus.png)

## Post Processing Metrics with recording rules

Recording rules allow for post processing metrics to perform additional analysis of traffic data or to detect abnormalities. Post processing is done on the Prometheus server. The `rule-files` section of the Prometheus configuration defines rule processing for the Prometheus server. As an example, [example_edgedns_traffic_alerts.rules](https://github.com/akamai/akamai-edgedns-traffic-exporter/blob/master/example_edgedns_traffic_alerts.rules), defines recording rules to prepare for excessive NXDOMAIN hits detection in an interval. Here are example configuration settings that define additional metrics and the expressions to produce the metrics.

```
- record: instance_zone:edgedns_traffic_nxd_hits_per_interval:max1m
  # zone must be literal. Can't template expressions
  expr: max_over_time(edgedns_traffic_nxd_hits_per_interval{zone="example.zone"}[1m])
- record: instance_zone:edgedns_traffic_nxd_hits_per_interval_summary:mean
  expr: |2
    edgedns_traffic_nxd_hits_per_interval_summary_sum{zone="example.zone"}
    /
    edgedns_traffic_dns_hits_per_interval_summary_count{zone="example.zone"}
- record: instance_zone:edgedns_traffic_nxd_hits_per_interval_summary:sub_mean
  expr: (instance_zone:edgedns_traffic_nxd_hits_per_interval:max1m - instance_zone:edgedns_traffic_nxd_hits_per_interval_summary:mean*10)
```

This configuration identifies the largest number of NXDOMAIN hits in the last minute, calculates the current average NXDOMAIN interval rate, and  compares the high interval with a threshhold set as the average times 10. In this way, Prometheus record events of NXDOMAIN spikes indicating DNS abuse.

Prometheus can present these metrics in a graph and make them available to detect and generate an alert.
 
## Alerting on traffic metrics

To detect an alert on an event or abnormality, two actions must be taken. First, an alert rule defines the activity of interest and the alert conditions. Rule examples can be found in [example_edgedns_traffic_alerts.rules](https://github.com/akamai/akamai-edgedns-traffic-exporter/blob/master/example_edgedns_traffic_alerts.rules). Here is a snippet from the rules file:

```
- alert: NXDHitsOutOfBounds
  expr: instance_zone:edgedns_traffic_nxd_hits_per_interval_summary:sub_mean >= 0
  labels:
    zone: "example.zone"
    severity: critical
  annotations:
    summary: "NXD Hits Exceeded Rolling average * 10"
    description: "Job: {{ $labels.job }} Instance: {{ $labels.instance }} has NXDOMAIN interval hit count (current value: {{ $value }}s) compared to rolling average"
```

This configuration presents an alert rule that checks whether the most recent NXDOMAIN metric exceeds the size of our defined thresh hold. Prometheus will generate an alert if the conditional check is true.

The second step is to configure the AlertManager (e.g. the receiver of the alert) to pick up the alert and propagate it accordingly.

[example_alertmanager_edgedns_traffic.yml](https://github.com/akamai/akamai-edgedns-traffic-exporter/blob/master/example_alertmanager_edgedns_traffic.yml) is a simple example alertmanager configuration to receive this alert and propagate it via email.

### Simple Gmail receiver

Each alert that fires produces messages for receivers. A simple notification receiver is to use Gmail with an app password. The following example shows a minimal configuration for the `alertmanager.yml` file.

```
global:
  resolve_timeout: 1m

route:
  receiver: 'gmail-notifications'

receivers:
- name: 'gmail-notifications'
  email_configs:
  - to: user@gmail.com
    from: user@gmail.com
    smarthost: smtp.gmail.com:587
    auth_username: user@gmail.com
    auth_identity: user@gmail.com
    auth_password: app-password
    send_resolved: true
```

## Troubleshooting

* Make sure the target is live and up in Prometheus Status > Targets.

![Status > Targets](/static/target.png)

* Make sure the service definition is correct in Prometheus Status > Service Discovery.

![Status > Targets](/static/service.png)

* Make sure the exporter is providing metrics to Prometheus. Visit the URL for the exporter (e.g. http://localhost:9801) and look for metrics such as the following DNS hits interval.

```
# HELP edgedns_traffic_dns_hits_per_interval Number of DNS hits per 5 minute interval (per zone)
# TYPE edgedns_traffic_dns_hits_per_interval gauge
edgedns_traffic_dns_hits_per_interval{zone="edgedns.zone"} 75
```

* Make sure the scrape interval and timeout levels in the exporter configuration are at least 30s.

```
scrape_interval: 30s # By default, scrape targets every 15 seconds.
scrape_timeout: 30s
```

* If using a docker image for the Edge DNS exporter, Prometheus might need to explicitly reference the target appropriately.

```
static_configs:
- targets: ['docker.for.mac.localhost:9801']
```

* For rules, Prometheus will assume the full path is `/etc/prometheus/`. If using a Docker image, reference to the file outside of the container must have a volume mount (e.g. `-v ~/go/src/github.com/akamai-edgedns-traffic-exporter/example_edgedns_traffic_alerts.rules:/etc/prometheus/example_edgedns_traffic_alerts.rules`). Visit Status > Configuration within the Prometheus application and validate the `rules_files:` setting and Status > Rules to ensure the evaluation state is `OK`. The `promtool` is also helpful to validate rule syntax. Valid rule configurations will earn a `SUCCESS: 4 rules found` message.

* To validate notification receiver workflow, create an alert expression that is always true. A good example is to match for the known, static instance domain and port.

```
- alert: Test Receiver Workflow
  expr: akamai_edgedns_traffic_exporter_build_info{instance="docker.for.mac.localhost:9801"} == 1
  for: 10s
  labels:
    cluster: test
    severity: warning
  annotations:
    action: No action
    description: Alert from {{ $labels.instance }}
```

## Future Work

* The [Akamai Edge DNS Traffic Report](https://developer.akamai.com/api/cloud_security/edge_dns_traffic_reporting/v1.html) API provides historical DNS query and NXDOMAIN traffic. Backfill time series improvements will allow loading Edge DNS past data.

## License

Apache License 2.0, see [LICENSE](https://github.com/akamai/akamai-edgedns-traffic-exporter/master/LICENSE).
