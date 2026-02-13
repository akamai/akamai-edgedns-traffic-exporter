// Copyright 2020 Akamai Technologies, Inc.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/version"
	"github.com/sirupsen/logrus"

	kingpin "github.com/alecthomas/kingpin/v2"

	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	edgegrid "github.com/akamai/AkamaiOPEN-edgegrid-golang/v12/pkg/edgegrid"
	"gopkg.in/yaml.v3"
)

const (
	defaultlistenaddress = ":9801"
	namespace            = "edgedns_traffic"
	//MinsInHour            = 60
	HoursInDay = 24
	//DaysInWeek            = 7
	trafficReportInterval = 5 // mins
	lookbackDefaultDays   = 1
	//intervalsPerDay       = (MinsInHour / trafficReportInterval) * HoursInDay
)

var (
	configFile           = kingpin.Flag("config.file", "Edge DNS Traffic exporter configuration file. Default: ./edgedns.yml").Default("edgedns.yml").String()
	listenAddress        = kingpin.Flag("web.listen-address", "The address to listen on for HTTP requests.").Default(defaultlistenaddress).String()
	edgegridHost         = kingpin.Flag("edgedns.edgegrid-host", "The Akamai Edgegrid host auth credential.").String()
	edgegridClientSecret = kingpin.Flag("edgedns.edgegrid-client-secret", "The Akamai Edgegrid client_secret credential.").String()
	edgegridClientToken  = kingpin.Flag("edgedns.edgegrid-client-token", "The Akamai Edgegrid client_token credential.").String()
	edgegridAccessToken  = kingpin.Flag("edgedns.edgegrid-access-token", "The Akamai Edgegrid access_token credential.").String()
	//include_estimates	= kingpin.Flag("edgedns.end-time", "Flag to include estimates in traffic reports.").Bool()
	//time_zone		= kingpin.Flag("edgedns.time-zone", "The timezone to use for start and end time.").String()
	timestampLabel   = kingpin.Flag("edgedns.timestamp-label", "Creates time series with traffic timestamp as label.").Bool()
	trafficTimestamp = kingpin.Flag("edgedns.traffic-timestamp", "Create time series with traffic timestamp.").Bool()

	// invalidMetricChars    = regexp.MustCompile("[^a-zA-Z0-9_:]")
	lookbackDuration = time.Hour * HoursInDay * lookbackDefaultDays
	//edgednsErrorDesc  = prometheus.NewDesc("akamai_edgedns_traffic__error", "Error collecting metrics", nil, nil)
)

// Exporter config
type EdgednsTrafficConfig struct {
	Zones         []string `yaml:"zones"`
	EdgercPath    string   `yaml:"edgerc_path"`
	EdgercSection string   `yaml:"edgerc_section"`
	SummaryWindow string   `yaml:"summary_window"`    // mins, hours, days, [weeks]. Default lookbackDefaultDays
	TSLabel       bool     `yaml:"timestamp_label"`   // Creates time series with traffic timestamp as label
	UseTimestamp  bool     `yaml:"traffic_timestamp"` // Create time series with traffic timestamp
}

type EdgednsTrafficExporter struct {
	TrafficExporterConfig EdgednsTrafficConfig
	LastTimestamp         map[string]time.Time // index by zone name
	AkamaiClient          *AkamaiClient
}

func NewEdgednsTrafficExporter(edgednsConfig EdgednsTrafficConfig, lastTimestamp map[string]time.Time, akamaiClient *AkamaiClient) *EdgednsTrafficExporter {
	return &EdgednsTrafficExporter{
		TrafficExporterConfig: edgednsConfig,
		LastTimestamp:         lastTimestamp,
		AkamaiClient:          akamaiClient,
	}
}

// Metric Definitions
// Summaries map by zone
var dnsSummaryMap map[string]prometheus.Summary = make(map[string]prometheus.Summary)
var nxdSummaryMap map[string]prometheus.Summary = make(map[string]prometheus.Summary)

// Interval Hits map by zone
var dnsHitsMap map[string][]float64 = make(map[string][]float64)
var nxdHitsMap map[string][]float64 = make(map[string][]float64)
var hitsMapCap int

// Initialize Akamai Edgegrid Config. Priority order:
// 1. Command line
// 2. Edgerc path
// 3. Environment
// 4. Default
func initAkamaiConfig(trafficExporterConfig EdgednsTrafficConfig) (*AkamaiClient, error) {

	var config *edgegrid.Config
	var err error

	if *edgegridHost != "" && *edgegridClientSecret != "" && *edgegridClientToken != "" && *edgegridAccessToken != "" {
		edgeconf := edgegrid.Config{
			Host:         *edgegridHost,
			ClientToken:  *edgegridClientToken,
			ClientSecret: *edgegridClientSecret,
			AccessToken:  *edgegridAccessToken,
			MaxBody:      131072,
		}
		config = &edgeconf
	} else if *edgegridHost != "" || *edgegridClientSecret != "" || *edgegridClientToken != "" || *edgegridAccessToken != "" {
		fmt.Printf("Command line Auth Keys are incomplete. Looking for alternate definitions.")
	}

	if config == nil {
		config, err = EdgegridInit(trafficExporterConfig.EdgercPath, trafficExporterConfig.EdgercSection)
		if err != nil {
			return nil, fmt.Errorf("error initializing Akamai Edgegrid config: %w", err)
		}
	}

	if config.Host == "" {
		return nil, fmt.Errorf("host is empty: environment variables not detected")
	}

	dnsClient, sess, err := CreateDNSClient(config)
	if err != nil {
		return nil, fmt.Errorf("error creating DNS client: %w", err)
	}

	return &AkamaiClient{
		DNSClient: dnsClient,
		Session:   sess,
	}, nil
}

// Initialize locally maintained maps
func createZoneMaps(zones []string) {

	for _, zone := range zones {
		labels := prometheus.Labels{"zone": zone}

		dnsSummaryMap[zone] = prometheus.NewSummary(
			prometheus.SummaryOpts{
				Namespace:   namespace,
				Name:        "dns_hits_per_interval_summary",
				Help:        "Number of DNS hits per 5 minute interval (per zone)",
				MaxAge:      lookbackDuration,
				BufCap:      prometheus.DefBufCap * 2,
				ConstLabels: labels,
			})
		nxdSummaryMap[zone] = prometheus.NewSummary(
			prometheus.SummaryOpts{
				Namespace:   namespace,
				Name:        "nxd_hits_per_interval_summary",
				Help:        "Number of NXDomain hits per 5 minute interval (per zone)",
				MaxAge:      lookbackDuration,
				BufCap:      prometheus.DefBufCap * 2,
				ConstLabels: labels,
			})
		intervals := lookbackDuration / (time.Minute * 5)
		hitsMapCap = int(intervals)
		dnsHitsMap[zone] = make([]float64, 0, hitsMapCap)
		nxdHitsMap[zone] = make([]float64, 0, hitsMapCap)
	}
}

// Calculate summary window duration based on config and save in lookbackDuration global variable
func calcSummaryWindowDuration(window string) error {

	var datawin int
	var err error
	var multiplier time.Duration

	logrus.Debugf("Window: %s", window)
	if window == "" {
		return fmt.Errorf("summary window not set")
	}
	// Get the last character as the unit
	iunit := strings.ToLower(window[len(window)-1:])

	// Check if the last character is a digit (meaning no unit provided)
	if iunit[0] >= '0' && iunit[0] <= '9' {
		datawin, err = strconv.Atoi(window)
		multiplier = time.Hour * 24 // Default to days
	} else {
		valStr := window[0 : len(window)-1]
		datawin, err = strconv.Atoi(valStr)

		switch iunit {
		case "m":
			multiplier = time.Minute
			if datawin < trafficReportInterval {
				datawin = trafficReportInterval
			}
		case "h":
			multiplier = time.Hour
		case "d":
			multiplier = time.Hour * 24
		default:
			return fmt.Errorf("invalid unit %q in summary window", iunit)
		}
	}

	if err != nil {
		logrus.Warnf("Error parsing window value: %s", err.Error())
		return err
	}

	lookbackDuration = multiplier * time.Duration(datawin)
	logrus.Debugf("Calculated lookbackDuration: %v", lookbackDuration)
	return nil
}

// Describe function
func (e *EdgednsTrafficExporter) Describe(ch chan<- *prometheus.Desc) {

	ch <- prometheus.NewDesc("akamai_edgedns", "Akamai Edgedns", nil, nil)
}

// Collect function
func (e *EdgednsTrafficExporter) Collect(ch chan<- prometheus.Metric) {
	logrus.Debugf("Entering EdgeDNS Collect")

	endtime := time.Now().UTC() // Use same current time for all zones

	// TODO: Purge old data points

	// Collect metrics for each zone
	for _, zone := range e.TrafficExporterConfig.Zones {

		logrus.Debugf("Processing zone %s", zone)

		// get last timestamp recorded. bump a minute. Make sure at least 5 minutes
		lasttime := e.LastTimestamp[zone].Add(time.Minute)
		if endtime.Before(lasttime.Add(time.Minute * 5)) {
			lasttime = lasttime.Add(time.Minute * 5)
		}
		qargs := CreateQueryArgs(lasttime, endtime)
		logrus.Debugf("Fetching Report for zone %s. Args: [%v}", zone, qargs)
		ctx := context.Background()
		zoneTrafficReport, err := GetTrafficReport(ctx, e.AkamaiClient.DNSClient, e.AkamaiClient.Session, zone, qargs)
		if err != nil {
			var statusCode int
			if apiErr, ok := err.(interface{ Status() int }); ok {
				statusCode = apiErr.Status()
			} else if apiErr, ok := err.(interface{ StatusCode() int }); ok {
				statusCode = apiErr.StatusCode()
			}

			if statusCode == 500 {
				logrus.Warnf("Server error from Akamai API for zone %s, skipping.", zone)
				continue
			}
			logrus.Errorf("Error retrieving traffic report for zone %s: %v — skipping zone", zone, err)
			continue
		}

		reportList := ConvertTrafficRecordsResponse(zoneTrafficReport)
		sort.Slice(reportList.TrafficRecords[:], func(i, j int) bool {
			return reportList.TrafficRecords[i].Timestamp.Before(reportList.TrafficRecords[j].Timestamp)
		})
		logrus.Debugf("Traffic data: [%v]", reportList.TrafficRecords)

		for _, reportInstance := range reportList.TrafficRecords {
			// TODO: Worry about overwriting existing? Catch for now and skip.
			//reportInstance.DNSHits = math.Round(reportInstance.DNSHits * 86400)
			//reportInstance.NXDHits = math.Round(reportInstance.NXDHits * 86400)
			if !reportInstance.Timestamp.After(e.LastTimestamp[zone]) {
				logrus.Debugf("Instance timestamp: [%v]. Last timestamp: [%v]", reportInstance.Timestamp, e.LastTimestamp[zone])
				logrus.Warnf("Attempting to re process report instance: [%v]. Skipping.", reportInstance)
				continue
			}
			// See if we missed an interval. Use averages to fill in.
			logrus.Debugf("Instance timestamp: [%v]. Last timestamp: [%v]", reportInstance.Timestamp, e.LastTimestamp[zone])
			if reportInstance.Timestamp.After(e.LastTimestamp[zone].Add(time.Minute * (trafficReportInterval + 1))) {
				reportInstance.Timestamp = e.LastTimestamp[zone].Add(time.Minute * trafficReportInterval)
				logrus.Debugf("Filling in entry with timestamp: %v", reportInstance.Timestamp)
				// Missed interval insert with averages
				dnsLen := int64(len(dnsHitsMap[zone]))
				var dnsHitsSum float64
				// calc current rolling dns sum
				for _, dhit := range dnsHitsMap[zone] {
					dnsHitsSum += dhit
				}
				nxdLen := int64(len(nxdHitsMap[zone]))
				var nxdHitsSum float64
				// calc current rolling nxd sum
				for _, nhit := range nxdHitsMap[zone] {
					nxdHitsSum += nhit
				}
				if dnsLen > 0 {
					reportInstance.DNSHits = float64(dnsHitsSum) / float64(dnsLen)
					reportInstance.NXDHits = float64(nxdHitsSum) / float64(nxdLen)
				}
			}

			// Update rolling hit sums
			dnsHitsLen := len(dnsHitsMap[zone])
			if dnsHitsLen == hitsMapCap {
				// Make room
				dnsHitsMap[zone] = dnsHitsMap[zone][1:]
				nxdHitsMap[zone] = nxdHitsMap[zone][1:]
			}
			dnsHitsMap[zone] = append(dnsHitsMap[zone], reportInstance.DNSHits)
			nxdHitsMap[zone] = append(nxdHitsMap[zone], reportInstance.NXDHits)
			// Check if preserving report instance timestamp as a label
			var tsLabels = []string{"zone"}
			if e.TrafficExporterConfig.TSLabel {
				tsLabels = append(tsLabels, "interval_timestamp")
			}
			// DNS Hits
			ts := reportInstance.Timestamp.Format(time.RFC3339)
			desc := prometheus.NewDesc(prometheus.BuildFQName(namespace, "", "dns_hits_per_interval"), "Number of DNS hits per 5 minute interval (per zone)", tsLabels, nil)
			logrus.Debugf("Creating DNS metric. Zone: %s, Hits: %v, Timestamp: %v", zone, reportInstance.DNSHits, ts)
			var dnsmetric prometheus.Metric
			var nxdmetric prometheus.Metric
			if e.TrafficExporterConfig.TSLabel {
				dnsmetric = prometheus.MustNewConstMetric(
					desc, prometheus.GaugeValue, float64(reportInstance.DNSHits), zone, ts)
			} else {
				dnsmetric = prometheus.MustNewConstMetric(
					desc, prometheus.GaugeValue, float64(reportInstance.DNSHits), zone)
			}
			if !e.TrafficExporterConfig.UseTimestamp {
				ch <- dnsmetric
			} else {
				ch <- prometheus.NewMetricWithTimestamp(reportInstance.Timestamp, dnsmetric)
			}
			// NXD Hits
			desc = prometheus.NewDesc(prometheus.BuildFQName(namespace, "", "nxd_hits_per_interval"), "Number of NXD hits per 5 minute interval (per zone)", tsLabels, nil)
			logrus.Debugf("Creating NXD metric. Zone: %s, Hits: %v, Timestamp: %v", zone, reportInstance.NXDHits, ts)
			if e.TrafficExporterConfig.TSLabel {
				nxdmetric = prometheus.MustNewConstMetric(
					desc, prometheus.GaugeValue, float64(reportInstance.NXDHits), zone, ts)
			} else {
				nxdmetric = prometheus.MustNewConstMetric(
					desc, prometheus.GaugeValue, float64(reportInstance.NXDHits), zone)
			}
			if !e.TrafficExporterConfig.UseTimestamp {
				ch <- nxdmetric
			} else {
				ch <- prometheus.NewMetricWithTimestamp(reportInstance.Timestamp, nxdmetric)
			}
			// Summaries
			dnsSummaryMap[zone].Observe(float64(reportInstance.DNSHits))
			nxdSummaryMap[zone].Observe(float64(reportInstance.NXDHits))

			// Update last timestamp processed
			if reportInstance.Timestamp.After(e.LastTimestamp[zone]) {
				logrus.Debugf("Updating Last Timestamp from %v TO %v", e.LastTimestamp[zone], reportInstance.Timestamp)
				e.LastTimestamp[zone] = reportInstance.Timestamp
			}
			// only process one each interval!
			break
		}
	}
}

func init() {
	// This replaces the old version.NewCollector("your_exporter_name")
	buildInfo := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "akamai_edgedns_traffic_exporter",
		Name:      "build_info",
		Help:      "Build info with version, revision, branch, goversion",
		ConstLabels: prometheus.Labels{
			"version":   version.Version,
			"revision":  version.Revision,
			"branch":    version.Branch,
			"goversion": version.GoVersion,
		},
	})

	buildInfo.Set(1) // always 1 — it's just an info label metric
	prometheus.MustRegister(buildInfo)
}

func main() {

	logLevel := kingpin.Flag("log.level", "Only log messages with the given severity or above. Valid levels: [debug, info, warn, error, fatal]").Default("info").Enum("debug", "info", "warn", "error", "fatal")
	logFormat := kingpin.Flag("log.format", "Set the log target and format. Example: logger:stderr?json=true").Default("logger:stderr").String()

	//log.AddFlags(kingpin.CommandLine)
	kingpin.Version(version.Print("akamai_edgedns_traffic_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	level, err := logrus.ParseLevel(strings.ToLower(*logLevel))
	if err != nil {
		logrus.Errorf("Invalid log level %q, defaulting to info", *logLevel)
		level = logrus.InfoLevel
	}

	logrus.SetLevel(level)
	if strings.Contains(*logFormat, "json=true") {
		logrus.SetFormatter(&logrus.JSONFormatter{})
	} else {
		logrus.SetFormatter(&logrus.TextFormatter{
			FullTimestamp: true,
		})
	}
	// Now your logs will follow the flag!
	logrus.Infof("Logging level set to %s", logrus.GetLevel())

	logrus.Infof("Config file: %s", *configFile)
	logrus.Info("Starting Edge DNS Traffic exporter", version.Info())
	logrus.Info("Build context", version.BuildContext())

	edgednsTrafficConfig, err := loadConfig(*configFile) // save?
	if err != nil {
		logrus.Fatalf("Error loading akamai_edgedns_traffic_exporter config file: %v", err)
	}

	logrus.Debugf("Exporter configuration: [%v]", edgednsTrafficConfig)

	if *timestampLabel {
		edgednsTrafficConfig.TSLabel = true
	}
	if *trafficTimestamp {
		edgednsTrafficConfig.UseTimestamp = true
	}

	// Initalize Akamai Edgegrid ...
	akamaiClient, err := initAkamaiConfig(edgednsTrafficConfig)
	if err != nil {
		logrus.Fatalf("Error initializing Akamai Edgegrid config: %s", err.Error())
	}

	lookbackDuration = time.Hour * 24 * time.Duration(lookbackDefaultDays)

	if edgednsTrafficConfig.SummaryWindow != "" {
		err = calcSummaryWindowDuration(edgednsTrafficConfig.SummaryWindow)
		if err != nil {
			logrus.Warnf("Retention window is not valid. Using default (%d days)", lookbackDefaultDays)
		}
	} else {
		logrus.Warnf("Retention window is not configured. Using default (%d days)", lookbackDefaultDays)
	}

	tstart := time.Now().UTC().Add(lookbackDuration * -1)

	logrus.Infof("Edge DNS Traffic exporter start time: %v", tstart)

	// Populate LastTimestamp per Zone. Start time applies to all.
	lastTimeStamp := make(map[string]time.Time) // index by zone name
	for _, zone := range edgednsTrafficConfig.Zones {
		lastTimeStamp[zone] = tstart
	}

	// Create/register collector
	edgednsTrafficCollector := NewEdgednsTrafficExporter(edgednsTrafficConfig, lastTimeStamp, akamaiClient)
	prometheus.MustRegister(edgednsTrafficCollector)

	// Create and register Summaries
	createZoneMaps(edgednsTrafficConfig.Zones)
	for _, sum := range dnsSummaryMap {
		prometheus.MustRegister(sum)
	}
	for _, sum := range nxdSummaryMap {
		prometheus.MustRegister(sum)
	}

	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html>
			<head><title>akamai_edgedns_traffic_exporter</title></head>
			<body>
			<h1>akamai_edgedns_traffic_exporter</h1>
			<p><a href="/metrics">Metrics</a></p>
			</body>
			</html>`))
	})

	logrus.Info("Beginning to serve on address ", *listenAddress)
	logrus.Fatal(http.ListenAndServe(*listenAddress, nil))

}

func loadConfig(configFile string) (EdgednsTrafficConfig, error) {
	if fileExists(configFile) {
		// Load config from file
		configData, err := os.ReadFile(configFile)
		if err != nil {
			return EdgednsTrafficConfig{}, err
		}

		return loadConfigContent(configData)
	}

	logrus.Infof("Config file %v does not exist, using default values", configFile)
	return EdgednsTrafficConfig{}, nil

}

func loadConfigContent(configData []byte) (EdgednsTrafficConfig, error) {
	config := EdgednsTrafficConfig{}
	err := yaml.Unmarshal(configData, &config)
	if err != nil {
		return config, err
	}

	logrus.Info("akamai_edgedns_traffic_exporter config loaded")
	return config, nil
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}
