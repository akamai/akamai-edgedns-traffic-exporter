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
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/log"
	"github.com/prometheus/common/version"

	kingpin "gopkg.in/alecthomas/kingpin.v2"

	"fmt"
	client "github.com/akamai/AkamaiOPEN-edgegrid-golang/client-v1"
	edgegrid "github.com/akamai/AkamaiOPEN-edgegrid-golang/edgegrid"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
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
}

func NewEdgednsTrafficExporter(edgednsConfig EdgednsTrafficConfig, lastTimestamp map[string]time.Time) *EdgednsTrafficExporter {
	return &EdgednsTrafficExporter{
		TrafficExporterConfig: edgednsConfig,
		LastTimestamp:         lastTimestamp,
	}
}

// Metric Definitions
// Summaries map by zone
var dnsSummaryMap map[string]prometheus.Summary = make(map[string]prometheus.Summary)
var nxdSummaryMap map[string]prometheus.Summary = make(map[string]prometheus.Summary)

// Interval Hits map by zone
var dnsHitsMap map[string][]int64 = make(map[string][]int64)
var nxdHitsMap map[string][]int64 = make(map[string][]int64)
var hitsMapCap int

// Initialize Akamai Edgegrid Config. Priority order:
// 1. Command line
// 2. Edgerc path
// 3. Environment
// 4. Default
func initAkamaiConfig(trafficExporterConfig EdgednsTrafficConfig) error {

	if *edgegridHost != "" && *edgegridClientSecret != "" && *edgegridClientToken != "" && *edgegridAccessToken != "" {
		edgeconf := edgegrid.Config{}
		edgeconf.Host = *edgegridHost
		edgeconf.ClientToken = *edgegridClientSecret
		edgeconf.ClientSecret = *edgegridClientToken
		edgeconf.AccessToken = *edgegridAccessToken
		edgeconf.MaxBody = 131072
		return edgeInit(edgeconf)
	} else if *edgegridHost != "" || *edgegridClientSecret != "" || *edgegridClientToken != "" || *edgegridAccessToken != "" {
		log.Warnf("Command line Auth Keys are incomplete. Looking for alternate definitions.")
	}

	// Edgegrid will also check for environment variables ...
	err := EdgegridInit(trafficExporterConfig.EdgercPath, trafficExporterConfig.EdgercSection)
	if err != nil {
		log.Fatalf("Error initializing Akamai Edgegrid config: %s", err.Error())
		return err
	}

	log.Debugf("Edgegrid config: [%v]", edgegridConfig)

	return nil

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
		dnsHitsMap[zone] = make([]int64, 0, hitsMapCap)
		nxdHitsMap[zone] = make([]int64, 0, hitsMapCap)
	}
}

// Calculate summary window duration based on config and save in lookbackDuration global variable
func calcSummaryWindowDuration(window string) error {

	var datawin int
	var err error
	var multiplier time.Duration = time.Hour * time.Duration(HoursInDay) // assume days

	log.Debugf("Window: %s", window)
	if window == "" {
		return fmt.Errorf("Summary window not set")
	}
	iunit := window[len(window)-1:]
	if !strings.Contains("mhd", strings.ToLower(iunit)) {
		// no units. default days
		datawin, err = strconv.Atoi(window)
	} else {
		len := window[0 : len(window)-1]
		datawin, err = strconv.Atoi(len)
		if strings.ToLower(iunit) == "m" {
			multiplier = time.Minute
			if err == nil && datawin < trafficReportInterval {
				datawin = trafficReportInterval
			}
		} else if strings.ToLower(iunit) == "h" {
			multiplier = time.Hour
		}
	}
	if err != nil {
		log.Warnf("ERROR: %s", err.Error())
		return err
	}
	log.Debugf("multiplier: [%v} units: [%v]", multiplier, datawin)
	lookbackDuration = multiplier * time.Duration(datawin)
	return nil

}

// Describe function
func (e *EdgednsTrafficExporter) Describe(ch chan<- *prometheus.Desc) {

	ch <- prometheus.NewDesc("akamai_edgedns", "Akamai Edgedns", nil, nil)
}

// Collect function
func (e *EdgednsTrafficExporter) Collect(ch chan<- prometheus.Metric) {
	log.Debugf("Entering EdgeDNS Collect")

	endtime := time.Now().UTC() // Use same current time for all zones

	// TODO: Purge old data points

	// Collect metrics for each zone
	for _, zone := range e.TrafficExporterConfig.Zones {

		log.Debugf("Processing zone %s", zone)

		// get last timestamp recorded. bump a minute. Make sure at least 5 minutes
		lasttime := e.LastTimestamp[zone].Add(time.Minute)
		if endtime.Before(lasttime.Add(time.Minute * 5)) {
			lasttime = lasttime.Add(time.Minute * 5)
		}
		qargs := CreateQueryArgs(lasttime, endtime)
		log.Debugf("Fetching Report for zone %s. Args: [%v}", zone, qargs)
		zoneTrafficReport, err := GetTrafficReport(zone, qargs)
		if err != nil {
			apierr, ok := err.(client.APIError)
			if ok && apierr.Status == 500 {
				log.Warnf("Unable to get traffic report for zone %s. Internal error ... Skipping.", zone)
				continue
			}
			log.Errorf("Unable to get traffic report for zone %s ... Skipping. Error: %s", zone, err.Error())
			continue
		}
		reportList := ConvertTrafficRecordsResponse(zoneTrafficReport)
		sort.Slice(reportList.TrafficRecords[:], func(i, j int) bool {
			return reportList.TrafficRecords[i].Timestamp.Before(reportList.TrafficRecords[j].Timestamp)
		})
		log.Debugf("Traffic data: [%v]", reportList.TrafficRecords)

		for _, reportInstance := range reportList.TrafficRecords {
			// TODO: Worry about overwriting existing? Catch for now and skip.
			if !reportInstance.Timestamp.After(e.LastTimestamp[zone]) {
				log.Debugf("Instance timestamp: [%v]. Last timestamp: [%v]", reportInstance.Timestamp, e.LastTimestamp[zone])
				log.Warnf("Attempting to re process report instance: [%v]. Skipping.", reportInstance)
				continue
			}
			// See if we missed an interval. Use averages to fill in.
			log.Debugf("Instance timestamp: [%v]. Last timestamp: [%v]", reportInstance.Timestamp, e.LastTimestamp[zone])
			if reportInstance.Timestamp.After(e.LastTimestamp[zone].Add(time.Minute * (trafficReportInterval + 1))) {
				reportInstance.Timestamp = e.LastTimestamp[zone].Add(time.Minute * trafficReportInterval)
				log.Debugf("Filling in entry with timestamp: %v", reportInstance.Timestamp)
				// Missed interval insert with averages
				dnsLen := int64(len(dnsHitsMap[zone]))
				var dnsHitsSum int64
				// calc current rolling dns sum
				for _, dhit := range dnsHitsMap[zone] {
					dnsHitsSum += dhit
				}
				nxdLen := int64(len(nxdHitsMap[zone]))
				var nxdHitsSum int64
				// calc current rolling nxd sum
				for _, nhit := range nxdHitsMap[zone] {
					nxdHitsSum += nhit
				}
				if dnsLen > 0 {
					reportInstance.DNSHits = dnsHitsSum / dnsLen
					reportInstance.NXDHits = nxdHitsSum / nxdLen
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
			log.Debugf("Creating DNS metric. Zone: %s, Hits: %v, Timestamp: %v", zone, reportInstance.DNSHits, ts)
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
			log.Debugf("Creating NXD metric. Zone: %s, Hits: %v, Timestamp: %v", zone, reportInstance.NXDHits, ts)
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
				log.Debugf("Updating Last Timestamp from %v TO %v", e.LastTimestamp[zone], reportInstance.Timestamp)
				e.LastTimestamp[zone] = reportInstance.Timestamp
			}
			// only process one each interval!
			break
		}
	}
}

func init() {
	prometheus.MustRegister(version.NewCollector("akamai_edgedns_traffic_exporter"))
}

func main() {

	log.AddFlags(kingpin.CommandLine)
	kingpin.Version(version.Print("akamai_edgedns_traffic_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	log.Infof("Config file: %s", *configFile)
	// TODO: Remove
	//log.Infof("Start: %s", *start)
	//log.Infof("Start Time: %s", *start_time)

	log.Info("Starting Edge DNS Traffic exporter", version.Info())
	log.Info("Build context", version.BuildContext())

	edgednsTrafficConfig, err := loadConfig(*configFile) // save?
	if err != nil {
		log.Fatalf("Error loading akamai_edgedns_traffic_exporter config file: %v", err)
	}

	log.Debugf("Exporter configuration: [%v]", edgednsTrafficConfig)

	// Initalize Akamai Edgegrid ...
	err = initAkamaiConfig(edgednsTrafficConfig)
	if err != nil {
		log.Fatalf("Error initializing Akamai Edgegrid config: %s", err.Error())
	}

	tstart := time.Now().UTC().Add(time.Minute * time.Duration(trafficReportInterval*-1)) // assume start time is Exporter launch less 5 mins
	if edgednsTrafficConfig.SummaryWindow != "" {
		err = calcSummaryWindowDuration(edgednsTrafficConfig.SummaryWindow)
		if err == nil {
			tstart = time.Now().UTC().Add(lookbackDuration * -1)
		} else {
			log.Warnf("Retention window is not valid. Using default (%d days)", lookbackDefaultDays)
		}
	} else {
		log.Warnf("Retention window is not configured. Using default (%d days)", lookbackDefaultDays)
	}
	// TODO: DO we want to expose start time or only lookback window?
	/*
		if len(*start) > 0 && len(*start_time) > 0 {
			serr := validateTrafficDate(*start)
			sterr := validateTrafficTime(*start_time)
			if serr != nil {
				log.Warnf("start validation failed: %s. Using current date and time", err.Error())
			} else if sterr != nil {
				log.Warnf("start_time validation failed: %s. Using current date and time", err.Error())
			} else {
				s := *start
				st := *start_time
				yr, _ := strconv.Atoi(s[0:4])
				mn, _ := strconv.Atoi(s[4:6])
				dy, _ := strconv.Atoi(s[6:8])
				hr, _ := strconv.Atoi(st[0:2])
				mm, _ := strconv.Atoi(st[3:5])
				tstart = time.Date(
					yr,
					time.Month(mn),
					dy,
					hr,
					mm,
					0,
					0,
					time.UTC)
			}
		}
	*/

	log.Infof("Edge DNS Traffic exporter start time: %v", tstart)

	// Populate LastTimestamp per Zone. Start time applies to all.
	lastTimeStamp := make(map[string]time.Time) // index by zone name
	for _, zone := range edgednsTrafficConfig.Zones {
		lastTimeStamp[zone] = tstart
	}

	// Create/register collector
	edgednsTrafficCollector := NewEdgednsTrafficExporter(edgednsTrafficConfig, lastTimeStamp)
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
		w.Write([]byte(`<html>
			<head><title>akamai_edgedns_traffic_exporter</title></head>
			<body>
			<h1>akamai_edgedns_traffic_exporter</h1>
			<p><a href="/metrics">Metrics</a></p>
			</body>
			</html>`))
	})

	log.Info("Beginning to serve on address ", *listenAddress)
	log.Fatal(http.ListenAndServe(*listenAddress, nil))

}

func loadConfig(configFile string) (EdgednsTrafficConfig, error) {
	if fileExists(configFile) {
		// Load config from file
		configData, err := ioutil.ReadFile(configFile)
		if err != nil {
			return EdgednsTrafficConfig{}, err
		}

		return loadConfigContent(configData)
	}

	log.Infof("Config file %v does not exist, using default values", configFile)
	return EdgednsTrafficConfig{}, nil

}

func loadConfigContent(configData []byte) (EdgednsTrafficConfig, error) {
	config := EdgednsTrafficConfig{}
	err := yaml.Unmarshal(configData, &config)
	if err != nil {
		return config, err
	}

	log.Info("akamai_edgedns_traffic_exporter config loaded")
	return config, nil
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}
