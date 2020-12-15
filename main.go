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

	"gopkg.in/yaml.v2"
	"io/ioutil"
	"net/http"
	"os"
	"sort"
	"strconv"
	"time"
)

const (
	defaultlistenaddress = ":9999"
	namespace            = "edgedns_traffic"
)

var (
	configFile    = kingpin.Flag("config.file", "Edge DNS Traffic exporter configuration file.").Default("edgedns.yml").String()
	listenAddress = kingpin.Flag("web.listen-address", "The address to listen on for HTTP requests.").Default(defaultlistenaddress).String()
	listZones     = kingpin.Flag("list.zones", "List available Edge DNS zones and exit.").Bool()
	//zone			= kingpin.Flag("edgedns.zone", "The Edge DNS zone to retrieve traffic reports from.").String()
	start                  = kingpin.Flag("edgedns.start", "The start date <yyyymmdd> for the traffic reports.").String()
	start_time             = kingpin.Flag("edgedns.start-time", "The start time <hh:mm> for the traffic reports.").String()
	edgegrid_host          = kingpin.Flag("edgedns.edgegrid-host", "The Akamai Edgegrid host auth credential.").String()
	edgegrid_client_secret = kingpin.Flag("edgedns.edgegrid-client-secret", "The Akamai Edgegrid client_secret credential.").String()
	edgegrid_client_token  = kingpin.Flag("edgedns.edgegrid-client-token", "The Akamai Edgegrid client_token credential.").String()
	edgegrid_access_token  = kingpin.Flag("edgedns.edgegrid-access-token", "The Akamai Edgegrid access_token credential.").String()
	//end		        = kingpin.Flag("edgedns.end", "The end date <yyyymmdd> for the traffic reports.").String()
	//end_time		= kingpin.Flag("edgedns.end-time", "The end time <hh:mm> for the traffic reports.").String()
	//include_estimates	= kingpin.Flag("edgedns.end-time", "Flag to include estimates in traffic reports.").Bool()
	//time_zone		= kingpin.Flag("edgedns.time-zone", "The timezone to use for start and end time.").String()

	// invalidMetricChars    = regexp.MustCompile("[^a-zA-Z0-9_:]")
	edgednsErrorDesc = prometheus.NewDesc("akamai_edgedns_traffic__error", "Error collecting metrics", nil, nil)
)

// Exporter config
type EdgednsTrafficConfig struct {
	Zones           []string `yaml:"zones"`
	EdgercPath      string   `yaml:"edgerc_path"`
	EdgercSection   string   `yaml:"edgerc_section"`
	Retentionwindow string   `yaml:"retention_window"`
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
/*
var dnsHitsMetric = prometheus.NewGauge(prometheus.GaugeOpts{
        Name: "dns_hits_per_interval", Help: "Number of DNS hits per 5 minute interval (per zone)"})
var nxdomainHitsMetric = prometheus.NewGauge(prometheus.GaugeOpts{
        Name: "nxdomain_hits_per_interval", Help: "Number of NXDomain hits per 5 minute interval (per zone)"})
*/
var dnsHitsMetric = prometheus.NewDesc(prometheus.BuildFQName(namespace, "", "dns_hits_per_interval"), "Number of DNS hits per 5 minute interval (per zone)", []string{"zone"}, nil)
var nxdomainHitsMetric = prometheus.NewDesc(prometheus.BuildFQName(namespace, "", "nxdomain_hits_per_interval"), "Number of NXDomain hits per 5 minute interval (per zone)", []string{"zone"}, nil)

// Describe finction
func (e *EdgednsTrafficExporter) Describe(ch chan<- *prometheus.Desc) {

	ch <- dnsHitsMetric
	ch <- nxdomainHitsMetric

}

func (e *EdgednsTrafficExporter) Collect(ch chan<- prometheus.Metric) {

	endtime := time.Now() // Use same current time for all zones
	// Collect metrics for each zone
	for _, zone := range e.TrafficExporterConfig.Zones {
		// get last timestamp recorded
		lasttime := e.LastTimestamp[zone].Add(time.Minute * 1)
		qargs := CreateQueryArgs(lasttime, endtime)

		log.Infof("Fetching Report for zone %s. Args: [%v}", zone, qargs)

		zoneTrafficReport, err := GetTrafficReport(zone, qargs)
		if err != nil {
			log.Errorf("Unable to get traffic report for zone %s ... Skipping. Error: %s", zone, err.Error())
			continue
		}
		reportList := ConvertTrafficRecordsResponse(zoneTrafficReport)
		sort.Slice(reportList.TrafficRecords[:], func(i, j int) bool {
			return reportList.TrafficRecords[i].Timestamp.Before(reportList.TrafficRecords[j].Timestamp)
		})

		log.Infof("List Length: %d", len(reportList.TrafficRecords))
		log.Infof("Traffic data: [%v]", reportList.TrafficRecords)

		for _, reportInstance := range reportList.TrafficRecords {
			// TODO: Worry about overwriting existing? Catch error minimally.

			//TODO: Fill in gaps with average?

			// create metics
			dnsmetric := prometheus.MustNewConstMetric(dnsHitsMetric, prometheus.GaugeValue, float64(reportInstance.DNSHits), zone)
			nxdmetric := prometheus.MustNewConstMetric(nxdomainHitsMetric, prometheus.GaugeValue, float64(reportInstance.NXDHits), zone)
			// Save with timestamp
			ch <- prometheus.NewMetricWithTimestamp(reportInstance.Timestamp, dnsmetric)
			ch <- prometheus.NewMetricWithTimestamp(reportInstance.Timestamp, nxdmetric)

			// Update last timestamp processed
			if reportInstance.Timestamp.After(e.LastTimestamp[zone]) {
				e.LastTimestamp[zone] = reportInstance.Timestamp
			}
		}
		// Set Last Interval timestamp retrieved
		//e.LastTimestamp[zone] = reportList.TrafficRecords[len(reportList.TrafficRecords)-1].Timestamp
	}
}

func init() {
	prometheus.MustRegister(version.NewCollector("akamai_edgedns_traffic_exporter"))
}

func main() {

	kingpin.Version(version.Print("akamai_edgedns_traffic_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	log.Infof("Config file: %s", *configFile)
	log.Infof("Start: %s", *start)
	log.Infof("Start Time: %s", *start_time)

	log.Info("Starting Edge DNS Traffic exporter", version.Info())
	log.Info("Build context", version.BuildContext())

	edgednsTrafficConfig, err := loadConfig(*configFile) // save?
	if err != nil {
		log.Fatalf("Error loading akamai_edgedns_traffic_exporter config file: %v", err)
	}

	// TODO: Change to debug
	log.Infof("Exporter configuration: [%v]", edgednsTrafficConfig)

	// TODO: Check for and use command line auth keys if present
	// Edgegrid will also check for environment variables ...
	err = EdgegridInit(edgednsTrafficConfig.EdgercPath, edgednsTrafficConfig.EdgercSection)
	if err != nil {
		log.Fatalf("Error initializing Akamai Edgegrid config: %s", err.Error())
	}

	// TODO: Change to debug
	log.Infof("Edgegrid config: [%v]", edgegridConfig)

	// TODO: process List Zones?

	tstart := time.Now() // assume start time is Exporter launch
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
	log.Debugf("Edge DNS Traffic exporter start time: %v", tstart)

	// Calculate start time based on command line args ... inc timezone
	// TODO: expose and apply timezone. convert to UTC
	// TODO: If start time provided ... need to worry about dups!

	// Populate LastTimestamp per Zone. Start time applies to all.
	lastTimeStamp := make(map[string]time.Time) // index by zone name
	for _, zone := range edgednsTrafficConfig.Zones {
		lastTimeStamp[zone] = tstart
	}

	edgednsTrafficCollector := NewEdgednsTrafficExporter(edgednsTrafficConfig, lastTimeStamp)
	prometheus.MustRegister(edgednsTrafficCollector)

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
		//log.Infof("Loading akamai_edgedns_traffic_exporter config file %v", configFile)

		// Load config from file
		configData, err := ioutil.ReadFile(configFile)
		if err != nil {
			return EdgednsTrafficConfig{}, err
		}

		return loadConfigContent(configData)
	}

	//log.Infof("Config file %v does not exist, using default values", configFile)
	return EdgednsTrafficConfig{}, nil

}

func loadConfigContent(configData []byte) (EdgednsTrafficConfig, error) {
	config := EdgednsTrafficConfig{}
	var err error

	err = yaml.Unmarshal(configData, &config)
	if err != nil {
		return config, err
	}

	//log.Info("akamai_edgedns_traffic_exporter config loaded")
	return config, nil
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}
