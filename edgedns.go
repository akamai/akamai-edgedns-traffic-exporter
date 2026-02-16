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
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	dns "github.com/akamai/AkamaiOPEN-edgegrid-golang/v12/pkg/dns"
	edgegrid "github.com/akamai/AkamaiOPEN-edgegrid-golang/v12/pkg/edgegrid"
	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v12/pkg/session"
)

const (
	TrafficRecordTimeOffsetFormat string = "01/02/2006 15:04 GMT-0700"
	TrafficRecordTimeFormat       string = "01/02/2006 15:04 GMT"
)

var (
	testflag bool = false
)

type Interval string

const (
	FIVE_MINUTES Interval = "FIVE_MINUTES"
	HOUR         Interval = "HOUR"
)

type AkamaiClient struct {
	DNSClient dns.DNS
	Session   session.Session
	UseLegacy bool
}

type TrafficReportQueryArgs struct {
	StartTime        time.Time `json:"start_time"` // RFC3339 / ISO 8601
	EndTime          time.Time `json:"end_time"`   // RFC3339 / ISO 8601
	IncludeEstimates bool      `json:"include_estimates,omitempty"`
	TimeZone         string    `json:"time_zone,omitempty"`
	Interval         Interval  `json:"interval,omitempty"`
}

type TrafficReportQueryArgs_Legacy struct {
	End              string `json:"end"`        // yyyymmdd
	EndTime          string `json:"end_time"`   // HH:mm
	Start            string `json:"start"`      // yyyymmdd
	StartTime        string `json:"start_time"` // HH:mm
	IncludeEstimates bool   `json:"include_estimates"`
	TimeZone         string `json:"time_zone,omitempty"`
}

type TrafficRecordsResponse [][]string

type TrafficRecord struct {
	Timestamp   time.Time
	DNSHits     float64
	NXDHits     float64
	SumRequests float64
}

type TrafficRecordList struct {
	TrafficRecords []TrafficRecord
}

// Init edgegrid Config
func EdgegridInit(edgercpath, section string) (*edgegrid.Config, error) {
	options := []edgegrid.Option{
		edgegrid.WithEnv(true),
	}
	if edgercpath != "" {
		options = append(options, edgegrid.WithFile(edgercpath))
	}
	if section != "" {
		options = append(options, edgegrid.WithSection(section))
	}

	config, err := edgegrid.New(options...)
	if err != nil {
		return nil, fmt.Errorf("edgegrid initialization failed. Error: %s", err.Error())
	}

	return config, nil
}

// CreateDNSClient creates a DNS client from Edgegrid config and returns it
func CreateDNSClient(config *edgegrid.Config) (dns.DNS, session.Session, error) {
	sess, err := session.New(
		session.WithSigner(config),
		session.WithHTTPTracing(false),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create EdgeGrid session: %w", err)
	}

	return dns.Client(sess), sess, nil
}

func validateTrafficDate(tdate string) error {
	if len(tdate) != 8 {
		return fmt.Errorf("date %s is invalid length", tdate)
	}

	parsedDate, err := time.Parse("20060102", tdate)
	if err != nil {
		return fmt.Errorf("date %s is invalid format", tdate)
	}
	now := time.Now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())

	if !parsedDate.Before(today) {
		return fmt.Errorf("date %s is not before today", tdate)
	}

	return nil
}

// validate time is of format hh:mm and within valid range.
func validateTrafficTime(ttime string) error {
	tt := strings.Split(ttime, ":")
	if len(tt) != 2 {
		return fmt.Errorf("time %s is invalid", ttime)
	}
	hr, err1 := strconv.Atoi(tt[0])
	min, err2 := strconv.Atoi(tt[1])
	if err1 != nil || err2 != nil || hr < 0 || hr > 23 || min < 0 || min > 59 {
		return fmt.Errorf("time %s is invalid", ttime)
	}
	return nil
}

// ValidateZone checks if zone exists using the dns client
func ValidateZone(ctx context.Context, client dns.DNS, zone string) error {

	if testflag {
		return nil
	}

	if client == nil {
		return fmt.Errorf("dnsClient is not initialized")
	}

	_, err := client.GetZone(ctx, dns.GetZoneRequest{Zone: zone})
	return err
}

// Create and return new TrafficReportQueryArgs object
func NewTrafficReportQueryArgs(start, end time.Time) *TrafficReportQueryArgs {
	return &TrafficReportQueryArgs{
		StartTime: start.UTC(),
		EndTime:   end.UTC(),
	}
}

func NewTrafficReportQueryArgs_Legacy(end, endtime, start, starttime string) *TrafficReportQueryArgs_Legacy {
	return &TrafficReportQueryArgs_Legacy{
		End:       end,
		EndTime:   endtime,
		Start:     start,
		StartTime: starttime,
	}
}

func CreateQueryArgs(startTime, endTime time.Time) *TrafficReportQueryArgs {
	interval := FIVE_MINUTES

	now := time.Now().UTC()

	// Ensure endTime doesn't go into the future
	if endTime.After(now) {
		endTime = now
	}

	// Ensure startTime doesn't go after (adjusted) endTime
	if startTime.After(endTime) {
		startTime = endTime.Add(-5 * time.Minute) // Shift start back 1 interval
	}

	startRounded := floorToInterval(startTime.UTC(), interval)
	endRounded := ceilToInterval(endTime.UTC(), interval)

	return &TrafficReportQueryArgs{
		StartTime: startRounded,
		EndTime:   endRounded,
		Interval:  interval,
	}
}

func CreateQueryArgs_Legacy(startTime, endTime time.Time) *TrafficReportQueryArgs_Legacy {
	start := startTime.UTC().Format("20060102")
	startTimeStr := startTime.UTC().Format("15:04")
	end := endTime.UTC().Format("20060102")
	endTimeStr := endTime.UTC().Format("15:04")
	return NewTrafficReportQueryArgs_Legacy(end, endTimeStr, start, startTimeStr)
}

// Util function to convert traffic interval time/date to time.Time object
func ConvertTrafficIntervalTime(intervaltime string) (time.Time, error) {
	if ts, err := time.Parse(time.RFC3339, intervaltime); err == nil {
		return ts, nil
	}
	if ts, err := time.Parse(TrafficRecordTimeFormat, intervaltime); err == nil {
		return ts, nil
	}
	if ts, err := time.Parse(TrafficRecordTimeOffsetFormat, intervaltime); err == nil {
		return ts, nil
	}
	return time.Time{}, fmt.Errorf("invalid time format: %s", intervaltime)
}

func safeParseFloat(s string) (float64, error) {
	if s == "N/A" || s == "" {
		return 0, nil
	}
	return strconv.ParseFloat(s, 64)
}

func ConvertTrafficRecordSlice(trslice []string) (TrafficRecord, error) {
	trafficRecord := TrafficRecord{}
	if len(trslice) < 3 {
		return trafficRecord, fmt.Errorf("invalid record length: %v", trslice)
	}
	ts, err := ConvertTrafficIntervalTime(trslice[0])
	if err != nil {
		return trafficRecord, err
	}
	dnsHits, err := safeParseFloat(trslice[1])
	if err != nil {
		return trafficRecord, err
	}
	nxdHits, err := safeParseFloat(trslice[2])
	if err != nil {
		return trafficRecord, err
	}

	trafficRecord.Timestamp = ts
	trafficRecord.DNSHits = dnsHits
	trafficRecord.NXDHits = nxdHits

	// Only attempt to parse SumRequests if the 4th column exists (New API)
	if len(trslice) >= 4 {
		sumReqs, err := safeParseFloat(trslice[3])
		if err != nil {
			return trafficRecord, err
		}
		trafficRecord.SumRequests = sumReqs
	}
	return trafficRecord, nil
}

func ConvertTrafficRecordsResponse(recordsresp TrafficRecordsResponse) TrafficRecordList {
	trafficRecordList := TrafficRecordList{}
	for _, rec := range recordsresp {
		tr, err := ConvertTrafficRecordSlice(rec)
		if err != nil {
			continue
		}
		trafficRecordList.TrafficRecords = append(trafficRecordList.TrafficRecords, tr)
	}
	return trafficRecordList
}

func prettyPrintJSON(raw []byte) string {
	var prettyJSON bytes.Buffer
	err := json.Indent(&prettyJSON, raw, "", "  ")
	if err != nil {
		return string(raw)
	}
	return prettyJSON.String()
}

// Rounds DOWN to the nearest interval boundary (e.g., 10:07 → 10:05)
func floorToInterval(t time.Time, interval Interval) time.Time {
	switch interval {
	case FIVE_MINUTES:
		return t.Truncate(5 * time.Minute)
	case HOUR:
		return t.Truncate(time.Hour)
	default:
		log.Printf("Unsupported interval: %s", interval)
		return t
	}
}

// Rounds UP to the next interval boundary (e.g., 10:07 → 10:10)
func ceilToInterval(t time.Time, interval Interval) time.Time {
	switch interval {
	case FIVE_MINUTES:
		if t.Truncate(5 * time.Minute).Equal(t) {
			return t
		}
		return t.Truncate(5 * time.Minute).Add(5 * time.Minute)
	case HOUR:
		if t.Truncate(time.Hour).Equal(t) {
			return t
		}
		return t.Truncate(time.Hour).Add(time.Hour)
	default:
		log.Printf("Unsupported interval: %s", interval)
		return t
	}
}

func GetTrafficReport(ctx context.Context, client dns.DNS, sess session.Session, zone string, trafficReportQueryArgs *TrafficReportQueryArgs) (TrafficRecordsResponse, error) {
	if client == nil {
		return nil, fmt.Errorf("dnsClient not initialized")
	}

	if err := ValidateZone(ctx, client, zone); err != nil {
		return nil, fmt.Errorf("zone not reachable: %w", err)
	}

	if trafficReportQueryArgs.StartTime.IsZero() || trafficReportQueryArgs.EndTime.IsZero() {
		return nil, fmt.Errorf("start_time or end_time is not set")
	}

	// construct GET url
	// Build the new API URL
	baseURL := "/reporting-api/v1/reports/authoritative-dns-traffic-by-time/versions/3/report-data"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	q := req.URL.Query()
	// Or better, pass full RFC3339 timestamps:
	q.Add("start", trafficReportQueryArgs.StartTime.Format(time.RFC3339))
	q.Add("end", trafficReportQueryArgs.EndTime.Format(time.RFC3339))

	q.Add("interval", string(trafficReportQueryArgs.Interval))
	q.Add("objectIds", zone)
	q.Add("metrics", "sum_hits,sum_nxdomain,sum_requests,total_hits,total_nxhits,peak_hits,peak_nxhits")

	req.URL.RawQuery = q.Encode()

	req.Header.Add("Accept", "text/csv")

	resp, err := sess.Exec(req, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Read full response body bytes for logging
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	logrus.Debugf("HTTP Response Status: %s", resp.Status)
	logrus.Debugf("=== RAW RESPONSE BODY ===")
	if strings.Contains(resp.Header.Get("Content-Type"), "application/json") {
		logrus.Debug(prettyPrintJSON(bodyBytes))
	} else {
		logrus.Debugf("Raw CSV Data: %d bytes received", len(bodyBytes))
	}
	logrus.Debugf("=== END RAW RESPONSE BODY ===")

	bodyReader := bytes.NewReader(bodyBytes)
	scanner := bufio.NewScanner(bodyReader)

	var csvLines []string
	inCSV := false
	for scanner.Scan() {
		line := scanner.Text()
		switch line {
		case "#COLUMNS_START", "#DATA_START":
			inCSV = true
			continue
		case "#COLUMNS_END", "#DATA_END":
			inCSV = false
			continue
		}

		if inCSV {
			csvLines = append(csvLines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to scan response body: %w", err)
	}

	if len(csvLines) == 0 {
		return nil, fmt.Errorf("no CSV data found in response")
	}
	csvReader := csv.NewReader(strings.NewReader(strings.Join(csvLines, "\n")))
	records, err := csvReader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSV data: %w", err)
	}

	if len(records) < 2 {
		return nil, fmt.Errorf("not enough CSV rows")
	}

	// Skip header, return data rows only
	dataRows := records[1:]

	if len(dataRows) == 0 {
		return nil, fmt.Errorf("no traffic data rows found")
	}

	return TrafficRecordsResponse(dataRows), nil

}

func GetTrafficReport_Legacy(ctx context.Context, client dns.DNS, sess session.Session, zone string, trafficReportQueryArgs_Legacy *TrafficReportQueryArgs_Legacy) (TrafficRecordsResponse, error) {
	if client == nil {
		return nil, fmt.Errorf("dnsClient not initialized")
	}

	if err := ValidateZone(ctx, client, zone); err != nil {
		return nil, fmt.Errorf("zone not reachable: %w", err)
	}

	if trafficReportQueryArgs_Legacy.StartTime == "" || trafficReportQueryArgs_Legacy.EndTime == "" {
		return nil, fmt.Errorf("start_time or end_time is not set")
	}

	baseURL := fmt.Sprintf("/data-dns/v1/traffic/%s", zone)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	q := req.URL.Query()
	q.Add("end", trafficReportQueryArgs_Legacy.End)
	q.Add("end_time", trafficReportQueryArgs_Legacy.EndTime)
	q.Add("start", trafficReportQueryArgs_Legacy.Start)
	q.Add("start_time", trafficReportQueryArgs_Legacy.StartTime)
	q.Add("include_estimates", strconv.FormatBool(trafficReportQueryArgs_Legacy.IncludeEstimates))
	req.URL.RawQuery = q.Encode()

	req.Header.Add("Accept", "text/csv")

	resp, err := sess.Exec(req, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("akamai legacy api returned status %d", resp.StatusCode)
	}

	r := csv.NewReader(resp.Body)
	records, err := r.ReadAll()
	if err != nil {
		return nil, err
	}

	return TrafficRecordsResponse(records[1:]), nil

}
