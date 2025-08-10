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

	dns "github.com/akamai/AkamaiOPEN-edgegrid-golang/v11/pkg/dns"
	edgegrid "github.com/akamai/AkamaiOPEN-edgegrid-golang/v11/pkg/edgegrid"
	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v11/pkg/session"
)

const (
	TrafficRecordTimeOffsetFormat string = "01/02/2006 15:04 GMT-0700"
	TrafficRecordTimeFormat       string = "01/02/2006 15:04 GMT"
)

var (
	// edgegridConfig contains the Akamai OPEN Edgegrid API credentials for automatic signing of requests
	//edgegridConfig edgegrid.Config = edgegrid.Config{}
	// testflag is used for test automation only
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
}

// Traffic Report Query args struct
/*type TrafficReportQueryArgs struct {
	// required
	End       string `json:"end"`        // yyyymmdd format
	EndTime   string `json:"end_time"`   // HH:mm format
	Start     string `json:"start"`      // yyyymmdd format
	StartTime string `json:"start_time"` // HH:mm format
	// optional
	IncludeEstimates bool   `json:"include_estimates"`
	TimeZone         string `json:"time_zone,omitempty"` //
}*/

type TrafficReportQueryArgs struct {
	StartTime        time.Time `json:"start_time"` // RFC3339 / ISO 8601
	EndTime          time.Time `json:"end_time"`   // RFC3339 / ISO 8601
	IncludeEstimates bool      `json:"include_estimates,omitempty"`
	TimeZone         string    `json:"time_zone,omitempty"`
	Interval         Interval  `json:"interval,omitempty"`
}

type TrafficRecordsResponse [][]string

type TrafficRecord struct {
	Timestamp time.Time
	DNSHits   int64
	NXDHits   int64
}

type TrafficRecordList struct {
	TrafficRecords []TrafficRecord
}

// Init edgegrid Config
func EdgegridInit(edgercpath, section string) (*edgegrid.Config, error) {

	config, err := edgegrid.New(
		edgegrid.WithFile(edgercpath),
		edgegrid.WithSection(section),
	)
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

// validate date in form yyyymmdd and < current date
/*func validateTrafficDate(tdate string) error {
	if len(tdate) != 8 {
		return fmt.Errorf("date %s is invalid", tdate)
	}
	_, err := time.Parse("20060102", tdate)
	return err
}*/

func validateTrafficDate(tdate string) error {
	if len(tdate) != 8 {
		return fmt.Errorf("date %s is invalid length", tdate)
	}

	parsedDate, err := time.Parse("20060102", tdate)
	if err != nil {
		return fmt.Errorf("date %s is invalid format", tdate)
	}

	// Compare with current date (ignore time)
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

// Create QueryArgs from provided start and end time
/*func CreateQueryArgs(startTime, endTime time.Time) *TrafficReportQueryArgs {
	e := endTime.UTC().Format(time.RFC3339)
	s := startTime.UTC().Format(time.RFC3339)

	partsE := strings.Split(e, "T")
	end := strings.ReplaceAll(partsE[0], "-", "")
	endtime := partsE[1][:5]

	partsS := strings.Split(s, "T")
	start := strings.ReplaceAll(partsS[0], "-", "")
	starttime := partsS[1][:5]

	return NewTrafficReportQueryArgs(end, endtime, start, starttime)
}*/

func CreateQueryArgs(startTime, endTime time.Time) *TrafficReportQueryArgs {
	interval := FIVE_MINUTES // You can make this dynamic if needed

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

func safeParseInt(s string) (int64, error) {
	if s == "N/A" || s == "" {
		return 0, nil
	}
	return strconv.ParseInt(s, 10, 64)
}

// Convert TrafficRecord object to string slice
/*func ConvertTrafficRecordSlice(trslice []string) (TrafficRecord, error) {
	trafficRecord := TrafficRecord{}
	if len(trslice) < 3 {
		return trafficRecord, fmt.Errorf("invalid record length")
	}
	ts, err := ConvertTrafficIntervalTime(trslice[0])
	if err != nil {
		return trafficRecord, err
	}
	dnsHits, err := strconv.ParseInt(trslice[1], 10, 64)
	if err != nil {
		return trafficRecord, err
	}
	nxdHits, err := strconv.ParseInt(trslice[2], 10, 64)
	if err != nil {
		return trafficRecord, err
	}
	return TrafficRecord{Timestamp: ts, DNSHits: dnsHits, NXDHits: nxdHits}, nil
}*/

func ConvertTrafficRecordSlice(trslice []string) (TrafficRecord, error) {
	trafficRecord := TrafficRecord{}
	if len(trslice) < 3 {
		return trafficRecord, fmt.Errorf("invalid record length")
	}
	ts, err := ConvertTrafficIntervalTime(trslice[0])
	if err != nil {
		return trafficRecord, err
	}
	dnsHits, err := safeParseInt(trslice[1])
	if err != nil {
		return trafficRecord, err
	}
	nxdHits, err := safeParseInt(trslice[2])
	if err != nil {
		return trafficRecord, err
	}
	return TrafficRecord{Timestamp: ts, DNSHits: dnsHits, NXDHits: nxdHits}, nil
}

func ConvertTrafficRecordsResponse(recordsresp TrafficRecordsResponse) TrafficRecordList {
	trafficRecordList := TrafficRecordList{}
	for i, rec := range recordsresp {
		if i == 0 {
			continue
		}
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

// GetTrafficReport retrieves and returns a zone traffic report slice of slices with provided query filters
// See https://developer.akamai.com/api/cloud_security/edge_dns_traffic_reporting/v1.html#gettrafficreport for detail
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
	req, err := http.NewRequest(http.MethodGet, baseURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	/*q := req.URL.Query()
	q.Add("end", trafficReportQueryArgs.End)
	q.Add("end_time", trafficReportQueryArgs.EndTime)
	q.Add("start", trafficReportQueryArgs.Start)
	q.Add("start_time", trafficReportQueryArgs.StartTime)
	q.Add("include_estimates", strconv.FormatBool(trafficReportQueryArgs.IncludeEstimates))
	if trafficReportQueryArgs.TimeZone != "" {
		q.Add("time_zone", trafficReportQueryArgs.TimeZone)
	}
	req.URL.RawQuery = q.Encode()*/

	q := req.URL.Query()
	// Or better, pass full RFC3339 timestamps:
	q.Add("start", trafficReportQueryArgs.StartTime.Format(time.RFC3339))
	q.Add("end", trafficReportQueryArgs.EndTime.Format(time.RFC3339))

	q.Add("interval", string(trafficReportQueryArgs.Interval))
	q.Add("objectIds", zone)
	//q.Add("metrics", "sum_hits,sum_nxdomain")

	req.URL.RawQuery = q.Encode()

	req.Header.Add("Accept", "text/csv")

	resp, err := sess.Exec(req, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	// Read full response body bytes for logging
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	log.Printf("HTTP Response Status: %s", resp.Status)
	log.Println("=== RAW RESPONSE BODY ===")
	log.Println(prettyPrintJSON(bodyBytes))
	log.Println("=== END RAW RESPONSE BODY ===")

	bodyReader := bytes.NewReader(bodyBytes)
	scanner := bufio.NewScanner(bodyReader)

	// Parse the CSV response (skip metadata/summary blocks)
	/*r := csv.NewReader(resp.Body)
	lines, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("failed to read CSV response: %w", err)
	}
	// Extract only actual data rows between #DATA_START and #DATA_END
	var dataRows [][]string
	inDataBlock := false

	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		switch strings.TrimSpace(line[0]) {
		case "#DATA_START":
			inDataBlock = true
		case "#DATA_END":
			inDataBlock = false
		default:
			if inDataBlock {
				dataRows = append(dataRows, line)
			}
		}
	}

	if len(dataRows) == 0 {
		return nil, fmt.Errorf("no traffic data found for zone: %s", zone)
	}

	return TrafficRecordsResponse(dataRows), nil*/
	// Read response line-by-line, skipping metadata and extracting CSV data only
	//scanner := bufio.NewScanner(resp.Body)

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
	/* //debug
	log.Println("=== RAW CSV RESPONSE LINES ===")
	for _, line := range csvLines {
		log.Println(line)
	}
	log.Println("=== END RAW CSV RESPONSE ===")*/

	// Parse only the CSV lines collected
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
