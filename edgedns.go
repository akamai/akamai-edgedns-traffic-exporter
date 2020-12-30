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
	"encoding/csv"
	"fmt"
	"github.com/akamai/AkamaiOPEN-edgegrid-golang/client-v1"
	dns "github.com/akamai/AkamaiOPEN-edgegrid-golang/configdns-v2"
	edgegrid "github.com/akamai/AkamaiOPEN-edgegrid-golang/edgegrid"
	"strconv"
	"strings"
	"time"
)

const (
	TrafficRecordTimeOffsetFormat string = "01/02/2006 15:04 GMT-0700"
	TrafficRecordTimeFormat       string = "01/02/2006 15:04 GMT"
)

var (
	// edgegridConfig contains the Akamai OPEN Edgegrid API credentials for automatic signing of requests
	edgegridConfig edgegrid.Config = edgegrid.Config{}
	// testflag is used for test automation only
	testflag bool = false
)

// Traffic Report Query args struct
type TrafficReportQueryArgs struct {
	// required
	End       string `json:"end"`        // yyyymmdd format
	EndTime   string `json:"end_time"`   // HH:mm format
	Start     string `json:"start"`      // yyyymmdd format
	StartTime string `json:"start_time"` // HH:mm format
	// optional
	IncludeEstimates bool   `json:"include_estimates"`
	TimeZone         string `json:"time_zone,omitempty"` //
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
func EdgegridInit(edgercpath, section string) error {

	config, err := edgegrid.Init(edgercpath, section)
	if err != nil {
		return fmt.Errorf("Edgegrid initialization failed. Error: %s", err.Error())
	}

	return edgeInit(config)
}

// Finish edgegrid init
func edgeInit(config edgegrid.Config) error {

	edgegridConfig = config
	dns.Init(config)

	return nil

}

// validate date in form yyyymmdd and < current date
func validateTrafficDate(tdate string) error {

	invalidDateErr := fmt.Errorf("Date %s is invalid", tdate)
	if len(tdate) != 8 {
		return invalidDateErr
	}
	currentTime := time.Now()
	tyear, err := strconv.Atoi(tdate[0:4])
	if err != nil {
		return invalidDateErr
	}
	tmonth, err := strconv.Atoi(tdate[4:6])
	if err != nil {
		return invalidDateErr
	}
	tday, err := strconv.Atoi(tdate[6:8])
	if err != nil {
		return invalidDateErr
	}

	if tyear > int(currentTime.Year()) {
		return fmt.Errorf("Date year %s is invalid", tdate)
	}
	if tmonth > 12 || (tyear == int(currentTime.Year()) && tmonth > int(currentTime.Month())) {
		return fmt.Errorf("Date month %s is invalid", tdate)
	}
	if tday > 31 || (tyear == int(currentTime.Year()) && tmonth == int(currentTime.Month()) && tday > int(currentTime.Day())) {
		return fmt.Errorf("Date day %s is invalid", tdate)
	}

	return nil
}

// validate time is of format hh:mm and within valid range.
func validateTrafficTime(ttime string) error {

	invalidTimeErr := fmt.Errorf("Time %s is invalid", ttime)
	tt := strings.Split(ttime, ":")
	if len(tt) != 2 {
		return invalidTimeErr
	}
	thr, err := strconv.Atoi(tt[0])
	if err != nil || thr > 23 { //> int(t.Hour()) {
		return invalidTimeErr
	}
	tmin, err := strconv.Atoi(tt[1])
	if err != nil || tmin > 59 { //> int(t.Minute()) {
		return invalidTimeErr
	}

	return nil

}

// see if zone exists
func validateZone(zone string) error {

	// don't want to do GetZone if testing
	if testflag {
		return nil
	}
	if edgegridConfig.Host == "" {
		return fmt.Errorf("Edgegrid not initialized")
	}
	if _, err := dns.GetZone(zone); err != nil {
		return err
	}

	return nil
}

// Create and return new TrafficReportQueryArgs object
func NewTrafficReportQueryArgs(end, endtime, start, starttime string) *TrafficReportQueryArgs {
	trafficqueryargs := &TrafficReportQueryArgs{End: end, EndTime: endtime, Start: start, StartTime: starttime}
	return trafficqueryargs
}

// Create QueryArgs from provided start and end time
func CreateQueryArgs(startTime, endTime time.Time) *TrafficReportQueryArgs {

	e := endTime.UTC().Format(time.RFC3339) // "2006-01-02T15:04:05Z07:00"
	parts := strings.Split(e, "T")
	end := strings.Join(strings.Split(parts[0], "-"), "")
	endtime := parts[1][0:5]
	s := startTime.UTC().Format(time.RFC3339) // "2006-01-02T15:04:05Z07:00"
	parts = strings.Split(s, "T")
	start := strings.Join(strings.Split(parts[0], "-"), "")
	starttime := parts[1][0:5]

	return NewTrafficReportQueryArgs(end, endtime, start, starttime)

}

//  Util function to convert traffic interval time/date to time.Time object
func ConvertTrafficIntervalTime(intervaltime string) (time.Time, error) {

	var ts time.Time
	var err error
	if strings.HasSuffix(intervaltime, "GMT") {
		ts, err = time.Parse(TrafficRecordTimeFormat, intervaltime)
	} else {
		ts, err = time.Parse(TrafficRecordTimeOffsetFormat, intervaltime)
	}

	return ts, err

}

// Convert TrafficRecord object to string slice
func ConvertTrafficRecordSlice(trslice []string) (TrafficRecord, error) {

	trafficRecord := TrafficRecord{}
	if len(trslice) < 3 {
		return trafficRecord, fmt.Errorf("Traffic record %s length is invalid", trslice)
	}
	ts, err := ConvertTrafficIntervalTime(trslice[0])
	if err != nil {
		return trafficRecord, fmt.Errorf("Traffic record timestamp %s is invalid", trslice)
	}
	dnsHits, err := strconv.ParseInt(trslice[1], 10, 64)
	if err != nil {
		return trafficRecord, fmt.Errorf("Traffic record DNS Hits %s is invalid", trslice)
	}
	nxdHits, err := strconv.ParseInt(trslice[2], 10, 64)
	if err != nil {
		return trafficRecord, fmt.Errorf("Traffic record NXD Hits %s is invalid", trslice)
	}
	trafficRecord.Timestamp = ts
	trafficRecord.DNSHits = dnsHits
	trafficRecord.NXDHits = nxdHits

	return trafficRecord, nil
}

func ConvertTrafficRecordsResponse(recordsresp TrafficRecordsResponse) TrafficRecordList {

	trafficRecordSlices := make([]TrafficRecord, 0)
	trafficRecordList := TrafficRecordList{TrafficRecords: trafficRecordSlices}
	for i, rec := range recordsresp {
		if i == 0 {
			continue // first line is header
		}
		newrec, err := ConvertTrafficRecordSlice(rec)
		if err != nil {
			// log
			continue
		}
		trafficRecordSlices = append(trafficRecordSlices, newrec)
	}
	trafficRecordList.TrafficRecords = trafficRecordSlices
	return trafficRecordList
}

// GetTrafficReport retrieves and returns a zone traffic report slice of slices with provided query filters
// See https://developer.akamai.com/api/cloud_security/edge_dns_traffic_reporting/v1.html#gettrafficreport for detail
// Example: /data-dns/v1/traffic/example.com?start=20131231&start_time=00:30&end=20140101&end_time=14:30&end_time&time_zone=example.com=GMT–08%3A00&include_estimates=false
func GetTrafficReport(zone string, trafficReportQueryArgs *TrafficReportQueryArgs) (TrafficRecordsResponse, error) {

	if err := validateZone(zone); err != nil {
		return nil, fmt.Errorf("GetTrafficReport Zone not reachable. %s", err.Error())
	}

	// construct GET url
	getURL := fmt.Sprintf("/data-dns/v1/traffic/%s", zone)
	if trafficReportQueryArgs.End == "" || trafficReportQueryArgs.Start == "" || trafficReportQueryArgs.EndTime == "" || trafficReportQueryArgs.StartTime == "" {
		return nil, fmt.Errorf("Required GetTrafficReport Query Args missing")
	}
	req, err := client.NewRequest(
		edgegridConfig,
		"GET",
		getURL,
		nil,
	)
	if err != nil {
		return TrafficRecordsResponse{}, err
	}
	req.Header.Add("Accept", "text/csv")

	q := req.URL.Query()
	q.Add("end", trafficReportQueryArgs.End)
	q.Add("end_time", trafficReportQueryArgs.EndTime)
	q.Add("start", trafficReportQueryArgs.Start)
	q.Add("start_time", trafficReportQueryArgs.StartTime)
	q.Add("include_estimates", strconv.FormatBool(trafficReportQueryArgs.IncludeEstimates))
	if trafficReportQueryArgs.TimeZone != "" {
		q.Add("time_zone", trafficReportQueryArgs.TimeZone)
	}
	req.URL.RawQuery = q.Encode()

	edgegrid.PrintHttpRequest(req, true)

	res, err := client.Do(edgegridConfig, req)
	if err != nil {
		return TrafficRecordsResponse{}, err
	}

	edgegrid.PrintHttpResponse(res, true)

	if client.IsError(res) {
		return TrafficRecordsResponse{}, client.NewAPIError(res)
	}
	/*
		Returned body example:

		START DATE/TIME,ALL DNS HITS,NXDOMAIN HITS
		09/09/2013 00:00 GMT,9199,145
		09/09/2013 00:05 GMT,8035,25
		09/09/2013 00:10 GMT,7929,20
		09/09/2013 00:15 GMT,9433,157
	*/

	r := csv.NewReader(res.Body) // bodyBytes)
	tr, err := r.ReadAll()
	if err != nil {
		return TrafficRecordsResponse{}, err
	}
	var temp interface{} = tr
	var trafficRecords TrafficRecordsResponse = TrafficRecordsResponse(temp.([][]string))
	return trafficRecords, nil
}
