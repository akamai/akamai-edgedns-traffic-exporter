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
	"fmt"
	"time"

	//"github.com/akamai/AkamaiOPEN-edgegrid-golang/jsonhooks-v1"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/h2non/gock.v1"

	edgegrid "github.com/akamai/AkamaiOPEN-edgegrid-golang/v11/pkg/edgegrid"
)

var (
	config = edgegrid.Config{
		Host:         "akaa-baseurl-xxxxxxxxxxx-xxxxxxxxxxxxx.luna.akamaiapis.net/",
		AccessToken:  "akab-access-token-xxx-xxxxxxxxxxxxxxxx",
		ClientToken:  "akab-client-token-xxx-xxxxxxxxxxxxxxxx",
		ClientSecret: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=",
		MaxBody:      2048,
		Debug:        false,
	}
)

func TestValidateTrafficDate(t *testing.T) {

	testDate := "20201031"
	err := validateTrafficDate(testDate)
	assert.NoError(t, err)
}

func TestValidateTrafficDate_Fail(t *testing.T) {

	testDate := "year1231"
	err := validateTrafficDate(testDate)
	assert.Error(t, err)

}

func TestValidateTrafficDate_BadYear(t *testing.T) {

	testDate := "20301231"
	err := validateTrafficDate(testDate)
	assert.Error(t, err)

}

func TestValidateTrafficDate_BadDay(t *testing.T) {

	testDate := "20201240"
	err := validateTrafficDate(testDate)
	assert.Error(t, err)

}

func TestValidateTrafficTime(t *testing.T) {

	testTime := "13:01"
	err := validateTrafficTime(testTime)
	assert.NoError(t, err)

}

func TestValidateTrafficTime_Fail(t *testing.T) {

	testTime := "1301" // missing colon
	err := validateTrafficTime(testTime)
	assert.Error(t, err)

}

func TestValidateTrafficTime_BadHour(t *testing.T) {

	testTime := "30:01"
	err := validateTrafficTime(testTime)
	assert.Error(t, err)

}

func TestValidateTrafficTime_BadMin(t *testing.T) {

	testTime := "13:72" // missing colon
	err := validateTrafficTime(testTime)
	assert.Error(t, err)

}

func TestValidateZone(t *testing.T) {

	dnsTestZone := "testzone.com"

	defer gock.Off()

	mock := gock.New(fmt.Sprintf("https://akaa-baseurl-xxxxxxxxxxx-xxxxxxxxxxxxx.luna.akamaiapis.net/config-dns/v2/zones/%s", dnsTestZone))
	mock.
		Get(fmt.Sprintf("/config-dns/v2/zones/%s", dnsTestZone)).
		HeaderPresent("Authorization").
		Reply(200).
		SetHeader("Content-Type", "application/json;charset=UTF-8").
		BodyString(`{
    			"zone": "testzone.com",
    			"type": "PRIMARY",
    			"comment": "This is a test zone",
    			"signAndServe": false
		}`)

	ctx := context.Background()
	client, sess, _ := CreateDNSClient(&config)
	err := ValidateZone(ctx, client, dnsTestZone)
	assert.NoError(t, err)

	_ = sess

}

func TestValidateZone_Bad(t *testing.T) {

	dnsTestZone := "testzone.com"

	defer gock.Off()

	mock := gock.New(fmt.Sprintf("https://akaa-baseurl-xxxxxxxxxxx-xxxxxxxxxxxxx.luna.akamaiapis.net/config-dns/v2/zones/%s", dnsTestZone))
	mock.
		Get(fmt.Sprintf("/config-dns/v2/zones/%s", dnsTestZone)).
		HeaderPresent("Authorization").
		Reply(404).
		SetHeader("Content-Type", "application/json;charset=UTF-8").
		BodyString(`Not Found`)

	ctx := context.Background()
	client, sess, _ := CreateDNSClient(&config)
	err := ValidateZone(ctx, client, dnsTestZone)
	assert.Error(t, err)

	_ = sess

}

func TestNewTrafficReportQueryArgs(t *testing.T) {
	startTime, err1 := time.Parse(time.RFC3339, "2024-01-03T13:55:00Z")
	endTime, err2 := time.Parse(time.RFC3339, "2024-01-03T14:15:00Z")
	assert.NoError(t, err1)
	assert.NoError(t, err2)

	qa := NewTrafficReportQueryArgs(startTime, endTime)

	assert.Equal(t, startTime.UTC(), qa.StartTime)
	assert.Equal(t, endTime.UTC(), qa.EndTime)
}

func TestConvertTrafficRecordSlice(t *testing.T) {
	data := []string{"2013-09-09T00:00:00Z", "9199", "145"}
	record, err := ConvertTrafficRecordSlice(data)
	assert.NoError(t, err)
	assert.Equal(t, int64(145), record.NXDHits)
	assert.Equal(t, int64(9199), record.DNSHits)
}

func TestConvertTrafficRecordSlice_Fail(t *testing.T) {
	invalidData := []string{"bad-date", "not-a-number", "NaN"}
	_, err := ConvertTrafficRecordSlice(invalidData)
	assert.Error(t, err)
}

func TestConvertTrafficRecordsResponse(t *testing.T) {
	response := TrafficRecordsResponse{
		{"START DATE/TIME", "ALL DNS HITS", "NXDOMAIN HITS"},
		{"2013-09-09T00:00:00Z", "9199", "145"},
		{"2013-09-09T00:05:00Z", "8888", "100"},
	}

	list := ConvertTrafficRecordsResponse(response)
	assert.Equal(t, int64(9199), list.TrafficRecords[0].DNSHits)
	assert.Equal(t, int64(100), list.TrafficRecords[1].NXDHits)
}

func TestGetTrafficReport(t *testing.T) {
	testflag = true
	zone := "testzone.com"

	startTime, err1 := time.Parse(time.RFC3339, "2024-01-03T13:55:00Z")
	endTime, err2 := time.Parse(time.RFC3339, "2024-01-03T14:15:00Z")
	assert.NoError(t, err1)
	assert.NoError(t, err2)

	queryargs := &TrafficReportQueryArgs{
		StartTime: startTime,
		EndTime:   endTime,
		Interval:  FIVE_MINUTES,
	}

	defer gock.Off()

	mockBody := `#METADATA_START
name,authoritative-dns-traffic-by-time
version,3
#METADATA_END
#COLUMNS_START
startdatetime,sum_hits,sum_nxdomain,sum_requests
#COLUMNS_END
#DATA_START
2024-01-03T13:55:00Z,4803.583281,4717.810405,4969
2024-01-03T14:00:00Z,2148.193568,930.434527,1591
2024-01-03T14:05:00Z,1753.48923,3337.304268,4901
2024-01-03T14:10:00Z,3834.168875,2510.499968,4761
#DATA_END`

	gock.New(fmt.Sprintf("https://akaa-baseurl-xxxxxxxxxxx-xxxxxxxxxxxxx.luna.akamaiapis.net/reporting-api/v1/reports/authoritative-dns-traffic-by-time/versions/3/report-data")).
		Get("/reporting-api/v1/reports/authoritative-dns-traffic-by-time/versions/3/report-data").
		MatchParam("start", startTime.Format(time.RFC3339)).
		MatchParam("end", endTime.Format(time.RFC3339)).
		MatchParam("objectIds", zone).
		MatchParam("interval", "FIVE_MINUTES").
		//MatchParam("metrics", "sum_hits,sum_nxdomain").
		Reply(200).
		Type("text/csv").
		BodyString(mockBody)

	ctx := context.Background()
	client, sess, _ := CreateDNSClient(&config)

	report, err := GetTrafficReport(ctx, client, sess, zone, queryargs)
	testflag = false

	assert.NoError(t, err)
	assert.Equal(t, "4803.583281", report[0][1])
	assert.Equal(t, "2510.499968", report[3][2])
}

func TestGetTrafficReport_BadArg(t *testing.T) {
	zone := "testzone.com"

	startTime, err1 := time.Parse(time.RFC3339, "2024-01-03T13:55:00Z")
	endTime, err2 := time.Parse(time.RFC3339, "2024-01-03T14:15:00Z")
	assert.NoError(t, err1)
	assert.NoError(t, err2)

	queryargs := &TrafficReportQueryArgs{
		StartTime: startTime,
		EndTime:   endTime,
		Interval:  FIVE_MINUTES,
	}

	defer gock.Off()

	gock.New(fmt.Sprintf("https://akaa-baseurl-xxxxxxxxxxx-xxxxxxxxxxxxx.luna.akamaiapis.net/reporting-api/v1/reports/authoritative-dns-traffic-by-time/versions/3/report-data")).
		Get("/reporting-api/v1/reports/authoritative-dns-traffic-by-time/versions/3/report-data").
		MatchParam("start", startTime.Format(time.RFC3339)).
		MatchParam("end", endTime.Format(time.RFC3339)).
		MatchParam("objectIds", zone).
		MatchParam("interval", "FIVE_MINUTES").
		MatchParam("metrics", "sum_hits,sum_nxdomain").
		Reply(500).
		Type("text/csv").
		BodyString("Internal Server Error")

	ctx := context.Background()
	client, sess, _ := CreateDNSClient(&config)

	_, err := GetTrafficReport(ctx, client, sess, zone, queryargs)
	assert.Error(t, err)
}
