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
	"fmt"
	//"github.com/akamai/AkamaiOPEN-edgegrid-golang/jsonhooks-v1"
	"github.com/stretchr/testify/assert"
	"gopkg.in/h2non/gock.v1"
	"testing"

	dns "github.com/akamai/AkamaiOPEN-edgegrid-golang/configdns-v2"
	edgegrid "github.com/akamai/AkamaiOPEN-edgegrid-golang/edgegrid"
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

	edgegridConfig = config
	dns.Init(config)
	err := validateZone(dnsTestZone)
	assert.NoError(t, err)

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

	edgegridConfig = config
	dns.Init(config)
	err := validateZone(dnsTestZone)
	assert.Error(t, err)

}

func TestNewTrafficReportQueryArgs(t *testing.T) {
	//(end, end_time, start, start_time string) *TrafficReportQueryArgs

	qaobject := NewTrafficReportQueryArgs("09/09/2013 00:00 GMT", "00:30", "09/09/2013 00:00 GMT", "00:10")
	assert.Equal(t, qaobject.End, "09/09/2013 00:00 GMT")

}

func TestConvertTrafficRecordSlice(t *testing.T) {
	//(trslice []string) (TrafficRecord, error)

	testdata := []string{"09/09/2013 00:00 GMT", "9199", "145"}
	testRecord, err := ConvertTrafficRecordSlice(testdata)
	assert.NoError(t, err)
	assert.Equal(t, testRecord.NXDHits, int64(145))

	testdata = []string{"09/09/2013 00:00 GMT-0500", "9199", "145"}
	testRecord, err = ConvertTrafficRecordSlice(testdata)
	assert.NoError(t, err)
	assert.Equal(t, testRecord.NXDHits, int64(145))

}

func TestConvertTrafficRecordSlice_Fail(t *testing.T) {
	//(trslice []string) (TrafficRecord, error)

}

func TestConvertTrafficRecordsResponse(t *testing.T) {
	//(recordsresp TrafficRecordsResponse) TrafficRecordList

	testdata := make(TrafficRecordsResponse, 0)
	testdata = append(testdata, []string{"START DATE/TIME", "ALL DNS HITS", "NXDOMAIN HITS"})
	testdata = append(testdata, []string{"09/09/2013 00:00 GMT", "9199", "145"})
	testdata = append(testdata, []string{"09/09/2013 00:05 GMT", "8888", "20"})
	testTrafficList := ConvertTrafficRecordsResponse(testdata)

	assert.Equal(t, int64(8888), testTrafficList.TrafficRecords[1].DNSHits)

}

func TestGetTrafficReport(t *testing.T) {
	//(zone string, trafficReportQueryArgs *TrafficReportQueryArgs) (TrafficRecordsResponse, error)

	testflag = true // flag to skip validate zone
	dnsTestZone := "testzone.com"
	queryargs := NewTrafficReportQueryArgs("20130909", "00:20", "20130909", "00:00")

	defer gock.Off()
	mock := gock.New(fmt.Sprintf("https://akaa-baseurl-xxxxxxxxxxx-xxxxxxxxxxxxx.luna.akamaiapis.net/data-dns/v1/traffic/%s", dnsTestZone))
	mock.
		Get(fmt.Sprintf("/data-dns/v1/traffic/%s", dnsTestZone)).
		HeaderPresent("Authorization").
		Reply(200).
		SetHeader("Content-Type", "text/csv").
		BodyString(`
START DATE/TIME, ALL DNS HITS, NXDOMAIN HITS
09/09/2013 00:00 GMT,9199,145
09/09/2013 00:05 GMT,8888,100
09/09/2013 00:10 GMT,7929,20
09/09/2013 00:15 GMT,9433,157`)

	edgegridConfig = config
	dns.Init(config)
	// returns type TrafficRecordsResponse [][]string
	report, err := GetTrafficReport(dnsTestZone, queryargs)
	testflag = false
	assert.NoError(t, err)
	assert.Equal(t, report[1][1], "9199")

}

func TestGetTrafficReport_BadArg(t *testing.T) {
	//(zone string, trafficReportQueryArgs *TrafficReportQueryArgs) (TrafficRecordsResponse, error)

	dnsTestZone := "testzone.com"
	queryargs := NewTrafficReportQueryArgs("20130908", "00:20", "20130909", "00:00")

	defer gock.Off()

	mock := gock.New(fmt.Sprintf("https://akaa-baseurl-xxxxxxxxxxx-xxxxxxxxxxxxx.luna.akamaiapis.net/data-dns/v1/traffic/%s", dnsTestZone))
	mock.
		Get(fmt.Sprintf("/data-dns/v1/traffic/%s", dnsTestZone)).
		HeaderPresent("Authorization").
		Reply(500).
		SetHeader("Content-Type", "application/json;charset=UTF-8").
		BodyString(`Server Error`)

	edgegridConfig = config
	dns.Init(config)
	// returns type TrafficRecordsResponse [][]string
	_, err := GetTrafficReport(dnsTestZone, queryargs)
	assert.Error(t, err)

}
