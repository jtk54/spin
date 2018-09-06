// Copyright (c) 2018, Google, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

package applications

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/spinnaker/spin/command"
	"github.com/spinnaker/spin/version"
)

const (
	APP = "app"
)

func TestMain(m *testing.M) {
	version.Version = "1.2.3" // Dummy version for testing.
	version.ReleasePhase = ""
	os.Exit(m.Run())
}

func TestApplicationGet_basic(t *testing.T) {
	ts := testGateApplicationGetSuccess()
	defer ts.Close()

	meta := command.ApiMeta{}
	args := []string{"--gate-endpoint", ts.URL, APP}
	cmd := ApplicationGetCommand{
		ApiMeta: meta,
	}
	ret := cmd.Run(args)
	if ret != 0 {
		t.Fatalf("Command failed with: %d", ret)
	}
}

func TestApplicationGet_flags(t *testing.T) {
	ts := testGateApplicationGetSuccess()
	defer ts.Close()

	meta := command.ApiMeta{}
	args := []string{"--gate-endpoint", ts.URL} // Missing positional arg.
	cmd := ApplicationGetCommand{
		ApiMeta: meta,
	}
	ret := cmd.Run(args)
	if ret == 0 { // Success is actually failure here, flags are malformed.
		t.Fatalf("Command failed with: %d", ret)
	}
}

func TestApplicationGet_malformed(t *testing.T) {
	ts := testGateApplicationGetMalformed()
	defer ts.Close()

	meta := command.ApiMeta{}
	args := []string{"--gate-endpoint", ts.URL, APP}
	cmd := ApplicationGetCommand{
		ApiMeta: meta,
	}
	ret := cmd.Run(args)
	if ret == 0 { // Success is actually failure here, return payload is malformed.
		t.Fatalf("Command failed with: %d", ret)
	}
}

func TestApplicationGet_fail(t *testing.T) {
	ts := GateServerFail()
	defer ts.Close()

	meta := command.ApiMeta{}
	args := []string{"--gate-endpoint", ts.URL, APP}
	cmd := ApplicationGetCommand{
		ApiMeta: meta,
	}
	ret := cmd.Run(args)
	if ret == 0 { // Success is actually failure here, internal server error.
		t.Fatalf("Command failed with: %d", ret)
	}
}

// testGateApplicationGetSuccess spins up a local http server that we will configure the GateClient
// to direct requests to. Responds with a 200 and a well-formed pipeline list.
func testGateApplicationGetSuccess() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, strings.TrimSpace(applicationJson))
	}))
}

// testGateApplicationGetMalformed returns a malformed list of pipeline configs.
func testGateApplicationGetMalformed() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, strings.TrimSpace(malformedApplicationGetJson))
	}))
}

const malformedApplicationGetJson = `
  "accounts": "account1",
  "cloudproviders": [
    "gce",
    "kubernetes"
  ],
  "createTs": "1527261941734",
  "email": "app",
  "instancePort": 80,
  "lastModifiedBy": "anonymous",
  "name": "app",
  "updateTs": "1527261941735",
  "user": "anonymous"
}
`

const applicationJson = `
{
  "accounts": "account1",
  "cloudproviders": [
    "gce",
    "kubernetes"
  ],
  "createTs": "1527261941734",
  "email": "app",
  "instancePort": 80,
  "lastModifiedBy": "anonymous",
  "name": "app",
  "updateTs": "1527261941735",
  "user": "anonymous"
}
`
