package imqsauth

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const origin = "http://localhost/"
const originHttpUrl = "http://localhost:3377"
const joeUserId = 1

// At present, most of the HTTP API tests are performed in the ruby script "resttest.rb".
// The Web Socket tests are the only HTTP tests performed here. It might be prudent to move
// the ruby-based tests in here too, provided one could keep the number of lines of code similar.

// NOTE: If you add ANY MORE tests here that use an actual HTTP server, then you're going to
// have to work around the fact that as of right now (Go 1.6) there is no way to gracefully
// stop a net/http Server. The only plausible thing I can think of is to keep the same server
// running for all tests. This is tricky, because you really want the server to start with
// a clean slate each time. However, it shouldn't be hard to add a 'resetForTest' function
// to ImqsCentral.
// This issue is tracked by https://github.com/golang/go/issues/4674. Take a look and see if
// that has been resolved in subsequent (post 1.6) versions of Go.

type TestNotification struct {
	Channel, Msg string
}

func TestDistributerPost(t *testing.T) {
	expectedChannelName := "authNotifications"
	expectedMessage := fmt.Sprintf("permissions_changed:%v", joeUserId)

	handleNotifyExpectJoeUserIdInMessage := func(w http.ResponseWriter, r *http.Request) {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			t.Errorf("Unexpected error while reading body of post message: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		dec := json.NewDecoder(strings.NewReader(string(body[:])))
		var data TestNotification
		if err := dec.Decode(&data); err == io.EOF {
			t.Errorf("Unexpected error in JSON: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if data.Channel != expectedChannelName {
			t.Errorf("Expected channel name: %v, instead: %v", expectedChannelName, data.Channel)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if data.Msg != expectedMessage {
			t.Errorf("Expected message: %v, instead: %v", expectedMessage, data.Msg)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}

	// Start distributor mock service
	server := httptest.NewServer(http.HandlerFunc(handleNotifyExpectJoeUserIdInMessage))
	defer server.Close()

	// Start auth service
	go func() {
		ic := &ImqsCentral{}
		ic.Config = &Config{}
		LoadTestConfig(ic, TestConfig1)
		ic.Config.NotificationUrl = server.URL
		ic.RunHttp()
	}()

	cookie, err := login()
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// Change a group, which sends a POST to the distributor service
	doRequestExpectOK(t, "PUT", originHttpUrl+"/create_group?groupname=socketusergroup", cookie)
	doRequestExpectOK(t, "POST", fmt.Sprintf("%v/set_user_groups?userid=%v&groups=enabled,socketusergroup", originHttpUrl, joeUserId), cookie)
}

func doRequest(verb, url, cookie string) (*http.Response, error) {
	request, err := http.NewRequest(verb, url, nil)
	if err != nil {
		return nil, err
	}
	if cookie != "" {
		request.Header.Add("Cookie", cookie)
	}
	return http.DefaultClient.Do(request)
}

func doRequestExpectOK(t *testing.T, verb, url, cookie string) *http.Response {
	response, err := doRequest(verb, url, cookie)
	if err != nil || response.StatusCode != 200 {
		t.Fatalf("Unexpected response from %v %v: %v %v", verb, url, response.Status, err)
	}
	return response
}

// Returns (Set-Cookie header, error)
func login() (string, error) {
	request, err := http.NewRequest("POST", originHttpUrl+"/login", nil)
	if err != nil {
		return "", err
	}

	request.SetBasicAuth("admin", "ADMIN")
	resp, err := http.DefaultClient.Do(request)
	if err != nil {
		return "", err
	}
	if resp.StatusCode == 200 {
		return resp.Header.Get("Set-Cookie"), nil
	} else {
		return "", nil
	}
}
