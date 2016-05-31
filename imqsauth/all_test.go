package imqsauth

import (
	"fmt"
	"golang.org/x/net/websocket"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

const origin = "http://localhost/"
const originHttpUrl = "http://localhost:3377"

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

func TestWebSocket(t *testing.T) {
	// start server
	go func() {
		ic := &ImqsCentral{}
		ic.Config = &Config{}
		LoadTestConfig(ic, TestConfig1)
		ic.RunHttp()
	}()

	const wsUrl = "ws://localhost:3377/notifications"

	cookie, err := login()
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// websocket with auth
	ws, err := createWebSocketAndConnect(wsUrl, origin, cookie)
	if err != nil {
		t.Fatalf("createWebSocketAndConnect (authorized) failed: %v", err)
	}

	// websocket without auth
	wsUnauthorized, err := createWebSocketAndConnect(wsUrl, origin, "")
	if err != nil {
		t.Fatalf("createWebSocketAndConnect (unauthorized) failed: %v", err)
	}

	// Ensure that our unauthorized websocket connection doesn't work.
	msg := ""
	if err := websocket.Message.Receive(wsUnauthorized, &msg); err != io.EOF {
		t.Fatalf("Expected to receieve ie.EOF error from unauthorized websocket, but instead got '%v'", err)
	}

	wsExpectNothing(t, ws)
	joeUserId := 1
	doRequestExpectOK(t, "PUT", originHttpUrl+"/create_group?groupname=socketusergroup", cookie)
	doRequestExpectOK(t, "POST", fmt.Sprintf("%v/set_user_groups?userid=%v&groups=enabled,socketusergroup", originHttpUrl, joeUserId), cookie)
	// expect to receive a message because set_user_groups affects us
	wsExpect(t, ws, fmt.Sprintf("auth:permissions_changed:%v", joeUserId))
	wsExpectNothing(t, ws)
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

func wsExpect(t *testing.T, ws *websocket.Conn, expect string) {
	ws.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	msg := ""
	if err := websocket.Message.Receive(ws, &msg); err != nil {
		t.Fatalf("Error receiving on websocket: %v", err)
	}
	if msg != expect {
		t.Fatalf("Incorrect value received on websocket:\nExpected: %v\nActual:   %v", expect, msg)
	}
}

func wsExpectNothing(t *testing.T, ws *websocket.Conn) {
	ws.SetReadDeadline(time.Now().Add(time.Millisecond))
	msg := ""
	if err := websocket.Message.Receive(ws, &msg); strings.Index(err.Error(), "i/o timeout") == -1 {
		t.Fatalf("Expected websocket to be silent, but instead got '%v' (msg = '%v')", err, msg)
	}
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

func createWebSocketAndConnect(wsUrlLocal string, wsOriginLocal string, cookie string) (*websocket.Conn, error) {
	wsUrlObject, err := url.Parse(wsUrlLocal)
	if err != nil {
		return nil, fmt.Errorf("Could not construct ws url: %v", err)
	}

	originUrlObject, err := url.Parse(wsOriginLocal)
	if err != nil {
		return nil, fmt.Errorf("Could not construct origin url: %v", err)
	}

	headers := http.Header{}
	headers.Add("Cookie", cookie)

	config := websocket.Config{
		Location: wsUrlObject,
		Origin:   originUrlObject,
		Version:  websocket.ProtocolVersionHybi13,
		Header:   headers,
	}
	ws, err := websocket.DialConfig(&config)
	return ws, err
}
