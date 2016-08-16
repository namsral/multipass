package multipass

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"
)

func TestAuthServeHTTP(t *testing.T) {
	service := &TestHandleService{}
	basepath := "/multipass"
	m, err := NewMultipass(basepath, service)
	if err != nil {
		t.Fatal(err)
	}
	m.Resources = []string{"/private"}

	next := &downstreamHandler{public: "a", private: "b"}
	auth := &Auth{Multipass: m, Next: next}

	tests := []struct {
		desc    string
		method  string
		path    string
		header  http.Header
		status  int         // expect field
		err     error       // expect field
		eHeader http.Header // expect field
		body    *bytes.Buffer
	}{
		{
			desc:   "serve mutipass",
			method: "GET",
			path:   "/multipass",
			status: http.StatusOK,
		},
		{
			desc:   "serve mutipass",
			method: "GET",
			path:   "/private",
			status: http.StatusSeeOther,
		},
		{
			desc:   "serve mutipass",
			method: "GET",
			path:   "/public",
			status: http.StatusOK,
			body:   bytes.NewBufferString(next.public),
		},
	}

	for i, test := range tests {
		record := httptest.NewRecorder()
		req := &http.Request{
			Method: test.method,
			URL:    &url.URL{Path: test.path},
			Header: test.header,
		}
		status, err := auth.ServeHTTP(record, req)
		if actual, expect := status, test.status; actual != expect {
			t.Errorf("test #%d; expect status %d, got %d", i, expect, actual)
		}
		if test.err != nil && !reflect.DeepEqual(test.err, err) {
			t.Errorf("test #%d; expect error %s, got %s", i, test.err, err)
		}
		for k1, v1 := range test.eHeader {
			var match bool
			for k2, v2 := range req.Header {
				if k1 == k2 && reflect.DeepEqual(v1, v2) {
					match = true
					continue
				}
			}
			if !match {
				t.Errorf("test #%d; expect header %s with value %s but dit not", i, k1, v1)
			}
		}
		if actual, expect := record.Body, test.body; expect != nil && !bytes.Equal(actual.Bytes(), expect.Bytes()) {
			t.Errorf("test #%d; expect matching body, but did not", i)
		}
	}
}

func TestNewMultipassRule(t *testing.T) {
	tests := []struct {
		rule      Rule
		shouldErr bool // expect field
	}{
		{
			rule:      Rule{},
			shouldErr: true,
		},
		{
			rule: Rule{
				SMTPAddr: "localhost:2525",
				MailFrom: "no-reply@dallas",
			},
			shouldErr: false,
		},
		{
			rule: Rule{
				Basepath: "/mp",
				SMTPAddr: "localhost:2525",
				MailFrom: "no-reply@dallas",
			},
			shouldErr: false,
		},
		{
			rule: Rule{
				SMTPAddr:  "localhost:2525",
				MailFrom:  "no-reply@dallas",
				Resources: []string{"/private"},
				Handles:   []string{"leeloo@dallas"},
				Expires:   time.Duration(time.Hour * 12),
			},
			shouldErr: false,
		},
	}

	for i, test := range tests {
		_, err := NewMultipassRule(test.rule)
		if err == nil && test.shouldErr {
			t.Errorf("test #%d; expect error, but did not", i)
			continue
		} else if err != nil && !test.shouldErr {
			t.Errorf("test #%d; expect no error, but did with %s", i, err)
			continue
		}
	}
}
