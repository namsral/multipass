// Copyright 2016 Lars Wiegman. All rights reserved. Use of this source code is
// governed by a BSD-style license that can be found in the LICENSE file.

package multipass

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/namsral/multipass/mock"

	jose "gopkg.in/square/go-jose.v1"
)

func newSignerAndPublicKey(t *testing.T) (jose.Signer, rsa.PublicKey) {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.PS512, pk)
	if err != nil {
		t.Fatal(err)
	}
	return signer, pk.PublicKey
}

type downstreamHandler struct {
	public  string
	private string
}

func (h downstreamHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	if r.Method == "GET" {
		switch r.URL.Path {
		case "/public":
			w.Write([]byte(h.public))
			return 200, nil
		case "/secret":
			w.Write([]byte(h.private))
			return 200, nil
		default:
			return http.StatusNotFound, nil
		}
	}
	return http.StatusMethodNotAllowed, nil
}

func TestTokenHandler(t *testing.T) {
	m, err := NewMultipass("")
	if err != nil {
		t.Fatal(err)
	}

	handles := []string{"leeloo@dallas", "korben@dallas", "ruby@rhod"}
	service := &mock.UserService{}
	service.NotifyFn = func(handle, loginurl string) error {
		return nil
	}
	service.ListedFn = func(handle string) bool {
		if handle == handles[len(handles)-1] {
			return false
		}
		for _, h := range handles[:len(handles)-1] {
			if h == handle {
				return true
			}
		}
		return false
	}
	service.AuthorizedFn = func(handle, rawurl string) bool {
		if service.Listed(handle) && rawurl == "/private" {
			return true
		}
		return false
	}
	m.SetUserService(service)

	token, err := m.AccessToken(handles[0])
	if err != nil {
		t.Fatal(err)
	}
	unregisteredHandleToken, err := m.AccessToken(handles[len(handles)-1])
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		desc    string
		method  string
		path    string
		header  http.Header
		status  int         // expect field
		err     error       // expect field
		eHeader http.Header // expect field
	}{
		{
			desc:   "request without token",
			method: "GET",
			path:   "/private",
			status: http.StatusUnauthorized,
			err:    ErrInvalidToken,
		},
		{
			desc:   "request with invalid token",
			method: "GET",
			path:   "/private",
			header: http.Header{"Cookie": []string{fmt.Sprint(&http.Cookie{Name: "jwt_token", Value: "garbage"})}},
			status: http.StatusUnauthorized,
			err:    ErrInvalidToken,
		},
		{
			desc:   "request with unregistered handle",
			method: "GET",
			path:   "/private",
			header: http.Header{"Cookie": []string{fmt.Sprint(&http.Cookie{Name: "jwt_token", Value: unregisteredHandleToken, Path: "//"})}},
			status: http.StatusForbidden,
			err:    ErrForbidden,
		},
		{
			desc:   "request with token forbidden resource",
			method: "GET",
			path:   "/more/private",
			header: http.Header{"Cookie": []string{fmt.Sprint(&http.Cookie{Name: "jwt_token", Value: token, Path: "/"})}},
			status: http.StatusForbidden,
		},
		{
			desc:    "request with token",
			method:  "GET",
			path:    "/private",
			header:  http.Header{"Cookie": []string{fmt.Sprint(&http.Cookie{Name: "jwt_token", Value: token, Path: "/"})}},
			status:  http.StatusOK,
			eHeader: http.Header{"Multipass-Handle": []string{handles[0]}},
		},
	}

	for i, test := range tests {
		record := httptest.NewRecorder()
		req := &http.Request{
			Method: test.method,
			URL:    &url.URL{Path: test.path},
			Header: test.header,
		}
		status, err := ResourceHandler(record, req, m)
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
				t.Errorf("test #%d; expect header %s with value %s but didn't", i, k1, v1)
			}
		}
	}
}

func TestMultipassHandlers(t *testing.T) {
	m, err := NewMultipass("")
	if err != nil {
		t.Fatal(err)
	}
	handles := []string{"leeloo@dallas", "korben@dallas", "ruby@rhod"}
	service := &mock.UserService{}
	service.NotifyFn = func(handle, loginurl string) error {
		return nil
	}
	service.ListedFn = func(handle string) bool {
		if handle == handles[len(handles)-1] {
			return false
		}
		for _, h := range handles[:len(handles)-1] {
			if h == handle {
				return true
			}
		}
		return false
	}
	service.AuthorizedFn = func(handle, rawurl string) bool {
		if !service.Listed(handle) {
			return false
		}
		if rawurl == "/private" {
			return true
		}
		return false
	}
	m.SetUserService(service)

	token, err := m.AccessToken(handles[0])
	if err != nil {
		t.Fatal(err)
	}
	unregisteredHandleToken, err := m.AccessToken(handles[len(handles)-1])
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		desc      string
		method    string
		path      string
		rawQuery  string
		postForm  url.Values
		header    http.Header
		status    int           // expect field
		body      *bytes.Buffer // expect field
		headerMap http.Header   // expect field
	}{
		{
			desc:   "post",
			method: "POST",
			path:   "/multipass/signout",
			status: http.StatusSeeOther,
		},
		{
			desc:   "method not allowed",
			method: "POST",
			path:   "/multipass",
			status: http.StatusMethodNotAllowed,
		},
		{
			desc:   "method not allowed",
			method: "GET",
			path:   "/multipass/signout",
			status: http.StatusMethodNotAllowed,
		},
		{
			desc:   "get",
			method: "GET",
			path:   "/multipass/confirm",
			status: http.StatusOK,
		},
		{
			desc:   "method not allowd",
			method: "POST",
			path:   "/multipass/confirm",
			status: http.StatusMethodNotAllowed,
		},
		{
			desc:   "method not allowed",
			method: "HEAD",
			path:   "/multipass/login",
			status: http.StatusMethodNotAllowed,
		},
		{
			desc:   "simple post",
			method: "GET",
			path:   "/multipass/login",
			status: http.StatusSeeOther,
		},
		{
			desc:      "submit handle",
			method:    "POST",
			path:      "/multipass/login",
			postForm:  url.Values{"handle": []string{"leeloo@dallas"}, "url": []string{"/private"}},
			status:    http.StatusSeeOther,
			headerMap: http.Header{"Location": []string{"/multipass/confirm"}},
		},
		{
			desc:      "submit unregisterd handle",
			method:    "POST",
			path:      "/multipass/login",
			postForm:  url.Values{"handle": []string{"ruby@rhod"}, "url": []string{"/private"}},
			status:    http.StatusSeeOther,
			headerMap: http.Header{"Location": []string{"/multipass/confirm"}},
		},
		{
			desc:      "get public key",
			method:    "GET",
			path:      "/multipass/pub.cer",
			status:    http.StatusOK,
			headerMap: http.Header{"Content-Type": []string{"application/pkix-cert"}},
		},
		{
			desc:   "not found",
			method: "GET",
			path:   "/private",
			status: http.StatusNotFound,
		},
		{
			desc:   "cookie with token",
			method: "GET",
			path:   "/multipass",
			header: http.Header{"Cookie": []string{
				fmt.Sprint(&http.Cookie{Name: "jwt_token", Value: token, Path: "/"}),
				fmt.Sprint(&http.Cookie{Name: "next_url", Value: token, Path: "/private"}),
			}},
			status: http.StatusOK,
		},
		{
			desc:   "cookie with unregistered user",
			method: "GET",
			path:   "/multipass",
			header: http.Header{"Cookie": []string{fmt.Sprint(&http.Cookie{Name: "jwt_token", Value: unregisteredHandleToken, Path: "/"})}},
			status: http.StatusOK,
		},
		{
			desc:   "cookie with invalid token",
			method: "GET",
			path:   "/multipass",
			header: http.Header{"Cookie": []string{fmt.Sprint(&http.Cookie{Name: "jwt_token", Value: "garbage", Path: "/"})}},
			status: http.StatusOK,
		},
		{
			desc:     "create cookies from token and url query parameter variables",
			method:   "GET",
			path:     "/multipass/login",
			rawQuery: "token=a&amp;url=b",
			status:   http.StatusSeeOther,
			header: http.Header{
				"Location": []string{"/multipath"},
				"Cookie": []string{
					fmt.Sprint(&http.Cookie{Name: "jwt_token", Value: "a", Path: "/"}),
					fmt.Sprint(&http.Cookie{Name: "next_url", Value: "b", Path: "/"}),
				}},
		},
	}

	for i, test := range tests {
		record := httptest.NewRecorder()
		req := &http.Request{
			Method:   test.method,
			URL:      &url.URL{Path: test.path, RawQuery: test.rawQuery},
			PostForm: test.postForm,
			Header:   test.header,
		}
		m.ServeHTTP(record, req)
		if actual, expect := record.Code, test.status; actual != expect {
			t.Errorf("test #%d; expect status %d, got %d", i, expect, actual)
		}
		for k1, v1 := range test.headerMap {
			var match bool
			for k2, v2 := range record.HeaderMap {
				if k1 == k2 && reflect.DeepEqual(v1, v2) {
					match = true
				}
			}
			if !match {
				t.Errorf("test #%d; expect header %s with value %s but did not", i, k1, v1)
			}
		}
	}
}

func TestVerifyToken(t *testing.T) {
	signer, pk := newSignerAndPublicKey(t)
	claims := &Claims{Handle: "leeloo@dallas", Expires: time.Now().Add(time.Hour * 12).Unix()}
	token, err := accessToken(signer, claims)
	if err != nil {
		t.Fatal(err)
	}
	a := strings.Split(token, ".")
	header := a[0]
	payload := a[1]
	signature := a[2]

	tests := []struct {
		header, payload, signature string
		shouldErr                  bool
	}{
		{header, payload, signature, false},
		{"", payload, signature, true},
		{header, payload, "", true},
		{header, "", signature, true},
	}

	for i, test := range tests {
		tokenStr := strings.Join([]string{test.header, test.payload, test.signature}, ".")
		_, err := validateToken(tokenStr, pk)
		if err == nil && test.shouldErr {
			t.Errorf("test #%d should return an error, but did not", i)
		} else if err != nil && !test.shouldErr {
			t.Errorf("test #%d should not return an error, but did with %s", i, err)
		}
	}
}

func TestValidateToken(t *testing.T) {
	tests := []struct {
		claims      *Claims
		shouldErr   bool
		shouldEqual bool
	}{
		{
			&Claims{Handle: "leeloo@dallas", Expires: time.Now().Add(time.Hour * 12).Unix()},
			false,
			true,
		},
		{
			&Claims{Handle: "leeloo@dallas", Expires: time.Now().Add(time.Hour * -12).Unix()},
			true,
			false,
		},
	}

	signer, pk := newSignerAndPublicKey(t)

	for i, test := range tests {
		token, err := accessToken(signer, test.claims)
		if err != nil {
			t.Errorf("test #%d failed to generate access token", i)
		}

		result, err := validateToken(token, pk)
		if err == nil && test.shouldErr {
			t.Errorf("test #%d should return an error, but did not", i)
		} else if err != nil && !test.shouldErr {
			t.Errorf("test #%d should not return an error, but did with %s", i, err)
		}
		if test.shouldEqual != reflect.DeepEqual(result, test.claims) {
			t.Errorf("test #%d result should equal actual, but did not", i)
		}
	}
}

func TestExtractToken(t *testing.T) {
	tests := []struct {
		desc      string
		rawQuery  string
		header    http.Header
		token     string // expect field
		shouldErr bool   // expect field
	}{
		{
			desc:      "no token",
			shouldErr: true,
		},
		{
			desc:   "token in Authorization header",
			token:  "fire",
			header: http.Header{"Authorization": []string{"Bearer fire"}},
		},
		{
			desc:  "token in Cookie header",
			token: "wind",
			header: http.Header{
				"Cookie": []string{
					fmt.Sprint(&http.Cookie{Name: "jwt_token", Value: "wind", Path: "/"}),
				}},
		},
		{
			desc:     "token in query parameter",
			token:    "water",
			rawQuery: "token=water",
		},
	}

	for i, test := range tests {
		req := &http.Request{
			Method: "GET",
			URL:    &url.URL{Path: "/", RawQuery: test.rawQuery},
			Header: test.header,
		}
		token, err := extractToken(req)
		if err == nil && test.shouldErr {
			t.Errorf("test #%d; expect error, but did not", i)
		} else if err != nil && !test.shouldErr {
			t.Errorf("test #%d expect no error, got %s", i, err)
		}
		if actual, expect := token, test.token; actual != expect {
			t.Errorf("test #%d; expect token %s, got %s", i, expect, actual)
		}
	}
}
