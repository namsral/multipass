// Copyright 2016 Lars Wiegman. All rights reserved. Use of this source code is
// governed by a BSD-style license that can be found in the LICENSE file.

package email

import (
	"bytes"
	"io/ioutil"
	"log"
	"net/mail"
	"reflect"
	"testing"
	"text/template"

	gomail "gopkg.in/gomail.v2"
)

func TestPathMatch(t *testing.T) {
	tests := []struct {
		pattern, path string
		match         bool //want
	}{
		// Valid matches
		{"/private", "/private", true},
		{"/private/", "/private/a/b", true},
		{"domain.tld:8080/private/", "domain.tld:8080/private/a/b", true},
		{"/", "/private/a/b", true},

		// Invalid matches
		{"/private/", "/private", false},
		{"/private", "/privat", false},
		{"/", "", false},
		{"domain.tld:8080/private", "domain.tld:8080/private/a/b", false},
		{"private", "/private", false},
		{"/private", "/private/", false},
		{"", "/private", false},
	}

	for i, test := range tests {
		want, got := test.match, MatchResource(test.pattern, test.path)
		if want != got {
			t.Errorf("test #%d; want %t, got %t", i, want, got)
		}
	}
}

func TestAddPattern(t *testing.T) {
	s := &UserService{}
	if err := s.AddResource("/private"); err != nil {
		t.Error(err)
	}
	if err := s.AddResource(""); err == nil {
		t.Error("expect error, got nil")
	}
}

func TestListed(t *testing.T) {
	s := &UserService{}
	if actual, expect := s.Listed("leeloo"), false; actual != expect {
		t.Errorf("expect %t, got %t", expect, actual)
	}
	if actual, expect := s.Listed("leeloo@dallas"), false; actual != expect {
		t.Errorf("expect %t, got %t", expect, actual)
	}
}

func TestAddHandle(t *testing.T) {
	s := &UserService{}
	if err := s.AddHandle("leeloo@dallas"); err != nil {
		t.Error(err)
	}
	if err := s.AddHandle("leeloo"); err == nil {
		t.Errorf("expect AddHandle to error, but did not")
	}
}

func TestAuthorized(t *testing.T) {
	s := &UserService{}
	pattern, handle, rawurl := "/private/", "leeloo@dallas", "/private/a"
	if err := s.AddHandle(handle); err != nil {
		t.Error(err)
	}
	if err := s.AddResource(pattern); err != nil {
		t.Error(err)
	}
	if actual, expect := s.Authorized(handle, "GET", rawurl), true; actual != expect {
		t.Errorf("want %t, got %t", expect, actual)
	}
	if actual, expect := s.Authorized("korben@dallas", "GET", rawurl), false; actual != expect {
		t.Errorf("want %t, got %t", expect, actual)
	}
	if actual, expect := s.Authorized("anonymous", "GET", "/public"), true; actual != expect {
		t.Errorf("want %t, got %t", expect, actual)
	}
}

func TestNotify(t *testing.T) {
	s := &UserService{}
	s.template = template.Must(template.New("").Parse(msgTmpl))
	s.channel = make(chan *gomail.Message)

	from, err := mail.ParseAddress("Multipass Bot <no-reply@dallas>")
	if err != nil {
		t.Error(err)
	}
	s.from = from

	handle := "leeloo@dallas"
	loginurl := "http://example.com/multipass/login?token="
	if err := s.Notify("leeloo", loginurl); err == nil {
		t.Error("expect Notify to error, but did not")
	}
	go func() {
		if err := s.Notify(handle, loginurl); err != nil {
			t.Error(err)
		}
	}()

	buf := new(bytes.Buffer)
	message, ok := <-s.channel
	if !ok {
		t.Error("oops")
	}
	n, err := message.WriteTo(buf)
	if err != nil {
		t.Error(err)
	}
	if n < 1 {
		t.Errorf("want n > 0, got %d", n)
	}
	if err := s.Close(); err != nil {
		t.Error(err)
	}
}

func TestSplitLocalDomain(t *testing.T) {
	tests := []struct {
		address, local, domain string
		shouldErr              bool
	}{
		// Valid addresses
		{"bob@example.com", "bob", "example.com", false},
		{"bob.smith@example.com", "bob.smith", "example.com", false},
		{"bob@example", "bob", "example", false},
		{"b@c", "b", "c", false},
		{"bob+plus@example.com", "bob+plus", "example.com", false},

		// Invalid addresses
		{"@example.com", "", "", true},
		{"bob@@example.com", "", "", true},
		{"bob@bob@example.com", "", "", true},
		{"bob@", "", "", true},
		{"@", "", "", true},
		{"", "", "", true},
	}
	for i, test := range tests {
		local, domain, err := SplitLocalDomain(test.address)
		if err != nil {
			if test.shouldErr {
				continue
			}
			t.Errorf("test #%d returned unexpected error %s", i, err)
			continue
		}
		if got, want := local, test.local; got != want {
			t.Errorf("test #%d; want local %s, got %s", i, want, got)
		}
		if got, want := domain, test.domain; got != want {
			t.Errorf("test #%d; want domain %s, got %s", i, want, got)
		}
	}
}

func TestMatchPattern(t *testing.T) {
	tests := []struct {
		pattern, address string
		shouldMatch      bool
	}{
		// Valid matches
		{"@", "bob@example.com", true},
		{"@example.com", "bob@example.com", true},
		{"bob@example.com", "bob@example.com", true},
		{"bob.smith@example.com", "bob.smith@example.com", true},
		{"bob+plus@example.com", "bob+plus@example.com", true},

		// Invalid matches
		{"@", "bob", false},
		{"@", "bob@", false},
		{"@", "@example", false},
		{"", "bob@example.com", false},
		{"bob", "bob@example.com", false},
		{"example.com", "bob@example.com", false},
		{"@example.org", "bob@example.com", false},
		{"bob@example.org", "ben@example.org", false},
		{"bob@example", "bob@example.com", false},
	}
	for i, test := range tests {
		got, want := MatchHandle(test.pattern, test.address), test.shouldMatch
		if got != want {
			t.Errorf("test #%d; want pattern %s to match address %s, but failed",
				i, test.pattern, test.address)
		}
	}

}

func TestValidHandle(t *testing.T) {
	tests := []struct {
		handle         string
		shouldValidate bool
	}{
		// Valid
		{"@", true},
		{"@example.com", true},
		{"bob@example.com", true},
		{"bob.smith@example.com", true},
		{"bob+plus@example.com", true},

		// Invalid
		{"", false},
		{"bob", false},
		{"example.com", false},
		{"bob@", false},
	}
	for i, test := range tests {
		got, want := ValidHandle(test.handle), test.shouldValidate
		if got != want {
			t.Errorf("test #%d; want ValidHandle(\"%s\") to return %t, got %t",
				i, test.handle, want, got)
		}
	}

}

func TestSendmail(t *testing.T) {
	m := gomail.NewMessage()
	m.SetHeader("From", "leeloo@dallas")
	m.SetHeader("To", "korben@dallas")
	m.SetBody("text/plain", "Hello!")

	output, err := sendmail(m, "cat")
	if err != nil {
		t.Errorf("cat: %v", err)
	}

	// Need to parse messages before comparison as the order of headers may
	// differ

	mGot, err := mail.ReadMessage(bytes.NewBuffer(output))
	if err != nil {
		log.Fatal(err)
	}

	buf := new(bytes.Buffer)
	if _, err := m.WriteTo(buf); err != nil {
		t.Error(err)
	}
	mWant, err := mail.ReadMessage(buf)
	if err != nil {
		t.Fatal(err)
	}

	if want, got := mWant.Header, mGot.Header; !reflect.DeepEqual(want, got) {
		t.Errorf("cat: want %q, got %q", want, got)
	}

	bGot, err := ioutil.ReadAll(mGot.Body)
	bWant, err := ioutil.ReadAll(mWant.Body)
	if want, got := bWant, bGot; !bytes.Equal(want, got) {
		t.Errorf("cat: want %q, got %q", want, got)
	}
}
