// Copyright 2016 Lars Wiegman. All rights reserved. Use of this source code is
// governed by a BSD-style license that can be found in the LICENSE file.

package email

import (
	"bytes"
	"net/mail"
	"testing"
	"text/template"

	gomail "gopkg.in/gomail.v2"
)

func TestPathMatch(t *testing.T) {
	tests := []struct {
		pattern, path string
		match         bool //want
	}{
		{"/private", "/private", true},
		{"/private/", "/private/a/b", true},
		{"domain.tld:8080/private/", "domain.tld:8080/private/a/b", true},
		{"/", "/private/a/b", true},
		{"/private/", "/private", false},
		{"/private", "/privat", false},
		{"/", "", false},
		{"domain.tld:8080/private", "domain.tld:8080/private/a/b", false},
		{"private", "/private", false},
		{"/private", "/private/", false},
		{"", "/private", false},
	}

	for i, test := range tests {
		want, got := test.match, pathMatch(test.pattern, test.path)
		if want != got {
			t.Errorf("test #%d; want %t, got %t", i, want, got)
		}
	}
}

func TestAddPattern(t *testing.T) {
	s := &UserService{}
	if err := s.AddPattern("/private"); err != nil {
		t.Error(err)
	}
	if err := s.AddPattern(""); err == nil {
		t.Error("expect error, got nil")
	}
}

func TestListed(t *testing.T) {
	s := &UserService{}
	if actual, expect := s.Listed("leeloo"), false; actual != expect {
		t.Error("expect %t, got %t", expect, actual)
	}
	if actual, expect := s.Listed("leeloo@dallas"), false; actual != expect {
		t.Error("expect %t, got %t", expect, actual)
	}
}

func TestRegister(t *testing.T) {
	s := &UserService{}
	if err := s.Register("leeloo@dallas"); err != nil {
		t.Error(err)
	}
	if err := s.Register("leeloo"); err == nil {
		t.Error("expect Register to error, but did not")
	}
}

func TestAuthorized(t *testing.T) {
	s := &UserService{}
	pattern, handle, rawurl := "/private/", "leeloo@dallas", "/private/a"
	if err := s.Register(handle); err != nil {
		t.Error(err)
	}
	if err := s.AddPattern(pattern); err != nil {
		t.Error(err)
	}
	if actual, expect := s.Authorized(handle, "GET", rawurl), true; actual != expect {
		t.Error("want %t, got %t", expect, actual)
	}
	if actual, expect := s.Authorized("korben@dallas", "GET", rawurl), false; actual != expect {
		t.Error("want %t, got %t", expect, actual)
	}
	if actual, expect := s.Authorized("anonymous", "GET", "/public"), true; actual != expect {
		t.Error("want %t, got %t", expect, actual)
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
		t.Error("want n > 0, got %d", n)
	}
	if err := s.Close(); err != nil {
		t.Error(err)
	}
}
