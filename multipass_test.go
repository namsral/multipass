// Copyright 2016 Lars Wiegman. All rights reserved. Use of this source code is
// governed by a BSD-style license that can be found in the LICENSE file.

package multipass

import (
	"net/http"
	"net/url"
	"testing"
)

func TestVerifyToken(t *testing.T) {
	var tests = struct{}{}
}

func TestExtractToken(t *testing.T) {
	actual := "test"

	req, err := http.NewRequest("GET", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	cookie := &http.Cookie{
		Name:  "jwt_token",
		Value: actual,
		Path:  req.URL.Path,
	}
	req.AddCookie(cookie)
	result, err := extractToken(req)
	if result != actual {
		t.Errorf("expected %s, got %s", actual, result)
	}

	req, err = http.NewRequest("GET", "?token="+actual, nil)
	if err != nil {
		t.Fatal(err)
	}
	if u, err := url.Parse("/?token=" + actual); err != nil {
		t.Fatal(err)
	} else {
		req.URL = u
	}
	result, err = extractToken(req)
	if result != actual {
		t.Errorf("expected %s, got %s", actual, result)
	}

	req, err = http.NewRequest("GET", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", "Bearer "+actual)
	result, err = extractToken(req)
	if result != actual {
		t.Errorf("expected %s, got %s", actual, result)
	}

	req, err = http.NewRequest("GET", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = extractToken(req)
	if err == nil {
		t.Error("expected error, got nil")
	}
}
