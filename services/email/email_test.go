// Copyright 2016 Lars Wiegman. All rights reserved. Use of this source code is
// governed by a BSD-style license that can be found in the LICENSE file.

package email

import "testing"

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
	}

	for i, test := range tests {
		want, got := test.match, pathMatch(test.pattern, test.path)
		if want != got {
			t.Errorf("test #%d; want %t, got %t", i, want, got)
		}
	}
}
