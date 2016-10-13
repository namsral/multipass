// Copyright 2016 Lars Wiegman. All rights reserved. Use of this source code is
// governed by a BSD-style license that can be found in the LICENSE file.

package multipass

import (
	"fmt"
	"html/template"
	"reflect"
	"testing"

	"github.com/namsral/multipass/mock"
)

func TestOptions(t *testing.T) {
	test := &options{
		Basepath: "/mp",
		Expires:  9,
		CSRF:     false,
		Template: *template.New("test"),
		Service:  new(mock.UserService),
	}

	testOpts := []Option{
		Basepath(test.Basepath),
		Expires(test.Expires),
		CSRF(test.CSRF),
		Template(test.Template),
		Service(test.Service),
	}

	m := New("", testOpts...)

	if got, want := m.opts.Basepath, test.Basepath; got != want {
		t.Errorf("want Basepath %q, got %q", want, got)
	}

	if got, want := m.opts.Expires, test.Expires; got != want {
		t.Errorf("want Expires %q, got %q", want, got)
	}

	if got, want := m.opts.CSRF, test.CSRF; got != want {
		t.Errorf("want CSRF %t, got %t", want, got)
	}

	if got, want := m.opts.Template, test.Template; !reflect.DeepEqual(want, got) {
		t.Errorf("want Template %v, got %v", want, got)
	}
	if got, want := m.opts.Service, test.Service; !reflect.DeepEqual(want, got) {
		t.Errorf("want Service %q, got %q", want, got)
	}
}

func TestBasepath(t *testing.T) {
	testCases := []struct {
		input string
		want  string
	}{
		{input: "", want: "/multipass"},
		{input: "/", want: "/multipass"},
		{input: "mp", want: "/mp"},
		{input: "/mp", want: "/mp"},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%q", tc.input), func(t *testing.T) {
			m := New("", Basepath(tc.input))
			if got := m.opts.Basepath; got != tc.want {
				t.Errorf("got %s; want %s", got, tc.want)
			}
		})
	}
}
