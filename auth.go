// Copyright 2016 Lars Wiegman. All rights reserved. Use of this source code is
// governed by a BSD-style license that can be found in the LICENSE file.

package multipass

import (
	"net/http"
	"net/url"
	"time"

	"github.com/mholt/caddy/caddyhttp/httpserver"

	"github.com/namsral/multipass/services/email"
)

// Auth wraps a Multipass instance to be used by the caddy web server.
type Auth struct {
	*Multipass
	Next httpserver.Handler
}

// ServeHTTP implements the httpserver.ServeHTTP interface from caddy.
func (a *Auth) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	m := a.Multipass

	if httpserver.Path(r.URL.Path).Matches(m.Basepath) {
		m.ServeHTTP(w, r)
		return 200, nil
	}

	for _, path := range m.Resources {
		if httpserver.Path(r.URL.Path).Matches(path) {
			if _, err := tokenHandler(w, r, m); err != nil {
				u, err := url.Parse(m.SiteAddr)
				if err != nil {
					return http.StatusInternalServerError, nil
				}
				v := url.Values{}
				v.Set("url", r.URL.String())
				u.RawQuery = v.Encode()
				u.Path = m.Basepath
				http.Redirect(w, r, u.String(), http.StatusSeeOther)
				return http.StatusSeeOther, nil
			}
		}
	}

	return a.Next.ServeHTTP(w, r)
}

// Rule holds the directive options parsed from a Caddyfile.
type Rule struct {
	Basepath  string
	Expires   time.Duration
	Resources []string
	Handles   []string

	SMTPAddr, SMTPUser, SMTPPass string
	MailFrom, MailTmpl           string
}

// NewMultipassRule return a new instance of Multipass from the given Rule.
// Returned error will most likely be parser errors.
func NewMultipassRule(r Rule) (*Multipass, error) {
	// Create a HandleService
	opt := &email.HandleOptions{
		r.SMTPAddr,
		r.SMTPUser,
		r.SMTPPass,
		r.MailFrom,
	}
	service, err := email.NewHandleService(opt)
	if err != nil {
		return nil, err
	}
	for _, handle := range r.Handles {
		service.Register(handle)
	}

	// Create a new Multipass service with
	// the given basepath and handle service
	m, err := NewMultipass(r.Basepath, service)
	if err != nil {
		return nil, err
	}

	if len(r.Resources) > 0 {
		m.Resources = r.Resources
	}
	if r.Expires > 0 {
		m.Expires = r.Expires
	}
	return m, nil
}
