// Copyright 2016 Lars Wiegman. All rights reserved. Use of this source code is
// governed by a BSD-style license that can be found in the LICENSE file.

package multipass

import (
	"net/http"
	"net/url"
	"time"

	"github.com/mholt/caddy/caddyhttp/httpserver"
	"github.com/namsral/multipass"
)

// Auth wraps a Multipass instance to be used by the caddy web server.
type Auth struct {
	*multipass.Multipass
	Next httpserver.Handler
}

// ServeHTTP implements the httpserver.ServeHTTP interface from caddy.
func (a *Auth) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	m := a.Multipass

	if httpserver.Path(r.URL.Path).Matches(m.Basepath()) {
		m.ServeHTTP(w, r)
		return 200, nil
	}

	if _, err := multipass.ResourceHandler(w, r, m); err != nil {
		v := url.Values{"next": []string{r.URL.String()}}
		u := &url.URL{
			Path:     m.Basepath(),
			RawQuery: v.Encode(),
		}
		location := u.String()
		http.Redirect(w, r, location, http.StatusSeeOther)
		return http.StatusSeeOther, nil
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

	SMTPClientName string // named SMTP client for sending mail message
	SMTPClientArgs []string
}
