package multipass

import (
	"net/http"
	"time"

	"github.com/mholt/caddy/caddyhttp/httpserver"
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
		return 0, nil
	}

	for _, path := range m.Resources {
		if httpserver.Path(r.URL.Path).Matches(path) {
			if _, err := tokenHandler(w, r, m); err != nil {
				r.Header.Set("Referer", r.URL.String())
				m.rootHandler(w, r)
				return 0, nil
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

// NewMultipassFromRule return a new instance of Multipass from the given Rule.
// Returned error will most likely be parser errors.
func NewMultipassFromRule(r Rule) (*Multipass, error) {
	m, err := NewMultipass(r.Basepath)
	if err != nil {
		return nil, err
	}

	if len(r.Resources) > 0 {
		m.Resources = r.Resources
	}
	if r.Expires > 0 {
		m.Expires = r.Expires
	}

	// Set EmailHandler options
	opt := &EmailOptions{
		r.SMTPAddr,
		r.SMTPUser,
		r.SMTPPass,
		r.MailFrom,
	}
	handler, err := NewEmailHandler(opt)
	if err != nil {
		return nil, err
	}
	for _, handle := range r.Handles {
		handler.Register(handle)
	}
	m.Handler = handler

	return m, nil
}
