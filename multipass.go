// Copyright 2016 Lars Wiegman. All rights reserved. Use of this source code is
// governed by a BSD-style license that can be found in the LICENSE file.

package multipass

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/gorilla/csrf"

	jose "gopkg.in/square/go-jose.v1"
)

// Portable errors
var (
	ErrInvalidToken = errors.New("invalid token")
	ErrForbidden    = errors.New(http.StatusText(http.StatusForbidden))
	ErrUnauthorized = errors.New(http.StatusText(http.StatusUnauthorized))
)

// options contains the optional settings for the Multipass instance.
type options struct {
	Expires  time.Duration
	Basepath string
	Service  UserService
	Template template.Template
	CSRF     bool
}

// Multipass implements the http.Handler interface which can handle
// authentication and authorization of users and resources using signed JWT.
type Multipass struct {
	siteaddr string
	handler  http.Handler
	opts     options
}

// New returns a new instance of Multipass with the given site address.
//
// The site address must point to the absolute base URL of the site.
//
// Multipass is initialized with the following defaults:
//     2048 bit key size
//     /multipass Basepath
//     24h token lifespan
func New(siteaddr string, opts ...Option) *Multipass {
	m := parseOptions(opts...)
	m.siteaddr = siteaddr

	// Generate and set a private key if none is set
	if k, err := PrivateKeyFromEnvironment(); k != nil && err == nil {
		log.Printf("Use private key from environment variable %s\n", PKENV)
	} else {
		key, err := rsa.GenerateKey(rand.Reader, DefaultKeySize)
		if err != nil {
			panic(err)
		}
		buf := new(bytes.Buffer)
		if err := pemEncodePrivateKey(buf, key); err != nil {
			panic(err)
		}
		os.Setenv(PKENV, buf.String())
	}

	switch m.opts.CSRF {
	case false:
		m.handler = http.HandlerFunc(m.routeHandler)
	default:
		m.handler = csrfProtect(http.HandlerFunc(m.routeHandler), m)
	}

	return m
}

// Basepath return the base path.
func (m *Multipass) Basepath() string {
	return m.opts.Basepath
}

// ServeHTTP satisfies the ServeHTTP interface
func (m *Multipass) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.handler.ServeHTTP(w, r)
}

// routeHandler routes request to the appropraite handler.
func (m *Multipass) routeHandler(w http.ResponseWriter, r *http.Request) {
	if s := strings.TrimSuffix(r.URL.Path, "/"); len(r.URL.Path) > len(s) {
		http.Redirect(w, r, s, http.StatusMovedPermanently)
	}

	var fn func(w http.ResponseWriter, r *http.Request)
	if p := strings.TrimPrefix(r.URL.Path, m.opts.Basepath); len(p) < len(r.URL.Path) {
		switch p {
		case "":
			fn = m.rootHandler
		case "/login":
			fn = m.loginHandler
		case "/signout":
			fn = m.signoutHandler
		case "/confirm":
			fn = m.confirmHandler
		case "/pub.cer":
			fn = m.publicKeyHandler
		}
	}
	if fn == nil {
		fn = func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(404)
			p := &page{
				Page: notfoundPage,
			}
			m.opts.Template.ExecuteTemplate(w, "page", p)
		}
	}
	fn(w, r)
}

// csrfProtect wraps the given http.Handler to protect against CSRF attacks.
// The CSRF key is persisted in the enviroment to not break CSRF
// validation between application restarts.
func csrfProtect(h http.Handler, m *Multipass) http.Handler {
	key, err := base64.StdEncoding.DecodeString(os.Getenv("MULTIPASS_CSRF_KEY"))
	if err != nil || len(key) != 32 {
		key = make([]byte, 32)
		_, err := rand.Read(key)
		if err != nil {
			panic(err)
		}
		// Persist key on reloads
		os.Setenv("MULTIPASS_CSRF_KEY", base64.StdEncoding.EncodeToString(key))
	}

	errorHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		p := &page{
			Page:         errorPage,
			ErrorMessage: "Sorry, your CSRF token is invalid",
		}
		m.opts.Template.ExecuteTemplate(w, "page", p)
	})

	opts := []csrf.Option{
		csrf.Secure(os.Getenv("MULTIPASS_DEV") == ""),
		csrf.Path(m.opts.Basepath),
		csrf.FieldName("csrf.token"),
		csrf.ErrorHandler(errorHandler),
	}

	return csrf.Protect(key, opts...)(h)
}

// rootHandler handles the "/" path of the Multipass handler.
// Shows login page when no JWT present
// Show continue or signout page when JWT is valid
// Show token invalid page when JWT is invalid
func (m *Multipass) rootHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {

		// Regular login page
		p := &page{
			Page:        loginPage,
			LoginPath:   path.Join(m.opts.Basepath, "login"),
			SignoutPath: path.Join(m.opts.Basepath, "signout"),
			CSRFField:   csrf.TemplateField(r),
		}

		// Show login page when there is no token
		tokenStr := GetTokenRequest(r)
		if len(tokenStr) == 0 {
			if s := r.URL.Query().Get("url"); !strings.HasPrefix(s, m.opts.Basepath) {
				p.NextURL = s
			}
			m.opts.Template.ExecuteTemplate(w, "page", p)
			return
		}
		pk, err := PrivateKeyFromEnvironment()
		if err != nil || pk == nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		claims, err := validateToken(tokenStr, pk.PublicKey)
		if err != nil {
			p.Page = tokenInvalidPage
			if s := r.URL.Query().Get("url"); !strings.HasPrefix(s, m.opts.Basepath) {
				p.NextURL = s
			}
			m.opts.Template.ExecuteTemplate(w, "page", p)
			return
		}
		// Authorize handle claim
		if ok := m.opts.Service.Listed(claims.Handle); !ok {
			p.Page = tokenInvalidPage
			m.opts.Template.ExecuteTemplate(w, "page", p)
			return
		}
		if cookie, err := r.Cookie("next_url"); err == nil {
			p.NextURL = cookie.Value
		}
		p.Page = continueOrSignoutPage
		m.opts.Template.ExecuteTemplate(w, "page", p)
		return
	}
	w.WriteHeader(http.StatusMethodNotAllowed)
}

func (m *Multipass) loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		if tokenStr := r.URL.Query().Get("token"); len(tokenStr) > 0 {
			cookie := &http.Cookie{
				Name:  "jwt_token",
				Value: tokenStr,
				Path:  "/",
			}
			http.SetCookie(w, cookie)
		}
		if nexturl := r.URL.Query().Get("url"); len(nexturl) > 0 {
			cookie := &http.Cookie{
				Name:  "next_url",
				Value: nexturl,
				Path:  "/",
			}
			http.SetCookie(w, cookie)
		}
		http.Redirect(w, r, m.opts.Basepath, http.StatusSeeOther)
		return
	}
	if r.Method == "POST" {
		r.ParseForm()
		handle := r.PostForm.Get("handle")
		if len(handle) > 0 {
			if m.opts.Service.Listed(handle) {
				token, err := m.AccessToken(handle)
				if err != nil {
					log.Print(err)
				}
				values := url.Values{}
				if s := r.PostForm.Get("url"); len(s) > 0 {
					values.Set("url", s)
				}
				loginURL, err := NewLoginURL(m.siteaddr, m.opts.Basepath, token, values)
				if err != nil {
					log.Print(err)
				}
				if err := m.opts.Service.Notify(handle, loginURL.String()); err != nil {
					log.Print(err)
				}
			}
			// Redirect even when the handle is not listed in order to prevent guessing
			location := path.Join(m.opts.Basepath, "confirm")
			http.Redirect(w, r, location, http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, m.opts.Basepath, http.StatusSeeOther)
		return
	}
	w.WriteHeader(http.StatusMethodNotAllowed)
}

func (m *Multipass) confirmHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		w.Header().Add("Content-Type", "text/html; charset=utf-8")
		p := &page{
			Page: tokenSentPage,
		}
		m.opts.Template.ExecuteTemplate(w, "page", p)
		return
	}
	w.WriteHeader(http.StatusMethodNotAllowed)
}

// signoutHandler deletes the jwt_token cookie and redirect to the login
// location.
func (m *Multipass) signoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		if cookie, err := r.Cookie("jwt_token"); err == nil {
			cookie.Expires = time.Now().AddDate(-1, 0, 0)
			cookie.MaxAge = -1
			cookie.Path = "/"
			http.SetCookie(w, cookie)
		}
		http.Redirect(w, r, m.opts.Basepath, http.StatusSeeOther)
		return
	}
	w.WriteHeader(http.StatusMethodNotAllowed)
}

// publicKeyHandler writes the public key to the given ResponseWriter to allow
// other to validate Multipass signed tokens.
func (m *Multipass) publicKeyHandler(w http.ResponseWriter, r *http.Request) {
	key, err := PrivateKeyFromEnvironment()
	if err != nil || key == nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
	err = pemEncodePublicKey(w, &key.PublicKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
	w.Header().Set("Content-Type", "application/pkix-cert")
}

// AccessToken returns a new signed and serialized token with the given handle
// as a claim.
func (m *Multipass) AccessToken(handle string) (tokenStr string, err error) {
	claims := &Claims{
		Handle:  handle,
		Expires: time.Now().Add(m.opts.Expires).Unix(),
	}
	key, err := PrivateKeyFromEnvironment()
	if err != nil || key == nil {
		return "", err
	}
	signer, err := jose.NewSigner(jose.PS512, key)
	if err != nil {
		return "", err
	}
	return accessToken(signer, claims)
}

// NewLoginURL returns a login url which can be used as a time limited login.
// Optional values will be encoded in the login URL.
func NewLoginURL(siteaddr, Basepath, token string, v url.Values) (*url.URL, error) {
	u, err := url.Parse(siteaddr)
	if err != nil {
		return u, err
	}
	u.Path = path.Join(Basepath, "login")
	v.Set("token", token)
	u.RawQuery = v.Encode()
	return u, nil
}

// ResourceHandler validates the token in the request before it writes the response.
// It adds the user handle if the user is authenticated and signs the any
// Multipass specific headers.
func ResourceHandler(w http.ResponseWriter, r *http.Request, m *Multipass) (int, error) {
	var key *rsa.PrivateKey
	var handle string
	var header = make(http.Header)

	token := GetTokenRequest(r)
	if len(token) > 0 {
		k, err := PrivateKeyFromEnvironment()
		if err != nil || k == nil {
			return http.StatusInternalServerError, errors.New("parsing private key from env failed")
		}
		key = k
		claims, err := validateToken(token, key.PublicKey)
		if err == nil {
			handle = claims.Handle
			header.Add("Multipass-Handle", handle)
		}
	}
	// Verify if user identified by handle is authorized to access resource
	if ok := m.opts.Service.Authorized(handle, r.Method, r.URL.String()); !ok {
		if handle == "" && token != "" {
			return http.StatusForbidden, ErrInvalidToken
		}
		if handle == "" {
			w.Header().Set("Www-Authenticate", "Bearer token_type=\"JWT\"")
			return http.StatusUnauthorized, ErrUnauthorized
		}
		return http.StatusForbidden, ErrForbidden
	}
	// Sign header
	if len(header) > 0 {
		if key == nil {
			key, err := PrivateKeyFromEnvironment()
			if err != nil || key == nil {
				return http.StatusInternalServerError, errors.New("parsing private key from env failed")
			}
		}
		SignHeader(header, key)
		copyHeader(r.Header, header)
	}
	// Pass on authorized handle to downstream handlers
	return http.StatusOK, nil
}

// AuthHandler wraps any http.Handler to provide authentication using the
// given Multipass instance.
// Handlers from other http routers can be wrapped with little effort by
// copying the AuthHandler and make minor changes.
func AuthHandler(next http.Handler, m *Multipass) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		if ok := strings.HasPrefix(r.URL.Path, m.Basepath()); ok {
			m.ServeHTTP(w, r)
			return
		}
		if _, err := ResourceHandler(w, r, m); err != nil {
			v := url.Values{"url": []string{r.URL.String()}}
			u := &url.URL{
				Path:     m.Basepath(),
				RawQuery: v.Encode(),
			}
			location := u.String()
			http.Redirect(w, r, location, http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

// UserService is an interface used by the Multipass instance to query about
// listed handles, authorized resource access and to notify users about login
// urls. A handle is a unique user identifier, e.g. username, email address.
type UserService interface {
	// Listed returns true when the given handle is listed with the
	// service.
	Listed(handle string) bool

	// Authorized returns true when the user identified by the given handle is
	// authorized to access the given resource at rawurl with the given method.
	Authorized(handle, method, rawurl string) bool

	// Notify returns nil when the given login URL is successfully
	// communicated to the given handle.
	Notify(handle, loginurl string) error

	// Close closes any open connections.
	Close() error
}
