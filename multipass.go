// Copyright 2016 Lars Wiegman. All rights reserved. Use of this source code is
// governed by a BSD-style license that can be found in the LICENSE file.

package multipass

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	jose "gopkg.in/square/go-jose.v1"
)

// Portable errors
var (
	ErrInvalidToken = errors.New("invalid token")
)

// Multipass implements the http.Handler interface which can handle
// authentication and authorization of users and resources using signed JWT.
type Multipass struct {
	Resources []string
	Basepath  string
	SiteAddr  string
	Expires   time.Duration

	HandleService

	signer jose.Signer
	key    *rsa.PrivateKey
	tmpl   *template.Template
	mux    *http.ServeMux
}

// NewMultipass returns a new instance of Multipass with reasonalble defaults
// like a 2048 bit RSA key pair, /multipass as basepath, 24 hours before a
// token will expire.
func NewMultipass(basepath string, service HandleService) (*Multipass, error) {
	// Absolute the given basepath or set a default
	if len(basepath) > 0 {
		basepath = path.Join("/", basepath)
	} else {
		basepath = "/multipass"
	}

	// Generate the RSA key pari
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	signer, err := jose.NewSigner(jose.PS512, pk)
	if err != nil {
		return nil, err
	}

	// Load HTML templates
	tmpl, err := loadTemplates()
	if err != nil {
		return nil, err
	}

	m := &Multipass{
		Resources:     []string{"/"},
		Basepath:      basepath,
		Expires:       time.Hour * 24,
		HandleService: service,
		signer:        signer,
		key:           pk,
		tmpl:          tmpl,
	}

	// Create the router
	mux := http.NewServeMux()
	mux.HandleFunc(path.Join(basepath, "/"), m.rootHandler)
	mux.HandleFunc(path.Join(basepath, "/login"), m.loginHandler)
	mux.HandleFunc(path.Join(basepath, "/confirm"), m.confirmHandler)
	mux.HandleFunc(path.Join(basepath, "/signout"), m.signoutHandler)
	mux.HandleFunc(path.Join(basepath, "/pub.cer"), m.publickeyHandler)
	m.mux = mux

	return m, nil
}

// Claims are part of the JSON web token
type Claims struct {
	Handle    string   `json:"handle"`
	Resources []string `json:"resources"`
	Expires   int64    `json:"exp"`
}

// ServeHTTP satisfies the ServeHTTP interface
func (m *Multipass) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h, p := m.mux.Handler(r); len(p) > 0 {
		h.ServeHTTP(w, r)
		return
	}
	http.NotFound(w, r)
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
			LoginPath:   path.Join(m.Basepath, "login"),
			SignoutPath: path.Join(m.Basepath, "signout"),
		}

		// Show login page when there is no token
		tokenStr, err := extractToken(r)
		if err != nil {
			if s := r.URL.Query().Get("url"); !strings.HasPrefix(s, m.Basepath) {
				p.NextURL = s
			}
			m.tmpl.ExecuteTemplate(w, "page", p)
			return
		}
		var claims *Claims
		if claims, err = validateToken(tokenStr, m.key.PublicKey); err != nil {
			p.Page = tokenInvalidPage
			if s := r.URL.Query().Get("url"); !strings.HasPrefix(s, m.Basepath) {
				p.NextURL = s
			}
			m.tmpl.ExecuteTemplate(w, "page", p)
			return
		}
		// Authorize handle claim
		if ok := m.HandleService.Listed(claims.Handle); !ok {
			p.Page = tokenInvalidPage
			m.tmpl.ExecuteTemplate(w, "page", p)
			return
		}
		if cookie, err := r.Cookie("next_url"); err == nil {
			p.NextURL = cookie.Value
		}
		p.Page = continueOrSignoutPage
		m.tmpl.ExecuteTemplate(w, "page", p)
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
		http.Redirect(w, r, m.Basepath, http.StatusSeeOther)
		return
	}
	if r.Method == "POST" {
		r.ParseForm()
		handle := r.PostForm.Get("handle")
		if len(handle) > 0 {
			if m.HandleService.Listed(handle) {
				token, err := m.AccessToken(handle)
				if err != nil {
					log.Print(err)
				}
				values := url.Values{}
				if s := r.PostForm.Get("url"); len(s) > 0 {
					values.Set("url", s)
				}
				loginURL, err := NewLoginURL(m.SiteAddr, m.Basepath, token, values)
				if err != nil {
					log.Print(err)
				}
				if err := m.HandleService.Notify(handle, loginURL.String()); err != nil {
					log.Print(err)
				}
			}
			// Redirect even when the handle is not listed in order to prevent guessing
			location := path.Join(m.Basepath, "confirm")
			http.Redirect(w, r, location, http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, m.Basepath, http.StatusSeeOther)
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
		m.tmpl.ExecuteTemplate(w, "page", p)
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
		http.Redirect(w, r, m.Basepath, http.StatusSeeOther)
		return
	}
	w.WriteHeader(http.StatusMethodNotAllowed)
}

// publickeyHandler writes the public key to the given ResponseWriter to allow
// other to validate Multipass signed tokens.
func (m *Multipass) publickeyHandler(w http.ResponseWriter, r *http.Request) {
	data, err := x509.MarshalPKIXPublicKey(&m.key.PublicKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: data,
	}
	w.Header().Set("Content-Type", "application/pkix-cert")
	if err := pem.Encode(w, block); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

// AccessToken returns a new signed and serialized token with the given handle
// as a claim.
func (m *Multipass) AccessToken(handle string) (tokenStr string, err error) {
	exp := time.Now().Add(m.Expires)
	claims := &Claims{
		Handle:    handle,
		Resources: m.Resources,
		Expires:   exp.Unix(),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	jws, err := m.signer.Sign(payload)
	if err != nil {
		return "", err
	}

	return jws.CompactSerialize()
}

// NewLoginURL returns a login url which can be used as a time limited login.
// Optional values will be encoded in the login URL.
func NewLoginURL(siteaddr, basepath, token string, v url.Values) (*url.URL, error) {
	u, err := url.Parse(siteaddr)
	if err != nil {
		return u, err
	}
	u.Path = path.Join(basepath, "login")
	v.Set("token", token)
	u.RawQuery = v.Encode()
	return u, nil
}

func tokenHandler(w http.ResponseWriter, r *http.Request, m *Multipass) (int, error) {
	// Extract token from HTTP header, query parameter or cookie
	tokenStr, err := extractToken(r)
	if err != nil {
		return http.StatusUnauthorized, ErrInvalidToken
	}
	var claims *Claims
	if claims, err = validateToken(tokenStr, m.key.PublicKey); err != nil {
		return http.StatusUnauthorized, ErrInvalidToken
	}
	// Authorize handle claim
	if ok := m.HandleService.Listed(claims.Handle); !ok {
		return http.StatusUnauthorized, ErrInvalidToken
	}
	// Verify path claim
	var match bool
	for _, path := range claims.Resources {
		if strings.HasPrefix(r.URL.Path, path) {
			match = true
			continue
		}
	}
	if !match {
		return http.StatusUnauthorized, ErrInvalidToken
	}

	// Pass on authorized handle to downstream handlers
	r.Header.Set("Multipass-Handle", claims.Handle)
	return http.StatusOK, nil
}

// extractToken returns the JWT token embedded in the given request.
// JWT tokens can be embedded in the header prefixed with "Bearer ", with a
// "token" key query parameter or a cookie named "jwt_token".
func extractToken(r *http.Request) (string, error) {
	//from header
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		if len(h) > 7 {
			return h[7:], nil
		}
	}

	//from query parameter
	if token := r.URL.Query().Get("token"); len(token) > 0 {
		return token, nil
	}

	//from cookie
	if cookie, err := r.Cookie("jwt_token"); err == nil {
		return cookie.Value, nil
	}

	return "", fmt.Errorf("no token found")
}

func validateToken(token string, key rsa.PublicKey) (*Claims, error) {
	claims := &Claims{}

	// Verify token signature
	payload, err := verifyToken(token, key)
	if err != nil {
		return nil, err
	}
	// Unmarshal token claims
	if err := json.Unmarshal(payload, claims); err != nil {
		return nil, err
	}
	// Verify expire claim
	if time.Unix(claims.Expires, 0).Before(time.Now()) {
		return nil, errors.New("Token expired")
	}
	return claims, nil
}

// verifyToken returns the payload of the given token when the signature
// can be verified using the given public key.
func verifyToken(token string, key rsa.PublicKey) ([]byte, error) {
	var data []byte

	obj, err := jose.ParseSigned(token)
	if err != nil {
		return data, err
	}
	data, err = obj.Verify(&key)
	if err != nil {
		return data, err
	}
	return data, nil
}

// A HandleService is an interface used by a Multipass instance to register,
// list user handles and notify users about requested access tokens.
// A handle is a unique user identifier, e.g. email address.
type HandleService interface {
	// Register returns nil when the given handle is accepted for
	// registration with the service.
	// The handle is passed on by the Multipass instance and can represent
	// an username, email address or even an URI representing a connection to
	// a datastore. The latter allows the HandleService to be associated
	// with a RDBMS from which to verify listed users.
	Register(handle string) error

	// Listed returns true when the given handle is listed with the
	// service.
	Listed(handle string) bool

	// Notify returns nil when the given login URL is succesfully
	// communicated to the given handle.
	Notify(handle, loginurl string) error
}
