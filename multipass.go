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

	"github.com/mholt/caddy/caddyhttp/httpserver"

	jose "gopkg.in/square/go-jose.v1"
)

var ErrInvalidToken = errors.New("invalid token")

type Auth struct {
	*Multipass
	Next httpserver.Handler
}

type Rule struct {
	Basepath  string
	Expires   time.Duration
	Resources []string
	Handles   []string

	SMTPAddr, SMTPUser, SMTPPass string
	MailFrom, MailTmpl           string
}

type Multipass struct {
	Resources []string
	Basepath  string
	SiteAddr  string
	Expires   time.Duration

	Handler HandleService
	signer  jose.Signer
	key     *rsa.PrivateKey
	tmpl    *template.Template
}

func NewMultipassFromRule(r Rule) (*Multipass, error) {
	m, err := NewMultipass()
	if err != nil {
		return nil, err
	}
	if len(r.Resources) > 0 {
		m.Resources = r.Resources
	}
	if len(r.Basepath) > 0 {
		m.Basepath = path.Join("/", r.Basepath)
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

	tmpl, err := loadTemplates()
	if err != nil {
		return nil, err
	}
	m.tmpl = tmpl

	return m, nil
}

func NewMultipass() (*Multipass, error) {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	signer, err := jose.NewSigner(jose.PS512, pk)
	if err != nil {
		return nil, err
	}
	return &Multipass{
		Resources: []string{"/"},
		Basepath:  "/",
		Expires:   time.Hour * 24,
		key:       pk,
		signer:    signer,
	}, nil
}

// Claims are part of the JSON web token
type Claims struct {
	Handle    string   `json:"handle"`
	Resources []string `json:"resources"`
	Expires   int64    `json:"exp"`
}

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

func loginHandler(w http.ResponseWriter, r *http.Request, m *Multipass) (int, error) {
	if r.Method == "POST" {
		r.ParseForm()
		handle := r.PostForm.Get("handle")
		if len(handle) > 0 {
			if m.Handler.Listed(handle) {
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
				if err := m.Handler.Notify(handle, loginURL.String()); err != nil {
					log.Print(err)
				}
			}
			// Redirect even when the handle is not listed to prevent guessing
			location := path.Join(m.Basepath, "login/confirm")
			http.Redirect(w, r, location, http.StatusSeeOther)
			return http.StatusSeeOther, nil
		}
		var location string
		if s := r.PostForm.Get("url"); len(s) > 0 {
			location = s
		} else {
			location = path.Join(m.Basepath, "login")
		}
		http.Redirect(w, r, location, http.StatusSeeOther)
		return http.StatusSeeOther, nil
	}
	if r.Method == "GET" {
		if tokenStr := r.URL.Query().Get("token"); len(tokenStr) > 0 {
			cookie := &http.Cookie{
				Name:  "jwt_token",
				Value: tokenStr,
				Path:  "/",
			}
			http.SetCookie(w, cookie)
			nexturl := r.URL.Query().Get("url")
			if len(nexturl) == 0 || httpserver.Path(nexturl).Matches(m.Basepath) {
				nexturl = m.SiteAddr
			}
			p := &page{
				Page:        continueOrSignoutPage,
				SignoutPath: path.Join(m.Basepath, "signout"),
				NextURL:     nexturl,
			}
			m.tmpl.ExecuteTemplate(w, "page", p)
			return http.StatusOK, nil
		}
		p := &page{
			Page:        loginPage,
			LoginPath:   path.Join(m.Basepath, "login"),
			NextURL:     r.URL.String(),
			SignoutPath: path.Join(m.Basepath, "signout"),
		}
		m.tmpl.ExecuteTemplate(w, "page", p)
		return http.StatusOK, nil
	}
	return http.StatusMethodNotAllowed, nil
}

func confirmHandler(w http.ResponseWriter, r *http.Request, m *Multipass) (int, error) {
	w.Header().Add("Content-Type", "text/html; charset=utf-8")
	p := &page{
		Page: tokenSentPage,
	}
	m.tmpl.ExecuteTemplate(w, "page", p)
	return http.StatusOK, nil
}

func signoutHandler(w http.ResponseWriter, r *http.Request, m *Multipass) (int, error) {
	if r.Method == "POST" {
		if cookie, err := r.Cookie("jwt_token"); err == nil {
			cookie.Expires = time.Now().AddDate(-1, 0, 0)
			cookie.MaxAge = -1
			cookie.Path = "/"
			http.SetCookie(w, cookie)
		}
		loc := path.Join(m.Basepath, "login")
		http.Redirect(w, r, loc, http.StatusSeeOther)
		return http.StatusSeeOther, nil
	}
	return http.StatusMethodNotAllowed, nil
}

func publickeyHandler(w http.ResponseWriter, r *http.Request, m *Multipass) (int, error) {
	data, err := x509.MarshalPKIXPublicKey(&m.key.PublicKey)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: data,
	}
	w.Header().Set("Content-Type", "application/pkix-cert")
	if err := pem.Encode(w, block); err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
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
	if ok := m.Handler.Listed(claims.Handle); !ok {
		return http.StatusUnauthorized, ErrInvalidToken
	}
	// Verify path claim
	var match bool
	for _, path := range claims.Resources {
		if httpserver.Path(r.URL.Path).Matches(path) {
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

func (a *Auth) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	m := a.Multipass

	if httpserver.Path(r.URL.Path).Matches(m.Basepath) {
		switch r.URL.Path {
		case path.Join(m.Basepath, "pub.cer"):
			return publickeyHandler(w, r, m)
		case path.Join(m.Basepath, "login"):
			return loginHandler(w, r, m)
		case path.Join(m.Basepath, "login/confirm"):
			return confirmHandler(w, r, m)
		case path.Join(m.Basepath, "signout"):
			return signoutHandler(w, r, m)
		default:
			return http.StatusNotFound, nil
		}
	}

	for _, path := range m.Resources {
		if httpserver.Path(r.URL.Path).Matches(path) {
			if _, err := tokenHandler(w, r, m); err != nil {
				return loginHandler(w, r, m)
			}
		}
	}

	return a.Next.ServeHTTP(w, r)
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
