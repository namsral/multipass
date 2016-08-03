package multipass

import (
	"bytes"
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
	"net/smtp"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/mholt/caddy/caddyhttp/httpserver"

	jose "gopkg.in/square/go-jose.v1"
)

var ErrInvalidToken error = errors.New("invalid token")

type Auth struct {
	*Config
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

type Config struct {
	Resources []string
	Basepath  string
	SiteAddr  string
	Expires   time.Duration

	sender     Sender
	authorizer Authorizer
	signer     jose.Signer
	key        *rsa.PrivateKey
}

func ConfigFromRule(r Rule) (*Config, error) {
	config, err := NewConfig()
	if err != nil {
		return nil, err
	}
	if len(r.Resources) > 0 {
		config.Resources = r.Resources
	}
	if len(r.Basepath) > 0 {
		config.Basepath = r.Basepath
	}
	if r.Expires > 0 {
		config.Expires = r.Expires
	}

	smtpAddr := "localhost:25"
	if len(r.SMTPAddr) > 0 {
		smtpAddr = r.SMTPAddr
	}
	mailTmpl := emailTemplate
	if len(r.MailTmpl) > 0 {
		mailTmpl = r.MailTmpl
	}
	config.sender = NewMailSender(smtpAddr, nil, r.MailFrom, mailTmpl)

	authorizer := &EmailAuthorizer{list: []string{}}
	for _, handle := range r.Handles {
		authorizer.Add(handle)
	}
	config.authorizer = authorizer

	return config, nil
}

func NewConfig() (*Config, error) {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	signer, err := jose.NewSigner(jose.PS512, pk)
	if err != nil {
		return nil, err
	}
	return &Config{
		Resources: []string{"/"},
		Basepath:  "/",
		Expires:   time.Hour * 24,
		key:       pk,
		signer:    signer,
	}, nil
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

// Claims are part of the JSON web token
type Claims struct {
	Handle    string   `json:"handle"`
	Resources []string `json:"resources"`
	Expires   int64    `json:"exp"`
}

func (c *Config) AccessToken(handle string) (tokenStr string, err error) {
	exp := time.Now().Add(c.Expires)
	claims := &Claims{
		Handle:    handle,
		Resources: c.Resources,
		Expires:   exp.Unix(),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	jws, err := c.signer.Sign(payload)
	if err != nil {
		return "", err
	}

	return jws.CompactSerialize()
}

func (c *Config) LoginURL(u url.URL, tokenStr string) url.URL {
	u.Path = path.Join(c.Basepath, "login")
	v := url.Values{}
	v.Set("token", tokenStr)
	u.RawQuery = v.Encode()

	return u
}

func loginHandler(w http.ResponseWriter, r *http.Request, c *Config) (int, error) {
	if r.Method == "POST" {
		r.ParseForm()
		handle := r.PostForm.Get("handle")
		if len(handle) == 0 {
			loc := path.Join(c.Basepath, "login")
			http.Redirect(w, r, loc, http.StatusSeeOther)
			return http.StatusSeeOther, nil
		}
		switch c.authorizer.IsAuthorized(handle) {
		case true:
			token, err := c.AccessToken(handle)
			if err != nil {
				log.Print(err)
			}
			siteURL, err := url.Parse(c.SiteAddr)
			if err != nil {
				log.Fatal(err)
			}
			loginURL := c.LoginURL(*siteURL, token)
			if err := c.sender.Send(handle, loginURL.String()); err != nil {
				log.Print(err)
			}
		}
		w.Header().Add("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte("A login link has been sent to user with handle " + handle + " if your handle is authorized"))
		return http.StatusOK, nil
	}
	if r.Method == "GET" {
		if tokenStr := r.URL.Query().Get("token"); len(tokenStr) > 0 {
			cookie := &http.Cookie{
				Name:  "jwt_token",
				Value: tokenStr,
				Path:  "/",
			}
			http.SetCookie(w, cookie)
			r.URL.Path = ""
			r.URL.RawQuery = ""
			http.Redirect(w, r, r.URL.String(), http.StatusSeeOther)
			return http.StatusSeeOther, nil
		}
		w.Header().Add("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte("<html><body><form action=" + r.URL.Path + " method=POST><input type=text name=handle /><input type=submit></form></body></html>"))
		return http.StatusOK, nil
	}
	return http.StatusMethodNotAllowed, nil
}

func loginformHandler(w http.ResponseWriter, r *http.Request, c *Config) (int, error) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(`
<html><body>
<form action="` + path.Join(c.Basepath, "/login") + `" method=POST>
<input type=hidden name=url value="` + r.URL.String() + `"/>
<input type=text name=handle />
<input type=submit>
</form></body></html>
`))
	return http.StatusOK, nil
}

func signoutHandler(w http.ResponseWriter, r *http.Request, c *Config) (int, error) {
	if cookie, err := r.Cookie("jwt_token"); err == nil {
		cookie.Expires = time.Now().AddDate(-1, 0, 0)
		cookie.MaxAge = -1
		cookie.Path = "/"
		http.SetCookie(w, cookie)
	}
	loc := path.Join(c.Basepath, "login")
	http.Redirect(w, r, loc, http.StatusSeeOther)
	return http.StatusSeeOther, nil
}

func publickeyHandler(w http.ResponseWriter, r *http.Request, c *Config) (int, error) {
	data, err := x509.MarshalPKIXPublicKey(c.key.PublicKey)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: data,
	}
	if err := pem.Encode(w, block); err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}

func tokenHandler(w http.ResponseWriter, r *http.Request, c *Config) (int, error) {
	// Extract token from HTTP header, query parameter or cookie
	tokenStr, err := extractToken(r)
	if err != nil {
		return http.StatusUnauthorized, ErrInvalidToken
	}
	var claims *Claims
	if claims, err = validateToken(tokenStr, c.key.PublicKey); err != nil {
		return http.StatusUnauthorized, ErrInvalidToken
	}
	// Authorize handle claim
	if ok := c.authorizer.IsAuthorized(claims.Handle); !ok {
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
	return http.StatusOK, nil
}

func (a *Auth) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	c := a.Config
	var pathMatch bool
	for _, path := range c.Resources {
		if httpserver.Path(r.URL.Path).Matches(path) {
			pathMatch = true
			continue
		}
	}
	if !pathMatch {
		return a.Next.ServeHTTP(w, r)
	}

	switch r.URL.Path {
	case path.Join(c.Basepath, "pub.cer"):
		return publickeyHandler(w, r, c)
	case path.Join(c.Basepath, "login"):
		return loginHandler(w, r, c)
	case path.Join(c.Basepath, "signout"):
		return signoutHandler(w, r, c)
	default:
		if code, err := tokenHandler(w, r, c); err != nil {
			w.WriteHeader(code)
			return loginformHandler(w, r, c)
		}
	}
	return a.Next.ServeHTTP(w, r)
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

type Authorizer interface {
	IsAuthorized(handle string) bool
	Add(handle string) error
}

type EmailAuthorizer struct {
	lock sync.Mutex
	list []string
}

func (a *EmailAuthorizer) Add(handle string) error {
	a.lock.Lock()
	a.list = append(a.list, handle)
	a.lock.Unlock()
	return nil
}

func (a *EmailAuthorizer) IsAuthorized(handle string) bool {
	a.lock.Lock()
	for _, e := range a.list {
		if e == handle {
			a.lock.Unlock()
			return true
		}
	}
	a.lock.Unlock()
	return false
}

type Sender interface {
	Send(handle, loginURL string) error
}

type MailSender struct {
	auth     smtp.Auth
	addr     string
	from     string
	template *template.Template
}

func NewMailSender(addr string, auth smtp.Auth, from, msgTmpl string) *MailSender {
	t := template.Must(template.New("email").Parse(msgTmpl))
	return &MailSender{
		addr:     addr,
		auth:     auth,
		from:     from,
		template: t,
	}
}

const emailTemplate = `Subject: your access token
From: {{.From}}
To: {{.To}}
Date: {{.Date}}

Hi,

You requested an access token to login.

Follow the link to login {{.Link}}

If you didn't request an access token, please ignore this message.
`

func (s MailSender) Send(handle, link string) error {
	var msg bytes.Buffer
	data := struct {
		From, Date, To, Link string
	}{
		From: s.from,
		Date: time.Now().Format(time.RFC1123Z),
		To:   handle,
		Link: link,
	}
	if err := s.template.ExecuteTemplate(&msg, "email", data); err != nil {
		return err
	}
	return smtp.SendMail(s.addr, s.auth, s.from, []string{handle}, msg.Bytes())
}
