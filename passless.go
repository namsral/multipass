package passless

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/smtp"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"

	jose "gopkg.in/square/go-jose.v1"
)

const directive = "passless"

// Add directive to caddy source code
// source: github.com/mholt/caddy/caddyhttp/httpserver/plugin.go
func init() {
	caddy.RegisterPlugin(directive, caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

func setup(c *caddy.Controller) error {
	parse(c)
	c.OnStartup(func() error {
		fmt.Println(directive + " is intialized")
		return nil
	})

	h, err := NewConfig()
	if err != nil {
		return err
	}
	//h.sender = &logSender{template: "test"}
	h.sender = NewMailSender("hello@example.com", "localhost:2525", nil)
	h.authorizer = NewEmailAuthorizer()
	for _, e := range []string{"lisa@example.com", "bart@example.com"} {
		if err := h.authorizer.Add(e); err != nil {
			return err
		}
	}
	cfg := httpserver.GetConfig(c)
	mid := func(next httpserver.Handler) httpserver.Handler {
		h.Next = next
		return h
	}
	cfg.AddMiddleware(mid)

	return nil
}

func parse(c *caddy.Controller) {
	for c.Next() {
		args := c.RemainingArgs()
		for c.NextBlock() {
			fmt.Println("passless dir value", c.Val(), args)
		}
	}
}

type Authorizer interface {
	IsAuthorized(handle string) bool
	Add(handle string) error
}

func NewEmailAuthorizer() *EmailAuthorizer {
	auth := &EmailAuthorizer{}
	auth.list = []string{}

	return auth
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
	template string
}

func NewMailSender(from, addr string, auth smtp.Auth) *MailSender {
	return &MailSender{
		auth: auth,
		from: from,
		addr: addr,
	}
}

func (s MailSender) Send(handle, loginStr string) error {
	var body string
	switch len(s.template) > 0 {
	case true:
		body = fmt.Sprintf(s.template, handle, loginStr)
	default:
		body = fmt.Sprintf("handle: %s\nurl: %s", handle, loginStr)
	}
	dateH := "Date: " + time.Now().Format(time.RFC1123Z)
	subjectH := "Subject: your login link"
	fromH := "From: " + s.from
	toH := "To: " + handle
	msg := strings.Join([]string{dateH, subjectH, fromH, toH, "", body}, "\n")

	return smtp.SendMail(s.addr, s.auth, s.from, []string{handle}, []byte(msg))
}

type logSender struct {
	template string
}

func (s logSender) Send(handle, loginStr string) error {
	log.Println("handle:", handle, "login:", loginStr)
	return nil
}

type Config struct {
	sender     Sender
	authorizer Authorizer
	signer     jose.Signer
	privateKey *rsa.PrivateKey

	loginPath   string
	signoutPath string

	Next httpserver.Handler
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
		privateKey:  pk,
		signer:      signer,
		loginPath:   "/passless/login",
		signoutPath: "/passless/signout",
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

func verify(token string, pk rsa.PublicKey) ([]byte, error) {
	var data []byte

	obj, err := jose.ParseSigned(token)
	if err != nil {
		return data, err
	}
	data, err = obj.Verify(&pk)
	if err != nil {
		return data, err
	}
	return data, nil
}

type loginClaims struct {
	Handle  string `json:"handle"`
	Expires int64  `json:"exp"`
}

func (c *Config) newLoginLink(handle string, exp time.Time, urlStr string) (string, error) {
	claims := &loginClaims{
		Handle:  handle,
		Expires: exp.Unix(),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	jws, err := c.signer.Sign(payload)
	if err != nil {
		return "", err
	}

	v := url.Values{}

	tokenStr, err := jws.CompactSerialize()
	if err != nil {
		return "", err
	}
	v.Set("token", tokenStr)
	u, err := url.Parse(urlStr)
	if err != nil {
		return "", err
	}
	u.Path = c.loginPath
	u.RawQuery = v.Encode()

	return u.String(), nil
}

func publicKeyWriter(w io.Writer, pk *rsa.PublicKey) error {
	data, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		return err
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: data,
	}
	if err := pem.Encode(w, block); err != nil {
		return err
	}
	return nil
}

func (c *Config) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	switch r.URL.Path {
	case "/passless/pub.cer":
		if err := publicKeyWriter(w, &c.privateKey.PublicKey); err != nil {
			return http.StatusInternalServerError, err
		}
		return http.StatusOK, nil
	case c.loginPath:
		if r.Method == "POST" {
			r.ParseForm()
			handle := r.PostForm.Get("handle")
			if len(handle) == 0 {
				http.Redirect(w, r, c.loginPath, http.StatusSeeOther)
				return http.StatusSeeOther, nil
			}
			switch c.authorizer.IsAuthorized(handle) {
			case true:
				exp := time.Now().Add(time.Hour * 12)
				urlStr, err := c.newLoginLink(handle, exp, r.URL.String())
				if err != nil {
					log.Print(err)
				}
				if err := c.sender.Send(handle, urlStr); err != nil {
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
			w.Write([]byte("<html><body><form action=" + r.URL.Path + " method=POST><input type=text name=handle /><input type=submit></form></body></html>"))
			return http.StatusCreated, nil
		}
		return http.StatusMethodNotAllowed, nil
	case c.signoutPath:
		if cookie, err := r.Cookie("jwt_token"); err == nil {
			cookie.Expires = time.Now().AddDate(-1, 0, 0)
			cookie.MaxAge = -1
			cookie.Path = "/"
			http.SetCookie(w, cookie)
		}
		http.Redirect(w, r, c.loginPath, http.StatusSeeOther)
		return http.StatusSeeOther, nil
	}
	// Extract token from HTTP header, query parameter or cookie
	tokenStr, err := extractToken(r)
	if err != nil {
		return http.StatusUnauthorized, err
	}
	// Verify token signature
	payload, err := verify(tokenStr, c.privateKey.PublicKey)
	if err != nil {
		return http.StatusUnauthorized, err
	}
	// Unmarshal token claims
	claims := &loginClaims{}
	if err := json.Unmarshal(payload, claims); err != nil {
		return http.StatusUnauthorized, err
	}
	// Verify expire claim
	if time.Unix(claims.Expires, 0).Before(time.Now()) {
		return http.StatusForbidden, nil
	}
	// Authorize handle claim
	if ok := c.authorizer.IsAuthorized(claims.Handle); !ok {
		return http.StatusForbidden, nil
	}
	return c.Next.ServeHTTP(w, r)
}
