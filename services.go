package multipass

import (
	"bytes"
	"errors"
	"html/template"
	"net/smtp"
	"regexp"
	"sync"
	"time"
)

const emailTemplate = `Subject: Multipass login
From: {{.From}}
To: {{.To}}
Date: {{.Date}}

Hi,

You requested a Multipass access token. Please follow the link to login:

	{{.LoginURL}}

Didn't request an access token? Please ignore this message, no harm done.


Best,

Multipass Bot
`

// Validation error(s)
var (
	ErrNotEmail = errors.New(`expecting a valid email address ^[^@\s]+@[^@\s]+$`)
)

// Validation rule(s)
var (
	RuleEmail = regexp.MustCompile(`^[^@\s]+@[^@\s]+$`)
)

// A HandleService interface is used by a Multipass instance to verify
// listed user handles and send the users a login URL when they request an
// access token.
type HandleService interface {
	// Register returns nil when the given handle is accepted for
	// registration with the service.
	// The handle is passed on by the Multipass instance and can represent
	// an user handle, an email address or even a handle representing a URI to
	// a datastore. The latter allows the HandleService to be associated
	// with a RDBMS.
	Register(handle string) error

	// Listed returns true when the given handle is listed with the
	// service.
	Listed(handle string) bool

	// Notify returns nil when the given login URL is succesfully
	// communicated to the given handle.
	Notify(handle, loginurl string) error
}

// EmailHandler implements the HandleService interface. Handles are interperted
// as email addresses.
type EmailHandler struct {
	auth     smtp.Auth
	addr     string
	from     string
	template *template.Template

	lock sync.Mutex
	list []string
}

// NewEmailHandler return a new EmailHandler instance with the given options.
func NewEmailHandler(addr string, auth smtp.Auth, from, msgTmpl string) *EmailHandler {
	t := template.Must(template.New("email").Parse(msgTmpl))
	return &EmailHandler{
		addr:     addr,
		auth:     auth,
		from:     from,
		template: t,
	}
}

// Register returns nil when the given email address is valid.
func (s *EmailHandler) Register(email string) error {
	if RuleEmail.MatchString(email) == false {
		return ErrNotEmail
	}
	s.lock.Lock()
	s.list = append(s.list, email)
	s.lock.Unlock()
	return nil
}

// Listed return true when the given email address is listed.
func (s *EmailHandler) Listed(email string) bool {
	s.lock.Lock()
	for _, e := range s.list {
		if e == email {
			s.lock.Unlock()
			return true
		}
	}
	s.lock.Unlock()
	return false
}

// Notify returns nil when the given login URL is succesfully sent to the given
// email address.
func (s *EmailHandler) Notify(email, loginurl string) error {
	if RuleEmail.MatchString(email) == false {
		return ErrNotEmail
	}
	var msg bytes.Buffer
	data := struct {
		From, Date, To, LoginURL string
	}{
		From:     s.from,
		Date:     time.Now().Format(time.RFC1123Z),
		To:       email,
		LoginURL: loginurl,
	}
	if err := s.template.ExecuteTemplate(&msg, "email", data); err != nil {
		return err
	}
	return smtp.SendMail(s.addr, s.auth, s.from, []string{email}, msg.Bytes())
}
