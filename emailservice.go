package multipass

import (
	"bytes"
	"net"
	"net/mail"
	"net/smtp"
	"sync"
	"text/template"
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

// EmailHandleService implements the HandleService interface. Handles are interperted
// as email addresses.
type EmailHandleService struct {
	auth     smtp.Auth
	addr     string
	from     *mail.Address
	Template *template.Template

	lock sync.Mutex
	list []string
}

// EmailHandleOptions is used to construct a new EmailHandler using the
// NewEmailHandler function.
type EmailHandleOptions struct {
	Addr, Username, Password, FromAddr string
}

// NewEmailHandler returns a new EmailHandler instance with the given options.
func NewEmailHandler(opt *EmailHandleOptions) (*EmailHandleService, error) {
	host := "localhost"
	port := "25"
	if len(opt.Addr) > 0 {
		host = opt.Addr
	}
	if h, p, err := net.SplitHostPort(opt.Addr); err == nil {
		host = h
		port = p
	}
	addr := net.JoinHostPort(host, port)

	var auth smtp.Auth
	if len(opt.Username) > 0 && len(opt.Password) > 0 {
		auth = smtp.PlainAuth("", opt.Username, opt.Password, host)
	}

	from, err := mail.ParseAddress(opt.FromAddr)
	if err != nil {
		return nil, err
	}

	t := template.Must(template.New("email").Parse(emailTemplate))

	return &EmailHandleService{
		addr:     addr,
		auth:     auth,
		from:     from,
		Template: t,
	}, nil
}

// Register returns nil when the given address is valid.
func (s *EmailHandleService) Register(handle string) error {
	a, err := mail.ParseAddress(handle)
	if err != nil {
		return err
	}
	s.lock.Lock()
	s.list = append(s.list, a.Address)
	s.lock.Unlock()
	return nil
}

// Listed return true when the given address is listed.
func (s *EmailHandleService) Listed(handle string) bool {
	a, err := mail.ParseAddress(handle)
	if err != nil {
		return false
	}
	s.lock.Lock()
	for _, e := range s.list {
		if e == a.Address {
			s.lock.Unlock()
			return true
		}
	}
	s.lock.Unlock()
	return false
}

// Notify returns nil when the given login URL is succesfully sent to the given
// email address.
func (s *EmailHandleService) Notify(handle, loginurl string) error {
	a, err := mail.ParseAddress(handle)
	if err != nil {
		return err
	}
	var msg bytes.Buffer
	data := struct {
		From, Date, To, LoginURL string
	}{
		From:     s.from.String(),
		Date:     time.Now().Format(time.RFC1123Z),
		To:       a.String(),
		LoginURL: loginurl,
	}
	if err := s.Template.ExecuteTemplate(&msg, "email", data); err != nil {
		return err
	}
	return smtp.SendMail(s.addr, s.auth, s.from.String(), []string{a.Address}, msg.Bytes())
}
