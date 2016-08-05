package multipass

import (
	"bytes"
	"html/template"
	"net/smtp"
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

// HandleService implements the handle service
type HandleService interface {
	// Register returns nil when the given user handle is accepted for
	// registration with the service
	Register(handle string) error

	// Listed return true when the given user handle is listed with the
	// service
	Listed(handle string) bool

	// Notify return nul when the the given login link is succesfully
	// communicated to the given user handle
	Notify(handle, loginurl string) error
}

type EmailHandler struct {
	auth     smtp.Auth
	addr     string
	from     string
	template *template.Template

	lock sync.Mutex
	list []string
}

func NewEmailHandler(addr string, auth smtp.Auth, from, msgTmpl string) *EmailHandler {
	t := template.Must(template.New("email").Parse(msgTmpl))
	return &EmailHandler{
		addr:     addr,
		auth:     auth,
		from:     from,
		template: t,
	}
}

func (s *EmailHandler) Register(handle string) error {
	s.lock.Lock()
	s.list = append(s.list, handle)
	s.lock.Unlock()
	return nil
}

func (s *EmailHandler) Listed(handle string) bool {
	s.lock.Lock()
	for _, e := range s.list {
		if e == handle {
			s.lock.Unlock()
			return true
		}
	}
	s.lock.Unlock()
	return false
}

func (s *EmailHandler) Notify(handle, loginurl string) error {
	var msg bytes.Buffer
	data := struct {
		From, Date, To, LoginURL string
	}{
		From:     s.from,
		Date:     time.Now().Format(time.RFC1123Z),
		To:       handle,
		LoginURL: loginurl,
	}
	if err := s.template.ExecuteTemplate(&msg, "email", data); err != nil {
		return err
	}
	return smtp.SendMail(s.addr, s.auth, s.from, []string{handle}, msg.Bytes())
}
