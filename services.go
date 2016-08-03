package multipass

import (
	"bytes"
	"html/template"
	"net/smtp"
	"sync"
	"time"
)

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
