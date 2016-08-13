// Copyright 2016 Lars Wiegman. All rights reserved. Use of this source code is
// governed by a BSD-style license that can be found in the LICENSE file.

package email

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

// HandleService implements the HandleService interface. Handles are interperted
// as email addresses.
type HandleService struct {
	auth     smtp.Auth
	addr     string
	from     *mail.Address
	Template *template.Template

	lock sync.Mutex
	list []string
}

// HandleOptions is used to construct a new HandleService using the
// NewHandleService function.
type HandleOptions struct {
	Addr, Username, Password, FromAddr string
}

// NewHandleService returns a new HandleService instance with the given options.
func NewHandleService(opt *HandleOptions) (*HandleService, error) {
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

	return &HandleService{
		addr:     addr,
		auth:     auth,
		from:     from,
		Template: t,
	}, nil
}

// Register returns nil when the given address is valid.
func (s *HandleService) Register(handle string) error {
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
func (s *HandleService) Listed(handle string) bool {
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
func (s *HandleService) Notify(handle, loginurl string) error {
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
