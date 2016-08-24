// Copyright 2016 Lars Wiegman. All rights reserved. Use of this source code is
// governed by a BSD-style license that can be found in the LICENSE file.

package email

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/mail"
	"strconv"
	"sync"
	"text/template"
	"time"

	"gopkg.in/gomail.v2"
)

const msgTmpl = `
{{ define "text/plain" }}
Hi,

You requested a Multipass access token. Please follow the link to login.

	{{.LoginURL}}

Didn't request an access token? Please ignore this message, no harm done.

Be secure,

Multipass Bot
{{ end }}

{{ define "text/html" }}
<p>Hi,<p>

<p>You requested a Multipass access token. Please follow the link to login.</p>

<p><a href="{{.LoginURL}}">Multipass Login Link</a></p>

<p>Didn't request an access token? Please ignore this message, no harm done.</p>

<p>Be secure,</p>

<p>Multipass Bot</p>
{{ end }}
`

// HandleService implements the HandleService interface. Handles are interperted
// as email addresses.
type HandleService struct {
	from     *mail.Address
	Template *template.Template

	lock    sync.Mutex
	handles []string

	channel chan *gomail.Message
	dialer  *gomail.Dialer
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

	from, err := mail.ParseAddress(opt.FromAddr)
	if err != nil {
		return nil, err
	}

	t := template.Must(template.New("").Parse(msgTmpl))
	c := make(chan *gomail.Message)
	p, err := strconv.Atoi(port)
	if err != nil {
		return nil, err
	}
	d := gomail.NewDialer(host, p, opt.Username, opt.Password)

	go func() {
		var s gomail.SendCloser
		var err error
		open := false
		for {
			select {
			case m, ok := <-c:
				if !ok {
					return
				}
				if !open {
					if s, err = d.Dial(); err != nil {
						panic(err)
					}
					open = true
				}
				if err := gomail.Send(s, m); err != nil {
					log.Print(err)
				}
			case <-time.After(60 * time.Second):
				if open {
					if err := s.Close(); err != nil {
						log.Print(err)
					}
					open = false
				}
			}
		}
	}()

	s := &HandleService{
		from:     from,
		Template: t,
		channel:  c,
		dialer:   d,
	}

	return s, nil
}

// Register returns nil when the given address is valid.
func (s *HandleService) Register(handle string) error {
	a, err := mail.ParseAddress(handle)
	if err != nil {
		return err
	}
	s.lock.Lock()
	s.handles = append(s.handles, a.Address)
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
	for _, e := range s.handles {
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
	toAddr, err := mail.ParseAddress(handle)
	if err != nil {
		return err
	}

	m := gomail.NewMessage()
	m.SetHeader("From", s.from.String())
	m.SetHeader("Return-Path", fmt.Sprintf("<%s>", s.from.Address))
	m.SetHeader("To", toAddr.String())
	m.SetHeader("Date", time.Now().Format(time.RFC1123Z))
	m.SetHeader("Subject", "Multipass Login")

	data := struct{ LoginURL string }{LoginURL: loginurl}
	if m.AddAlternativeWriter("text/plain", func(w io.Writer) error {
		return s.Template.ExecuteTemplate(w, "text/plain", data)
	}); err != nil {
		return err
	}
	if m.AddAlternativeWriter("text/html", func(w io.Writer) error {
		return s.Template.ExecuteTemplate(w, "text/html", data)
	}); err != nil {
		return err
	}

	s.channel <- m
	return nil
}

// Close closes the channel to send mail messages.
func (s *HandleService) Close() error {
	close(s.channel)
	return nil
}
