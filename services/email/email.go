// Copyright 2016 Lars Wiegman. All rights reserved. Use of this source code is
// governed by a BSD-style license that can be found in the LICENSE file.

package email

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/mail"
	"os"
	"os/exec"
	"strconv"
	"strings"
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

// Portable errors
var (
	ErrInvalidHandle   = errors.New("invalid handle")
	ErrInvalidResource = errors.New("invalid resource")
	ErrInvalidAddress  = errors.New("invalid address")
)

// UserService implements the UserService interface. Handles are interperted
// as email addresses.
type UserService struct {
	from     *mail.Address
	template *template.Template

	lock      sync.Mutex
	handles   []string
	resources []string

	channel chan *gomail.Message
}

// Options is used to construct a new UserService using the
// NewUserService function.
type Options struct {
	FromAddr                     string
	SMTPAddr, SMTPUser, SMTPPass string
	SMTPClientName               string
	SMTPClientArgs               []string
}

// NewUserService returns a new UserService instance with the given options.
func NewUserService(opt Options) (*UserService, error) {
	s := &UserService{}
	from, err := mail.ParseAddress(opt.FromAddr)
	if err != nil {
		return nil, err
	}
	s.from = from
	s.template = template.Must(template.New("").Parse(msgTmpl))
	s.channel = make(chan *gomail.Message)

	switch opt.SMTPClientName != "" {
	case true:
		go runMSA(s.channel, opt.SMTPClientName, opt.SMTPClientArgs...)
	default:
		host := "localhost"
		port := 25
		if len(opt.SMTPAddr) > 0 {
			host = opt.SMTPAddr
		}
		h, p, err := net.SplitHostPort(opt.SMTPAddr)
		if err == nil {
			host = h
			i, err := strconv.Atoi(p)
			if err != nil {
				return nil, err
			}
			port = i
		}
		go runMTA(s.channel, host, opt.SMTPUser, opt.SMTPPass, port)
	}
	return s, nil
}

// sendmail runs the given named command with arguments and dumps the message
// to standard input. Standard output of the command is returned.
func sendmail(m *gomail.Message, name string, arg ...string) (output []byte, err error) {
	cmd := exec.Command(name, arg...)
	cmd.Stderr = os.Stderr
	buf := new(bytes.Buffer)
	cmd.Stdout, cmd.Stderr = buf, os.Stderr
	w, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	if err = cmd.Start(); err != nil {
		return nil, err
	}
	if _, err := m.WriteTo(w); err != nil {
		return nil, err
	}
	w.Close()
	err = cmd.Wait()
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func runMSA(c chan *gomail.Message, name string, arg ...string) {
	for {
		select {
		case m, ok := <-c:
			if !ok {
				return
			}
			if _, err := sendmail(m, name, arg...); err != nil {
				log.Println(err)
			}
		}
	}
}

func runMTA(c chan *gomail.Message, host, user, pass string, port int) {
	d := gomail.NewDialer(host, port, user, pass)
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
}

// AddResource adds the given resource or resource pattern to be used in
// user authorization.
func (s *UserService) AddResource(value string) error {
	s.lock.Lock()
	n := len(value)
	if n == 0 {
		return ErrInvalidResource
	}
	// If pattern is /tree/, insert a pattern for /tree
	if value[n-1] == '/' {
		s.resources = append(s.resources, value[:n-1])
	}
	s.resources = append(s.resources, value)
	s.lock.Unlock()
	return nil
}

// AddHandle registers the given handle or handle pattern to be used in
// user authorization.
func (s *UserService) AddHandle(value string) error {
	if ok := ValidHandle(value); !ok {
		return ErrInvalidHandle
	}
	s.lock.Lock()
	s.handles = append(s.handles, value)
	s.lock.Unlock()
	return nil
}

// Listed return true when the given address is listed.
func (s *UserService) Listed(handle string) bool {
	a, err := mail.ParseAddress(handle)
	if err != nil {
		return false
	}
	s.lock.Lock()
	for _, pattern := range s.handles {
		if ok := MatchHandle(pattern, a.Address); ok {
			s.lock.Unlock()
			return true
		}
	}
	s.lock.Unlock()
	return false
}

// Authorized returns true when an user identified with the given handle is
// authorized to access the resource at the given rawurl. Unknown resources
// are accessible to listed and unlisted user handlers.
func (s *UserService) Authorized(handle, method, rawurl string) bool {
	for _, pattern := range s.resources {
		if MatchResource(pattern, rawurl) {
			if ok := s.Listed(handle); ok {
				return true
			}
			return false
		}
	}
	return true
}

// Notify returns nil when the given login URL is successfully sent to the given
// email address.
func (s *UserService) Notify(handle, loginurl string) error {
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
		return s.template.ExecuteTemplate(w, "text/plain", data)
	}); err != nil {
		return err
	}
	if m.AddAlternativeWriter("text/html", func(w io.Writer) error {
		return s.template.ExecuteTemplate(w, "text/html", data)
	}); err != nil {
		return err
	}

	s.channel <- m
	return nil
}

// Close closes the channel to send mail messages.
func (s *UserService) Close() error {
	close(s.channel)
	return nil
}

// MatchResource reports wether handle matches the handle pattern.
// The pattern syntax is:
//   '/private'  matches the resources
//   '/private/' matches any resource in the subtree
//   'domain.tld:8080/private/' matches any resource in the subtree with host and port
func MatchResource(pattern, resource string) bool {
	n := len(pattern)
	if n == 0 {
		// should not happen
		return false
	}
	if pattern[n-1] != '/' {
		return pattern == resource
	}
	return len(resource) >= n && resource[0:n] == pattern
}

// SplitLocalDomain splits an email address into local and domain.
func SplitLocalDomain(address string) (local, domain string, err error) {
	a := strings.Split(address, "@")
	if len(a) != 2 {
		return local, domain, ErrInvalidAddress
	}
	local, domain = a[0], a[1]
	if len(local) == 0 || len(domain) == 0 {
		return local, domain, ErrInvalidAddress
	}
	return local, domain, nil
}

// MatchHandle reports wether handle matches the handle pattern.
// The pattern syntax is:
//   'bob@example.com' matches a single address
//   '@example.com'    matches any addresses with domain example.com
//   '@'               matches any address
func MatchHandle(pattern, handle string) bool {
	if len(pattern) == 0 {
		return false
	}
	_, domain, err := SplitLocalDomain(handle)
	if err != nil {
		return false
	}
	if pattern == "@" {
		return true
	}
	if strings.HasPrefix(pattern, "@") {
		return domain == pattern[1:]
	}
	return handle == pattern
}

// ValidHandle reports wether value is a valid handle or handle pattern.
// The pattern syntax is:
//   'bob@example.com' matches a single address
//   '@example.com'    matches any addresses with domain example.com
//   '@'               matches any address
func ValidHandle(value string) bool {
	if len(value) == 0 {
		return false
	}
	a := strings.Split(value, "@")
	if len(a) != 2 {
		return false
	}
	if len(a[0]) > 0 && len(a[1]) == 0 {
		return false
	}
	return true
}
