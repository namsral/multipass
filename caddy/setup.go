// Copyright 2016 Lars Wiegman. All rights reserved. Use of this source code is
// governed by a BSD-style license that can be found in the LICENSE file.

package multipass

// Add the multipass directive to the caddy source in order to build the plugin.
// source: github.com/mholt/caddy/caddyhttp/httpserver/plugin.go

import (
	"fmt"
	"path"
	"time"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
	"github.com/namsral/multipass"
	"github.com/namsral/multipass/services/email"
)

const directive = "multipass"

func init() {
	caddy.RegisterPlugin(directive, caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

func setup(c *caddy.Controller) error {
	cfg := httpserver.GetConfig(c)
	c.OnStartup(func() error {
		fmt.Printf("%s for %s is initialized\n", directive, cfg.Addr.String())
		return nil
	})

	rules, err := parse(c)
	if err != nil || len(rules) != 1 {
		return c.Err("invalid directive")
	}
	rule := rules[0]

	// Read mail template
	var mailtmpl string
	if s := path.Clean(rule.MailTmpl); len(s) > 0 {
		if path.IsAbs(s) {
			mailtmpl = s
		} else {
			mailtmpl = path.Join(cfg.Root, s)
		}
	}

	// Create an email UserService
	service, err := email.NewUserService(email.Options{
		SMTPAddr:       rule.SMTPAddr,
		SMTPUser:       rule.SMTPUser,
		SMTPPass:       rule.SMTPPass,
		FromAddr:       rule.MailFrom,
		SMTPClientName: rule.SMTPClientName,
		SMTPClientArgs: rule.SMTPClientArgs,
		MailTemplate:   mailtmpl,
	})
	if err != nil {
		return err
	}
	for _, v := range rule.Handles {
		if err := service.AddHandle(v); err != nil {
			return err
		}
	}
	if len(rule.Resources) > 0 {
		for _, v := range rule.Resources {
			if err := service.AddResource(v); err != nil {
				return err
			}
		}
	} else {
		service.AddResource("/")
	}

	opts := []multipass.Option{multipass.Service(service)}
	if len(rule.Basepath) > 0 {
		opts = append(opts, multipass.Basepath(rule.Basepath))
	}
	if rule.Expires > 0 {
		opts = append(opts, multipass.Expires(rule.Expires))
	}
	m := multipass.New(cfg.Addr.String(), opts...)

	mid := func(next httpserver.Handler) httpserver.Handler {
		return &Auth{
			Multipass: m,
			Next:      next,
		}
	}
	cfg.AddMiddleware(mid)

	c.OnShutdown(func() error {
		//TODO: Fix close method on private field
		// return multipass.UserService.Close()
		return nil
	})

	return nil
}

func parse(c *caddy.Controller) ([]Rule, error) {
	var rules []Rule
	for c.Next() {
		var rule Rule
		switch len(c.RemainingArgs()) {
		case 0:
			for c.NextBlock() {
				switch c.Val() {
				case "resources":
					args := c.RemainingArgs()
					rule.Resources = args
				case "basepath":
					args := c.RemainingArgs()
					if len(args) != 1 {
						return rules, c.Err("Expecting a single basepath")
					}
					rule.Basepath = args[0]
				case "handles":
					args := c.RemainingArgs()
					if len(args) <= 0 {
						return rules, c.Err("Expecting at least one handle")
					}
					rule.Handles = args
				case "expires":
					args := c.RemainingArgs()
					if len(args) != 1 {
						return rules, c.Err("Expecting a single Go formatted time duration")
					}
					d, err := time.ParseDuration(args[0])
					if err != nil {
						return rules, c.Err("Expecting a single Go formatted time duration")
					}
					rule.Expires = d
				case "smtp_addr":
					args := c.RemainingArgs()
					if len(args) != 1 {
						return rules, c.Err("Expecting a single SMTP server address")
					}
					rule.SMTPAddr = args[0]
				case "smtp_user":
					args := c.RemainingArgs()
					if len(args) != 1 {
						return rules, c.Err("Expecting a single SMTP username")
					}
					rule.SMTPUser = args[0]
				case "smtp_pass":
					args := c.RemainingArgs()
					if len(args) != 1 {
						return rules, c.Err("Expecting a single SMTP password")
					}
					rule.SMTPPass = args[0]
				case "mail_from":
					args := c.RemainingArgs()
					if len(args) != 1 {
						return rules, c.Err("Expecting a single mail from address")
					}
					rule.MailFrom = args[0]
				case "mail_tmpl":
					args := c.RemainingArgs()
					if len(args) != 1 {
						return rules, c.Err("Expecting a single mail template")
					}
					rule.MailTmpl = args[0]
				case "smtp_client":
					args := c.RemainingArgs()
					if len(args) == 0 {
						return rules, c.Err("Expecting at least a command")
					}
					rule.SMTPClientName = args[0]
					rule.SMTPClientArgs = args[len(args):]
				}
			}
			if len(rule.Handles) < 1 {
				return rules, c.Err("Expecting at least one handle")
			}
			if rule.MailFrom == "" {
				return rules, c.Err("Expecting a single mail from address FOOBAR")
			}
			rules = append(rules, rule)
		default:
			return rules, c.Err("Single line directives not supported")
		}
	}
	if len(rules) != 1 {
		return rules, c.Err("Expecting one directive per site" + string(len(rules)))
	}
	return rules, nil
}
