package multipass

import (
	"errors"
	"fmt"
	"time"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

const directive = "multipass"

// Add the multipass directive to the caddy source in order to build the plugin
// source: github.com/mholt/caddy/caddyhttp/httpserver/plugin.go
func init() {
	caddy.RegisterPlugin(directive, caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

func setup(c *caddy.Controller) error {
	c.OnStartup(func() error {
		fmt.Println(directive + " is intialized")
		return nil
	})

	rules, err := parse(c)
	if err != nil {
		return err
	}
	if len(rules) == 0 {
		return errors.New("No directive declared")
	}

	config, err := ConfigFromRule(rules[0])
	if err != nil {
		return err
	}

	cfg := httpserver.GetConfig(c)
	config.SiteAddr = cfg.Addr.String()
	mid := func(next httpserver.Handler) httpserver.Handler {
		return &Auth{
			Config: config,
			Next:   next,
		}
	}
	cfg.AddMiddleware(mid)

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
						return rules, c.Err("Expecting a single expiry time duration")
					}
					d, err := time.ParseDuration(args[0])
					if err != nil {
						return rules, c.Err("Expecting a valida Go formatted time duration")
					}
					rule.Expires = d
				case "smtp_addr":
					args := c.RemainingArgs()
					if len(args) != 1 {
						return rules, c.Err("Expecting a single SMTP address")
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
				}
			}
			if len(rule.Handles) == 0 {
				return rules, c.Err("Expecting at least one handle")
			}
			if len(rule.MailFrom) == 0 {
				return rules, c.Err("Expecting a single mail from addres")
			}
			if len(rules) > 0 {
				return rules, c.Err("Expecting one directive per site")
			}
			rules = append(rules, rule)
		default:
			return rules, c.Err("Single line directives not supported")
		}
	}
	return rules, nil
}
