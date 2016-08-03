package multipass

import (
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

	var configs []*Config
	for _, r := range rules {
		c, err := ConfigFromRule(r)
		if err != nil {
			return err
		}
		configs = append(configs, c)
	}

	cfg := httpserver.GetConfig(c)
	mid := func(next httpserver.Handler) httpserver.Handler {
		return &Auth{
			SiteAddr: cfg.Addr.String(),
			Configs:  configs,
			Next:     next,
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
				case "path":
					args := c.RemainingArgs()
					if len(args) != 1 {
						return rules, c.Err("Expecting only one resource per line")
					}
					rule.Path = args[0]
				case "transport":
					args := c.RemainingArgs()
					if len(args) != 1 {
						return rules, c.Err("Expecting a single transport")
					}
					rule.Transport = args[0]
				case "basepath":
					args := c.RemainingArgs()
					if len(args) != 1 {
						return rules, c.Err("Expecting a single basepath")
					}
					rule.Basepath = args[0]
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
				case "handles":
					args := c.RemainingArgs()
					if len(args) <= 0 {
						return rules, c.Err("Expecting at least one handle")
					}
					rule.Handles = args
				}
			}
			rules = append(rules, rule)
		default:
			return rules, c.Err("Single line directives not supported")
		}
	}
	return rules, nil
}
