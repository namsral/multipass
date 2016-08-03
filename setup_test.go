package multipass

import (
	"testing"
	"time"

	"github.com/mholt/caddy"
)

func TestParse(t *testing.T) {
	tests := []struct {
		input     string
		shouldErr bool
		expected  []Rule
	}{
		{`multipass {
			handles leeloo@dallas
			mail_from no-reply@dallas
		}`, false, []Rule{
			{
				Handles:  []string{"leeloo@dallas"},
				MailFrom: "no-reply@dallas",
			},
		}},
		{`multipass {
			path /resource
			basepath /multipass
			expires 24h
			handles leeloo@dallas korben@dallas
			smtp_addr localhost:2525
			smtp_user admin
			smtp_pass secret
			mail_from "Multipass <no-reply@dallas>"
			mail_tmpl email_template.eml
		}`, false, []Rule{
			{
				Path:     "/resource",
				Basepath: "/multipass",
				Expires:  time.Hour * 24,
				Handles:  []string{"leeloo@dallas", "korben@dallas"},
				SMTPAddr: "localhost:2525",
				SMTPUser: "admin",
				SMTPPass: "secret",
				MailFrom: "Multipass <no-reply@dallas>",
				MailTmpl: "email_template.eml",
			},
		}},
		{`multipass {
			path /resource
		  }`, true, []Rule{},
		},
		{`multipass {
			handles leeloo@dallas korben@dallas
			mail_from "Multipass <no-reply@dallas>"
		  }
		  multipass {
			handles leeloo@dallas korben@dallas
			mail_from "Multipass <no-reply@dallas>"
		  }`, true, []Rule{},
		},
	}
	for i, test := range tests {
		actual, err := parse(caddy.NewTestController("http", test.input))
		if err == nil && test.shouldErr {
			t.Errorf("test #%d should return an error, but did not", i)
		} else if err != nil && !test.shouldErr {
			t.Errorf("test #%d should not return an error, but did", i)
		}
		if !test.shouldErr && len(actual) != len(test.expected) {
			t.Errorf("test #%d: expected %d rules, actual %d rules", i, len(test.expected), len(actual))
		}

		for j, expectedRule := range test.expected {
			actualRule := actual[j]
			if actualRule.Path != expectedRule.Path {
				t.Errorf("test #%d, rule #%d: expected '%s', actual '%s'", i, j, expectedRule.Path, actualRule.Path)
			}
			if actualRule.Basepath != expectedRule.Basepath {
				t.Errorf("test #%d, rule #%d: expected '%s', actual '%s'", i, j, expectedRule.Basepath, actualRule.Basepath)
			}
			if actualRule.Expires != expectedRule.Expires {
				t.Errorf("test #%d, rule #%d: expected '%s', actual '%s'", i, j, expectedRule.Expires, actualRule.Expires)
			}
			if actualRule.SMTPAddr != expectedRule.SMTPAddr {
				t.Errorf("test #%d, rule #%d: expected '%s', actual '%s'", i, j, expectedRule.SMTPAddr, actualRule.SMTPAddr)
			}
			if actualRule.SMTPUser != expectedRule.SMTPUser {
				t.Errorf("test #%d, rule #%d: expected '%s', actual '%s'", i, j, expectedRule.SMTPUser, actualRule.SMTPUser)
			}
			if actualRule.SMTPPass != expectedRule.SMTPPass {
				t.Errorf("test #%d, rule #%d: expected '%s', actual '%s'", i, j, expectedRule.SMTPPass, actualRule.SMTPPass)
			}
			if actualRule.MailFrom != expectedRule.MailFrom {
				t.Errorf("test #%d, rule #%d: expected '%s', actual '%s'", i, j, expectedRule.MailFrom, actualRule.MailFrom)
			}
			if actualRule.MailTmpl != expectedRule.MailTmpl {
				t.Errorf("test #%d, rule #%d: expected '%s', actual '%s'", i, j, expectedRule.MailTmpl, actualRule.MailTmpl)
			}
			if len(actualRule.Handles) != len(expectedRule.Handles) {
				t.Errorf("test #%d: expected %d handles, actual %d handles", i, len(expectedRule.Handles), len(actualRule.Handles))
			}
		}
	}
}
