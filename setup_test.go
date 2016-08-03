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
		}`, false, []Rule{
			{
				Handles: []string{"leeloo@dallas"},
			},
		}},
		{`multipass {
			path /resource
			basepath /multipass
			expires 24h
			handles leeloo@dallas korben@dallas
			transport smtp://user:password@host:port
		}`, false, []Rule{
			{
				Path:      "/resource",
				Basepath:  "/multipass",
				Expires:   time.Hour * 24,
				Handles:   []string{"leeloo@dallas", "korben@dallas"},
				Transport: "smtp://user:password@host:port",
			},
		}},
		{`multipass {
			path /resource
		}`, true, []Rule{},
		},
	}
	for i, test := range tests {
		actual, err := parse(caddy.NewTestController("http", test.input))
		if err != nil && test.shouldErr {
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
			if actualRule.Transport != expectedRule.Transport {
				t.Errorf("test #%d, rule #%d: expected '%s', actual '%s'", i, j, expectedRule.Transport, actualRule.Transport)
			}
			if len(actualRule.Handles) != len(expectedRule.Handles) {
				t.Errorf("test #%d: expected %d handles, actual %d handles", i, len(expectedRule.Handles), len(actualRule.Handles))
			}
		}
	}
}
