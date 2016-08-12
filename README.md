Multipass
=========

Multipass is a reverse proxy to protect internet exposed web resources and services with automatic HTTPS and user authentication.

Automatic HTTPS is provided using [Let's Encrypt][lets].

User authentication is like basic-auth but without the password. Instead users request an access token by providing their email address in the log-in dialog.

Multipass can be downloaded from the [release][releases] page. It relies on the extendible [Caddy][caddy] web server but can also be used as a package to include in your own project.


### Goal

Protect internet exposed web resources and services with TLS and user authentication.


### Motivation

Many private or intranet services aren't well suited to expose to the internet. Using Multipass, the online service is protected using TLS and access can be granted on an individual basis by sending users an access token.


### How it works

Multipass works by sending the user a login link with an embedded access token. When the user follows the login link the access token is stored in the browser session and used to authenticate the user on successive requests. The access token is a JSON web token containing claims specific to Multipass and signed with an RSA key pair.

__User access flow:__

1. User visits protected resource
2. User is redirected to log-in page and enters a known handle, e.g. email address
3. An user access token is sent to user in the form of a login link
4. User follows the login link in the message to access the protected resource


__Configuration:__

In the following example, the service running on `localhost:9821` is proxied and protected to allow only users with handles leeloo@dallas and korben@dallas to access the  `/fhloston` and `/paradise` resources.

```
example.com {
	bind 0.0.0.0
	multipass {
		resources /fhloston /paradise
		handles leeloo@dallas korben@dallas
		basepath /multipass
		expires 24h
		smtp_addr localhost:2525
		mail_from "Multipass <no-reply@dallas>"
	}
	proxy / localhost:9821
	log stdout
}
```

- __resource__: path of resources to protect. _Default: /_
- __handles__: the handles which identify the users. _Required_
- __basepath__: path to the log-in and sign-out page. _Default: /multipass_
- __expires__: The time duration after which the token expires. Any time duration Go can [parse][goduration]. _Default: 12h_
- __smtp_addr__: Mailserver address used for sending login links. _Default: localhost:25_
- __mail_from__: From address used in email messages sent to users. _Required_


__JWT__

User access tokens are signed [JSON Web Tokens][jwt] which are passed on as login links and stored as cookies to support single sign-on.


__RSA key pair__

By default, Multipass uses a random RSA key pair to sign and verify user access tokens. These tokens can be also be used and verified by others using the public key. Made available at `[basepath]/pub.cer` when Multipass is running.

Including a signature prevents other from forging access tokens.


__Automatic HTTPS__

Multipass piggybacks on the [Caddy][caddy] web server which comes with automatic HTTPS using [Let's Encrypt][lets] and many more [features and plugins][caddydocs].


### Build

Building the Multipass command.

1. Get the Caddy web server source code

	```sh
	$ go get github.com/mholt/caddy
	```

2. Register Multipass as a caddy plugin by adding multipass to the caddy directive.

	Open `$GOPATH/src/github.com/mholt/caddy/caddyhttp/httpserver/plugin.go` in your favorite editor

	```go
	var directives = []string{
		...
	 	"expvar",
		"multipass", // <- insert this line somewhere before "proxy"
		"proxy",
		...
	}
	```

3. Get the Multipass source code and build the command:

	```sh
	$ go ithub.com/namsral/multipass
	$ go install github.com/namsral/multipass/cmd/multipass
	```

The next thing is to create a configuration file and run the multipass command.



[lets]:https://letsencrypt.org
[caddy]:https://caddyserver.com
[caddydocs]:https://caddyserver.com/docs
[jwt]:https://jwt.io
[goduration]:https://golang.org/pkg/time/#ParseDuration
[releases]:https://github.com/namsral/multipass/releases
[build]:https://github.com/namsral/multipass#build