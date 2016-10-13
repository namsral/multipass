Multipass
=========

[![Build Status](https://travis-ci.org/namsral/multipass.svg?branch=master)](https://travis-ci.org/namsral/multipass)
[![GoDoc](https://godoc.org/github.com/namsral/multipass?status.svg)](http://godoc.org/github.com/namsral/multipass)

![mutipass preview][preview]

__Better authentication for HTTP__

Multipass is like [HTTP Basic authentication][basic-auth] but better and without passwords.

Multipass implements the idea to authenticate users based on __something they own__ instead of __something they know__. This is better known as the second factor of [Two-factor Authentication][2fa].

Multipass comes in two forms; a single binary to run in front of your web services and as a [package](#include-in-go-project) to include in your Go project.


### Installation

Download the binary from the [releases][releases] page or [build](#build) from source.


### Usage


```sh
$ multipass -conf multipass.conf
```

For an example configuration see [Configuration](#configuration).


### Contribution

Bug reports and feature requests are welcome. Follow GiHub's guide to [using-pull-requests].


### Goal

Protect internet exposed web resources and services with automatic HTTPS (TLS) and provide user friendly authentication.


### Motivation

Many private web resources and services end up exposed on the internet, accessible by anyone. Think IP video cameras, Key-value stores, analytic applications and many more. Using Multipass, these web resources and services can be protected using automatic HTTPS (TLS) and access can be granted on an individual basis.


Further reading
---------------

- [Configuration](#configuration)
- [How it Works](#how-it-works)
	- User Flow
	- Configuration
	- JWT
	- RSA Key Pairs
	- Automatic HTTPS
	- Reverse Proxy
- [Include in Go project](#include-in-go-project)
- [Extending](#extending)


Build
-----

The Multipass binary depends on the excellent [Caddy][caddy] webserver.


1. Get the Caddy web server source code:

	```sh
	$ go get github.com/mholt/caddy
	```

2. Register Multipass as a caddy plugin by adding multipass to the caddy directive:

	Open `$GOPATH/src/github.com/mholt/caddy/caddyhttp/httpserver/plugin.go` in your favorite editor and make the following changes.

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
	$ go get github.com/namsral/multipass
	$ go install github.com/namsral/multipass/cmd/multipass
	```

The next thing is to create a configuration file and run the multipass command.


Configuration
-------------

### Syntax

Use the following syntax:

```
multipass {
	resources   path [path]
	handles     email [email]
	basepath    path
	expires     duration
	smtp_addr   host:port
	smtp_user   username
	smtp_pass   password
	smtp_client command [args...]
	mail_from   email
}
```

- __resources__: path of resources to protect. _Default: /_
- __handles__: the handles which identify the users; accepts wildcards like '@' and '@dallas'. _Required_
- __basepath__: path to the log-in and sign-out page. _Default: /multipass_
- __expires__: The time duration after which the token expires. Any time duration Go can [parse][goduration]. _Default: 24h_
- __smtp_addr__: Mailserver address used for sending login links. _Default: localhost:25_
- __smtp_user__: Mailserver username used for authentication.
- __smtp_pass__: Mailserver password used for authentication.
- __smtp_client__: SMTP client command with arguments. Mutually exclusive with __smtp_addr__
- __mail_from__: From address used in email messages sent to users. _Required_

### Examples:

In the following example, the service running on `localhost:2016` is proxied and protected to allow only users with handles leeloo@dallas and korben@dallas to access the  `/fhloston` and `/paradise` resources.

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
	proxy / localhost:2016
	log stdout
}
```

Same example but replaced the SMTP server with a SMTP client and accepts a domain wildcard:

```
example.com {
	bind 0.0.0.0
	multipass {
		resources /fhloston /paradise
		handles @dallas
		basepath /multipass
		expires 24h
		smtp_client /usr/sbin/sendmail -t -i
		mail_from "Multipass <no-reply@dallas>"
	}
	proxy / localhost:2016
	log stdout
}
```


How it works
------------

Multipass works by sending the user a login link with an embedded access token. When the user follows the login link the access token is stored in the browser session and used to authenticate the user on successive requests. The access token is a JSON web token containing claims specific to Multipass and signed with a RSA key pair.

__User flow:__

1. User visits protected resource
2. User is redirected to log-in page and enters a known handle, e.g. email address
3. An user access token is sent to user in the form of a login link
4. User follows the login link and is granted access the protected resource


__JWT__

Access tokens are signed [JSON Web Tokens][jwt] with specific claims like user handle and expire date. The tokens are embedded in login links which are sent to user.


__RSA key pairs__

A RSA key pair is used to sign user access tokens. These access tokens and other signatures can be verified by others using the public key made available at the url `[siteaddr][basepath]/pub.cer` when Multipass is running.

You can set your own private RSA key in the `MULTIPASS_RSA_PRIVATE_KEY` environment variable; make sure to PEM encode the private key.

When no private key is set, the `MULTIPASS_RSA_PRIVATE_KEY` environment variable is empty, a RSA key pair is randomly generated and stored in the environment. This ensures signatures still validate after Multipass reloads during a configuration reload.


__Automatic HTTPS__

Multipass piggybacks on the [Caddy][caddy] web server which comes with automatic HTTPS using [Let's Encrypt][lets] and many more [features and plugins][caddydocs].


__Reverse Proxy__

The user handle which was used to authenticate the user is passed down to the protected web services as a HTTP header:

```
Multipass-Handle: <user handle>
```


Include in Go project
---------------------

Multipass comes with `multipass.AuthHandler` which can wrap any [http.Handler][handler] to provide Multipass authentication. Handlers from other routers and frameworks can be supported, see the [caddy sub-package][caddy-sub-package] for an example.

In the example below, the appHandler function is wrapped using the AuthHandler
wrapper. It assumes you have a SMTP service running on `localhost:2525` and
a user identified by email address leeloo@dallas whom has access to the resource at
`/private`.

```go
package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/namsral/multipass"
	"github.com/namsral/multipass/services/email"
)

func appHandler(w http.ResponseWriter, r *http.Request) {
	handle := r.Header.Get("Multipass-Handle")
	if len(handle) == 0 {
		handle = "anonymous"
	}
	switch r.URL.Path {
	case "/", "/private":
		fmt.Fprintf(w, "Hello %s, welcome to %s", handle, r.URL.Path)
		return
	}
	http.NotFound(w, r)
}

func main() {
	service, err := email.NewUserService(email.Options{
		SMTPAddr: "localhost:2525",
		FromAddr: "Multipass Bot <noreply@dallas>",
	})
	if err != nil {
		log.Fatal(err)
	}
	service.AddHandle("leeloo@dallas") // Register user
	service.AddResource("/private")    // Make resource private

	addr := "localhost:6080"
	siteaddr := "http://" + addr
	m := multipass.New(siteaddr, multipass.Service(service))

	h := multipass.AuthHandler(http.HandlerFunc(appHandler), m)
	log.Fatal(http.ListenAndServe(addr, h))
}
```


Extending
---------

_Extending Multipass by implementing the UserService interface._

By implementing the UserService, shown below, Multipass can be extended to support other _user handles_ which can identify and other ways to notify users of requested login URLs.

```go
// UserService is an interface used by the Multipass instance to query about
// listed handles, authorized resource access and to notify users about login
// urls. A handle is a unique user identifier, e.g. username, email address.
type UserService interface {
	// Listed returns true when the given handle is listed with the
	// service.
	Listed(handle string) bool

	// Authorized returns true when the user identified by the given handle is
	// authorized to access the given resource at rawurl with the given method.
	Authorized(handle, method, rawurl string) bool

	// Notify returns nil when the given login URL is successfully
	// communicated to the given handle.
	Notify(handle, loginurl string) error

	// Close closes any open connections.
	Close() error
}
```


[lets]:https://letsencrypt.org
[caddy]:https://caddyserver.com
[caddydocs]:https://caddyserver.com/docs
[jwt]:https://jwt.io
[goduration]:https://golang.org/pkg/time/#ParseDuration
[releases]:https://github.com/namsral/multipass/releases
[2fa]:https://en.wikipedia.org/wiki/Multi-factor_authentication
[using-pull-requests]:https://help.github.com/articles/using-pull-requests/
[preview]: https://namsral.github.io/multipass/img/multipass.png "Multipass preview image"
[handler]: https://golang.org/pkg/net/http/#Handler
[basic-auth]: https://en.wikipedia.org/wiki/Basic_access_authentication "Basic access authentication"
[caddy-sub-package]: https://godoc.org/github.com/namsral/multipass/caddy
