![mutipass preview][preview]

Multipass
=========

Multipass is a remote proxy which can be used to protect web resources and services using user access control. Users are authenticated using a challenge; prove they are the owner of the registered email address by following a login link.

Multipass implements the idea to authenticate users based on __something they own__ instead of __something they know__. This is better known as the second factor of [Two-factor Authentication][2fa].

Login links are encoded [JSON Web Tokens][jwt] containing information about the user and their accessible resources. These tokens are used as access tokens with an expiration date and are signed using an on startup generated RSA key pair.


### Goal

Protect internet exposed web resources and services with automatic HTTPS (TLS) and provide user friendly authentication.


### Motivation

Many private web resources and services end up exposed on the internet, accessible by anyone. Think IP video cameras, Key-value stores, analytic applications and many more. Using Multipass, these web resources and services can be protected using automatic HTTPS (TLS) and access can be granted on an individual basis.


What's here?
------------

- [Installation](#installation)
- [Configuration](#configuration)
- [How it Works](#how-it-works)
	- User Flow
	- Configuration
	- JWT
	- RSA Key Pairs
	- Automatic HTTPS
	- Reverse Proxy
- [Extending](#extending)
- [Contributing](#contributing)

---


Installation
------------

Download the binary from the [releases][releases] page. If your platform isn't listed please submit a PR.


### Build

Building the Multipass command.

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

- __resources__: path of resources to protect. _Default: /_
- __handles__: the handles which identify the users. _Required_
- __basepath__: path to the log-in and sign-out page. _Default: /multipass_
- __expires__: The time duration after which the token expires. Any time duration Go can [parse][goduration]. _Default: 24h_
- __smtp_addr__: Mailserver address used for sending login links. _Default: localhost:25_
- __smtp_user__: Mailserver username used for authentication.
- __smtp_pass__: Mailserver password used for authentication.
- __mail_from__: From address used in email messages sent to users. _Required_


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


Extending
---------

_Exting Multipass by implementing the UserService interface._

The current __something they own__ is the users email address and access tokens are sent to this address. But the __something they own__ can also be a mobile number which can receive SMS messages, or a connected device which can receive Push notifications, chat messages and many more.  
By implementing the UserService, shown below, Multipass can be extended to support other _user handles_ which can identify and notify users.

```go
// A UserService is an interface used by a Multipass instance to register,
// list user handles and notify users about requested access tokens.
// A handle is a unique user identifier, e.g. email address.
type UserService interface {
	// Register returns nil when the given handle is accepted for
	// registration with the service.
	// The handle is passed on by the Multipass instance and can represent
	// an username, email address or even an URI representing a connection to
	// a datastore. The latter allows the UserService to be associated
	// with a RDBMS from which to verify listed users.
	Register(handle string) error

	// Listed returns true when the given handle is listed with the
	// service.
	Listed(handle string) bool

	// Authorized returns true when the user identified by the given handle is
	// authorized to access the given resource at rawurl.
	Authorized(handle, rawurl string) bool

	// Notify returns nil when the given login URL is succesfully
	// communicated to the given handle.
	Notify(handle, loginurl string) error

	// Close closes any open connections.
	Close() error
}
```


Contributing
------------

Contributing is easy:

1. Fork this repo
2. Checkout a new branch
3. Submit a pull-request

Or follow GiHub's guide to [using-pull-requests].


[lets]:https://letsencrypt.org
[caddy]:https://caddyserver.com
[caddydocs]:https://caddyserver.com/docs
[jwt]:https://jwt.io
[goduration]:https://golang.org/pkg/time/#ParseDuration
[releases]:https://github.com/namsral/multipass/releases
[2fa]:https://en.wikipedia.org/wiki/Multi-factor_authentication
[using-pull-requests]:https://help.github.com/articles/using-pull-requests/
[preview]: https://namsral.github.io/multipass/img/multipass.png "Multipass preview image"
