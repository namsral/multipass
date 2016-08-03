Multipass
=========

Multipass is a (micro)service which allows users to login and authenticate to a backend service with just their email address; no password.


### Goal

Grant users access to protected online resources by sending them a login link.  
No need to remember passwords when you have access to your email.


### Motivation

Many private or intranet services aren't well suited to make available online. Using Multipass, the online service is protected and access can be granted on an individual basis by sending users an access token.


### How it works

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
- __basepath__: path to the log-in and sign-out page. _Default: /_
- __expires__: The time duration after which the token expires. Any time duration Go can [parse][goduration]. _Default: 12h_
- __smtp_addr__: Mailserver address used for sending login links. _Default: localhost:25_
- __mail_from__: From address used in email messages sent to users. _Required_


__JWT__

User access tokens are signed [JSON Web Tokens][jwt] which are passed on as login links and stored as cookies to support single sign-on.


__RSA key pair__

By default, Multipass uses a random RSA key pair to sign and verify user access tokens. These tokens can be also be used and verified by others using the public key. Made available at `[basepath]/pub.cer` when Multipass is running.


__Automatic HTTPS__

Multipass piggybacks on the [Caddy][caddy] web server which comes with automatic HTTPS using [Let's Encrypt][lets] and many more [features and plugins][caddydocs].



[lets]:https://letsencrypt.org
[caddy]:https://caddyserver.com
[caddydocs]:https://caddyserver.com/docs
[jwt]:https://jwt.io
[goduration]:https://golang.org/pkg/time/#ParseDuration
