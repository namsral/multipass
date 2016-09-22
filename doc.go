// Copyright 2016 Lars Wiegman. All rights reserved. Use of this source code is
// governed by a BSD-style license that can be found in the LICENSE file.

/*
Package multipass implements an authentication service which can be
used to wrap any http.Handler(Func).

Multipass implements the concept to authenticate users based on something they
own instead of something they know. This is better known as the second factor
of Two-factor Authentication.

Quick Start

Wrap any http.Handler or http.HandlerFunc to provide user authentication.
In the example below, the appHandler function is wrapped using the AuthHandler
wrapper. It assumes you have a SMTP service running on `localhost:2525` and
user identified by email address leeloo@dallas has access to the resource at
`/private`.

	package main

	import (
		"fmt"
		"log"
		"net/http"

		"github.com/namsral/multipass"
		"github.com/namsral/multipass/services/email"
	)

	func appHandler(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			fmt.Fprintf(w, "this is the public page")
			return
		case "/private":
			fmt.Fprintf(w, "this is the private page")
			return
		}
		http.NotFound(w, r)
	}

	func main() {
		options := &email.Options{
			Addr:     "localhost:2525", // SMTP address
			FromAddr: "Multipass Bot <noreply@dallas>",
		}
		service, err := email.NewUserService(options)
		if err != nil {
			log.Fatal(err)
		}
		service.AddPattern("/private")    // Accessible to authenticated users
		service.Register("leeloo@dallas") // Only registered users are granted access

		addr := "localhost:6080"
		siteaddr := "http://" + addr
		m, err := multipass.NewMultipass(siteaddr)
		if err != nil {
			log.Fatal(err)
		}
		m.SetUserService(service) // Override the default UserService

		h := multipass.AuthHandler(http.HandlerFunc(appHandler), m)
		log.Fatal(http.ListenAndServe(addr, h))
	}


The package consist of three major components; Multipass, ResourceHandler
and UserService.


Multipass

Multipass is a http.Handler which issues and signs user tokens and
validates their signature.

	NewMultipass(siteaddr string) (*Multipass, error)

Multipass has it's own web UI which is available at the configurable basepath.
From the web UI users can request a login url to gain access to private
resources.

	Multipass.SetBasePath(basepath string)


UserService

User authorization is offloaded to the UserService service. Because the
UserService is an interface custom UserService's can be developed and plugged
into the Multipass instance. Allowing other means of authentication and
authorization besides the built-in email UserService.

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

An implementation can be found in the `services/email` package. This
implementations identifies users by their email address.


ResourceHandler

ResourceHandler accepts a http.ResponseWriter and http.Request and
determines if the request is from an authenticated user and if this user
is authorized to access the requested resource according to the
UserService.
The ResourceHandler extracts any user token from the header,
cookie header or query parameters and validates the user tokens signature with
preset or pre-generated key pairs.

	ResourceHandler(w http.ResponseWriter, r *http.Request, m *Multipass) (int, error)

*/
package multipass
