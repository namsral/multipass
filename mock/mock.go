// Copyright 2016 Lars Wiegman. All rights reserved. Use of this source code is
// governed by a BSD-style license that can be found in the LICENSE file.

package mock

// UserService represents a mock implementation of multipass.UserService.
type UserService struct {
	RegisterFn      func(handle string) error
	RegisterInvoked bool

	ListedFn      func(handle string) error
	ListedInvoked bool

	Notify        func(handle, loginurl string) error
	NotifyInvoked bool

	CloseFn      func() error
	CloseInvoked bool
}

// Register invokes the mock Implementation and marks the function as invoked.
func (s *UserService) Register(handle string) error {
	s.RegisterInvoked = true
	return s.RegisterFn(handle)
}

// Listed invokes the mock Implementation and marks the function as invoked.
func (s *UserService) Listed(handle string) bool {
	s.ListedInvoked = true
	return s.ListedFn(handle)
}

// Notify invokes the mock Implementation and marks the function as invoked.
func (s *UserService) Notify(handle, loginurl string) error {
	s.NotifyInvoked = true
	return s.NotifyFn(handle)
}

// Close invokes the mock Implementation and marks the function as invoked.
func (s *UserService) Close() error {
	s.CloseInvoked = true
	return s.CloseFn(handle)
}
