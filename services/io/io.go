package io

import (
	"fmt"
	"io"
	"sync"
)

// UserService is an implementation of multipass.UserService which writes all
// method input to the writer element.
type UserService struct {
	writer io.Writer
	lock   sync.Mutex
}

// NewUserService returns a new UserService instance with the given io.Writer
// as the writer element.
func NewUserService(w io.Writer) *UserService {
	return &UserService{
		writer: w,
	}
}

// Register implements the multipass.UserService.Register method. It writes
// the given arguments to the UserService's writer element followed by a
// newline character.
func (s *UserService) Register(handle string) error {
	s.lock.Lock()
	fmt.Fprintln(s.writer, handle)
	s.lock.Unlock()
	return nil
}

// Listed implements the multipass.UserService.Listed method. It writes
// the given arguments to the UserService's writer element followed by a
// newline character. It returns true when the length of the given handle is
// more than 0.
func (s *UserService) Listed(handle string) bool {
	s.lock.Lock()
	fmt.Fprintln(s.writer, handle)
	s.lock.Unlock()
	return len(handle) > 0
}

// Notify implements the multipass.UserService.Notify method. It writes
// the given arguments to the UserService's writer element followed by a
// newline character.
func (s *UserService) Notify(handle, loginurl string) error {
	s.lock.Lock()
	fmt.Fprintln(s.writer, handle)
	fmt.Fprintln(s.writer, loginurl)
	s.lock.Unlock()
	return nil
}

// Close implements the multipass.UserService.Close method. It always returns
// nil.
func (s *UserService) Close() error {
	return nil
}
