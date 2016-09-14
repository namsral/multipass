package multipass

import (
	"io"
	"os"
)

// DefaultHandleService is the default HandleService used by Multipass.
var DefaultHandleService = NewWriterHandleService(os.Stdout)

// A HandleService is an interface used by a Multipass instance to register,
// list user handles and notify users about requested access tokens.
// A handle is a unique user identifier, e.g. email address.
type HandleService interface {
	// Register returns nil when the given handle is accepted for
	// registration with the service.
	// The handle is passed on by the Multipass instance and can represent
	// an username, email address or even an URI representing a connection to
	// a datastore. The latter allows the HandleService to be associated
	// with a RDBMS from which to verify listed users.
	Register(handle string) error

	// Listed returns true when the given handle is listed with the
	// service.
	Listed(handle string) bool

	// Notify returns nil when the given login URL is succesfully
	// communicated to the given handle.
	Notify(handle, loginurl string) error

	// Close closes any open connections.
	Close() error
}

// WriterHandleService implements the HandleService interface.
// Used as the default HandleService in new Multipass instances and can be
// used in tests.
type WriterHandleService struct {
	writer io.Writer
}

// NewDefaultHandleService allocates and returns a new DefaultHandleService.
func NewWriterHandleService(w io.Writer) *WriterHandleService {
	return &WriterHandleService{
		writer: w,
	}
}

func (s *WriterHandleService) Register(handle string) error {
	s.writer.Write([]byte(handle))
	return nil
}

func (s *WriterHandleService) Listed(handle string) bool {
	return len(handle) > 0
}

func (s *WriterHandleService) Notify(handle, loginurl string) error {
	s.writer.Write([]byte(handle))
	s.writer.Write([]byte(loginurl))
	return nil
}

func (s *WriterHandleService) Close() error {
	return nil
}
