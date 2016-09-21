#### [0.3.0] - 2016-09-21
### Added
- Add doc.go to explain package basics
- Add AuthHandler for wrapping http.Handler
- Add tests for service.email package
- Add Www-Authenticate header when no authentication is provided
- Add method UserService.Authorized(handle, loginurl) bool to authorized
  requests
- Create package mock with UserService implements to assit with tests
- Add private key to environment for tokens to survice a config reload
- Add funcs pemEncodePrivateKey, pemDecodePrivateKey and pemEncodePublicKey

### Changed
- Remove Resources field from Claims; Authorization is handled by UserService
- Rename TokenHandler to ResourceHandler
- Replace TestHandleService with mock.UserService
- Update email.UserService.Authorized to allow anonymous acces to unlisted
  resources
- Rename HandleService to UserService
- Rename WriterHandleService to multipass.services.io.UserService
- Rename email.EmailOptions to email.Options
- Return error when there is more than one directive
- Replace ServeMux with simple switch statement
- Move Caddy setup code to its own package
- Refactor NewMultipass to accept a siteaddr
- Remove NewMultupassRule as it adds unncessary complexity
- Remove private key from Multipass instance, load from environment

#### [0.2.0] - 2016-08-27
### Added
- Add support for HTML mail message

### Changed
- HandleService interface to include Close method
- Polish form improve email input on mobile

### Fixed
- Fix missing mandatory header Return-Path
- Fix typos in README.md and templates.go
- Fix blocking of Notify() calls by backgrounding message sending
- Fix aberrant input appearance on Mobile Safari

## [0.1.0] - 2016-08-16
### Added
- Initial release
