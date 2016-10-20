#### [0.4.0] - 2016-10-20
### Added
- Add support for custom mail template
- Add functional options
- Add CSRF protection to basepath requests
- Add support for SMTP clients (MSA)
- Add func sendmail and runMSA to support SMTP clients
- Add func PrivateKeyFromEnvironment to replace pemDecodePrivateKey
- Add missing license headers
- Add header signature
- Add go vet command to Travic CI
- Add Travis CI configuration
- Support Caddy's CaddyFile server type association
- Add support for wildcard user handles
- Add example to use multipass.AuthHandler and email.UserService
- Extend UserService.Authorized method to accept Request.Method

### Changed
- Refactor TestSendmail cleanup ineffectual assignments
- Rename instances of next URL to "next" for consistency
- Move default UserService setup to parseOptions
- Update key size with const DefaultKeySize
- Delete files which got accidentally comitted in dd41fec3
- Update test rename email.UserService.Register to AddHandle
- Update docs rename email.UserService.Register to AddHandle
- Update caddy package to reflect changes in email.UserService
- Rename function multipass.NewMultipass to multipass.New
- Rename fields in email.Option to improve readability
- Remove error result type from loadTemplates() as it always returns nil

### Fixed
- Fix TestSendmail allow for unsorted headers
- Fix inaccessable public resources with invalid token
- Fix unset default for the resources parameter
- Fix ResourceHandler returns StatusForibidden without embedded token


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
