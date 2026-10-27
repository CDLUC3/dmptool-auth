# dmptool-auth CHANGELOG

## v1.0.1
- Added `AGENTS.md` and `CLAUDE.md` files
- Fixed mismatching `u.failedLoginAttempts` to `u.failed_sign_in_attempts` because updating password was failing
- Added `x-shib-identity-provider` header so that we can look up the Affiliation in `/sso/callback`
- Removed errors describing lock outs and remaining attempts
- Added `wasJustLocked` flag to `PublicUser` to indicate if the user was just locked out after a failed login attempt
- Updated `/sso/callback` to look up the user by their email address they used or the SSO id
- Updated the `/sso-check` to see if the user already has an sso id and then use their org or check by email domain
- Added an `auth:sso-login-attempt` cache key to retain the email the user used to begin the `/sso/passthru` process so we can use it in `/sso/callback` to look up the user by email address if they don't have an sso id yet
- Added a "locked out of your account" email that gets sent to the user when they are locked out of their account after too many failed login attempts
- Updated the Pending SSO sign up token creation 

## v1.0.0
- Initial release of the dmptool-auth service, providing authentication and authorization functionalities for the DMP Tool application.
- Added `POST sso-check` endpoint to verify whether an email address is associated with an affiliation that supports SSO.
- Added `findSsoEntityId` function to retrieve the SSO entity ID for a given email domain.
