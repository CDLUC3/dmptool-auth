# dmptool-auth CHANGELOG

## v1.0.2
- Updated `/sign-out` function to revoke `jti` rather than `userId`, so that user can sign out and log back in with a valid access token before the 15-minute period. Updated `revoke` and `isRevoked` in `tokenService.ts`to use `jti` rather than `userId` to revoke. Also, addressed `zod` and `body-parser` vulnerabilities.
- Added OAuth 2.0 client-credentials access-token issuance and client-authenticated token revocation.
- Added `OIDC_CLIENT_CREDENTIALS_TOKEN_TTL` environment variable to configure the lifetime of the client-credentials access-token.

## v1.0.1
- Fixed issue where a user could not sign up with affiliation "OTHER". It was inserting "Other" as the `affiliationId` in the `users` table.
- Updated `/sign-out` function to revoke `jti` rather than `userId`, so that user can sign out and log back in with a valid access token before the 15-minute period. Updated `revoke` and `isRevoked` in `tokenService.ts`to use `jti` rather than `userId` to revoke. Also, addressed `zod` and `body-parser` vulnerabilities.
- Added `AGENTS.md` and `CLAUDE.md` files
- Fix issue where the `affiliation` and `affiliationId` in the token were incorrect and causing the UI to send back the affiliation's display name in the final sign up
- Fix a logic issue where an SSO sign up that has an exact match on the email the SSO returned to an entry in the `userEmails` table was logging in, but not linking the account.
- Fix an issue where successful login was directing the user to their `/account/connections` page instead of `/`
- Fix an issue with encrypting the SSO ids.
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
