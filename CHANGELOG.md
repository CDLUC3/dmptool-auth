# dmptool-auth CHANGELOG

## v1.0.2
- Updated `/sign-out` function to revoke `jti` rather than `userId`, so that user can sign out and log back in with a valid access token before the 15-minute period. Updated `revoke` and `isRevoked` in `tokenService.ts`to use `jti` rather than `userId` to revoke. Also, addressed `zod` and `body-parser` vulnerabilities.

## v1.0.1
- Fixed mismatching `u.failedLoginAttempts` to `u.failed_sign_in_attempts` because updating password was failing

## v1.0.0
- Initial release of the dmptool-auth service, providing authentication and authorization functionalities for the DMP Tool application.
- Added `POST sso-check` endpoint to verify whether an email address is associated with an affiliation that supports SSO.
- Added `findSsoEntityId` function to retrieve the SSO entity ID for a given email domain.
