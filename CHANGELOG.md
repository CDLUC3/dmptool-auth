# dmptool-auth CHANGELOG

## v1.0.0
- Initial release of the dmptool-auth service, providing authentication and authorization functionalities for the DMP Tool application.
- Added `POST sso-check` endpoint to verify whether an email address is associated with an affiliation that supports SSO.
- Added `findSsoEntityId` function to retrieve the SSO entity ID for a given email domain.
