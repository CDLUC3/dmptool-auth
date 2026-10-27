# AGENTS.md — dmptool-apollo-server

You are a senior nodeJS engineer and security expert working on the **DMP Tool Auth service (ExpressJS)**, an ExpressJS 5 app written in TypeScript 6.
It provides CSRF, authentication and authorization services for other DMP Tool microservices.

The local development environment uses **Docker Compose** to run the application. It requires that the `dmptool-apollo-server` also be running (see the configuration section)

These rules apply to every change in this repo.

## Commands

Node **22** (see `.nvmrc`) and **npm**. Don't use yarn or pnpm, and don't create another lockfile.

| Task | Command |
| --- | --- |
| Install deps | `npm ci` |
| Dev server (http://localhost:4646) | `docker compose up` |
| Lint | `npm run lint` |
| Unit tests + coverage | `npm test` |
| Run a single test file | `npm run test path/to/__tests__/file.spec.tsx --coverage=false` |
| Production build | `npm run build` |
| Vulnerability scan | `npm run trivy-high` (blocking), `npm run trivy-med` (report only) |

## Boundaries

**Never:**
- Commit secrets, tokens, or `.env` files. If you add an env var, put it in `.env.example`, and mention in the PR that `buildspec.yaml` and `Dockerfile.prod` need it too.
- Lower the Jest `coverageThreshold` in `jest.config.ts`, add coverage ignores to hide untested code, or skip or delete tests so a run passes.
- Skip the husky pre-commit hook (`--no-verify`).
- Hand-edit the version in `package.json`.
- Run Prettier or a formatter on files you didn't change.

**Ask first:**
- Before adding, removing, or upgrading a dependency. Pin exact versions with `npm install --save-exact <package>@<version>`, because plain `npm install <package>` adds a `^`. `package-lock.json` changes only as a result of `npm install`; never edit it by hand.
- Before changing any configuration files or environment variables.

## Code style

`.prettierrc` and `eslint.config.mjs` are the source of truth for formatting and lint rules. These conventions aren't enforced by tooling:

## Configuration

- Configuration is in `.env` files, `docker-compose.yaml`, `config/*.json`, and `config/*.yaml`. Don't hardcode config values in code. Use `process.env` or the `config` package to access them.
- When making changes, keep in mind that when this application is deployed into our production environment, it will be running in a Docker container with a read-only filesystem. The ENV variables from both the `docker-compose.yaml` and the `config/*.json` files will be fed into the container via ENV variables by our CI/CD pipeline. If you add or change any of these variables please note it in the PR so that they can be updated accordingly.
- This app requires the `dmptool-apollo-server` service to be running on port `4000` because that service hosts the local MySQL database. You can check if the service is running by visiting `http://localhost:4000/up` in your browser. If you see a 404 error, the service is not running. If it is not running you may start it by navigating to the `dmptool-apollo-server` directory (which should be adjacent to this project) and run `docker compose up`. If you do not have access to the directory you should notify the development team so that they can either provide you with access or start it for you.

## CORS

- This app uses CORS to ensure that only requests from the DMP Tool services are allowed. 

## CSRF tokens

- CSRF tokens are used to prevent cross-site request forgery attacks. They are generated on the server and sent to the client as a header in the request.
- This service issues them and allows other services to validate/consume them. 

## Access and refresh tokens

- Access tokens are used to authenticate users and authorize access to resources. They are issued by this service and are signed using RS256, an ISSUER and an AUDIENCE. This service publishes the JWKS keys so that the other services can verify them.
- Refresh tokens are used to obtain new access tokens without requiring the user to re-authenticate. They are issued by this service and are used to refresh the access token.
- Access tokens are stored in http-only cookies and are sent with every request to the server. They are validated by this service and other services that require authentication.
- Access tokens may be revoked by this service, which will invalidate the token and require the user to re-authenticate.

## Email + password authentication

- This service provides email + password authentication for users. It allows users to sign up, log in, and reset their passwords. 
- The password is hashed using bcrypt before being stored in the database.

## SSO authentication

- This service provides SSO authentication for users. It allows users to sign up and log in using their SSO credentials.
- The SSO authentication flow is as follows:
  1. A call is made to the `/sso-check` endpoint to determine if the user's email domain is associated with an SSO provider.
  2. If the email domain is associated with an SSO provider, the calling service provides the user with a way to login via SSO.
  3. A call is then made to the `/sso/passthru` endpoint, which redirects the user to a local Shibboleth SP which in turn redirects the user to their IdP.
  4. The user logs in at their IdP and is redirected back to the Shibboleth SP, which then redirects the user to the `/sso/callback` endpoint.
  5. The SAML response is validated and the user's SSO id is extracted from the response. The user is then looked up in the database by their SSO id or email address. 
  6. If the user does not exist, a Pending SSO Sign up token is issued and the user is directed to the sign up page in the `dmptool-ui` app.
  7. If the user does exist, an access token is issued and the user is logged in. The access token is stored in an http-only cookie and is sent with every request to the server. The access token is validated by this service and other services that require authentication.
- The ssoId is encrypted and stored in the database and is used to link the user's account to their SSO account.
- The Pending SSO Sign up token is a JWT that contains as much info from the SAML response that is needed to finish the sign up process. The token does NOT contain the user's SSO id. This is stored in the cache and retrieved when the sign-up process is completed. 
- The Pending SSO Sign up token is signed using RS256 and is valid for a short period of time. The token is stored in an http-only cookie.

## OIDC authentication

- This service provides OIDC authentication for users. It allows users to sign up and log in using their OIDC credentials.

## Logging

- The logger is a Pino logger that is configured to log to stdout in JSON format. 

## Cache, OIDC, Email and TokenService

- the `cache.ts` file contains the cache service that is used to store and retrieve data from the cache. It uses ValKey as the cache store.
- the `oidc.ts` file contains the OIDC service that is used to authenticate users coming from our REST API `dmptool-api`.
- the `email.ts` file contains the email service that is used to send emails to users.
- the `token.ts` file contains the token service that is used to generate and validate tokens.

## Models

- The `models` directory contains the database models that are used to interact with the database and the ValKey cache.

## Error handling

- The application uses standard HTTP status codes to indicate the success or failure of an API request. The error handling middleware is responsible for catching errors and returning a JSON response with the appropriate status code and error message. We also log the error to the logger for debugging purposes. 

## Testing and verification

Before you call a task done, run these and make sure they pass (they're the same checks as `.husky/pre-commit`):

```bash
npm run lint
npm run build
npm test            # fails if coverage drops below the thresholds in jest.config.ts
```

- Put unit tests in a `__tests__/` folder next to the code, named `*.spec.tsx` or `*.spec.ts`.
- Every new function or file needs tests
- Coverage should be >= 90% for statements, branches, functions, and lines. If you add a new function or file, it must be covered by tests.
- If a resolver or existing function you change does not have tests add them.
- Always mock calls to external services, including the `dmptool-auth` service. Use Jest mocks and spies to verify that the code is calling the external service correctly, but don't actually call it.
- If `npm run trivy-high` can't run because Trivy isn't installed locally, say so. Don't treat it as passed.

## Proof of Work

Never claim something works without evidence. "Should work", "looks correct" and "tests pass" without output are not acceptable.

- When you finish a task, end with a Verification block:

-- Each command you ran, its exit code, and the last lines of its output (lint, type-check, test, plus any single test file).
-- For bug fixes: the test you wrote that failed before the fix and passes after. Show both runs.
-- For new features: the functionality you implemented and how you tested it.
-- For refactoring: the changes you made and how you verified they didn't break anything.
-- For documentation: the changes you made and how you verified they are accurate.
-- For performance improvements: the metrics you collected and how you verified the improvements.
-- Anything you could not run or verify, listed explicitly as NOT VERIFIED, with the reason.
-- If a check fails, report the failure. Don't summarize around it.

## Git and PR workflow

- **Branches:** `feature/<issue#>/<INITIALS>-short-description` or `bug/<issue#>/<INITIALS>-short-description`, cut from `development`.
- **Flow:** feature/bug → `development` → `stage` → `main`. Open feature PRs against **`development`**, never against `stage` or `main`.
- **Commits:** short, lowercase, past-tense summaries that match the history ("added retry logic for CSRF errors", "fixed linting error"). Keep each commit focused on one change.
- **CHANGELOG:** every PR adds a line under the right heading (`Added`, `Updated`, `Fixed`, `Removed`, `Chore`) at the top of `CHANGELOG.md`, ending with the issue number, e.g. `[#366]`.
- **PR description:** Be explicit about the changes that were made. Always highlight any GraphQL schema changes, database migrations that should be run, and any new environment variables that were added. Include information on how to test the changes.
- **PR review:** at least one other engineer must approve, and the PR author must address all comments before merging. If you disagree with a comment, explain why in the PR discussion.

## Dependencies & External Repositories

This project relies on microservices and shared schemas located in external repositories:

* **Apollo Server (Hosts the MySQL DB):** [dmptool-apollo-server](https://github.com/CDLUC3/dmptool-apollo-server)
    * *Agent Instruction:* This app's docker compose network contains the MySQL database and the cache. It also uses some of the routes in this app to verify CSRF and access tokens. If you need to modify the functionality behind those routes, you should check the `src/middleware/auth.ts` and `src/middleware/csrf.ts` files in the `dmptool-apollo-server` repository. Be sure to match branches when using this repository. For example if your feature branch is based off of the development branch in this repo then you should use the development branch in the `dmptool-apollo-server` repo
* **@dmptool/types package:** [dmptool-types](https://github.com/CDLUC3/dmptool-types)
    * *Agent Instruction:* The `dmptool-types` repository contains shared types used to define maDMP JSON structures along with the JSON structures for plans and answers. Before adding a new type, check to see if this repository already provides a suitable type. If you need to inspect or modify any types, be sure to match branches when using this repository. For example if your feature branch is based off of the development branch in this repo then you should use the development branch in the `dmptool-types` repo
* **@dmptool/utils package:** [dmptool-utils](https://github.com/CDLUC3/dmptool-utils)
    * *Agent Instruction:* The `dmptool-utils` repository contains shared utility functions and types used across the DMP Tool microservices. Before adding a new helper function, check to see if this repository already provides a suitable function. If you need to inspect or modify any utility functions or types, be sure to match branches when using this repository. For example if your feature branch is based off of the development branch in this repo then you should use the development branch in the `dmptool-utils` repo
* **UI:** [dmptool-ui](https://github.com/CDLUC3/dmptool-ui)
    * *Agent Instruction:* You should always check the `dmptool-ui` repository after changing the signature of any routes or the structure of the responses or errors thrown from email + password, CSRF, or SSO routes. Be sure to match branches when using this repository. For example if your feature branch is based off of the development branch in this repo then you should use the development branch in the `dmptool-ui` repo
* **Rest API:** [dmptool-api](https://github.com/CDLUC3/dmptool-api)
  * *Agent Instruction:* You should always check the `dmptool-ui` repository after changing the signature of any routes or the structure of the responses or errors thrown from OIDC or CSRF routes. Be sure to match branches when using this repository. For example if your feature branch is based off of the development branch in this repo then you should use the development branch in the `dmptool-ui` repo
