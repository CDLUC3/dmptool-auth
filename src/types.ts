import type { ResultSetHeader } from "mysql2";
import type { Logger } from "pino";
import type { KeyvValkeyOptions } from "@keyv/valkey";
import type { ConnectionParams } from "@dmptool/utils";
import type { JWK } from "jose";
import type { AdapterPayload } from "oidc-provider";

// Application configuration interface. This is used to configure the auth service.
export interface Config {
  logger: Logger;
  port: number;

  env: string;
  domain: string;
  applicationName: string;
  helpDeskAddress: string;
  helpPageUrl: string;
  doNotReplyAddress: string;
  maxFailedSignInAttempts: number;

  issuer: string;
  audienceUI: string;
  audienceAPI: string;

  tokens: {
    access: string;
    refresh: string;
    ssoPending: string;
    validAudiences: string[];
    keyRotationSeconds: number;
  };

  cache: KeyvValkeyOptions;
  database: ConnectionParams;
  shibbolethProxySecret?: string;

  // Password hashing configuration
  cookieSecure: boolean;
  pepperSecret: string;
  bcryptSaltRounds: number;

  oidcClients: OAuthClient[];
  ttl: {
    csrf: number;
    passwordReset: number;

    uiAccess: number;
    uiRefresh: number;

    oidcCode: number;
    oidcAccess: number;
    oidcRefresh: number;
    oidcGrant: number;
    oidcIdToken: number;
    oidcInteraction: number;
  };

  ses: SesConnectionParams;
}

// AWS SES connection parameters. These are used to send emails from the auth service.
export interface SesConnectionParams {
  region: string;
  accessKey: string;
  accessSecret: string;
  endpoint: string;
  port: number;
}

// A response from the @dmptool/utils queryTable function. Results is an array of rows when a SELECT
// statement is executed, or a ResultSetHeader when an INSERT, UPDATE, or DELETE statement is executed.
// Fields is an array of field metadata.
export interface dbQueryResponse {
  results: unknown[] | ResultSetHeader,
  fields: unknown[]
}

// A row from the authKeys table in the database. The jwks field contains a JSON string or object representing
export interface KeyRow {
  jwks: StoredKeySet | string;
}

// A retired signing key is a public key that was previously used to sign JWTs, but has been replaced by a new key.
// Retired keys are retained for a period of time to allow verification of in-flight tokens.
export interface RetiredSigningKey {
  expiresAt: string;
  key: JWK;
}

// A stored key set is a collection of signing keys, including the current active key and any retired keys.
export interface StoredKeySet {
  keys: JWK[];
  createdAt?: string;
  retired?: RetiredSigningKey[];
}

// A row from the oidc table in the database. The payload field contains a JSON object representing the OIDC session data.
export interface OidcRow {
  payload: AdapterPayload;
}

// A row from the users table in the database. The fields are in camelCase to match the database schema.
export interface UserRow extends Record<string, unknown> {
  id: number | string;
  email: string;
  password: string;
  role: string;
  givenName: string | null;
  surName: string | null;
  affiliationId: string | null;
  languageId: string | null;
  ssoId: string | null;
  tokenVersion: number | null;
  locked: boolean;
  failed_sign_in_attempts: number | null;
}

// A user object used in the application. The fields are in camelCase to match the database schema.
export interface User {
  id: string;
  email: string;
  passwordHash: string;
  givenName: string;
  surName: string;
  role: string;
  affiliationId: string;
  languageId: string;
  tokenVersion: number;
  ssoId?: string;
  acceptedTerms: boolean;
  locked: boolean;
  remainingSignInAttempts: number;
}

// A public user object that omits the passwordHash field. This is used when returning user data to clients.
export type PublicUser = Omit<User, 'passwordHash'>;

// Our DB schema uses CamelCase for column names, but oidc-provider expects snake_case.
// We define two interfaces to represent the same data in both formats.
export interface OAuthClientRow {
  clientId: string;
  clientSecret: string | null;
  clientName: string | null;
  applicationType: string;
  tokenEndpointAuthMethod: string;
  grantTypes: unknown;
  responseTypes: unknown;
  requirePkce: number;
  clientMetadata: unknown;
  redirectUris: string;
}

// An OAuth client object used in the application. The fields are in snake_case to match the oidc-provider expectations.
export interface OAuthClient {
  client_id: string;
  client_secret: string | null;
  client_name: string | null;
  application_type: string;
  token_endpoint_auth_method: string;
  grant_types: unknown;
  response_types: unknown;
  require_pkce: boolean;
  client_metadata: unknown;
  redirect_uris: string[];
}

// The data stored in the cache for a refresh token. This includes the user ID, the JWT ID (jti) of the access token,
// and the token version.
export interface RefreshTokenData {
  userId: string;
  jti: string;
  tokenVersion: number;
}

// The data stored in the cache for a password reset token. This includes the user ID and the JWT ID (jti) of the access token.
export interface TokenClaims {
  id: string;
  email: string;
  givenName: string;
  surName: string;
  role: string;
  affiliationId: string;
  languageId: string;
  jti: string;
  tokenVersion: number;
}

// The data stored in the cache for a password reset token. This includes the user ID and the JWT ID (jti) of the access token.
export interface ShibbolethAssertion {
  uid?: string;
  email?: string;
  affiliation?: string;
  displayName?: string;
  givenName?: string;
  surName?: string;
  sessionId?: string;
}
