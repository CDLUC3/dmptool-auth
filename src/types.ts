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

  issuer: string;

  tokens: {
    access: string;
    refresh: string;
    ssoPending: string;
    audience: string;
    validAudiences: string[];
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

export interface KeyRow {
  jwks: { keys: JWK[] };
}

export interface OidcRow {
  payload: AdapterPayload;
}

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
  failed_login_attempts: number | null;
}

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
  failed_login_attempts: number;
}

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

export interface RefreshTokenData {
  userId: string;
  jti: string;
  tokenVersion: number;
}

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

export interface ShibbolethAssertion {
  uid?: string;
  email?: string;
  affiliation?: string;
  displayName?: string;
  givenName?: string;
  surName?: string;
  sessionId?: string;
}
