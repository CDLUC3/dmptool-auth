import { decodeJwt, jwtVerify } from 'jose';
import { beforeEach, describe, expect, it, jest } from '@jest/globals';
import type {Config, PublicUser} from '../types.js';
import { MockMySqlStore } from './mocks/mockMySql.js';
import { MockValkeyCache } from './mocks/mockValkey.js';

let database: MockMySqlStore;
const queryTable = jest.fn((config: unknown, sql: string, values?: unknown[]) =>
  database.query(config, sql, values),
);

jest.unstable_mockModule('@dmptool/utils', () => ({ queryTable }));

const { KeyStore } = await import('../models/keyStore.js');
const { TokenService } = await import('../tokenService.js');
const { UserStore } = await import('../models/userStore.js');

const config: Config = {
  logger: {
    level: 'silent',
    silent: true,
    msgPrefix: undefined,
    fatal: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
    info: jest.fn(),
    debug: jest.fn(),
    trace: jest.fn(),
  } as unknown as Config['logger'],
  port: 3000,
  env: 'test',
  domain: 'https://app.example.test',
  applicationName: 'DMP Tool',
  helpDeskAddress: 'help@example.test',
  helpPageUrl: 'https://app.example.test/help',
  doNotReplyAddress: 'no-reply@example.test',
  issuer: 'https://auth.example.test',
  audienceUI: 'https://app.example.test',
  audienceAPI: 'https://api.example.test',
  tokens: {
    access: 'test_access',
    refresh: 'test_refresh',
    ssoPending: 'test_sso_pending',
    validAudiences: ['https://app.example.test', 'https://api.example.test'],
  },
  cache: {},
  database: {
    logger: undefined as unknown as Config['logger'],
    host: 'localhost',
    port: 3306,
    user: 'test',
    password: 'test',
    database: 'test',
  },
  ses: {
    region: 'us-west-2',
    accessKey: 'test-access-key',
    accessSecret: 'test-access-secret',
    endpoint: 'email-smtp.us-west-2.amazonaws.com',
    port: 587,
  },
  cookieSecure: false,
  shibbolethProxySecret: 'test-shibboleth-secret',
  pepperSecret: 'test-pepper-secret',
  bcryptSaltRounds: 4,
  ttl: {
    csrf: 3600,
    uiAccess: 900,
    uiRefresh: 60 * 60 * 24 * 30,
    passwordReset: 60 * 60 * 2,
    oidcCode: 600,
    oidcAccess: 900,
    oidcRefresh: 60 * 60 * 24 * 30,
    oidcGrant: 60 * 60 * 8,
    oidcIdToken: 900,
    oidcInteraction: 600,
  },
  oidcClients: [],
};

describe('TokenService', () => {
  beforeEach(() => {
    database = new MockMySqlStore();
    queryTable.mockClear();
  });

  it('issues RS256 legacy claims, rotates refresh tokens, and reports revocations', async () => {
    const cache = new MockValkeyCache();
    const keys = await KeyStore.load(config);
    const users = new UserStore(config);
    const user = await users.create({
      email: 'alice@example.test',
      password: 'Passw0rd!',
      givenName: 'Alice',
      surName: 'Example',
      affiliationId: 'https://ror.org/example',
      languageId: 'en',
      role: 'RESEARCHER',
      acceptedTerms: true,
      failed_login_attempts: 0
    });
    expect(user).toBeDefined();
    const service = new TokenService(cache, keys, config.ttl.uiAccess, config.ttl.uiRefresh, config.ttl.passwordReset);
    const tokens = await service.issue(config.tokens.validAudiences[0]!, user!);
    const claims = decodeJwt(tokens.accessToken);

    expect(claims).toMatchObject({
      id: user!.id,
      email: user!.email,
      givenName: 'Alice',
      surName: 'Example',
      role: 'RESEARCHER',
      affiliationId: 'https://ror.org/example',
      languageId: 'en',
      tokenVersion: 0,
      iss: 'https://auth.example.test',
      aud: 'https://app.example.test',
    });
    expect((await jwtVerify(tokens.accessToken, await import('jose').then(({ importJWK }) => importJWK(keys.publicJwks().keys[0]!, 'RS256')))).protectedHeader.alg).toBe('RS256');
    await expect(service.consumeRefreshToken(tokens.refreshToken)).resolves.toMatchObject({ userId: user!.id });
    await expect(service.consumeRefreshToken(tokens.refreshToken)).resolves.toBeUndefined();
    await expect(service.isRevoked(claims.jti as string)).resolves.toBe(false);
    await service.revoke(claims.jti as string);
    await expect(service.isRevoked(claims.jti as string)).resolves.toBe(true);
  });

  it('uses the configured password reset TTL and lets expired reset tokens disappear naturally', async () => {
    const cache = new MockValkeyCache();
    const keys = await KeyStore.load(config);
    const service = new TokenService(cache, keys, 900, 60, 0);

    const token = await service.issuePasswordResetToken('user-1');

    expect(cache.set).toHaveBeenCalledWith(`auth:password-reset:${token}`, 'user-1', 0);
    await expect(service.passwordResetUserId(token)).resolves.toBeUndefined();
  });

  it('fails if the audience is not known', async () => {
    const cache = new MockValkeyCache();
    const keys = await KeyStore.load(config);
    const service = new TokenService(cache, keys, 900, 60, 0);
    const user = {
      id: '1',
      tokenVersion: 123,
      email: 'alice@example.test',
      password: 'Passw0rd!',
      givenName: 'Alice',
      surName: 'Example',
      affiliationId: 'https://ror.org/example',
      languageId: 'en',
      role: 'RESEARCHER',
      acceptedTerms: true,
      failed_login_attempts: 0
    } as PublicUser;
    expect(user).toBeDefined();


    await expect(service.issue('unknown-audience', user)).rejects.toThrow('Invalid audience for access token');
  });

  it('verifies active access tokens and rejects revoked or malformed ones', async () => {
    const cache = new MockValkeyCache();
    const keys = await KeyStore.load(config);
    const service = new TokenService(cache, keys);
    const user = {
      id: '1',
      tokenVersion: 123,
      email: 'alice@example.test',
      password: 'Passw0rd!',
      givenName: 'Alice',
      surName: 'Example',
      affiliationId: 'https://ror.org/example',
      languageId: 'en',
      role: 'RESEARCHER',
      acceptedTerms: true,
      failed_login_attempts: 0
    } as PublicUser;
    const { accessToken } = await service.issue(config.tokens.validAudiences[0]!, user);

    await expect(service.verifyAccessToken(accessToken)).resolves.toMatchObject({
      id: user.id,
      jti: expect.any(String),
    });

    const { jti } = decodeJwt(accessToken) as { jti: string };
    await service.revoke(jti);

    await expect(service.verifyAccessToken(accessToken)).resolves.toBeUndefined();
    await expect(service.verifyAccessToken('not-a-token')).resolves.toBeUndefined();
  });

  it('returns and deletes active password reset tokens', async () => {
    const cache = new MockValkeyCache();
    const keys = await KeyStore.load(config);
    const service = new TokenService(cache, keys, 900, 60, 60);
    const token = await service.issuePasswordResetToken('user-1');

    await expect(service.passwordResetUserId(token)).resolves.toBe('user-1');
    await service.deletePasswordResetToken(token);
    await expect(service.passwordResetUserId(token)).resolves.toBeUndefined();
  });
});
