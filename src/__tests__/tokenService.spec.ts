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
  maxFailedSignInAttempts: 5,
  issuer: 'https://auth.example.test',
  audienceUI: 'https://app.example.test',
  audienceAPI: 'https://api.example.test',
  tokens: {
    access: 'test_access',
    refresh: 'test_refresh',
    ssoPending: 'test_sso_pending',
    validAudiences: ['https://app.example.test', 'https://api.example.test'],
    keyRotationSeconds: 60 * 60 * 24 * 30,
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
    emailConfirmation: 60 * 60 * 24,
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
      locked: false,
      remainingSignInAttempts: 5
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
      locked: false,
      remainingSignInAttempts: 5
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
      locked: false,
      remainingSignInAttempts: 5
    } as PublicUser;
    const { accessToken } = await service.issue(config.tokens.validAudiences[0]!, user);
    const { accessToken: secondAccessToken } = await service.issue(config.tokens.validAudiences[0]!, user);

    await expect(service.verifyAccessToken(accessToken)).resolves.toMatchObject({
      id: user.id,
      jti: expect.any(String),
    });

    const { jti } = decodeJwt(accessToken) as { jti: string };
    await service.revoke(jti);

    await expect(service.verifyAccessToken(accessToken)).resolves.toBeUndefined();
    // Revoking one token must not affect other tokens issued to the same user
    await expect(service.verifyAccessToken(secondAccessToken)).resolves.toMatchObject({ id: user.id });
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

  it('stores email confirmation tokens by hash with the configured TTL', async () => {
    const cache = new MockValkeyCache();
    const keys = await KeyStore.load(config);
    const service = new TokenService(cache, keys, 900, 60, 60, 900, 777);

    const token = await service.issueEmailConfirmationToken('user-1', 'alias@example.test');

    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const storedKeys = cache.set.mock.calls.map(([key]) => key);
    expect(storedKeys.some((key) => key.includes(token))).toBe(false);
    expect(cache.set).toHaveBeenCalledWith(
      expect.stringMatching(/^auth:email-confirmation:[0-9a-f]{64}$/),
      JSON.stringify({ userId: 'user-1', email: 'alias@example.test' }),
      777,
    );
    expect(cache.set).toHaveBeenCalledWith(
      expect.stringMatching(/^auth:email-confirmation-owner:[0-9a-f]{64}$/),
      expect.stringMatching(/^[0-9a-f]{64}$/),
      777,
    );
  });

  it('defaults email confirmation tokens to a 24 hour TTL', async () => {
    const cache = new MockValkeyCache();
    const keys = await KeyStore.load(config);
    const service = new TokenService(cache, keys);

    await service.issueEmailConfirmationToken('user-1', 'alias@example.test');

    expect(cache.set).toHaveBeenCalledWith(expect.stringMatching(/^auth:email-confirmation:/), expect.any(String), 86_400);
  });

  it('reads email confirmation tokens without using them up, then uses them up only once', async () => {
    const cache = new MockValkeyCache();
    const keys = await KeyStore.load(config);
    const service = new TokenService(cache, keys);
    const token = await service.issueEmailConfirmationToken('user-1', 'alias@example.test');
    const claim = { userId: 'user-1', email: 'alias@example.test' };

    await expect(service.emailConfirmationClaim(token)).resolves.toEqual(claim);
    await expect(service.emailConfirmationClaim(token)).resolves.toEqual(claim);
    await expect(service.consumeEmailConfirmationToken(token)).resolves.toEqual(claim);
    await expect(service.consumeEmailConfirmationToken(token)).resolves.toBeUndefined();
    await expect(service.emailConfirmationClaim(token)).resolves.toBeUndefined();
    await expect(service.emailConfirmationClaim('unknown-token')).resolves.toBeUndefined();
  });

  it('replaces an earlier email confirmation token when a new one is issued', async () => {
    const cache = new MockValkeyCache();
    const keys = await KeyStore.load(config);
    const service = new TokenService(cache, keys);
    const first = await service.issueEmailConfirmationToken('user-1', 'alias@example.test');
    const other = await service.issueEmailConfirmationToken('user-2', 'alias@example.test');
    const second = await service.issueEmailConfirmationToken('user-1', ' Alias@Example.test ');

    await expect(service.emailConfirmationClaim(first)).resolves.toBeUndefined();
    await expect(service.emailConfirmationClaim(second)).resolves.toMatchObject({ userId: 'user-1' });
    // Tokens issued to another user for the same address are not affected
    await expect(service.emailConfirmationClaim(other)).resolves.toMatchObject({ userId: 'user-2' });
  });

  it('expires and deletes email confirmation tokens', async () => {
    const cache = new MockValkeyCache();
    const keys = await KeyStore.load(config);
    const expiring = new TokenService(cache, keys, 900, 60, 60, 900, 0);
    const expired = await expiring.issueEmailConfirmationToken('user-1', 'alias@example.test');
    await expect(expiring.emailConfirmationClaim(expired)).resolves.toBeUndefined();

    const service = new TokenService(cache, keys);
    const token = await service.issueEmailConfirmationToken('user-1', 'alias@example.test');
    await service.deleteEmailConfirmationToken(token);
    await expect(service.emailConfirmationClaim(token)).resolves.toBeUndefined();
    await expect(service.deleteEmailConfirmationToken(token)).resolves.toBeUndefined();
  });
});
