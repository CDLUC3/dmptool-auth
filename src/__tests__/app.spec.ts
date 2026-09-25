import request from 'supertest';
import { decodeJwt } from 'jose';
import { beforeEach, describe, expect, it, jest } from '@jest/globals';
import type {Config, OAuthClient} from '../types.js';
import type { CacheInterface } from '../cache.js';
import type { Mail, SMTPSentMessageInfo } from 'nodemailer';
import { MockMySqlStore } from './mocks/mockMySql.js';
import { MockValkeyCache } from './mocks/mockValkey.js';

let database: MockMySqlStore;
const queryTable = jest.fn((config: unknown, sql: string, values?: unknown[]) =>
  database.query(config, sql, values),
);

jest.unstable_mockModule('@dmptool/utils', () => ({ queryTable }));
jest.unstable_mockModule('../cache.js', () => ({ Cache: MockValkeyCache }));

import type { Logger } from 'pino';
const { createApp } = await import('../app.js');
const { Cache } = await import('../cache.js');
const { KeyStore } = await import('../models/keyStore.js');
const { createProvider } = await import('../oidc.js');
const { TokenService } = await import('../tokenService.js');
const { UserStore } = await import('../models/userStore.js');
const shibbolethProxyHeaders = { 'x-shib-proxy-secret': 'test-shibboleth-secret' };
const mockLogger = { debug: jest.fn(), error: jest.fn(), info: jest.fn(), warn: jest.fn() } as unknown as Logger;
const sendMail = jest.fn<(message: { html?: string }) => Promise<{ messageId: string }>>();
const emailer = { sendMail } as unknown as Mail<SMTPSentMessageInfo>;

const buildApp = async () => {
  const config: Config = {
    logger: mockLogger,
    port: 3000,
    env: 'test',
    domain: 'https://app.example.test',
    applicationName: 'DMP Tool',
    helpDeskAddress: 'help@example.test',
    helpPageUrl: 'https://app.example.test/help',
    doNotReplyAddress: 'no-reply@example.test',
    issuer: 'http://auth.example.test',
    audienceUI: 'my-ui',
    audienceAPI: 'my-api',
    tokens: {
      access: 'test_access',
      refresh: 'test_refresh',
      ssoPending: 'test_sso_pending',
      validAudiences: ['my-ui', 'my-api'],
    },
    cache: {},
    database: {
      logger: mockLogger,
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
    shibbolethProxySecret: shibbolethProxyHeaders['x-shib-proxy-secret'],
    pepperSecret: 'test-pepper-secret',
    bcryptSaltRounds: 4,
    ttl: {
      csrf: 3600,
      uiAccess: 600,
      uiRefresh: 604800,
      passwordReset: 123,
      oidcCode: 120,
      oidcAccess: 900,
      oidcRefresh: 31536000,
      oidcGrant: 120,
      oidcIdToken: 600,
      oidcInteraction: 600,
    },
    oidcClients: [{
      client_id: 'web',
      client_secret: 'secret',
      redirect_uris: ['http://client.example.test/callback'],
      response_types: ['code'],
      grant_types: ['authorization_code', 'refresh_token'],
    } as OAuthClient],
  };
  const cache: CacheInterface = new Cache(config);
  const keys = await KeyStore.load(config);
  const users = new UserStore(config);
  const provider = createProvider(config, cache, users, keys);
  return {
    app: createApp({
      config,
      cache,
      emailer,
      users,
      provider,
      tokens: new TokenService(
        cache,
        keys,
        config.ttl.uiAccess,
        config.ttl.uiRefresh,
        config.ttl.passwordReset,
      ),
    }),
    cache,
    users,
  };
};

describe('authentication routes', () => {
  beforeEach(() => {
    database = new MockMySqlStore();
    queryTable.mockClear();
    sendMail.mockReset();
    sendMail.mockResolvedValue({ messageId: 'message-1' });
  });

  it('supports the csrf, signup, sign-in, refresh, and sign-out workflow', async () => {
    const { app } = await buildApp();
    const agent = request.agent(app);
    const csrf = await agent.get('/csrf').expect(200);
    const csrfToken = csrf.headers['x-csrf-token'] as string;
    await request(app).post('/csrf/verify')
      .set('X-CSRF-Token', csrfToken)
      .expect(200, { valid: true });

    const signup = await agent.post('/signup')
      .set('X-CSRF-Token', csrfToken)
      .send({
        email: 'alice@example.test',
        password: 'Passw0rd!',
        givenName: 'Alice',
        surName: 'Example',
        affiliationId: 'https://ror.org/example',
        acceptedTerms: 'true',
      })
      .expect(201);
    expect(signup.body).toEqual({ success: true, message: 'ok' });
    expect(setCookies(signup).join(';')).toContain('test_access=');
    const accessCookie = setCookies(signup).find((value) => value.startsWith('test_access='));
    expect(decodeJwt(accessCookie!.split(';')[0].slice('test_access='.length)).role).toBe('RESEARCHER');

    const refresh = await agent.post('/refresh-token')
      .set('X-CSRF-Token', signup.headers['x-csrf-token'] as string)
      .expect(200);
    expect(refresh.body.success).toBe(true);
    const refreshedAccessCookie = setCookies(refresh).find((value) => value.startsWith('test_access='));
    const refreshedJti = decodeJwt(refreshedAccessCookie!.split(';')[0].slice('test_access='.length)).jti as string;
    await request(app).get(`/revocations/${refreshedJti}`).expect(200, { revoked: false });

    await agent.post('/signout')
      .set('X-CSRF-Token', refresh.headers['x-csrf-token'] as string)
      .expect(200);
    await request(app).get(`/revocations/${refreshedJti}`).expect(200, { revoked: true });

    const signinCsrf = await agent.get('/csrf').expect(200);
    const signin = await agent.post('/signin')
      .set('X-CSRF-Token', signinCsrf.headers['x-csrf-token'] as string)
      .send({ email: 'alice@example.test', password: 'Passw0rd!' })
      .expect(200);
    expect(signin.body).toEqual({ success: true, message: 'ok' });
  });

  it('reports whether CSRF tokens are valid without consuming them', async () => {
    const { app } = await buildApp();
    const agent = request.agent(app);
    const issued = await agent.get('/csrf').expect(200);
    const token = issued.headers['x-csrf-token'] as string;

    await request(app).post('/csrf/verify')
      .set('X-CSRF-Token', token)
      .expect(200, { valid: true });
    await request(app).post('/csrf/verify').expect(200, { valid: false });
    await request(app).post('/signin')
      .set('X-CSRF-Token', token)
      .send({ email: 'nobody@example.test', password: 'Passw0rd!' })
      .expect(401, { success: false, message: 'Invalid credentials' });
  });

  it('issues one-time password reset tokens and rejects invalid reset attempts', async () => {
    const { app, cache } = await buildApp();
    const agent = request.agent(app);
    const signupCsrf = await agent.get('/csrf').expect(200);
    await agent.post('/signup')
      .set('X-CSRF-Token', signupCsrf.headers['x-csrf-token'] as string)
      .send({
        email: 'alice@example.test',
        password: 'Passw0rd!',
        givenName: 'Alice',
        surName: 'Example',
        affiliationId: '',
        acceptedTerms: 'true',
      })
      .expect(201);

    const resetCsrf = await request(app).get('/csrf').expect(200);
    const issued = await request(app).post('/password-reset/token')
      .set('X-CSRF-Token', resetCsrf.headers['x-csrf-token'] as string)
      .send({ email: 'alice@example.test' })
      .expect(201);
    expect(issued.body).toEqual({ success: true, message: 'ok' });
    const html = sendMail.mock.calls[0]?.[0]?.html ?? '';
    const token = new URL(html.match(/href="([^"]+)"/)?.[1] ?? '').searchParams.get('token');
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(cache.set).toHaveBeenCalledWith(`auth:password-reset:${token}`, '1', 123);

    await request(app).post('/password-reset/verify')
      .send({ token })
      .expect(200, { valid: true });
    await expect(cache.get(`auth:password-reset:${token}`)).resolves.toBe('1');
    await request(app).post('/password-reset/verify')
      .send({ token: 'expired-token' })
      .expect(200, { valid: false });
    await request(app).post('/password-reset/verify')
      .expect(200, { valid: false });

    await request(app).post('/password-reset').send({
      token,
      password: 'Passw0rd!',
      passwordConfirmation: 'Different1!',
    }).expect(400, { success: false, message: 'Passwords do not match' });

    await request(app).post('/password-reset').send({
      token: 'expired-token',
      password: 'NewPassw0rd!',
      passwordConfirmation: 'NewPassw0rd!',
    }).expect(400, { success: false, message: 'Invalid or expired password reset token' });

    await request(app).post('/password-reset').send({
      token,
      password: 'weak',
      passwordConfirmation: 'weak',
    }).expect(400, { success: false, message: 'Invalid password format' });

    await request(app).post('/password-reset').send({
      token,
      password: 'NewPassw0rd!',
      passwordConfirmation: 'NewPassw0rd!',
    }).expect(200, { success: true, message: 'ok' });
    await expect(cache.get(`auth:password-reset:${token}`)).resolves.toBeUndefined();

    await request(app).post('/password-reset/verify')
      .send({ token })
      .expect(200, { valid: false });
    await request(app).post('/password-reset').send({
      token,
      password: 'Another1!',
      passwordConfirmation: 'Another1!',
    }).expect(400, { success: false, message: 'Invalid or expired password reset token' });

    const signinCsrf = await agent.get('/csrf').expect(200);
    await agent.post('/signin')
      .set('X-CSRF-Token', signinCsrf.headers['x-csrf-token'] as string)
      .send({ email: 'alice@example.test', password: 'NewPassw0rd!' })
      .expect(200, { success: true, message: 'ok' });
  });

  it('requires an email address for unauthenticated password reset requests', async () => {
    const { app } = await buildApp();
    const csrf = await request(app).get('/csrf').expect(200);
    await request(app).post('/password-reset/token')
      .set('X-CSRF-Token', csrf.headers['x-csrf-token'] as string)
      .expect(400, { success: false, message: 'Email is required' });
  });

  it('does not issue a reset token for an unknown email address', async () => {
    const { app, cache } = await buildApp();
    const csrf = await request(app).get('/csrf').expect(200);

    await request(app).post('/password-reset/token')
      .set('X-CSRF-Token', csrf.headers['x-csrf-token'] as string)
      .send({ email: 'nobody@example.test' })
      .expect(404, { success: false, message: 'User not found' });
    expect(cache.set).not.toHaveBeenCalledWith(expect.stringMatching(/^auth:password-reset:/), expect.anything(), expect.anything());
  });

  it('removes the reset token when the email cannot be delivered', async () => {
    sendMail.mockRejectedValueOnce(new Error('SMTP unavailable'));
    const { app, cache } = await buildApp();
    const signupCsrf = await request(app).get('/csrf').expect(200);
    await request(app).post('/signup')
      .set('X-CSRF-Token', signupCsrf.headers['x-csrf-token'] as string)
      .send({
        email: 'alice@example.test',
        password: 'Passw0rd!',
        givenName: 'Alice',
        surName: 'Example',
        affiliationId: '',
        acceptedTerms: 'true',
      })
      .expect(201);

    const resetCsrf = await request(app).get('/csrf').expect(200);
    await request(app).post('/password-reset/token')
      .set('X-CSRF-Token', resetCsrf.headers['x-csrf-token'] as string)
      .send({ email: 'alice@example.test' })
      .expect(502, { success: false, message: 'Unable to send password reset email' });
    expect(cache.del).toHaveBeenCalledWith([expect.stringMatching(/^auth:password-reset:/)]);
  });

  it('changes an authenticated user password after validating the current password', async () => {
    const { app } = await buildApp();
    const agent = request.agent(app);
    const signupCsrf = await agent.get('/csrf').expect(200);
    await agent.post('/signup')
      .set('X-CSRF-Token', signupCsrf.headers['x-csrf-token'] as string)
      .send({
        email: 'alice@example.test',
        password: 'Passw0rd!',
        givenName: 'Alice',
        surName: 'Example',
        affiliationId: '',
        acceptedTerms: 'true',
      })
      .expect(201);

    await agent.post('/change-password').send({
      currentPassword: 'Passw0rd!',
      newPassword: 'NewPassw0rd!',
      newPasswordConfirmation: 'NewPassw0rd!',
    }).expect(403, { error: 'Invalid CSRF token' });

    const missingAccessTokenCsrf = await request(app).get('/csrf').expect(200);
    await request(app).post('/change-password')
      .set('X-CSRF-Token', missingAccessTokenCsrf.headers['x-csrf-token'] as string)
      .send({
        currentPassword: 'Passw0rd!',
        newPassword: 'NewPassw0rd!',
        newPasswordConfirmation: 'NewPassw0rd!',
      })
      .expect(401, { success: false, message: 'Invalid access token' });

    const changeCsrf = await agent.get('/csrf').expect(200);
    await agent.post('/change-password')
      .set('X-CSRF-Token', changeCsrf.headers['x-csrf-token'] as string)
      .send({
        currentPassword: 'WrongPass1!',
        newPassword: 'NewPassw0rd!',
        newPasswordConfirmation: 'NewPassw0rd!',
      })
      .expect(401, { success: false, message: 'Invalid current password' });

    const mismatchedConfirmationCsrf = await agent.get('/csrf').expect(200);
    await agent.post('/change-password')
      .set('X-CSRF-Token', mismatchedConfirmationCsrf.headers['x-csrf-token'] as string)
      .send({
        currentPassword: 'Passw0rd!',
        newPassword: 'NewPassw0rd!',
        newPasswordConfirmation: 'Different1!',
      })
      .expect(400, { success: false, message: 'Passwords do not match' });

    const invalidPasswordCsrf = await agent.get('/csrf').expect(200);
    await agent.post('/change-password')
      .set('X-CSRF-Token', invalidPasswordCsrf.headers['x-csrf-token'] as string)
      .send({
        currentPassword: 'Passw0rd!',
        newPassword: 'weak',
        newPasswordConfirmation: 'weak',
      })
      .expect(400, { success: false, message: 'Invalid password format' });

    const successfulChangeCsrf = await agent.get('/csrf').expect(200);
    await agent.post('/change-password')
      .set('X-CSRF-Token', successfulChangeCsrf.headers['x-csrf-token'] as string)
      .send({
        currentPassword: 'Passw0rd!',
        newPassword: 'NewPassw0rd!',
        newPasswordConfirmation: 'NewPassw0rd!',
      })
      .expect(200, { success: true, message: 'ok' });

    const signinCsrf = await agent.get('/csrf').expect(200);
    await agent.post('/signin')
      .set('X-CSRF-Token', signinCsrf.headers['x-csrf-token'] as string)
      .send({ email: 'alice@example.test', password: 'Passw0rd!' })
      .expect(401, { success: false, message: 'Invalid credentials' });

    const newPasswordSigninCsrf = await agent.get('/csrf').expect(200);
    await agent.post('/signin')
      .set('X-CSRF-Token', newPasswordSigninCsrf.headers['x-csrf-token'] as string)
      .send({ email: 'alice@example.test', password: 'NewPassw0rd!' })
      .expect(200, { success: true, message: 'ok' });
  });

  it('validates password reset payloads and forwards unexpected reset errors', async () => {
    const { app, cache, users } = await buildApp();

    await request(app).post('/password-reset').send({
      token: 'reset-token',
      password: 'NewPassw0rd!',
    }).expect(400, { success: false, message: 'token, password, and passwordConfirmation are required' });

    await cache.set('auth:password-reset:reset-token', '1', 123);
    jest.spyOn(users, 'resetPassword').mockRejectedValueOnce(new Error('Database unavailable'));
    await request(app).post('/password-reset').send({
      token: 'reset-token',
      password: 'NewPassw0rd!',
      passwordConfirmation: 'NewPassw0rd!',
    }).expect(500, { success: false, message: 'Internal server error' });
  });

  it('redirects a Shibboleth assertion for an unknown account to registration', async () => {
    const { app } = await buildApp();
    const result = await request(app).get('/sso/callback/sso-session')
      .set(shibbolethProxyHeaders)
      .set('x-shib-eppn', 'alice@example.test')
      .set('x-shib-mail', 'alice@example.test')
      .set('x-shib-session-id', 'sso-session')
      .expect(302);

    expect(result.headers.location).toBe('/signup');
    expect(setCookies(result).join(';')).toContain(`test_sso_pending=sso-session`);
  });

  it('rejects invalid credentials and invalid csrf requests, and exposes provider discovery', async () => {
    const { app } = await buildApp();
    await request(app).post('/signin')
      .send({ email: 'nobody@example.test', password: 'Passw0rd!' })
      .expect(403, { error: 'Invalid CSRF token' });
    const csrf = await request(app).get('/csrf').expect(200);
    await request(app).post('/signin')
      .set('X-CSRF-Token', csrf.headers['x-csrf-token'] as string)
      .send({ email: 'nobody@example.test', password: 'Passw0rd!' })
      .expect(401, { success: false, message: 'Invalid credentials' });
    const discovery = await request(app).get('/.well-known/openid-configuration').expect(200);
    expect(discovery.body.issuer).toBe('http://auth.example.test');
  });

  it('issues cookies for a known Shibboleth user', async () => {
    const { app } = await buildApp();
    const csrf = await request(app).get('/csrf').expect(200);
    await request(app).post('/signup')
      .set('X-CSRF-Token', csrf.headers['x-csrf-token'] as string)
      .send({
      email: 'alice@example.test',
      password: 'Passw0rd!',
      givenName: 'Alice',
      surName: 'Example',
      affiliationId: '',
      ssoId: 'alice@example.test',
      acceptedTerms: 'true',
    }).expect(201);
    const result = await request(app).get('/sso/callback/sso-session')
      .set(shibbolethProxyHeaders)
      .set('x-shib-eppn', 'alice@example.test')
      .set('x-shib-mail', 'alice@example.test')
      .expect(302);
    expect(result.headers.location).toBe('/');
    expect(setCookies(result).join(';')).toContain('test_access=');
  });

  it('rejects an invalid Shibboleth callback payload', async () => {
    const { app } = await buildApp();

    await request(app).get('/sso/callback')
      .set(shibbolethProxyHeaders)
      .set('x-shib-eppn', 'alice@example.test')
      .expect(400, { success: false, message: 'Missing Shibboleth identity headers' });
  });

  it('returns expected errors for health, credential, refresh, and SSO edge cases', async () => {
    const { app, cache } = await buildApp();
    const agent = request.agent(app);

    await agent.get('/healthz').expect(200, { status: 'ok' });
    expect(cache.get).toHaveBeenCalledWith('healthcheck');

    const csrf = await agent.get('/csrf').expect(200);
    await agent.post('/signin')
      .set('X-CSRF-Token', csrf.headers['x-csrf-token'] as string)
      .send({})
      .expect(401, { success: false, message: 'Invalid credentials' });

    const refreshCsrf = await agent.get('/csrf').expect(200);
    await agent.post('/refresh-token')
      .set('X-CSRF-Token', refreshCsrf.headers['x-csrf-token'] as string)
      .expect(401, { success: false, message: 'No refresh token available' });

    await request(app).get('/sso').query({ email: 'invalid', entityId: 'https://idp.example.test' })
      .expect(400, { success: false, message: 'Invalid email address' });
    await request(app).get('/sso').query({ email: 'alice@example.test' })
      .expect(400, { success: false, message: 'entityId is required' });
    await request(app).get('/sso/callback')
      .set(shibbolethProxyHeaders)
      .expect(400, { success: false, message: 'Missing Shibboleth identity headers' });
  });

  it('handles JWKS redirects, tokenless sign-out, and POST SSO passthrough', async () => {
    const { app } = await buildApp();
    const agent = request.agent(app);

    await request(app).get('/jwks.json').expect(302).expect('Location', '/.well-known/jwks.json');

    const csrf = await agent.get('/csrf').expect(200);
    await agent.post('/signout')
      .set('X-CSRF-Token', csrf.headers['x-csrf-token'] as string)
      .expect(200, {});

    const passthrough = await request(app).post('/sso/passthru')
      .send({ email: 'alice@example.test', entityId: 'https://idp.example.test' })
      .expect(302);
    expect(passthrough.headers.location).toContain('entityId=https%3A%2F%2Fidp.example.test');
  });

  it('rejects duplicate signups with a conflict response', async () => {
    const { app } = await buildApp();
    const agent = request.agent(app);
    const user = {
      email: 'alice@example.test',
      password: 'Passw0rd!',
      givenName: 'Alice',
      surName: 'Example',
      affiliationId: 'https://ror.org/example',
      acceptedTerms: 'true',
    };
    const csrf = await agent.get('/csrf').expect(200);
    const created = await agent.post('/signup')
      .set('X-CSRF-Token', csrf.headers['x-csrf-token'] as string)
      .send(user)
      .expect(201);

    await agent.post('/signup')
      .set('X-CSRF-Token', created.headers['x-csrf-token'] as string)
      .send(user)
      .expect(409, { success: false, message: 'A user with this email already exists' });
  });

  it('rejects Shibboleth headers not authenticated by the trusted proxy', async () => {
    const { app } = await buildApp();

    await request(app).get('/sso/callback')
      .set('x-shib-eppn', 'alice@example.test')
      .set('x-shib-mail', 'alice@example.test')
      .expect(403, { success: false, message: 'Untrusted Shibboleth proxy' });
  });

  it('registers an unknown Shibboleth user from the pending SSO assertion', async () => {
    const { app, cache } = await buildApp();
    const agent = request.agent(app);

    const passthru = await agent.get('/sso/passthru')
      .query({ email: 'alice@example.test', entityId: 'https://idp.example.test' })
      .expect(302);
    const shibbolethLogin = new URL(passthru.headers.location, 'http://auth.example.test');
    expect(shibbolethLogin.pathname).toBe('/Shibboleth.sso/Login');
    expect(shibbolethLogin.searchParams.get('entityId')).toBe('https://idp.example.test');
    expect(shibbolethLogin.searchParams.get('target')).toBe('http://auth.example.test/sso/callback');

    const callback = await agent.get('/sso/callback/sso-session')
      .set(shibbolethProxyHeaders)
      .set('x-shib-eppn', 'alice@example.test')
      .set('x-shib-mail', 'alice@example.test')
      .set('x-shib-givenname', 'Alice')
      .set('x-shib-sn', 'Example')
      .set('x-shib-session-id', 'sso-session')
      .expect(302);
    expect(callback.headers.location).toBe('/signup');
    expect(cookie(callback, 'test_sso_pending')).toBe('sso-session');
    await expect(cache.get('auth:sso-pending:sso-session')).resolves.toEqual(expect.stringContaining('alice@example.test'));
    expect(cookie(callback, 'test_access')).toBeUndefined();
    expect(cookie(callback, 'test_refresh')).toBeUndefined();

    const csrf = await agent.get('/csrf').expect(200);
    const signup = await agent.post('/signup')
      .set('X-CSRF-Token', csrf.headers['x-csrf-token'] as string)
      .send({
        password: 'Passw0rd!',
        givenName: 'Alice',
        surName: 'Example',
        affiliationId: 'https://ror.org/example',
        acceptedTerms: 'true',
      })
      .expect(201, { success: true, message: 'ok' });
    expect(database.findUserByEmail('alice@example.test')).toMatchObject({
      email: 'alice@example.test',
      ssoId: 'alice@example.test',
      role: 'RESEARCHER',
    });
    expect(cookie(signup, 'test_access')).toBeDefined();
    expect(cookie(signup, 'test_refresh')).toBeDefined();
    expect(cookie(signup, 'test_sso_pending')).toBeDefined();
    await expect(cache.get('auth:sso-pending:sso-session')).resolves.toBeUndefined();
  });

  it('issues tokens when a Shibboleth assertion matches an existing SSO user', async () => {
    const { app } = await buildApp();
    const agent = request.agent(app);
    const csrf = await agent.get('/csrf').expect(200);

    await agent.post('/signup')
      .set('X-CSRF-Token', csrf.headers['x-csrf-token'] as string)
      .send({
        email: 'alice@example.test',
        password: 'Passw0rd!',
        givenName: 'Alice',
        surName: 'Example',
        affiliationId: 'https://ror.org/example',
        ssoId: 'alice@example.test',
        acceptedTerms: 'true',
      })
      .expect(201);

    const callback = await request(app).get('/sso/callback')
      .set(shibbolethProxyHeaders)
      .set('x-shib-eppn', 'alice@example.test')
      .set('x-shib-mail', 'alice@example.test')
      .expect(302);
    expect(callback.headers.location).toBe('/');
    expect(cookie(callback, 'test_access')).toBeDefined();
    expect(cookie(callback, 'test_refresh')).toBeDefined();
    expect(decodeJwt(cookie(callback, 'test_access')!).email).toBe('alice@example.test');
  });

  it('resolves database OAuth clients after the provider has started', async () => {
    const { app } = await buildApp();
    database.addOauthClient({
      client_id: 'external',
      client_secret: 'secret',
      client_name: 'External integration',
      application_type: 'web',
      token_endpoint_auth_method: 'client_secret_basic',
      grant_types: ['authorization_code'],
      response_types: ['code'],
      require_pkce: false,
      client_metadata: null,
      redirect_uris: ['https://external.example.test/callback'],
    });

    const authorization = await request(app).get('/auth')
      .query({
        client_id: 'external',
        response_type: 'code',
        scope: 'openid',
        redirect_uri: 'https://external.example.test/callback',
      })
      .expect(303);
    expect(authorization.headers.location).toMatch(/^\/interaction\//);

    database.setOauthClientActive('external', false);
    await request(app).get('/auth')
      .query({
        client_id: 'external',
        response_type: 'code',
        scope: 'openid',
        redirect_uri: 'https://external.example.test/callback',
      })
      .expect(400);
  });

  it('redirects authorization interactions to the configured external sign-in UI', async () => {
    const previousSignInUrl = process.env.OAUTH2_SIGN_IN_URL;
    process.env.OAUTH2_SIGN_IN_URL = 'https://login.example.test/authorize';
    try {
      const { app } = await buildApp();
      database.addOauthClient({
        client_id: 'external-ui',
        client_secret: 'secret',
        client_name: 'External UI integration',
        application_type: 'web',
        token_endpoint_auth_method: 'client_secret_basic',
        grant_types: ['authorization_code'],
        response_types: ['code'],
        require_pkce: false,
        client_metadata: null,
        redirect_uris: ['https://external.example.test/callback'],
      });

      const authorization = await request(app).get('/auth')
        .query({
          client_id: 'external-ui',
          response_type: 'code',
          scope: 'openid',
          redirect_uri: 'https://external.example.test/callback',
        })
        .expect(303);
      expect(authorization.headers.location).toMatch(/^https:\/\/login\.example\.test\/authorize\?uid=/);
    } finally {
      if (previousSignInUrl === undefined) delete process.env.OAUTH2_SIGN_IN_URL;
      else process.env.OAUTH2_SIGN_IN_URL = previousSignInUrl;
    }
  });

  it('handles OAuth authorization-code failures and token issuance', async () => {
    const { app, users } = await buildApp();
    const agent = request.agent(app);
    const client = {
      client_id: 'external',
      client_secret: 'secret',
      client_name: 'External integration',
      application_type: 'web',
      token_endpoint_auth_method: 'client_secret_basic',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      require_pkce: false,
      client_metadata: null,
      redirect_uris: ['https://external.example.test/callback'],
    };
    database.addOauthClient(client);
    await users.create({
      email: 'alice@example.test',
      password: 'Passw0rd!',
      givenName: 'Alice',
      surName: 'Example',
      affiliationId: 'https://ror.org/example',
      languageId: 'en-US',
      role: 'RESEARCHER',
      acceptedTerms: true,
      failed_login_attempts: 0
    });

    const invalidClient = await request(app).get('/auth')
      .query({
        client_id: 'missing',
        response_type: 'code',
        scope: 'openid',
        redirect_uri: client.redirect_uris[0],
      })
      .expect(400);
    expect(invalidClient.headers['content-type']).toMatch(/^text\/html/);
    expect(invalidClient.text).toContain('Authentication request could not be completed');

    const invalidRequest = await request(app).get('/auth')
      .query({
        client_id: client.client_id,
        response_type: 'code',
        scope: 'openid',
        redirect_uri: 'https://untrusted.example.test/callback',
      })
      .expect(400);
    expect(invalidRequest.headers['content-type']).toMatch(/^text\/html/);
    expect(invalidRequest.text).toContain('Authentication request could not be completed');

    const authorization = await agent.get('/auth')
      .query({
        client_id: client.client_id,
        response_type: 'code',
        scope: 'openid offline_access',
        redirect_uri: client.redirect_uris[0],
        state: 'client-state',
        prompt: 'consent',
      })
      .expect(303);
    const loginUid = interactionUid(authorization);
    expect(authorization.headers.location).toBe(`/interaction/${loginUid}`);
    expect(authorization.headers['set-cookie']).toBeDefined();

    const loginDetails = await agent.get(`/interaction/${loginUid}`).expect(200);
    expect(loginDetails.body).toMatchObject({
      uid: loginUid,
      prompt: 'login',
      clientId: client.client_id,
    });

    const login = await agent.post(`/interaction/${loginUid}`)
      .send({ email: 'alice@example.test', password: 'Passw0rd!' })
      .expect(303);
    expect(login.headers.location).toContain('/auth/');

    const resume = new URL(login.headers.location, 'http://auth.example.test');
    const consent = await agent.get(`${resume.pathname}${resume.search}`).expect(303);
    const consentUid = interactionUid(consent);
    const consentDetails = await agent.get(`/interaction/${consentUid}`).expect(200);
    expect(consentDetails.body).toMatchObject({
      uid: consentUid,
      prompt: 'consent',
      clientId: client.client_id,
    });

    const consentComplete = await agent.post(`/interaction/${consentUid}`)
      .send({})
      .expect(303);
    expect(consentComplete.headers.location).toContain('/auth/');
    const consentResume = new URL(consentComplete.headers.location, 'http://auth.example.test');
    const authorizationComplete = await agent.get(`${consentResume.pathname}${consentResume.search}`).expect(303);
    if (authorizationComplete.headers.location?.startsWith('/interaction/')) {
      const nextUid = interactionUid(authorizationComplete);
      const nextInteraction = await agent.get(`/interaction/${nextUid}`).expect(200);
      throw new Error(`Unexpected interaction after consent: ${nextInteraction.body.prompt}`);
    }
    const callback = new URL(authorizationComplete.headers.location);
    expect(callback.origin).toBe('https://external.example.test');
    expect(callback.pathname).toBe('/callback');
    expect(callback.searchParams.get('state')).toBe('client-state');
    const code = callback.searchParams.get('code');
    expect(code).toBeTruthy();

    const token = await request(app).post('/token')
      .auth(client.client_id, client.client_secret)
      .type('form')
      .send({
        grant_type: 'authorization_code',
        code,
        redirect_uri: client.redirect_uris[0],
      })
      .expect(200);
    expect(token.headers['content-type']).toMatch(/^application\/json/);
    expect(token.body).toMatchObject({
      token_type: 'Bearer',
      access_token: expect.any(String),
      refresh_token: expect.any(String),
      expires_in: expect.any(Number),
    });

    const refreshed = await request(app).post('/token')
      .auth(client.client_id, client.client_secret)
      .type('form')
      .send({ grant_type: 'refresh_token', refresh_token: token.body.refresh_token })
      .expect(200);
    expect(refreshed.headers['content-type']).toMatch(/^application\/json/);
    expect(refreshed.body).toMatchObject({
      token_type: 'Bearer',
      access_token: expect.any(String),
      refresh_token: expect.any(String),
    });

    const consumedCode = await request(app).post('/token')
      .auth(client.client_id, client.client_secret)
      .type('form')
      .send({
        grant_type: 'authorization_code',
        code,
        redirect_uri: client.redirect_uris[0],
      })
      .expect(400);
    expect(consumedCode.headers['content-type']).toMatch(/^application\/json/);
    expect(consumedCode.body).toMatchObject({ error: 'invalid_grant' });
  });

  it('enforces CSRF and validation while rotating and revoking authentication tokens', async () => {
    const { app, cache } = await buildApp();
    const agent = request.agent(app);
    const validSignup = {
      email: 'alice@example.test',
      password: 'Passw0rd!',
      givenName: 'Alice',
      surName: 'Example',
      affiliationId: 'https://ror.org/example',
      acceptedTerms: 'true',
    };

    await agent.post('/signup')
      .send(validSignup)
      .expect(403, { error: 'Invalid CSRF token' });

    const csrf = await agent.get('/csrf').expect(200, 'ok');
    const csrfToken = csrf.headers['x-csrf-token'] as string;
    expect(csrfToken).toMatch(/^[a-f0-9]{32}$/);
    await expect(cache.get(`auth:csrf:${csrfToken}`)).resolves.toBe('1');

    const missingEmail = await agent.post('/signup')
      .set('X-CSRF-Token', csrfToken)
      .send({ ...validSignup, email: undefined })
      .expect(400, { success: false, message: 'email, password, givenName, and surName are required' });
    const invalidPasswordCsrf = missingEmail.headers['x-csrf-token'] as string;
    expect(invalidPasswordCsrf).toMatch(/^[a-f0-9]{32}$/);

    const invalidPassword = await agent.post('/signup')
      .set('X-CSRF-Token', invalidPasswordCsrf)
      .send({ ...validSignup, password: 'Passw0rd()' })
      .expect(500, { success: false, message: 'Internal server error' });
    const signupCsrf = invalidPassword.headers['x-csrf-token'] as string;

    const signup = await agent.post('/signup')
      .set('X-CSRF-Token', signupCsrf)
      .send(validSignup)
      .expect(201, { success: true, message: 'ok' });
    expect(database.findUserByEmail(validSignup.email)).toMatchObject({
      email: validSignup.email,
      role: 'RESEARCHER',
      givenName: 'Alice',
      surName: 'Example',
      affiliationId: validSignup.affiliationId,
      acceptedTerms: true,
      languageId: 'en-US',
      tokenVersion: 0,
    });
    const signupAccessCookie = cookie(signup, 'test_access');
    const signupRefreshCookie = cookie(signup, 'test_refresh');
    expect(signupAccessCookie).toBeDefined();
    expect(signupRefreshCookie).toBeDefined();
    await expect(cache.get(`auth:refresh:${signupRefreshCookie}`)).resolves.toBeDefined();
    const signinCsrf = signup.headers['x-csrf-token'] as string;
    expect(signinCsrf).toMatch(/^[a-f0-9]{32}$/);

    const signout = await agent.post('/signout')
      .set('X-CSRF-Token', signinCsrf)
      .expect(200, {});
    expect(setCookies(signout).join(';')).toContain('test_access=;');
    expect(setCookies(signout).join(';')).toContain('test_refresh=;');
    await expect(cache.get(`auth:refresh:${signupRefreshCookie}`)).resolves.toBeUndefined();

    const signin = await agent.post('/signin')
      .set('X-CSRF-Token', signout.headers['x-csrf-token'] as string)
      .send({ email: validSignup.email, password: validSignup.password })
      .expect(200, { success: true, message: 'ok' });
    const signinAccessCookie = cookie(signin, 'test_access');
    const signinRefreshCookie = cookie(signin, 'test_refresh');
    expect(signinAccessCookie).toBeDefined();
    expect(signinRefreshCookie).toBeDefined();

    const refresh = await agent.post('/refresh-token')
      .set('X-CSRF-Token', signin.headers['x-csrf-token'] as string)
      .expect(200, { success: true, message: 'ok' });
    const refreshedAccessCookie = cookie(refresh, 'test_access');
    const refreshedRefreshCookie = cookie(refresh, 'test_refresh');
    expect(refreshedAccessCookie).not.toBe(signinAccessCookie);
    expect(refreshedRefreshCookie).not.toBe(signinRefreshCookie);
    await expect(cache.get(`auth:refresh:${signinRefreshCookie}`)).resolves.toBeUndefined();
    await expect(cache.get(`auth:refresh:${refreshedRefreshCookie}`)).resolves.toBeDefined();

    const revoke = await agent.post('/signout')
      .set('X-CSRF-Token', refresh.headers['x-csrf-token'] as string)
      .expect(200, {});
    await expect(cache.get(`auth:refresh:${refreshedRefreshCookie}`)).resolves.toBeUndefined();

    await agent.post('/refresh-token')
      .set('X-CSRF-Token', revoke.headers['x-csrf-token'] as string)
      .set('Cookie', `test_refresh=${refreshedRefreshCookie}`)
      .expect(401, { success: false, message: 'Refresh token has expired' });
  });
});

const setCookies = (response: request.Response): string[] => {
  const value = response.headers['set-cookie'];
  return value === undefined ? [] : Array.isArray(value) ? value : [value];
};

const cookie = (response: request.Response, name: string): string | undefined =>
  setCookies(response)
    .find((value) => value.startsWith(`${name}=`))
    ?.split(';')[0]
    ?.slice(`${name}=`.length);

const interactionUid = (response: request.Response): string => {
  const uid = response.headers.location?.match(/^\/interaction\/([^?]+)$/)?.[1];
  if (!uid) throw new Error(`Expected an interaction redirect, received: ${response.headers.location}`);
  return uid;
};
