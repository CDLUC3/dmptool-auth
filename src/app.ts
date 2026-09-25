import { randomUUID, timingSafeEqual } from 'node:crypto';
import { decodeJwt } from 'jose';
import cookieParser from 'cookie-parser';
import express, { type Express, type NextFunction, type Request, type Response } from 'express';
import type { Grant, Interaction, Provider, UnknownObject } from 'oidc-provider';
import type { CacheInterface } from './cache.js';
import type { AuthTokens, TokenService } from './tokenService.js';
import type {Config, PublicUser, RefreshTokenData, ShibbolethAssertion} from './types.js';
import type { UserStore } from './models/userStore.js';
import type { Mail, SMTPSentMessageInfo } from "nodemailer";
import {sendResetPasswordEmail} from "./email.js";

interface Dependencies {
  config: Config;
  cache: CacheInterface;
  emailer: Mail<SMTPSentMessageInfo>
  users: UserStore;
  tokens: TokenService;
  provider: Provider;
}

const cookieOptions = (secure: boolean, maxAge: number) => ({
  httpOnly: true,
  secure,
  sameSite: 'lax' as const,
  path: '/',
  maxAge: maxAge * 1000,
});

const assertionFromHeaders = (headers: Request['headers']): ShibbolethAssertion => ({
  uid: headers['x-shib-eppn']?.toString(),
  email: headers['x-shib-mail']?.toString(),
  affiliation: headers['x-shib-affiliation']?.toString(),
  displayName: headers['x-shib-displayname']?.toString(),
  givenName: headers['x-shib-givenname']?.toString(),
  surName: headers['x-shib-sn']?.toString(),
  sessionId: headers['x-shib-session-id']?.toString(),
});

const hasTrustedShibbolethProxy = (headers: Request['headers'], secret: string | undefined): boolean => {
  const supplied = headers['x-shib-proxy-secret']?.toString();
  if (!secret || !supplied) return false;
  const expectedBuffer = Buffer.from(secret);
  const suppliedBuffer = Buffer.from(supplied);
  return expectedBuffer.length === suppliedBuffer.length && timingSafeEqual(expectedBuffer, suppliedBuffer);
};

const stringArray = (value: unknown): string[] =>
  Array.isArray(value) && value.every((item): item is string => typeof item === 'string') ? value : [];

/**
 * Write the access and refresh tokens to the response cookies.
 *
 * @param response the Express response object to which the cookies will be written
 * @param tokens the access and refresh tokens to be written to the cookies
 * @param config the configuration object containing cookie settings
 */
const writeTokens = (
  response: Response,
  tokens: Awaited<ReturnType<TokenService['issue']>>,
  config: Config
): void => {
  response.cookie(config.tokens.access, tokens.accessToken, cookieOptions(config.cookieSecure, tokens.expiresIn));
  response.cookie(config.tokens.refresh, tokens.refreshToken, cookieOptions(config.cookieSecure, config.ttl.uiRefresh));
};

/**
 * Create an Express application with the given dependencies.
 *
 * @param param0 An object containing the dependencies required to create the Express application
 * @param param0.config The configuration object containing application settings
 * @param param0.cache The cache object used for storing and retrieving data
 * @param param0.emailer The emailer object used for sending email notifications
 * @param param0.users The user repository used for managing user accounts
 * @param param0.tokens The token service used for issuing and managing access and refresh tokens
 * @param param0.provider The OIDC provider used for handling OpenID Connect interactions
 * @returns An Express application instance with the configured routes and middleware
 */
export const createApp = (
  { config, cache, emailer, users, tokens, provider }: Dependencies
): Express => {
  const app: Express = express();
  app.disable('x-powered-by');
  app.use(express.json());
  app.use(cookieParser());

  /**
   * Health check endpoint to verify that the application is running and able to connect to the cache.
   *
   * @route GET /healthz
   * @returns A JSON response with a status of "ok" if the application is healthy, or an error response if not
   */
  app.get('/healthz', async (_request: Request, response: Response): Promise<void> => {
    await cache.get('healthcheck');
    response.status(200).json({ status: 'ok' });
  });

  /**
   * CSRF token endpoint to generate and return a new CSRF token.
   *
   * @route GET /csrf
   * @returns A response with the generated CSRF token in the "X-CSRF-Token" header and a status of "ok"
   */
  app.get('/csrf', async (_request: Request, response: Response, next: NextFunction): Promise<void> => {
    try {
      const token = randomUUID().replaceAll('-', '');
      await cache.set(`auth:csrf:${token}`, '1', config.ttl.csrf);
      response.set('Access-Control-Expose-Headers', 'X-CSRF-Token');
      response.set('X-CSRF-Token', token).status(200).send('ok');
    } catch (error) {
      next(error);
    }
  });

  /**
   * Endpoint for checking whether a CSRF token is valid without consuming it.
   *
   * @route POST /csrf/verify
   * @param request The Express request object
   * @param response The Express response object
   * @param next The next middleware function in the stack
   * @returns A JSON response indicating whether the CSRF token is valid
   */
  app.post('/csrf/verify', async (request: Request, response: Response, next: NextFunction): Promise<void> => {
    try {
      const token: string | undefined = request.header('X-CSRF-Token');
      response.status(200).json({ valid: Boolean(token && await cache.get(`auth:csrf:${token}`)) });
    } catch (error) {
      next(error);
    }
  });

  /**
   * CSRF protection middleware to validate the CSRF token for certain routes.
   *
   * @param request The Express request object
   * @param response The Express response object
   * @param next The next middleware function in the stack
   * @returns A response with a status of 403 if the CSRF token is invalid, or calls the next middleware function if valid
   */
  app.use(async (request: Request, response: Response, next: NextFunction): Promise<void> => {
    if (!['/signup', '/signin', '/refresh-token', '/signout', '/password-reset/token', '/change-password'].includes(request.path)
      || ['GET', 'HEAD', 'OPTIONS'].includes(request.method)) {
      next();
      return;
    }

    // Fetch the CSRF token from the request header and validate it against the cache
    const token: string | undefined = request.header('X-CSRF-Token');
    if (!token || !(await cache.consume(`auth:csrf:${token}`))) {
      response.status(403).json({ error: 'Invalid CSRF token' });
      return;
    }

    // Generate a replacement CSRF token after atomically consuming the used token.
    const replacement: string = randomUUID().replaceAll('-', '');
    await cache.set(`auth:csrf:${replacement}`, '1', 3600);
    response.set('Access-Control-Expose-Headers', 'X-CSRF-Token');
    response.set('X-CSRF-Token', replacement);
    next();
  });

  /**
   * Redirect endpoint for the JWKS (JSON Web Key Set) to the well-known location.
   *
   * @param _request The Express request object
   * @param response The Express response object
   * @returns A JSON response indicating the success or failure of the operation
   * @returns A 302 redirect response to the well-known JWKS location
   */
  app.get('/jwks.json', (_request: Request, response: Response): void => {
    response.redirect(302, '/.well-known/jwks.json');
  });

  /**
   * Endpoint for checking whether an access token has been revoked.
   *
   * @route GET /revocations/:jti
   * @param request The Express request object
   * @param response The Express response object
   * @param next The next middleware function in the stack
   * @returns A JSON response indicating whether the JTI is revoked
   */
  app.get('/revocations/:jti', async (request: Request, response: Response, next: NextFunction): Promise<void> => {
    try {
      const { jti } = request.params;
      if (typeof jti !== 'string') {
        config.logger.debug({ params: request.params }, 'Revocations - missing JTI parameter');
        response.status(400).json({ success: false, message: 'jti must be a string' });
        return;
      }
      config.logger.debug({ jti}, 'Revocations - received request');
      response.status(200).json({ revoked: await tokens.isRevoked(jti) });
    } catch (error) {
      next(error);
    }
  });

  /**
   * Endpoint for signing up a new user.
   *
   * @route POST /signup
   * @param request The Express request object
   * @param response The Express response object
   * @param next The next middleware function in the stack
   * @returns A JSON response indicating the success or failure of the operation
   */
  app.post('/signup', async (request: Request, response: Response, next: NextFunction): Promise<void> => {
    try {
      const body = request.body as Record<string, string | undefined>;
      const pendingSignupId = request.cookies[`${config.tokens.ssoPending}`] as string | undefined;
      const pendingSignup: string | undefined = pendingSignupId
        ? await cache.get(`auth:sso-pending:${pendingSignupId}`)
        : undefined;
      const assertion: ShibbolethAssertion | undefined = pendingSignup ? JSON.parse(pendingSignup) as ShibbolethAssertion : undefined;
      const assertionSubject: string | undefined = assertion?.uid ?? assertion?.email;
      const email: string | undefined = assertion?.email ?? body.email;
      const password: string | undefined = body.password;
      const givenName: string | undefined = body.givenName ?? assertion?.givenName;
      const surName: string | undefined = body.surName ?? assertion?.surName;
      const affiliationId: string | undefined = body.affiliationId;
      const acceptedTerms: boolean = typeof body.acceptedTerms === 'string'
          ? ['1', 'true', 'yes'].includes(body.acceptedTerms.toLowerCase())
          : Boolean(body.acceptedTerms);
      const languageId: string | undefined = body.languageId;
      const ssoId: string | undefined = assertionSubject ?? body.ssoId;
      if (!email || !password || !givenName || !surName) {
        response.status(400).json({ success: false, message: 'email, password, givenName, and surName are required' });
        return;
      }

      config.logger.debug({ email, givenName, surName, affiliationId }, 'Sign up - received request');
      const user: PublicUser | undefined = await users.create({
        email,
        password,
        givenName,
        surName,
        affiliationId: affiliationId ?? '',
        languageId: languageId ?? '',
        role: 'RESEARCHER', // We always default to RESEARCHER for new signups
        ssoId,
        acceptedTerms,
        failed_login_attempts: 0,
      });
      if (!user) {
        config.logger.debug({ email }, 'Sign up - failure to create user');
        response.status(400).json({ success: false, message: 'Failed to create user' });
        return;
      }

      const issued: AuthTokens = await tokens.issue(user);
      writeTokens(response, issued, config);
      if (pendingSignupId) {
        await cache.del([`auth:sso-pending:${pendingSignupId}`]);
        response.clearCookie(config.tokens.ssoPending, { path: '/' });
      }
      config.logger.debug({ email }, 'Sign up - user created successfully');
      response.status(201).json({ success: true, message: 'ok' });
    } catch (error) {
      config.logger.error({ error }, 'Sign up - error occurred');
      if (error instanceof Error && error.message.includes('already exists')) {
        response.status(409).json({ success: false, message: error.message });
        return;
      }
      next(error);
    }
  });

  /**
   * Endpoint for signing in a user via email and password.
   *
   * @route POST /signin
   * @param request The Express request object
   * @param response The Express response object
   * @param next The next middleware function in the stack
   * @returns A JSON response indicating the success or failure of the operation
   */
  app.post('/signin', async (request: Request, response: Response, next: NextFunction): Promise<void> => {
    try {
      const { email, password } = request.body as Record<string, string>;
      if (!email || !password) {
        config.logger.debug({ email }, 'Sign in - failed');
        response.status(401).json({ success: false, message: 'Invalid credentials' });
        return;
      }
      // Authenticate the user using the provided email and password
      const user: PublicUser | undefined = await users.authenticate(email, password);
      if (!user) {
        config.logger.debug({ email }, 'Sign in - no matching user found');
        response.status(401).json({ success: false, message: 'Invalid credentials' });
        return;
      }

      // Issue new access and refresh tokens for the authenticated user
      config.logger.debug({ email }, 'Sign in - issuing tokens');
      const issued: AuthTokens = await tokens.issue(user);
      writeTokens(response, issued, config);
      response.status(200).json({ success: true, message: 'ok' });
    } catch (error) {
      next(error);
    }
  });

  /**
   * Endpoint for refreshing the access token using a valid refresh token.
   *
   * @route POST /refresh-token
   * @param request The Express request object
   * @param response The Express response object
   * @param next The next middleware function in the stack
   * @returns A JSON response indicating the success or failure of the operation
   */
  app.post('/refresh-token', async (request: Request, response: Response, next: NextFunction): Promise<void> => {
    try {
      const refreshToken = request.cookies[config.tokens.refresh] as string | undefined;
      config.logger.debug({ refreshToken }, 'Refresh token - from cache');

      if (!refreshToken) {
        config.logger.debug({ refreshToken }, 'Refresh token - Not found in cache');
        response.status(401).json({ success: false, message: 'No refresh token available' });
        return;
      }
      // Fetch the refresh token record from the cache and validate it against the user record
      const record: RefreshTokenData | undefined = await tokens.consumeRefreshToken(refreshToken);
      config.logger.debug({ refreshToken, userId: record?.userId }, 'Refresh token - found user ID');
      const user: PublicUser | undefined = record ? await users.findById(record.userId) : undefined;
      if (!record || !user || user.tokenVersion !== record.tokenVersion) {
        config.logger.debug({ refreshToken, tokenVersion: record?.tokenVersion }, 'Refresh token - expired');
        response.status(401).json({ success: false, message: 'Refresh token has expired' });
        return;
      }
      // Revoke the old refresh token and issue a new one
      await tokens.revoke(record.jti);
      const issued: AuthTokens = await tokens.issue(user);

      // Write the new access and refresh tokens to the response cookies
      config.logger.debug({ refreshToken, userId: record?.userId }, 'Refresh token - issuing new tokens');
      writeTokens(response, issued, config);
      response.status(200).json({ success: true, message: 'ok' });
    } catch (error) {
      next(error);
    }
  });

  /**
   * Endpoint for signing out a user.
   *
   * @route POST /signout
   * @param request The Express request object
   * @param response The Express response object
   * @param next The next middleware function in the stack
   * @returns A JSON response indicating the success or failure of the operation
   */
  app.post('/signout', async (request: Request, response: Response, next: NextFunction): Promise<void> => {
    try {
      const accessToken = request.cookies[config.tokens.access] as string | undefined;
      const refreshToken = request.cookies[config.tokens.refresh] as string | undefined;
      if (accessToken) {
        config.logger.debug({ accessToken }, 'Sign out - revoking access token');
        const { jti } = decodeJwt(accessToken);
        if (typeof jti === 'string') await tokens.revoke(jti);
      }
      if (refreshToken) await tokens.consumeRefreshToken(refreshToken);
      config.logger.debug({ accessToken }, 'Sign out - clearing cookies');
      response.clearCookie(config.tokens.access, { path: '/' });
      response.clearCookie(config.tokens.refresh, { path: '/' });
      response.clearCookie(config.tokens.ssoPending, { path: '/' });
      response.status(200).json({});
    } catch (error) {
      next(error);
    }
  });

  /**
   * Create a password reset token for the specified email address
   *
   * @route POST /password-reset/token
   */
  app.post('/password-reset/token', async (request: Request, response: Response, next: NextFunction): Promise<void> => {
    try {
      const email = (request.body as Record<string, unknown> | undefined)?.email;
      if (typeof email !== 'string') {
        response.status(400).json({ success: false, message: 'Email is required' });
        return;
      }
      const claims = await users.findByEmail(email);
      if (!claims) {
        response.status(404).json({ success: false, message: 'User not found' });
        return;
      }
      const token = await tokens.issuePasswordResetToken(claims.id);
      const delivered = await sendResetPasswordEmail(config, emailer, claims.email, token);
      if (!delivered) {
        await tokens.deletePasswordResetToken(token);
        response.status(502).json({ success: false, message: 'Unable to send password reset email' });
        return;
      }
      response.status(201).json({ success: true, message: 'ok' });
    } catch (error) {
      next(error);
    }
  });

  /**
   * Check whether a password reset token is still valid without consuming it.
   *
   * @route POST /password-reset/verify
   */
  app.post('/password-reset/verify', async (request: Request, response: Response, next: NextFunction): Promise<void> => {
    try {
      const token = (request.body as Record<string, unknown> | undefined)?.token;
      const valid = typeof token === 'string' && Boolean(await tokens.passwordResetUserId(token));
      response.status(200).json({ valid });
    } catch (error) {
      next(error);
    }
  });

  /**
   * Reset a password using a time-limited password reset token.
   *
   * @route POST /password-reset
   */
  app.post('/password-reset', async (request: Request, response: Response, next: NextFunction): Promise<void> => {
    try {
      const { token, password, passwordConfirmation } = request.body as Record<string, unknown>;
      if (typeof token !== 'string' || typeof password !== 'string' || typeof passwordConfirmation !== 'string') {
        response.status(400).json({ success: false, message: 'token, password, and passwordConfirmation are required' });
        return;
      }
      if (password !== passwordConfirmation) {
        response.status(400).json({ success: false, message: 'Passwords do not match' });
        return;
      }
      const userId = await tokens.passwordResetUserId(token);
      if (!userId || !(await users.resetPassword(userId, password))) {
        response.status(400).json({ success: false, message: 'Invalid or expired password reset token' });
        return;
      }
      await tokens.deletePasswordResetToken(token);
      response.status(200).json({ success: true, message: 'ok' });
    } catch (error) {
      if (error instanceof Error && error.message === 'Invalid password format') {
        response.status(400).json({ success: false, message: error.message });
        return;
      }
      next(error);
    }
  });

  /**
   * Change the authenticated user's password after verifying their current password.
   *
   * @route POST /change-password
   */
  app.post('/change-password', async (request: Request, response: Response, next: NextFunction): Promise<void> => {
    try {
      const { currentPassword, newPassword, newPasswordConfirmation } = request.body as Record<string, unknown>;
      if (
        typeof currentPassword !== 'string'
        || typeof newPassword !== 'string'
        || typeof newPasswordConfirmation !== 'string'
      ) {
        response.status(400).json({
          success: false,
          message: 'currentPassword, newPassword, and newPasswordConfirmation are required',
        });
        return;
      }
      if (newPassword !== newPasswordConfirmation) {
        response.status(400).json({ success: false, message: 'Passwords do not match' });
        return;
      }

      const accessToken = request.cookies[config.tokens.access] as string | undefined;
      const claims = accessToken ? await tokens.verifyAccessToken(accessToken) : undefined;
      if (!claims) {
        response.status(401).json({ success: false, message: 'Invalid access token' });
        return;
      }
      if (!(await users.changePassword(claims.id, currentPassword, newPassword))) {
        response.status(401).json({ success: false, message: 'Invalid current password' });
        return;
      }
      response.status(200).json({ success: true, message: 'ok' });
    } catch (error) {
      if (error instanceof Error && error.message === 'Invalid password format') {
        response.status(400).json({ success: false, message: error.message });
        return;
      }
      next(error);
    }
  });

  /**
   * Endpoint for handling SSO login.
   *
   * @route POST /sso
   * @param request The Express request object
   * @param response The Express response object
   * @param next The next middleware function in the stack
   * @returns A redirect response to the SSO login page
   */
  app.all(['/sso', '/sso/passthru'], (request: Request, response: Response) => {
    const values: unknown = request.method === 'GET' ? request.query : request.body;
    const { email, entityId } = values as Record<string, string>;
    if (!email || !email.includes('@')) {
      config.logger.warn({ email, entityId }, 'SSO Passthru - invalid email');
      response.status(400).json({ success: false, message: 'Invalid email address' });
      return;
    }
    if (!entityId) {
      config.logger.warn({ email }, 'SSO Passthru - missing entityId');
      response.status(400).json({ success: false, message: 'entityId is required' });
      return;
    }
    const target = new URL('/sso/callback', config.issuer);
    const queryString = `target=${encodeURIComponent(target.toString())}&entityId=${encodeURIComponent(entityId)}`;
    config.logger.debug({ email, entityId, target, queryString }, 'SSO Passthru - initiated');
    response.redirect(302, `/Shibboleth.sso/Login?${queryString}`);
  });

  /**
   * Endpoint for handling SSO callback from the identity provider.
   *
   * @route GET /sso/callback
   * @param request The Express request object
   * @param response The Express response object
   * @param next The next middleware function in the stack
   * @returns A redirect response to the signup page if the user is not found, or a redirect to the home page
   * if the user is authenticated
   */
  app.all(['/sso/callback', '/sso/callback/:id'], async (request: Request, response: Response, next: NextFunction): Promise<void> => {
    try {
      if (!hasTrustedShibbolethProxy(request.headers, config.shibbolethProxySecret)) {
        config.logger.warn({ params: request.params }, 'SSO Callback - untrusted proxy');
        response.status(403).json({ success: false, message: 'Untrusted Shibboleth proxy' });
        return;
      }
      const assertion: ShibbolethAssertion = assertionFromHeaders(request.headers);
      const subject: string | undefined = assertion.uid ?? assertion.email;
      if (!subject || !assertion.email) {
        config.logger.warn({ assertion }, 'SSO Callback - missing Shibboleth identity headers');
        response.status(400).json({ success: false, message: 'Missing Shibboleth identity headers' });
        return;
      }
      const user: PublicUser | undefined = await users.findBySsoId(subject);
      if (!user) {
        config.logger.debug({ subject }, 'SSO Callback - no matching user found');
        const signupId: string = assertion.sessionId ?? crypto.randomUUID();
        await cache.set(`auth:sso-pending:${signupId}`, JSON.stringify(assertion), 600);
        response.cookie(config.tokens.ssoPending, signupId, cookieOptions(config.cookieSecure, 600));
        response.status(302).location('/signup').send();
        return;
      }

      config.logger.debug({ user }, 'SSO Callback - user authenticated');
      const issued: AuthTokens = await tokens.issue(user);
      writeTokens(response, issued, config);
      response.status(302).location('/').send();
    } catch (error) {
      next(error);
    }
  });

  /**
   * Endpoint for retrieving interaction details.
   *
   * @route GET /interaction/:uid
   * @param request The Express request object
   * @param response The Express response object
   * @param next The next middleware function in the stack
   * @returns A JSON response containing the interaction details
   */
  app.get('/interaction/:uid', async (request: Request, response: Response, next: NextFunction): Promise<void> => {
    try {
      const details: Interaction = await provider.interactionDetails(request, response);
      config.logger.debug({ details }, 'OIDC interaction - received request');
      response.status(200).json({
        uid: details.uid,
        prompt: details.prompt.name,
        clientId: details.params.client_id,
        params: details.params,
      });
    } catch (error) {
      config.logger.error({ error }, 'OIDC interaction - error');
      next(error);
    }
  });

  /**
   * Endpoint for handling interaction responses.
   *
   * @route POST /interaction/:uid
   * @param request The Express request object
   * @param response The Express response object
   * @param next The next middleware function in the stack
   * @returns A JSON response indicating the success or failure of the operation
   */
  app.post('/interaction/:uid', async (request: Request, response: Response, next: NextFunction): Promise<void> => {
    try {
      const details: Interaction = await provider.interactionDetails(request, response);
      if (details.prompt.name === 'login') {
        config.logger.debug({ details }, 'OIDC interaction - login initiated');
        const { email, password } = request.body as Record<string, string>;
        const user: PublicUser | undefined = await users.authenticate(email, password);
        if (!user) {
          config.logger.debug({ details }, 'OIDC interaction - no user found');
          response.status(401).json({ error: 'invalid_credentials' });
          return;
        }
        config.logger.debug({ details }, 'OIDC interaction - login successful');
        await provider.interactionFinished(request, response, {
          login: { accountId: user.id, acr: 'pwd', amr: ['pwd'], remember: true, ts: Math.floor(Date.now() / 1000) },
        });
        return;
      }
      if (details.prompt.name === 'consent') {
        config.logger.debug({ details }, 'OIDC interaction - consent initiated');
        const accountId: string | undefined = details.session?.accountId;
        const clientId: string | unknown = details.params.client_id;
        if (typeof accountId !== 'string' || typeof clientId !== 'string') {
          config.logger.debug({ details }, 'OIDC interaction - missing account or client ID');
          throw new Error('Consent interaction is missing an account or client ID');
        }
        const grant: Grant | undefined = details.grantId
          ? await provider.Grant.find(details.grantId)
          : new provider.Grant({
            accountId,
            clientId,
          });
        config.logger.debug({ grant }, 'OIDC interaction - fetched grant');
        if (!grant) throw new Error(`Unable to load grant: ${details.grantId}`);

        const consentDetails: UnknownObject = details.prompt.details;
        const missingScopes: string[] = stringArray(consentDetails.missingOIDCScope);
        if (missingScopes.length > 0) {
          config.logger.debug({ details, missingScopes }, 'OIDC interaction - adding scope');
          grant.addOIDCScope(missingScopes.join(' '));
        }
        const missingClaims: string[] = stringArray(consentDetails.missingOIDCClaims);
        if (missingClaims.length > 0) {
          config.logger.debug({ details, missingClaims }, 'OIDC interaction - adding claims');
          grant.addOIDCClaims(missingClaims);
        }
        if (consentDetails.missingResourceScopes) {
          for (const [resource, scopes] of Object.entries(consentDetails.missingResourceScopes)) {
            const missingResourceScopes: string[] = stringArray(scopes);
            if (missingResourceScopes.length > 0) {
                config.logger.debug({ details, resource, scopes }, 'OIDC interaction - adding resource scopes');
              grant.addResourceScope(resource, missingResourceScopes.join(' '));
            }
          }
        }
        await provider.interactionFinished(
          request,
          response,
          { consent: { grantId: await grant.save() } },
          { mergeWithLastSubmission: true },
        );
        config.logger.debug({ details }, 'OIDC interaction - success');
        return;
      }

      config.logger.debug({ details }, 'OIDC interaction - unsupported');
      response.status(400).json({ error: 'unsupported_interaction' });
    } catch (error) {
      config.logger.error({ error }, 'OIDC interaction - error');
      next(error);
    }
  });

  /**
   * Endpoint for handling the OIDC callback.
   *
   * @route GET /callback
   * @param request The Express request object
   * @param response The Express response object
   * @returns A redirect response to the home page
   */
  app.use((request: Request, response: Response): Promise<void> => provider.callback()(request, response));

  /**
   * Error handling middleware to catch unhandled errors and return a 500 response.
   *
   * @param error The error object that was thrown
   * @param _request The Express request object
   * @param response The Express response object
   * @param next The next middleware function in the stack
   * @returns A JSON response with a status of 500 and an error message
   */
  app.use((error: unknown, _request: Request, response: Response, next: express.NextFunction): void => {
    void next;
    response.status(500).json({ success: false, message: 'Internal server error' });
    if (process.env.NODE_ENV !== 'test') console.error(error);
  });
  return app;
};
