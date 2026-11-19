import { createHash, randomBytes, randomUUID } from 'node:crypto';
import type { CacheInterface } from './cache.js';
import type { KeyStore } from './models/keyStore.js';
import type {
  PendingSSOSignupClaim,
  PublicUser,
  ShibbolethAssertion,
  TokenClaims
} from './types.js';
import { normalizeEmail } from './utils.js';

// Helper functions to generate cache keys for refresh tokens and revoked access tokens
const refreshKey = (token: string): string => `auth:refresh:${token}`;
const revokedKey = (jti: string): string => `auth:revoked:${jti}`;
const passwordResetKey = (token: string): string => `auth:password-reset:${token}`;

// Email confirmation tokens are stored by their SHA-256 hash so that a copy of the cache does not contain
// usable confirmation links. The owner key lets us replace an older link when a new one is requested.
const sha256 = (value: string): string => createHash('sha256').update(value).digest('hex');
const emailConfirmationKey = (tokenHash: string): string => `auth:email-confirmation:${tokenHash}`;
const emailConfirmationOwnerKey = (userId: string, email: string): string =>
  `auth:email-confirmation-owner:${sha256(`${userId}:${normalizeEmail(email)}`)}`;

/**
 * The user and email address that an email confirmation token was issued for.
 */
export interface EmailConfirmationClaim {
  userId: string;
  email: string;
}

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

/**
 * TokenService is responsible for issuing and managing access and refresh tokens for users.
 * It uses ValKey to manage refresh tokens and access-token revocations.
 */
export class TokenService {
  constructor(
    private readonly cache: CacheInterface,
    private readonly keyStore: KeyStore,
    private readonly accessTtlSeconds = 900,
    private readonly refreshTtlSeconds: number = 60 * 60 * 24 * 30,
    private readonly passwordResetTtlSeconds: number = 60 * 60 * 2,
    private readonly pendingSSOTtlSeconds: number = 900,
    private readonly emailConfirmationTtlSeconds: number = 60 * 60 * 24,
  ) {}

  /**
   * Issue a new access token and refresh token for the given user.
   * The access token is signed using the KeyStore and has a short TTL, while the refresh token is stored in the
   * ValKey with a longer TTL.
   *
   * @param audience The audience for the tokens.
   * @param user The user for whom to issue the tokens.
   * @returns A Promise that resolves to an object containing the access token, refresh token, and expiration time.
   */
  async issue(audience: string, user: PublicUser): Promise<AuthTokens> {
    const jti: string = randomUUID();
    const claims: TokenClaims = {
      id: user.id,
      email: user.email,
      givenName: user.givenName,
      surName: user.surName,
      role: user.role,
      affiliationId: user.affiliationId,
      languageId: user.languageId,
      jti,
      tokenVersion: user.tokenVersion,
    };
    const accessToken: string = await this.keyStore.issueAccessToken(audience, claims, this.accessTtlSeconds);
    const refreshToken: string = randomUUID();
    await this.cache.set(
      refreshKey(refreshToken),
      JSON.stringify({ userId: user.id, jti, tokenVersion: user.tokenVersion }),
      this.refreshTtlSeconds,
    );
    return { accessToken, refreshToken, expiresIn: this.accessTtlSeconds };
  }

  /**
   * Consume a refresh token by looking it up in ValKey. If found, the refresh token is deleted.
   *
   * @param refreshToken the refresh token to consume
   * @returns A Promise that resolves to an object containing the user ID, jti, and token version if the refresh token
   * is valid, or undefined if not found.
   */
  async consumeRefreshToken(refreshToken: string): Promise<{ userId: string; jti: string; tokenVersion: number } | undefined> {
    const record: string | undefined = await this.cache.consume(refreshKey(refreshToken));
    if (!record) return undefined;

    return JSON.parse(record) as { userId: string; jti: string; tokenVersion: number };
  }

  /**
   * Revoke an access token by storing its jti in the cache with a TTL equal to the access token's TTL.
   *
   * @param jti the unique identifier of the access token to revoke
   * @returns A Promise that resolves when the access token has been revoked.
   */
  async revoke(jti: string): Promise<void> {
    await this.cache.set(revokedKey(jti), '1', this.accessTtlSeconds);
  }

  /**
   * Determine whether an access token has been revoked.
   *
   * @param jti the unique identifier of the access token to check
   * @returns whether the access token has been revoked
   */
  async isRevoked(jti: string): Promise<boolean> {
    return (await this.cache.get(revokedKey(jti))) !== undefined;
  }

  /**
   * Verify a current, non-revoked access token.
   */
  async verifyAccessToken(accessToken: string): Promise<TokenClaims | undefined> {
    try {
      const claims: TokenClaims = await this.keyStore.verifyAccessToken(accessToken);
      return await this.isRevoked(claims.jti) ? undefined : claims;
    } catch {
      return undefined;
    }
  }

  /**
   * Create a cryptographically secure, time-limited pending SSO sign up token.
   */
  async issuePendingSSOSignupToken(audience: string, payload: ShibbolethAssertion): Promise<{ signupId: string, token: string }> {
    const signupId: string = randomUUID();
    const token: string = await this.keyStore.issuePendingSSOSignupToken(audience, signupId, payload, this.pendingSSOTtlSeconds);

    // Add the original SAML assertion to the cache so that we can use it later when the
    // user completes the signup process
    await this.cache.set(
      `auth:sso-pending:${signupId}`,
      JSON.stringify(payload),
      this.pendingSSOTtlSeconds
    );
    return { signupId, token };
  }

  /**
   * Retrieve the original SAML assertion for a pending SSO sign-up from the cache.
   *
   * @param signupId the unique identifier for the pending SSO sign-up
   * @returns a Promise that resolves to the ShibbolethAssertion if found, or undefined if not found
   */
  async getPendingSSOSignupAssertion(signupId: string): Promise<ShibbolethAssertion | undefined> {
    const record: string | undefined = await this.cache.get(`auth:sso-pending:${signupId}`);
    if (!record) return undefined;

    return JSON.parse(record) as ShibbolethAssertion;
  }

  /**
   * Verify a current, pending SSO sign-up token.
   */
  async verifyPendingSSOSignupToken(token: string): Promise<PendingSSOSignupClaim | undefined> {
    try {
      return await this.keyStore.verifyPendingSSOSignupToken(token);
    } catch {
      return undefined;
    }
  }

  /**
   * Create a cryptographically secure, time-limited password reset token.
   */
  async issuePasswordResetToken(userId: string): Promise<string> {
    const token: string = randomBytes(32).toString('base64url');
    await this.cache.set(passwordResetKey(token), userId, this.passwordResetTtlSeconds);
    return token;
  }

  /**
   * Return the user ID associated with a still-valid password reset token.
   */
  async passwordResetUserId(token: string): Promise<string | undefined> {
    return this.cache.get(passwordResetKey(token));
  }

  /**
   * Remove a password reset token after its password update succeeds.
   */
  async deletePasswordResetToken(token: string): Promise<void> {
    await this.cache.del([passwordResetKey(token)]);
  }

  /**
   * Create a cryptographically secure, time-limited, single-use token that confirms the user owns the email
   * address. Any earlier token for the same user and email stops working, so only the newest link is valid.
   *
   * @param userId the ID of the user who added the email address
   * @param email the email address to confirm
   * @returns the token to include in the confirmation link
   */
  async issueEmailConfirmationToken(userId: string, email: string): Promise<string> {
    const ownerKey: string = emailConfirmationOwnerKey(userId, email);
    const previousHash: string | undefined = await this.cache.consume(ownerKey);
    if (previousHash) {
      await this.cache.del([emailConfirmationKey(previousHash)]);
    }

    const token: string = randomBytes(32).toString('base64url');
    const tokenHash: string = sha256(token);
    const claim: EmailConfirmationClaim = { userId, email };
    await this.cache.set(emailConfirmationKey(tokenHash), JSON.stringify(claim), this.emailConfirmationTtlSeconds);
    await this.cache.set(ownerKey, tokenHash, this.emailConfirmationTtlSeconds);
    return token;
  }

  /**
   * Return the user and email for a still-valid email confirmation token without using it up.
   *
   * @param token the token from the confirmation link
   * @returns the claim, or undefined if the token is unknown or has expired
   */
  async emailConfirmationClaim(token: string): Promise<EmailConfirmationClaim | undefined> {
    const record: string | undefined = await this.cache.get(emailConfirmationKey(sha256(token)));
    return record ? JSON.parse(record) as EmailConfirmationClaim : undefined;
  }

  /**
   * Use up an email confirmation token. The read and delete happen in one step, so a token can only be
   * used once even if two requests arrive at the same time.
   *
   * @param token the token from the confirmation link
   * @returns the claim, or undefined if the token is unknown, expired or already used
   */
  async consumeEmailConfirmationToken(token: string): Promise<EmailConfirmationClaim | undefined> {
    const record: string | undefined = await this.cache.consume(emailConfirmationKey(sha256(token)));
    if (!record) return undefined;

    const claim = JSON.parse(record) as EmailConfirmationClaim;
    await this.cache.del([emailConfirmationOwnerKey(claim.userId, claim.email)]);
    return claim;
  }

  /**
   * Remove an email confirmation token, e.g. when the confirmation email could not be sent.
   *
   * @param token the token to remove
   */
  async deleteEmailConfirmationToken(token: string): Promise<void> {
    await this.consumeEmailConfirmationToken(token);
  }
}
