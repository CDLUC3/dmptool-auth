import { randomBytes, randomUUID } from 'node:crypto';
import type { CacheInterface } from './cache.js';
import type { KeyStore } from './models/keyStore.js';
import type { PublicUser, TokenClaims } from './types.js';

// Helper functions to generate cache keys for refresh tokens and revoked access tokens
const refreshKey = (token: string): string => `auth:refresh:${token}`;
const revokedKey = (jti: string): string => `auth:revoked:${jti}`;
const passwordResetKey = (token: string): string => `auth:password-reset:${token}`;

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
    private readonly passwordResetTtlSeconds = 60 * 60 * 2,
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
      const claims = await this.keyStore.verifyAccessToken(accessToken);
      return await this.isRevoked(claims.jti) ? undefined : claims;
    } catch {
      return undefined;
    }
  }

  /**
   * Create a cryptographically secure, time-limited password reset token.
   */
  async issuePasswordResetToken(userId: string): Promise<string> {
    const token = randomBytes(32).toString('base64url');
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
}
