import { exportJWK, generateKeyPair, importJWK, jwtVerify, type CryptoKey, type JWK, SignJWT } from 'jose';
import { queryTable } from '@dmptool/utils';
import type { Config, dbQueryResponse, KeyRow, TokenClaims } from "../types.js";

const keyName = 'auth:oidc:jwks';

const authKeysTable: string = process.env.DB_AUTH_KEYS_TABLE || 'auth_keys';

/**
 * KeyStore is responsible for managing the signing keys used to issue JWTs.
 * It loads persisted key material from MySQL or generates keys on first use.
 */
export class KeyStore {
  private constructor(
    private readonly issuer: string,
    private readonly signingKey: CryptoKey,
    readonly jwks: { keys: JWK[] },
  ) {}

  /**
   * Load the KeyStore from MySQL or generate new keys if none exist.
   *
   * @param config the configuration object containing database and logger settings
   * @returns a Promise that resolves to a KeyStore instance
   * @throws an error if the stored JWKS does not contain a private signing key
   */
  static async load(config: Config): Promise<KeyStore> {
    const response: dbQueryResponse = await queryTable(
        { ...config.database, logger: config.logger },
      `SELECT jwks FROM ${authKeysTable} WHERE name = ?`,
      [keyName]
    );
    if (response && Array.isArray(response.results) && response.results[0]) {
      const result: KeyRow = response.results[0] as KeyRow;
      const row: KeyRow['jwks'] = typeof result.jwks === 'string' ? JSON.parse(result.jwks) : result.jwks;
      const keys: JWK[] = row?.keys || [];
      const signing: JWK | undefined = keys.find((key: JWK): boolean => key.d !== undefined);
      if (!signing) throw new Error('Stored JWKS does not contain a private signing key');

      const imported: CryptoKey | Uint8Array<ArrayBufferLike> = await importJWK(signing, 'RS256');
      if (imported instanceof Uint8Array) throw new Error('Stored signing key must be asymmetric');
      config.logger.info('Found existing signing key in database');

      return new KeyStore(config.issuer, imported, { keys });
    }

    // Otherwise, generate a new key pair and persist it.
    config.logger.info('No signing key found in database; generating new key pair');
    const { privateKey, publicKey } = await generateKeyPair('RS256', { extractable: true });
    const privateJwk: JWK = await exportJWK(privateKey);
    const publicJwk: JWK = await exportJWK(publicKey);
    privateJwk.kid = publicJwk.kid = 'auth-service-rs256-1';
    privateJwk.use = publicJwk.use = 'sig';
    privateJwk.alg = publicJwk.alg = 'RS256';
    const jwks = { keys: [privateJwk, publicJwk] };
    await queryTable(
      { ...config.database, logger: config.logger },
      `INSERT INTO ${authKeysTable} (name, jwks) VALUES (?, ?)`,
      [keyName, JSON.stringify(jwks)]
    );

    return new KeyStore(config.issuer, privateKey, jwks);
  }

  /**
   * Return the public JWKS for the OIDC discovery endpoint.
   *
   * @returns an object containing the public keys in JWKS format
   */
  publicJwks(): { keys: JWK[] } {
    return { keys: this.jwks.keys.filter((key): boolean => key.d === undefined) };
  }

  /**
   * Issue an access token with the given claims and expiration time.
   *
   * @param claims the claims to include in the JWT payload
   * @param expiresInSeconds the expiration time in seconds (default: 900)
   * @returns a Promise that resolves to the signed JWT string
   */
  async issueAccessToken(claims: TokenClaims, expiresInSeconds = 900): Promise<string> {
    return new SignJWT({ ...claims })
      .setProtectedHeader({ alg: 'RS256', kid: 'auth-service-rs256-1', typ: 'JWT' })
      .setIssuer(this.issuer)
      .setSubject(claims.id)
      .setIssuedAt()
      .setExpirationTime(`${expiresInSeconds}s`)
      .sign(this.signingKey);
  }

  /**
   * Verify an access token issued by this service and return its application claims.
   */
  async verifyAccessToken(token: string): Promise<TokenClaims> {
    const verificationJwk: JWK | undefined = this.publicJwks().keys[0];
    if (!verificationJwk) throw new Error('No public signing key is available');
    const verificationKey = await importJWK(verificationJwk, 'RS256');
    const { payload } = await jwtVerify(token, verificationKey, {
      algorithms: ['RS256'],
      issuer: this.issuer,
    });
    if (
      typeof payload.id !== 'string'
      || typeof payload.email !== 'string'
      || typeof payload.givenName !== 'string'
      || typeof payload.surName !== 'string'
      || typeof payload.role !== 'string'
      || typeof payload.affiliationId !== 'string'
      || typeof payload.languageId !== 'string'
      || typeof payload.jti !== 'string'
      || typeof payload.tokenVersion !== 'number'
      || payload.sub !== payload.id
    ) {
      throw new Error('Invalid access token claims');
    }
    return {
      id: payload.id,
      email: payload.email,
      givenName: payload.givenName,
      surName: payload.surName,
      role: payload.role,
      affiliationId: payload.affiliationId,
      languageId: payload.languageId,
      jti: payload.jti,
      tokenVersion: payload.tokenVersion,
    };
  }
}
