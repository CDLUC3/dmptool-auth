import {
  decodeProtectedHeader,
  exportJWK,
  generateKeyPair,
  importJWK,
  jwtVerify,
  type CryptoKey,
  type JWK,
  SignJWT,
} from 'jose';
import { queryTable } from '@dmptool/utils';
import type { Config, dbQueryResponse, KeyRow, RetiredSigningKey, StoredKeySet, TokenClaims } from "../types.js";

const keyName = 'auth:oidc:jwks';
const authKeysTable: string = process.env.DB_AUTH_KEYS_TABLE || 'auth_keys';

/**
 * Returns the public portion of a JWK by removing private key properties.
 *
 * @param key The JWK to extract the public key from
 * @returns A new JWK containing only the public key properties
 */
const publicKey = (key: JWK): JWK => {
  const publicJwk = { ...key };
  (['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'] as const).forEach((property): void => {
    delete publicJwk[property];
  });
  return publicJwk;
};

/**
 * Generates a new RSA key pair for signing JWTs and returns the private key and JWKS.
 *
 * @returns A Promise that resolves to an object containing the private key and JWKS
 */
const createKeyPair = async (): Promise<{ privateKey: CryptoKey; jwks: { keys: JWK[] } }> => {
  const { privateKey, publicKey: generatedPublicKey } = await generateKeyPair('RS256', { extractable: true });
  const privateJwk: JWK = await exportJWK(privateKey);
  const publicJwk: JWK = await exportJWK(generatedPublicKey);
  const kid = `auth-service-rs256-${crypto.randomUUID()}`;
  privateJwk.kid = publicJwk.kid = kid;
  privateJwk.use = publicJwk.use = 'sig';
  privateJwk.alg = publicJwk.alg = 'RS256';
  return { privateKey, jwks: { keys: [privateJwk, publicJwk] } };
};

/**
 * Finds the active signing key from a list of JWKs. The active signing key is the one that contains a private key (i.e., has a 'd' property).
 *
 * @param keys An array of JWKs to search for the active signing key
 * @returns The active signing key if found, otherwise undefined
 */
const activeSigningKey = (keys: JWK[]): JWK | undefined => keys.find((key): boolean => key.d !== undefined);

/**
 * Filters the list of retired signing keys to only include those that have not yet expired.
 *
 * @param retired An array of retired signing keys to filter
 * @param now The current date and time
 * @returns An array of retained public keys
 */
const retainedPublicKeys = (retired: RetiredSigningKey[], now: Date): RetiredSigningKey[] =>
  retired.filter(({ expiresAt }): boolean => new Date(expiresAt) > now);

/**
 * KeyStore is responsible for managing the signing keys used to issue JWTs.
 * It loads persisted key material from MySQL, rotates it on a configured interval,
 * and retains retired public keys long enough to verify in-flight access tokens.
 */
export class KeyStore {
  private constructor(
    private readonly issuer: string,
    private readonly signingKey: CryptoKey,
    readonly jwks: StoredKeySet,
    private readonly validAudiences: string[],
  ) {}

  /**
   * Load the KeyStore from MySQL, rotating an expired signing key, or generate
   * an initial key pair if none exists. Rotation is evaluated during service startup.
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
    // If the query returned a row, parse the JWKS and check if the signing key needs to be rotated.
    if (response && Array.isArray(response.results) && response.results[0]) {
      const result: KeyRow = response.results[0] as KeyRow;
      const row: StoredKeySet = typeof result.jwks === 'string' ? JSON.parse(result.jwks) : result.jwks;
      const keys: JWK[] = row?.keys || [];
      const signing: JWK | undefined = activeSigningKey(keys);
      if (!signing) throw new Error('Stored JWKS does not contain a private signing key');

      const now = new Date();
      const rotationSeconds: number = config.tokens.keyRotationSeconds;
      const createdAt: Date | undefined = row.createdAt ? new Date(row.createdAt) : undefined;
      const rotationDue: boolean = !createdAt || Number.isNaN(createdAt.valueOf())
        || now.valueOf() - createdAt.valueOf() >= rotationSeconds * 1000;
      const retired: RetiredSigningKey[] = retainedPublicKeys(row.retired ?? [], now);

      if (rotationDue) {
        const { privateKey, jwks } = await createKeyPair();
        const retentionSeconds: number = Math.max(
          config.ttl.uiAccess,
          config.ttl.oidcAccess,
        ) + 60;
        const persisted: StoredKeySet = {
          keys: jwks.keys,
          createdAt: now.toISOString(),
          retired: [
            ...retired,
            {
              key: publicKey(signing),
              expiresAt: new Date(now.valueOf() + retentionSeconds * 1000).toISOString(),
            },
          ],
        };
        await queryTable(
          { ...config.database, logger: config.logger },
          `UPDATE ${authKeysTable} SET jwks = ? WHERE name = ?`,
          [JSON.stringify(persisted), keyName],
        );
        config.logger.info('Rotated signing key in database');
        return new KeyStore(config.issuer, privateKey, persisted, config.tokens.validAudiences);
      }

      const imported: CryptoKey | Uint8Array<ArrayBufferLike> = await importJWK(signing, 'RS256');
      if (imported instanceof Uint8Array) throw new Error('Stored signing key must be asymmetric');
      config.logger.info('Found existing signing key in database');

      return new KeyStore(
        config.issuer,
        imported,
        { keys, createdAt: row.createdAt, retired },
        config.tokens.validAudiences,
      );
    }

    // Otherwise, no record was found in the db so generate a new key pair and persist it.
    config.logger.info('No signing key found in database; generating new key pair');
    const { privateKey, jwks } = await createKeyPair();
    const persisted: StoredKeySet = { ...jwks, createdAt: new Date().toISOString(), retired: [] };
    await queryTable(
      { ...config.database, logger: config.logger },
      `INSERT INTO ${authKeysTable} (name, jwks) VALUES (?, ?)`,
      [keyName, JSON.stringify(persisted)]
    );

    return new KeyStore(config.issuer, privateKey, persisted, config.tokens.validAudiences);
  }

  /**
   * Return the public JWKS for the OIDC discovery endpoint.
   *
   * @returns an object containing the public keys in JWKS format
   */
  publicJwks(): { keys: JWK[] } {
    return {
      keys: [
        ...this.jwks.keys.filter((key): boolean => key.d === undefined),
        ...(this.jwks.retired ?? []).map(({ key }): JWK => key),
      ],
    };
  }

  /**
   * Issue an access token with the given claims and expiration time.
   *
   * @param audience the audience for the access token
   * @param claims the claims to include in the JWT payload
   * @param expiresInSeconds the expiration time in seconds (default: 900)
   * @returns a Promise that resolves to the signed JWT string
   */
  async issueAccessToken(audience: string, claims: TokenClaims, expiresInSeconds = 900): Promise<string> {
    if (!audience) throw new Error('Audience is required to issue an access token');

    // Make sure the specified audience is known to us
    const validatedAudience: string | undefined = this.validAudiences.includes(audience) ? audience : undefined;
    if (!validatedAudience) throw new Error('Invalid audience for access token');

    return new SignJWT({ ...claims })
      .setProtectedHeader({ alg: 'RS256', kid: activeSigningKey(this.jwks.keys)?.kid, typ: 'JWT' })
      .setIssuer(this.issuer)
      .setAudience(validatedAudience)
      .setSubject(claims.id)
      .setIssuedAt()
      .setExpirationTime(`${expiresInSeconds}s`)
      .sign(this.signingKey);
  }

  /**
   * Verify an access token issued by this service and return its application claims.
   *
   * @param token the JWT access token to verify
   * @returns a Promise that resolves to the application claims
   */
  async verifyAccessToken(token: string): Promise<TokenClaims> {
    const { alg, kid } = decodeProtectedHeader(token);
    if (alg !== 'RS256' || !kid) throw new Error('Invalid access token header');
    const verificationJwk: JWK | undefined = this.publicJwks().keys.find((key): boolean => key.kid === kid);
    if (!verificationJwk) throw new Error('No public signing key is available');
    const verificationKey = await importJWK(verificationJwk, 'RS256');
    const { payload } = await jwtVerify(token, verificationKey, {
      algorithms: ['RS256'],
      issuer: this.issuer,
      audience: this.validAudiences,
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
