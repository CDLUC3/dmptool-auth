import { decodeJwt, importJWK, jwtVerify } from 'jose';
import { beforeEach, describe, expect, it, jest } from '@jest/globals';

const queryTable = jest.fn<(config: unknown, sql: string, values?: unknown[]) => Promise<unknown>>();
jest.unstable_mockModule('@dmptool/utils', () => ({ queryTable }));
const { KeyStore } = await import('../keyStore.js');

const config = {
  issuer: 'https://auth.example.test',
  database: {},
  logger: { info: jest.fn() },
};

beforeEach(() => {
  queryTable.mockReset();
});

describe('KeyStore', () => {
  it('reloads the JWKS format that it persists', async () => {
    queryTable
      .mockResolvedValueOnce({ results: [], fields: [] })
      .mockResolvedValueOnce({ results: { affectedRows: 1 }, fields: [] });

    const first = await KeyStore.load(config as never);
    const persistedJwks = JSON.parse(queryTable.mock.calls[1]![2]![1] as string);
    queryTable.mockResolvedValueOnce({ results: [{ jwks: persistedJwks }], fields: [] });
    const second = await KeyStore.load(config as never);

    expect(first.publicJwks().keys).toEqual(second.publicJwks().keys);
    expect(first.publicJwks().keys[0]).not.toHaveProperty('d');
    expect(queryTable).toHaveBeenCalledWith(
      expect.anything(),
      expect.stringContaining('INSERT INTO auth_keys'),
      ['auth:oidc:jwks', expect.any(String)],
    );
  });

  it('loads serialized stored keys and excludes private keys', async () => {
    queryTable
      .mockResolvedValueOnce({ results: [], fields: [] })
      .mockResolvedValueOnce({ results: { affectedRows: 1 }, fields: [] });
    const generated = await KeyStore.load(config as never);
    const persisted = queryTable.mock.calls[1][2]![1] as string;
    queryTable.mockResolvedValueOnce({ results: [{ jwks: persisted }], fields: [] });

    const reloaded = await KeyStore.load(config as never);

    expect(reloaded.publicJwks().keys).toEqual(generated.publicJwks().keys);
    expect(config.logger.info).toHaveBeenCalledWith('Found existing signing key in database');
  });

  it('rejects a stored JWKS without a private signing key', async () => {
    queryTable.mockResolvedValueOnce({
      results: [{ jwks: { jwks: { keys: [{ kty: 'RSA', kid: 'public-only' }] } } }],
      fields: [],
    });

    await expect(KeyStore.load(config as never)).rejects.toThrow(
      'Stored JWKS does not contain a private signing key',
    );
  });

  it('issues an RS256 access token with the configured issuer and supplied claims', async () => {
    queryTable
      .mockResolvedValueOnce({ results: [], fields: [] })
      .mockResolvedValueOnce({ results: { affectedRows: 1 }, fields: [] });
    const store = await KeyStore.load(config as never);
    const token = await store.issueAccessToken({
      id: 'user-1',
      email: 'user@example.test',
      givenName: 'User',
      surName: 'Example',
      role: 'RESEARCHER',
      affiliationId: 'affiliation-1',
      languageId: 'en',
      jti: 'jti-1',
      tokenVersion: 0,
    }, 60);

    expect(decodeJwt(token)).toMatchObject({ iss: config.issuer, sub: 'user-1', jti: 'jti-1' });
    const publicKey = await importJWK(store.publicJwks().keys[0]!, 'RS256');
    await expect(jwtVerify(token, publicKey)).resolves.toMatchObject({
      protectedHeader: { alg: 'RS256', kid: 'auth-service-rs256-1' },
    });
  });
});
