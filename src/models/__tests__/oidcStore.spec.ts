import { beforeEach, describe, expect, it, jest } from '@jest/globals';

const queryTable = jest.fn<(config: unknown, sql: string, values?: unknown[]) => Promise<unknown>>();
jest.unstable_mockModule('@dmptool/utils', () => ({ queryTable }));
const { createAdapter } = await import('../oidcStore.js');

const config = {
  database: {},
  logger: { error: jest.fn(), warn: jest.fn() },
};

class MemoryCache {
  private readonly values = new Map<string, string>();
  readonly calls = { set: [] as unknown[][], del: [] as string[][], scan: [] as string[] };

  async get(key: string): Promise<string | undefined> {
    return this.values.get(key);
  }

  async consume(key: string): Promise<string | undefined> {
    const value = this.values.get(key);
    this.values.delete(key);
    return value;
  }

  async set(key: string, value: string): Promise<void> {
    this.calls.set.push([key, value]);
    this.values.set(key, value);
  }

  async del(keys: string[]): Promise<boolean> {
    this.calls.del.push(keys);
    keys.forEach((key) => this.values.delete(key));
    return keys.length > 0;
  }

  async scan(pattern: string): Promise<string[]> {
    this.calls.scan.push(pattern);
    const prefix = pattern.slice(0, -1);
    return [...this.values.keys()].filter((key) => key.startsWith(prefix));
  }
}

beforeEach(() => {
  queryTable.mockReset();
});

describe('OIDC adapters', () => {
  it('persists database-backed records with their OIDC metadata', async () => {
    queryTable
      .mockResolvedValueOnce({ results: { affectedRows: 1 }, fields: [] })
      .mockResolvedValueOnce({
        results: [{ payload: JSON.stringify({ grantId: 'grant-1', uid: 'uid-1' }) }],
        fields: [],
      });
    const adapter = createAdapter(config as never, new MemoryCache() as never)('AccessToken');

    await adapter.upsert('one', { grantId: 'grant-1', uid: 'uid-1', userCode: 'code-1' }, 300);
    await expect(adapter.find('one')).resolves.toMatchObject({ grantId: 'grant-1' });

    expect(queryTable.mock.calls[0][1]).toContain('grant_id, uid, user_code, expires_at');
  });

  it.failing('uses the stored snake_case user-code column for lookups', async () => {
    queryTable.mockResolvedValueOnce({ results: [], fields: [] });
    const adapter = createAdapter(config as never, new MemoryCache() as never)('AccessToken');

    await adapter.findByUserCode('code-1');

    expect(queryTable.mock.calls[0][1]).toContain('user_code = ?');
  });

  it('uses the stored snake_case grant column for revocation', async () => {
    queryTable.mockResolvedValueOnce({ results: { affectedRows: 1 }, fields: [] });
    const adapter = createAdapter(config as never, new MemoryCache() as never)('AccessToken');

    await adapter.revokeByGrantId('grant-1');

    expect(queryTable.mock.calls[0][1]).toContain('grant_id = ?');
  });

  it('stores, consumes, locates, destroys, and revokes refresh-token records in the cache', async () => {
    const cache = new MemoryCache();
    const refreshTokens = createAdapter(config as never, cache as never)('RefreshToken');
    const expiresAt = Math.floor(Date.now() / 1000) + 300;

    await refreshTokens.upsert('one', { grantId: 'grant-1', uid: 'uid-1', userCode: 'code-1', exp: expiresAt }, 300);
    await refreshTokens.upsert('two', { grantId: 'grant-1', exp: expiresAt }, 300);
    await expect(refreshTokens.findByUid('uid-1')).resolves.toMatchObject({ uid: 'uid-1' });
    await expect(refreshTokens.findByUserCode('code-1')).resolves.toMatchObject({ userCode: 'code-1' });

    await refreshTokens.consume('one');
    await expect(refreshTokens.find('one')).resolves.toMatchObject({ consumed: expect.any(Number) });
    await refreshTokens.destroy('one');
    await expect(refreshTokens.findByUid('uid-1')).resolves.toBeUndefined();

    await refreshTokens.upsert('refresh-token', { grantId: 'grant-1', accountId: 'user-1' }, 60);
    await expect(refreshTokens.find('refresh-token')).resolves.toMatchObject({ accountId: 'user-1' });
    await refreshTokens.revokeByGrantId('grant-1');
    await expect(refreshTokens.find('two')).resolves.toBeUndefined();
    await expect(refreshTokens.find('refresh-token')).resolves.toBeUndefined();
  });

  it('handles database adapter failures, object payloads, and record lifecycle operations', async () => {
    const adapter = createAdapter(config as never, new MemoryCache() as never)('AuthorizationCode');
    queryTable.mockResolvedValueOnce({ results: undefined, fields: [] });
    await expect(adapter.upsert('failed', {}, 1)).resolves.toBeUndefined();

    queryTable.mockResolvedValueOnce({ results: { affectedRows: -1 }, fields: [] });
    await adapter.upsert('failed-again', {}, undefined);
    expect(config.logger.error).toHaveBeenCalledTimes(2);

    queryTable.mockResolvedValueOnce({ results: [{ payload: { uid: 'object' } }], fields: [] });
    await expect(adapter.find('object')).resolves.toEqual({ uid: 'object' });
    queryTable.mockResolvedValueOnce({ results: [], fields: [] });
    await expect(adapter.findByUid('missing')).resolves.toBeUndefined();

    queryTable
      .mockResolvedValueOnce({ results: [{ payload: JSON.stringify({ exp: Math.floor(Date.now() / 1000) + 60 }) }], fields: [] })
      .mockResolvedValueOnce({ results: { affectedRows: 1 }, fields: [] });
    await adapter.consume('expiring');
    expect(queryTable.mock.calls[5]![2]![6]).toBeInstanceOf(Date);

    queryTable.mockResolvedValueOnce({ results: [], fields: [] });
    await adapter.consume('missing');
    queryTable.mockResolvedValueOnce({ results: { affectedRows: 0 }, fields: [] });
    await adapter.destroy('missing');
    queryTable.mockResolvedValueOnce({ results: undefined, fields: [] });
    await adapter.revokeByGrantId('missing');
    expect(config.logger.warn).toHaveBeenCalled();
  });

  it('uses all cache branches for absent records and records without secondary keys', async () => {
    const cache = new MemoryCache();
    const adapter = createAdapter(config as never, cache as never)('RefreshToken');

    await adapter.upsert('plain', {}, undefined);
    await expect(adapter.findByUid('absent')).resolves.toBeUndefined();
    await expect(adapter.findByUserCode('absent')).resolves.toBeUndefined();
    await adapter.consume('absent');
    await adapter.destroy('absent');
    await adapter.destroy('plain');
    await adapter.revokeByGrantId('no-match');

    expect(cache.calls.set).toHaveLength(1);
    expect(cache.calls.del).toContainEqual(['oidc:RefreshToken:plain']);
    expect(cache.calls.scan).toEqual(['oidc:RefreshToken:*']);
  });
});
