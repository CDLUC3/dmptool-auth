import { describe, expect, it, jest } from '@jest/globals';
import type { Config } from '../types.js';

const redis = { getdel: jest.fn<(key: string) => Promise<string | null>>() };
const store = {
  _getKeyName: jest.fn((key: string) => `valkey:${key}`),
  redis,
};
const instance = {
  get: jest.fn<(key: string) => Promise<string | undefined>>(),
  set: jest.fn<(key: string, value: string, ttl?: number) => Promise<void>>(),
  deleteMany: jest.fn<(keys: string[]) => Promise<boolean>>(),
  disconnect: jest.fn<() => Promise<void>>(),
  deserializeData: jest.fn<(value: string) => Promise<{ value?: string } | undefined>>(),
  _getKeyPrefix: jest.fn((key: string) => `keyv:${key}`),
  on: jest.fn(),
  store,
  iterator: undefined as undefined | ((options: { prefix: string }) => AsyncGenerator<string>),
};
instance.on.mockReturnValue(instance);
const createKeyv = jest.fn<(config: unknown) => typeof instance>(() => instance);

jest.unstable_mockModule('@keyv/valkey', () => ({ createKeyv }));
const { Cache } = await import('../cache.js');

const config = {
  cache: { uri: 'redis://valkey.example.test:6379' },
  logger: { debug: jest.fn(), error: jest.fn() },
} as unknown as Config;

describe('Cache', () => {
  it('uses configured ValKey, supports operations, and atomically consumes one-time values', async () => {
    const cache = new Cache(config);
    expect(createKeyv).toHaveBeenCalledWith(config.cache);

    instance.get.mockResolvedValueOnce('value');
    await expect(cache.get('key')).resolves.toBe('value');

    instance.set.mockResolvedValue(undefined);
    await cache.set('without-ttl', 'value');
    await cache.set('with-ttl', 'value', 60);
    expect(instance.set).toHaveBeenNthCalledWith(1, 'without-ttl', 'value');
    expect(instance.set).toHaveBeenNthCalledWith(2, 'with-ttl', 'value', 60_000);

    redis.getdel.mockResolvedValueOnce('serialized').mockResolvedValueOnce(null);
    instance.deserializeData.mockResolvedValueOnce({ value: 'consumed' });
    await expect(cache.consume('one-time')).resolves.toBe('consumed');
    await expect(cache.consume('missing')).resolves.toBeUndefined();
    expect(redis.getdel).toHaveBeenCalledWith('valkey:keyv:one-time');

    instance.deleteMany.mockResolvedValue(true);
    await expect(cache.del([])).resolves.toBe(false);
    await expect(cache.del(['one', 'two'])).resolves.toBe(true);

    instance.iterator = async function* (): AsyncGenerator<string> {
      yield 'auth:one';
      yield 'other:two';
    };
    await expect(cache.scan('auth:')).resolves.toEqual(['auth:one']);
    await cache.close();
    expect(instance.disconnect).toHaveBeenCalled();
  });

  it('rejects scans when the configured store cannot iterate', async () => {
    const cache = new Cache(config);
    instance.iterator = undefined;

    await expect(cache.scan('auth:')).rejects.toThrow('This store does not support iteration.');
  });
});
