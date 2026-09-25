import { jest } from '@jest/globals';
import type { CacheInterface } from '../../cache.js';
import type { Config } from '../../types.js';

interface Entry {
  value: string;
  expiresAt?: number;
}

/**
 * A mock replacement for Cache whose Jest spies operate on an in-memory ValKey store.
 */
export class MockValkeyCache implements CacheInterface {
  private readonly values = new Map<string, Entry>();

  constructor(_config?: Config) {
    void _config;
  }

  readonly get = jest.fn(async (key: string): Promise<string | undefined> => {
    const entry = this.values.get(key);
    if (!entry) return undefined;
    if (entry.expiresAt !== undefined && entry.expiresAt <= Date.now()) {
      this.values.delete(key);
      return undefined;
    }
    return entry.value;
  });

  readonly consume = jest.fn(async (key: string): Promise<string | undefined> => {
    const value = await this.get(key);
    if (value !== undefined) this.values.delete(key);
    return value;
  });

  readonly set = jest.fn(async (key: string, value: string, ttlSeconds?: number): Promise<void> => {
    this.values.set(key, {
      value,
      expiresAt: ttlSeconds === undefined ? undefined : Date.now() + ttlSeconds * 1000,
    });
  });

  readonly del = jest.fn(async (keys: string[]): Promise<boolean> => {
    const deleted = keys.some((key) => this.values.delete(key));
    return deleted;
  });

  readonly scan = jest.fn(async (prefix: string): Promise<string[]> => {
    const expression = new RegExp(`^${prefix.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replaceAll('\\*', '.*')}`);
    const keys = await Promise.all([...this.values.keys()].map(async (key) => (await this.get(key)) ? key : undefined));
    return keys.filter((key): key is string => key !== undefined && expression.test(key));
  });

  readonly close = jest.fn(async (): Promise<void> => undefined);
}
