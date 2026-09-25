import type { CacheInterface } from '../cache.js';

interface Entry {
  value: string;
  expiresAt?: number;
}

export class CacheSpecTs implements CacheInterface {
  private readonly values = new Map<string, Entry>();

  async get(key: string): Promise<string | undefined> {
    const entry = this.values.get(key);
    if (!entry) return undefined;
    if (entry.expiresAt !== undefined && entry.expiresAt <= Date.now()) {
      this.values.delete(key);
      return undefined;
    }
    return entry.value;
  }

  async consume(key: string): Promise<string | undefined> {
    const value = await this.get(key);
    if (value !== undefined) this.values.delete(key);
    return value;
  }

  async set(key: string, value: string, ttlSeconds?: number): Promise<void> {
    this.values.set(key, { value, expiresAt: ttlSeconds === undefined ? undefined : Date.now() + ttlSeconds * 1000 });
  }

  async del(keys: string[]): Promise<boolean> {
    return keys.some((key) => this.values.delete(key));
  }

  async scan(pattern: string): Promise<string[]> {
    const expression = new RegExp(`^${pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replaceAll('\\*', '.*')}$`);
    return [...this.values.keys()].filter((key) => expression.test(key) && this.values.has(key));
  }

  async close(): Promise<void> {}
}
