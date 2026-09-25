import type Keyv from "keyv";
import { createKeyv } from '@keyv/valkey';
import type { Config } from "./types.js";

export interface CacheInterface {
  get(key: string): Promise<string | undefined>;
  consume(key: string): Promise<string | undefined>;
  scan(prefix: string): Promise<string[]>;
  set(key: string, value: string, ttlSeconds?: number): Promise<void>;
  del(keys: string[]): Promise<boolean>;
  close(): Promise<void>;
}

/**
 * The ValKey cache data source. The cache is used to store the refresh and CSRF tokens
 * as well as the list of revoked access tokens (using the JTI).
 */
export class Cache implements CacheInterface {
  public readonly instance: Keyv;

  constructor(public readonly config: Config) {
    this.instance = createKeyv(this.config.cache).on('error', (err: Error) => {
      this.config.logger.error({ err }, 'Error occurred in the cache');
    });
  }

  /**
   * Get the value associated with the given key from the cache.
   * If the key does not exist, null is returned.
   *
   * @param key The key to retrieve from the cache.
   * @returns A Promise that resolves to the value associated with the key, or
   * null if the key does not exist.
   */
  async get(key: string): Promise<string | undefined> {
    this.config.logger.debug({ key }, 'Fetching value from cache');
    return this.instance.get(key);
  }

  /**
   * Atomically retrieves and deletes the value for a one-time-use cache key.
   */
  async consume(key: string): Promise<string | undefined> {
    this.config.logger.debug({ key }, 'Consuming value from cache');
    const store = this.instance.store as {
      _getKeyName(key: string): string;
      redis: { getdel(key: string): Promise<string | null> };
    };
    const serialized = await store.redis.getdel(store._getKeyName(this.instance._getKeyPrefix(key)));
    if (serialized === null) return undefined;
    return (await this.instance.deserializeData<string>(serialized))?.value;
  }

  /**
   * Scan the cache for keys that start with the given prefix.
   *
   * @param prefix the prefix to scan for in the cache keys
   * @returns A Promise that resolves to an array of keys that match the prefix.
   */
  async scan(prefix: string): Promise<string[]> {
    this.config.logger.debug({ prefix }, 'Scanning cache for keys with prefix');
    const keys: string[] = [];

    // Ensure the iterator exists for the store
    if (typeof this.instance.iterator !== 'function') {
      throw new Error('This store does not support iteration.');
    }

    for await (const key of this.instance.iterator({ prefix })) {
      if (key.startsWith(prefix)) {
        keys.push(key);
      }
    }
    return keys;
  }

  /**
   * Set the value associated with the given key in the cache, with an optional
   * time-to-live (TTL) in seconds.
   *
   * @param key The key to set in the cache.
   * @param value The value to associate with the key in the cache.
   * @param ttlSeconds Optional time-to-live (TTL) in seconds for the key-value pair.
   * If not provided, the key will not expire.
   * @returns A Promise that resolves when the key-value pair has been set in the cache.
   */
  async set(key: string, value: string, ttlSeconds?: number): Promise<void> {
    this.config.logger.debug({ key }, 'Setting value in cache');
    if (ttlSeconds === undefined) await this.instance.set(key, value);
    else await this.instance.set(key, value, ttlSeconds * 1000);
  }

  /**
   * Delete the given keys from the cache. If a key does not exist, it will be ignored.
   *
   * @param keys The keys to delete from the cache.
   * @returns A Promise that resolves when the keys have been deleted from the cache.
   */
  async del(keys: string[]): Promise<boolean> {
    this.config.logger.debug({ keys }, 'Deleting values from cache');
    return (keys.length > 0) ? await this.instance.deleteMany(keys) : false;
  }

  /**
   * Close the connection to the Redis server. This method should be called when the cache is no longer needed,
   * to free up resources.
   */
  async close(): Promise<void> {
    this.config.logger.debug('Closing cache connection');
    await this.instance.disconnect();
  }
}
