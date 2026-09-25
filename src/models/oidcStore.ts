import type { ResultSetHeader } from "mysql2";
import type { Adapter, AdapterPayload } from 'oidc-provider';
import { queryTable } from '@dmptool/utils';
import type { CacheInterface } from '../cache.js';
import type { Config, dbQueryResponse, OidcRow } from "../types.js";
import { OauthClientStore } from './oauthClientStore.js';



const oidcTable: string = process.env.DB_OIDC_RECORDS_TABLE || 'oidc_records';

/**
 * Calculates the expiration date based on the provided expiresIn value.
 *
 * @param expiresIn The number of seconds until the record expires. If undefined,
 * the expiration date will be null.
 * @returns A Date object representing the expiration date, or null if expiresIn is undefined.
 */
const expiry = (expiresIn?: number): Date | null => {
  return expiresIn === undefined ? null : new Date(Date.now() + expiresIn * 1000);
};

export class OidcDbStore implements Adapter {
  constructor(private readonly config: Config, public readonly model: string) {}

  /**
   * Inserts or updates a record in the oidc_records table.
   * If a record with the same model and id already exists, it will be updated with the new payload
   * and expiration date.
   *
   * @param id The unique identifier for the record.
   * @param payload The payload to be stored in the record.
   * @param expiresIn Optional number of seconds until the record expires. If undefined, the expiration
   * date will be null.
   * @returns A Promise that resolves to true if the record was inserted or updated, or false if the
   * operation failed.
   */
  async upsert(id: string, payload: AdapterPayload, expiresIn?: number): Promise<void | undefined> {
    const response: dbQueryResponse = await queryTable(
      { ...this.config.database, logger: this.config.logger },
      `INSERT INTO ${oidcTable} (model, id, payload, grant_id, uid, user_code, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON DUPLICATE KEY 
           UPDATE payload = VALUES(payload), grant_id = VALUES(grant_id), uid = VALUES(uid),
           user_code = VALUES(user_code), expires_at = VALUES(expires_at)`,
        [this.model, id, JSON.stringify(payload), payload.grantId ?? null, payload.uid ?? null,
          payload.userCode ?? null, expiry(expiresIn)],
    );
    if (!response.results) {
      this.config.logger.error(`Failed to upsert OIDC record with model: ${this.model}, id: ${id}`);
      return undefined;
    }

    const resultSet: ResultSetHeader = response.results as ResultSetHeader;
    if (resultSet.affectedRows < 0) {
      this.config.logger.error(`Failed to upsert OIDC record with model: ${this.model}, id: ${id}`);
      return undefined;
    }
    return;
  }

  /**
   * Finds a record in the oidc_records table by its model and unique identifier.
   * Only returns the record if it has not expired.
   *
   * @param id The unique identifier for the record.
   * @returns A Promise that resolves to the AdapterPayload if found, or undefined if not found or expired.
   */
  async find(id: string): Promise<AdapterPayload | undefined> {
    const response: dbQueryResponse = await queryTable(
      { ...this.config.database, logger: this.config.logger },
      `SELECT payload FROM ${oidcTable} 
              WHERE model = ? AND id = ? AND (expires_at IS NULL OR expires_at > UTC_TIMESTAMP())`,
      [this.model, id],
    );
    if (!Array.isArray(response.results) || !response.results[0]) {
      this.config.logger.warn(`Failed to find OIDC record with model: ${this.model}, id: ${id}`);
      return undefined;
    }

    const row: OidcRow = response.results[0] as OidcRow;
    return typeof row.payload === 'string' ? JSON.parse(row.payload) as AdapterPayload : row.payload;
  }

  /**
   * Finds a record in the oidc_records table by its model and unique user identifier (uid).
   * Only returns the record if it has not expired.
   *
   * @param uid The unique user identifier for the record.
   * @returns A Promise that resolves to the AdapterPayload if found, or undefined if not found or expired.
   */
  async findByUid(uid: string): Promise<AdapterPayload | undefined> {
    const response: dbQueryResponse = await queryTable(
        { ...this.config.database, logger: this.config.logger },
        `SELECT payload FROM ${oidcTable} 
              WHERE model = ? AND uid = ? AND (expires_at IS NULL OR expires_at > UTC_TIMESTAMP())`,
        [this.model, uid],
    );
    if (!Array.isArray(response.results) || !response.results[0]) {
      this.config.logger.warn(`Failed to find OIDC record with model: ${this.model}, uid: ${uid}`);
      return undefined;
    }

    const row: OidcRow = response.results[0] as OidcRow;
    return typeof row.payload === 'string' ? JSON.parse(row.payload) as AdapterPayload : row.payload;
  }

  /**
   * Finds a record in the oidc_records table by its model and unique user code.
   * Only returns the record if it has not expired.
   *
   * @param userCode The unique user code for the record.
   * @returns A Promise that resolves to the AdapterPayload if found, or undefined if not found or expired.
   */
  async findByUserCode(userCode: string): Promise<AdapterPayload | undefined> {
    const response: dbQueryResponse = await queryTable(
        { ...this.config.database, logger: this.config.logger },
        `SELECT payload FROM ${oidcTable} 
              WHERE model = ? AND userCode = ? AND (expires_at IS NULL OR expires_at > UTC_TIMESTAMP())`,
        [this.model, userCode],
    );
    if (!Array.isArray(response.results) || !response.results[0]) {
      this.config.logger.warn(`Failed to find OIDC record with model: ${this.model}, userCode: ${userCode}`);
      return undefined;
    }

    const row: OidcRow = response.results[0] as OidcRow;
    return typeof row.payload === 'string' ? JSON.parse(row.payload) as AdapterPayload : row.payload;
  }

  /**
   * Marks a record in the OIDC records table as consumed by setting its consumed timestamp to the current time.
   *
   * @param id the unique identifier for the record
   */
  async consume(id: string): Promise<void> {
    const payload: AdapterPayload | undefined = await this.find(id);
    if (!payload) return;

    payload.consumed = Math.floor(Date.now() / 1000);
    const ttl: number | undefined = payload.exp
        ? Math.max(1, payload.exp - Math.floor(Date.now() / 1000))
        : undefined;

    await this.upsert(id, payload, ttl);
  }

  /**
   * Deletes a record from the OIDC records table by its model and unique identifier.
   *
   * @param id the unique identifier for the record
   */
  async destroy(id: string): Promise<void> {
    const response: dbQueryResponse = await queryTable(
      { ...this.config.database, logger: this.config.logger },
      `DELETE FROM ${oidcTable} WHERE model = ? AND id = ?`,
      [this.model, id]
    );
    if (!response.results || (response.results as ResultSetHeader).affectedRows === 0) {
      this.config.logger.error(`Failed to destroy OIDC record with model: ${this.model}, id: ${id}`);
    }
  }

  /**
   * Deletes all records from the OIDC records table that are associated with a specific grant ID.
   *
   * @param grantId the grant ID for which all associated records should be deleted
   */
  async revokeByGrantId(grantId: string): Promise<void> {
    const response: dbQueryResponse = await queryTable(
      { ...this.config.database, logger: this.config.logger },
      `DELETE FROM ${oidcTable} WHERE model = ? AND grant_id = ?`,
      [this.model, grantId]
    );
    if (!response.results || (response.results as ResultSetHeader).affectedRows === 0) {
      this.config.logger.warn(`No OIDC records found to revoke for model: ${this.model}, grantId: ${grantId}`);
    }
  }
}

/**
 * CacheAdapter is an implementation of the Adapter interface that uses a Cache instance to store and retrieve OIDC records.
 * It provides methods to upsert, find, consume, destroy, and revoke records based on their unique identifiers, user identifiers, or grant IDs.
 * The records are stored in the cache with optional expiration times.
 */
class OidcCachStore implements Adapter {
  constructor(
    private readonly cache: CacheInterface,
    readonly model: string,
  ) {}

  // Helper methods to generate cache keys based on the model name and identifiers.
  private key(id: string): string { return `oidc:${this.model}:${id}`; }
  private uidKey(uid: string): string { return `oidc:${this.model}:uid:${uid}`; }
  private userCodeKey(userCode: string): string { return `oidc:${this.model}:user-code:${userCode}`; }

  /**
   * Inserts or updates a record in the cache.
   * If a record with the same id already exists, it will be updated with the new payload and expiration time.
   * The record is stored in the cache with a key based on the model name and id.
   * If the payload contains a uid or userCode, additional keys are created to allow for lookup by those values.
   *
   * @param id The unique identifier for the record.
   * @param payload The payload to be stored in the record.
   * @param expiresIn Optional number of seconds until the record expires. If undefined, the record will not expire.
   */
  async upsert(id: string, payload: AdapterPayload, expiresIn?: number): Promise<void> {
    await this.cache.set(this.key(id), JSON.stringify(payload), expiresIn);
    if (payload.uid) await this.cache.set(this.uidKey(payload.uid), id, expiresIn);
    if (payload.userCode) await this.cache.set(this.userCodeKey(payload.userCode), id, expiresIn);
  }

  /**
   * Finds a record in the cache by its unique identifier.
   * Returns the AdapterPayload if found, or undefined if not found.
   *
   * @param id The unique identifier for the record.
   * @returns A Promise that resolves to the AdapterPayload if found, or undefined if not found.
   */
  async find(id: string): Promise<AdapterPayload | undefined> {
    const payload: string | undefined = await this.cache.get(this.key(id));
    return payload ? JSON.parse(payload) as AdapterPayload : undefined;
  }

  /**
   * Finds a record in the cache by its unique user identifier (uid).
   * Returns the AdapterPayload if found, or undefined if not found.
   *
   * @param uid The unique user identifier for the record.
   * @returns A Promise that resolves to the AdapterPayload if found, or undefined if not found.
   */
  async findByUid(uid: string): Promise<AdapterPayload | undefined> {
    const id: string | undefined = await this.cache.get(this.uidKey(uid));
    return id ? this.find(id) : undefined;
  }

  /**
   * Finds a record in the cache by its unique user code.
   * Returns the AdapterPayload if found, or undefined if not found.
   *
   * @param userCode The unique user code for the record.
   * @returns A Promise that resolves to the AdapterPayload if found, or undefined if not found.
   */
  async findByUserCode(userCode: string): Promise<AdapterPayload | undefined> {
    const id: string | undefined = await this.cache.get(this.userCodeKey(userCode));
    return id ? this.find(id) : undefined;
  }

  /**
   * Marks a record in the cache as consumed by setting its consumed timestamp to the current time.
   * If the record has an expiration time, it will be updated to ensure it does not expire before the current time.
   *
   * @param id The unique identifier for the record to be consumed.
   */
  async consume(id: string): Promise<void> {
    const record: string | undefined = await this.cache.consume(this.key(id));
    if (!record) return;
    const payload = JSON.parse(record) as AdapterPayload;
    payload.consumed = Math.floor(Date.now() / 1000);
    const ttl: number | undefined = payload.exp
      ? Math.max(1, payload.exp - Math.floor(Date.now() / 1000))
      : undefined;
    await this.upsert(id, payload, ttl);
  }

  /**
   * Deletes a record from the cache by its unique identifier.
   * If the record has a uid or userCode, those keys will also be deleted from the cache.
   *
   * @param id The unique identifier for the record to be deleted.
   */
  async destroy(id: string): Promise<void> {
    const payload: AdapterPayload | undefined = await this.find(id);
    const keys: string[] = [this.key(id)];
    if (payload?.uid) keys.push(this.uidKey(payload.uid));
    if (payload?.userCode) keys.push(this.userCodeKey(payload.userCode));
    await this.cache.del(keys);
  }

  /**
   * Deletes all records from the cache that are associated with a specific grant ID.
   * This method scans the cache for all keys associated with the model name, retrieves each record,
   * and deletes those that have a matching grant ID.
   *
   * @param grantId
   */
  async revokeByGrantId(grantId: string): Promise<void> {
    const keys: string[] = await this.cache.scan(`oidc:${this.model}:*`);
    await Promise.all(keys.map(async (key: string): Promise<void> => {
      const id: string = key.slice(`oidc:${this.model}:`.length);
      const payload: AdapterPayload | undefined = await this.find(id);
      if (payload?.grantId === grantId) await this.destroy(id);
    }));
  }
}

const createClientAdapter = (config: Config): Adapter => ({
  find: async (id: string): Promise<AdapterPayload | undefined> =>
    await new OauthClientStore().findActive(config, id) as AdapterPayload | undefined,
} as Adapter);

/**
 * Creates an OIDC adapter based on the provided database and cache instances.
 * Refresh tokens use ValKey, clients are resolved on demand from MySQL, and all
 * remaining provider records are stored in MySQL.
 *
 * @param config The configuration object containing database settings.
 * @param cache The Cache instance to be used for the CacheAdapter.
 * @returns A function that takes an adapter name and returns the appropriate Adapter instance.
 */
export const createAdapter = (config: Config, cache: CacheInterface) =>
  (name: string): Adapter => {
    if (name === 'RefreshToken') return new OidcCachStore(cache, name);
    if (name === 'Client') return createClientAdapter(config);
    return new OidcDbStore(config, name);
  };
