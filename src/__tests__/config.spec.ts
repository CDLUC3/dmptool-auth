import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import type { Logger } from 'pino';

const getSSMParameter = jest.fn<() => Promise<string | undefined>>();
jest.unstable_mockModule('@dmptool/utils', () => ({
  EnvironmentEnum: { DEV: 'DEV' },
  getSSMParameter,
  toErrorMessage: (error: unknown) => error instanceof Error ? error.message : String(error),
}));
const { loadConfig } = await import('../config.js');

const logger = {
  fatal: jest.fn(),
} as unknown as Logger;
const environment = { ...process.env };

beforeEach(() => {
  process.env = {
    ...environment,
    RDS_USERNAME: 'auth',
    RDS_PASSWORD: 'password',
    ISSUER: 'https://auth.example.test',
    COOKIE_SECURE: 'true',
    NODE_ENV: 'test',
  };
  getSSMParameter.mockReset();
  getSSMParameter.mockResolvedValue('credential');
  jest.clearAllMocks();
});

afterEach(() => {
  process.env = environment;
});

describe('loadConfig', () => {
  it('loads configured database, cache, and OIDC TTL values', async () => {
    process.env.CACHE_HOST = 'valkey.example.test';
    process.env.CACHE_PORT = '6380';
    process.env.OIDC_CLIENTS_JSON = '[]';
    process.env.PASSWORD_RESET_TOKEN_TTL = '123';

    const config = await loadConfig(logger);

    expect(config.issuer).toBe('https://auth.example.test');
    expect(config.cookieSecure).toBe(true);
    expect(config.database).toMatchObject({ host: 'localhost', user: 'credential', password: 'credential' });
    expect(config.cache).toMatchObject({ uri: 'redis://valkey.example.test:6380', useRedisSets: true });
    expect(config.ttl.oidcInteraction).toBeGreaterThan(0);
    expect(config.ttl.passwordReset).toBe(123);
  });

  it('uses local cache defaults when cache environment values are absent', async () => {
    process.env.DEPLOYMENT_ENV = 'DEV';
    delete process.env.CACHE_HOST;
    delete process.env.CACHE_PORT;
    delete process.env.CACHE_CONNECT_TIMEOUT;
    delete process.env.CACHE_DISCONNECT_TIMEOUT;
    delete process.env.CACHE_KEEP_ALIVE;
    delete process.env.PASSWORD_RESET_TOKEN_TTL;

    const config = await loadConfig(logger);

    expect(config.cache).toMatchObject({
      uri: 'redis://localhost:6379',
      connectTimeout: 30_000,
      disconnectTimeout: 30_000,
      keepAlive: 60_000,
    });
    expect(config.ttl.passwordReset).toBe(7_200);
  });

  it('uses the local issuer fallback when ISSUER is not configured', async () => {
    delete process.env.ISSUER;

    const config = await loadConfig(logger);

    expect(config.issuer).toBe('http://localhost:3000');
  });

  it('rejects malformed client configuration and insecure production settings', async () => {
    process.env.OIDC_CLIENTS_JSON = '{}';
    await expect(loadConfig(logger)).rejects.toThrow('OIDC_CLIENTS_JSON must be valid JSON array');

    process.env.OIDC_CLIENTS_JSON = '[]';
    process.env.NODE_ENV = 'production';
    process.env.ISSUER = 'http://auth.example.test';
    await expect(loadConfig(logger)).rejects.toThrow('ISSUER must use HTTPS in production');

    process.env.ISSUER = 'https://auth.example.test';
    process.env.COOKIE_SECURE = 'false';
    await expect(loadConfig(logger)).rejects.toThrow('COOKIE_SECURE must be true in production');
  });

  it('rejects configuration when database credentials cannot be loaded', async () => {
    delete process.env.RDS_USERNAME;
    delete process.env.RDS_PASSWORD;
    getSSMParameter.mockImplementation(async (_config, name) =>
      name === 'SesAccessKey' || name === 'SesAccessSecret' ? 'credential' : undefined);

    await expect(loadConfig(logger)).rejects.toThrow('Failed to get MySQL configuration');
    expect(logger.fatal).toHaveBeenCalledWith('Missing RdsUserName in SSM Parameter Store!');
  });

  it('rejects configuration when the database password is unavailable', async () => {
    delete process.env.RDS_PASSWORD;
    getSSMParameter.mockImplementation(async (_config, name) => name === 'SesAccessKey' || name === 'SesAccessSecret'
      ? 'credential'
      : name === 'RdsUsername' ? 'auth' : undefined);

    await expect(loadConfig(logger)).rejects.toThrow('Failed to get MySQL configuration');
    expect(logger.fatal).toHaveBeenCalledWith('Missing RdsPassword in SSM Parameter Store!');
  });

  it('rejects configuration when SES credentials cannot be loaded', async () => {
    getSSMParameter.mockResolvedValue(undefined);

    await expect(loadConfig(logger)).rejects.toThrow('Failed to get SES configuration');
    expect(logger.fatal).toHaveBeenCalledWith('Missing SesAccessKey in SSM Parameter Store!');

    getSSMParameter.mockImplementation(async (_config, name) => name === 'SesAccessKey' ? 'credential' : undefined);
    await expect(loadConfig(logger)).rejects.toThrow('Failed to get SES configuration');
    expect(logger.fatal).toHaveBeenCalledWith('Missing SesAccessSecret in SSM Parameter Store!');
  });
});
