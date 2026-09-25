import type { Logger } from "pino";
import type { KeyvValkeyOptions } from "@keyv/valkey";
import {
  type ConnectionParams,
  EnvironmentEnum,
  getSSMParameter,
  type SsmConnectionParams,
  toErrorMessage
} from "@dmptool/utils";
import type { Config, OAuthClient, SesConnectionParams } from "./types.js";

/**
 * Returns the SSM connection parameters
 *
 * @param logger The logger to use for logging
 * @returns The SSM connection parameters
 */
const getSSMConfig = async (
    logger: Logger,
): Promise<SsmConnectionParams | undefined> => {
  // If running locally, the SSM_ENDPOINT variable will be set
  return {
    logger,
    region: process.env.AWS_REGION || 'us-west-2',
    endpoint: process.env.SSM_ENDPOINT,
    useTLS: process.env.SSM_ENDPOINT === undefined
  };
}

const getSESConfig = async (
    ssmConfig: SsmConnectionParams,
    env: EnvironmentEnum = EnvironmentEnum.DEV
): Promise<SesConnectionParams | undefined> => {
  const inDevMode: boolean = ['development', 'test'].includes(process.env.NODE_ENV || 'development');
  const sesAccessKey: string | undefined = inDevMode ? 'DUMMY_KEY' : await getSSMParameter(ssmConfig, 'SesAccessKey', env);
  const sesAccessSecret: string | undefined = inDevMode ? 'DUMMY_SECRET' : await getSSMParameter(ssmConfig, 'SesAccessSecret', env);

  if (!sesAccessKey) {
    ssmConfig.logger.fatal('Missing SesAccessKey in SSM Parameter Store!');
    return undefined;
  }
  if (!sesAccessSecret) {
    ssmConfig.logger.fatal('Missing SesAccessSecret in SSM Parameter Store!');
    return undefined;
  }

  return {
    region: process.env.AWS_REGION || 'us-west-2',
    accessKey: sesAccessKey,
    accessSecret: sesAccessSecret,
    endpoint: process.env.SES_ENDPOINT || 'localhost',
    port: Number.parseInt(process.env.SES_PORT || '587', 10),
  };
}

/**
 * Helper function to get the RDS connection parameters
 *
 * @param ssmConfig the configuration for fetching parameters from SSM
 * @param env the environment to use for fetching parameters from SSM
 * @returns the RDS connection parameters
 */
const getMySQLConfig = async (
    ssmConfig: SsmConnectionParams,
    env: EnvironmentEnum = EnvironmentEnum.DEV
): Promise<ConnectionParams | undefined> => {
  const rdsUser: string | undefined = await getSSMParameter(ssmConfig, 'RdsUsername', env);
  const rdsPassword: string | undefined = await getSSMParameter(ssmConfig, 'RdsPassword', env);

  if (!rdsUser) {
    ssmConfig.logger.fatal('Missing RdsUserName in SSM Parameter Store!');
    return undefined;
  }
  if (!rdsPassword) {
    ssmConfig.logger.fatal('Missing RdsPassword in SSM Parameter Store!');
    return undefined;
  }

  return {
    logger: ssmConfig.logger,
    host: process.env.DB_HOST || 'localhost',
    port: Number(process.env.DB_PORT) || 3306,
    user: rdsUser,
    password: rdsPassword,
    database: process.env.DB_DATABASE || 'dmp'
  };
}

/**
 * Returns the cache configuration
 */
const getCacheConfig = (): KeyvValkeyOptions => {
  return {
    uri: `redis://${process.env.CACHE_HOST || 'localhost'}:${process.env.CACHE_PORT || '6379'}`,
    tls: ['development', 'test'].includes(process.env.NODE_ENV || 'development') ? undefined : {},
    connectTimeout: Number.parseInt(process.env.CACHE_CONNECT_TIMEOUT || '30000') ?? 30000, // 30 second default
    disconnectTimeout: Number.parseInt(process.env.CACHE_DISCONNECT_TIMEOUT || '30000') ?? 30000, // 30 second default
    keepAlive: Number.parseInt(process.env.CACHE_KEEP_ALIVE || '60000') ?? 60000, // 60 seconds
    useRedisSets: true, // improves performance for certain operations
    retryStrategy(times: number): number {
      // Exponential backoff with jitter to protect AWS endpoints from storming
      return Math.min(times * 100, 2000);
    },
  };
}

/**
 * Returns a required URL from the environment or a fallback.
 *
 * @param name the name of the environment variable to read
 * @param fallback an optional fallback value if the environment variable is not set
 * @returns the URL string
 * @throws if the environment variable is not set and no fallback is provided, or if the value is not a valid URL
 */
const requiredUrl = (name: string, fallback?: string): string => {
  const value: string | undefined = process.env[name] ?? fallback;
  if (!value) throw new Error(`${name} is required`);
  new URL(value);
  return value.replace(/\/$/, '');
};

/**
 * Loads the configuration from environment variables.
 *
 * @returns the configuration object
 * @throws if any required environment variable is missing or invalid
 */
export const loadConfig = async (logger: Logger): Promise<Config> => {
  const clientsJson: string = process.env.OIDC_CLIENTS_JSON ?? '[]';
  let oidcClients: OAuthClient[];
  try {
    const parsed: unknown = JSON.parse(clientsJson);
    if (!Array.isArray(parsed)) throw new Error('must be an array');
    oidcClients = parsed as OAuthClient[];
  } catch (error) {
    throw new Error(
      `OIDC_CLIENTS_JSON must be valid JSON array of OAuthClient objects: ${toErrorMessage(error)}`,
      { cause: error },
    );
  }

  const env: EnvironmentEnum = process.env.DEPLOYMENT_ENV
      ? EnvironmentEnum[process.env.DEPLOYMENT_ENV as keyof typeof EnvironmentEnum]
      : EnvironmentEnum.DEV;

  const ssmConfig: SsmConnectionParams | undefined = await getSSMConfig(logger);
  if (!ssmConfig) {
    throw new Error('Failed to get SSM configuration');
  }
  const sesConfig: SesConnectionParams | undefined = await getSESConfig(ssmConfig, env);
  if (!sesConfig) {
    throw new Error('Failed to get SES configuration');
  }
  const mysqlConfig: ConnectionParams | undefined = await getMySQLConfig(ssmConfig, env);
  if (!mysqlConfig) {
    throw new Error('Failed to get MySQL configuration');
  }

  const cacheConfig: KeyvValkeyOptions = getCacheConfig();
  const issuer = requiredUrl('ISSUER', 'http://localhost:3000');
  const audienceUI: string = process.env.AUDIENCE_UI || 'my-ui';
  const audienceAPI: string = process.env.AUDIENCE_API || 'my-api';

  const cookieSecure = process.env.COOKIE_SECURE === 'true';
  if (process.env.NODE_ENV === 'production') {
    if (new URL(issuer).protocol !== 'https:') {
      throw new Error('ISSUER must use HTTPS in production');
    }
    if (!cookieSecure) {
      throw new Error('COOKIE_SECURE must be true in production');
    }
  }

  return {
    env: process.env.NODE_ENV ?? 'development',
    logger,
    port: Number.parseInt(process.env.PORT ?? '3000', 10),

    domain: process.env.DOMAIN ?? 'localhost',
    applicationName: process.env.APPLICATION_NAME ?? 'my app',
    helpDeskAddress: process.env.HELP_DESK_ADDRESS ?? 'help@example.com',
    helpPageUrl: process.env.HELP_HOST ?? 'localhost',
    doNotReplyAddress: process.env.DO_NOT_REPLY_ADDRESS ?? 'no-reply@example.com',

    database: mysqlConfig,
    cache: cacheConfig,
    ses: sesConfig,

    issuer,
    audienceUI,
    audienceAPI,
    cookieSecure,

    tokens: {
      access: process.env.ACCESS_TOKEN_NAME ?? 'access_token',
      refresh: process.env.REFRESH_TOKEN_NAME ?? 'refresh_token',
      ssoPending: process.env.SSO_PENDING_TOKEN_NAME ?? 'sso_pending_token',
      validAudiences: [audienceUI, audienceAPI],
    },

    shibbolethProxySecret: process.env.SHIBBOLETH_PROXY_SECRET,

    pepperSecret: process.env.PEPPER_SECRET ?? 'default-pepper-secret',
    bcryptSaltRounds: Number.parseInt(process.env.BCRYPT_SALT_ROUNDS ?? '10', 10),

    ttl: {
      csrf: Number.parseInt(process.env.CSRF_TTL ?? '3600', 10),
      passwordReset: Number.parseInt(process.env.PASSWORD_RESET_TOKEN_TTL ?? '7200', 10),

      uiAccess: Number.parseInt(process.env.UI_ACCESS_TOKEN_TTL ?? '900', 10),
      uiRefresh: Number.parseInt(process.env.UI_REFRESH_TOKEN_TTL ?? '604800', 10),

      oidcCode: Number.parseInt(process.env.OIDC_CODE_TTL ?? '120', 10),
      oidcAccess: Number.parseInt(process.env.OIDC_ACCESS_TOKEN_TTL ?? '900', 10),
      oidcRefresh: Number.parseInt(process.env.OIDC_REFRESH_TOKEN_TTL ?? '3.154e+7', 10),
      oidcGrant: Number.parseInt(process.env.OIDC_GRANT_TTL ?? '120', 10),
      oidcIdToken: Number.parseInt(process.env.OIDC_ID_TOKEN_TTL ?? '600', 10),
      oidcInteraction: Number.parseInt(process.env.OIDC_INTERACTION_TTL ?? '600', 10),
    },

    oidcClients,
  };
};
