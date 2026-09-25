import { type Logger } from 'pino';
import type Provider from "oidc-provider";
import type { Express } from "express";
import type { IncomingMessage, Server, ServerResponse } from "node:http";
import type { Mail, SMTPSentMessageInfo } from "nodemailer";
import { initializeLogger, LogLevelEnum } from "@dmptool/utils";
import { Cache } from './cache.js';
import { loadConfig } from './config.js';
import { createProvider } from './oidc.js';
import { createApp } from './app.js';
import { initializeEmailTransporter } from './email.js';
import { TokenService } from './tokenService.js';
import type { Config } from './types.js';
import { KeyStore } from './models/keyStore.js';
import { UserStore } from './models/userStore.js';

// Initialize the logger
const logLevel: LogLevelEnum = process.env.LOG_LEVEL
  ? LogLevelEnum[process.env.LOG_LEVEL.toUpperCase() as keyof typeof LogLevelEnum]
  : LogLevelEnum.INFO;
const logger: Logger = initializeLogger('auth', logLevel);

// Load the application configuration from environment variables and SSM Parameter Store
const config: Config = await loadConfig(logger);

// Initialize the cache, load the keyStore and userStore from the database
const emailer: Mail<SMTPSentMessageInfo> = initializeEmailTransporter(config);
const cache = new Cache(config);
const keys: KeyStore = await KeyStore.load(config);
const users = new UserStore(config);

// set up the OIDC provider
const provider: Provider = createProvider(
  config,
  cache,
  users,
  keys,
);

// Create and start the Express application
const app: Express = createApp({
  config,
  cache,
  emailer,
  users,
  tokens: new TokenService(
    cache,
    keys,
    config.tokens.audience,
    config.ttl.uiAccess,
    config.ttl.uiRefresh,
    config.ttl.passwordReset,
  ),
  provider
});

const server: Server<typeof IncomingMessage, typeof ServerResponse> = app.listen(config.port, () => {
  console.log(`Auth service listening at ${config.issuer}`)
});

const close = async (): Promise<void> => {
  server.close();
  await cache.close();
};

process.once('SIGINT', () => void close());
process.once('SIGTERM', () => void close());
