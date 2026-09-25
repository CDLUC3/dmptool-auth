import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import type { Logger } from 'pino';
import type { Config } from '../types.js';

const createTransport = jest.fn();
jest.unstable_mockModule('nodemailer', () => ({
  createTransport,
  default: { createTransport },
}));

const { initializeEmailTransporter, sendResetPasswordEmail } = await import('../email.js');

const environment = { ...process.env };
const logger = {
  debug: jest.fn(),
  error: jest.fn(),
  info: jest.fn(),
} as unknown as Logger;
const sendMail = jest.fn<() => Promise<{ messageId: string }>>();
const emailer = { sendMail } as Parameters<typeof sendResetPasswordEmail>[1];

const config: Config = {
  logger,
  port: 3000,
  env: 'test',
  domain: 'https://app.example.test',
  applicationName: 'DMP Tool',
  helpDeskAddress: 'help@example.test',
  helpPageUrl: 'https://app.example.test/help',
  doNotReplyAddress: 'no-reply@example.test',
  issuer: 'https://auth.example.test',
  tokens: {
    access: 'access',
    refresh: 'refresh',
    ssoPending: 'sso-pending',
  },
  cache: {},
  database: {
    logger,
    host: 'localhost',
    port: 3306,
    user: 'test',
    password: 'test',
    database: 'test',
  },
  cookieSecure: false,
  pepperSecret: 'test-pepper',
  bcryptSaltRounds: 4,
  oidcClients: [],
  ttl: {
    csrf: 3600,
    passwordReset: 7200,
    uiAccess: 900,
    uiRefresh: 604800,
    oidcCode: 120,
    oidcAccess: 900,
    oidcRefresh: 604800,
    oidcGrant: 120,
    oidcIdToken: 600,
    oidcInteraction: 600,
  },
  ses: {
    region: 'us-west-2',
    accessKey: 'access-key',
    accessSecret: 'access-secret',
    endpoint: 'email-smtp.us-west-2.amazonaws.com',
    port: 587,
  },
};

beforeEach(() => {
  process.env = { ...environment, NODE_ENV: 'test' };
  jest.clearAllMocks();
  sendMail.mockResolvedValue({ messageId: 'message-1' });
});

afterEach(() => {
  process.env = environment;
});

describe('email service', () => {
  it('uses STARTTLS on port 587 and implicit TLS on port 465', () => {
    initializeEmailTransporter(config);
    expect(createTransport).toHaveBeenLastCalledWith(expect.objectContaining({
      host: config.ses.endpoint,
      port: 587,
      secure: false,
      requireTLS: true,
      auth: { user: 'access-key', pass: 'access-secret' },
    }));

    initializeEmailTransporter({ ...config, ses: { ...config.ses, port: 465 } });
    expect(createTransport).toHaveBeenLastCalledWith(expect.objectContaining({
      port: 465,
      secure: true,
      requireTLS: false,
    }));
  });

  it('sends a reset email with the tokenized reset link outside development', async () => {
    process.env.NODE_ENV = 'production';

    await expect(sendResetPasswordEmail(config, emailer, 'alice@example.test', 'reset-token')).resolves.toBe(true);

    expect(sendMail).toHaveBeenCalledWith(expect.objectContaining({
      from: '"DMP Tool" <no-reply@example.test>',
      replyTo: 'help@example.test',
      to: 'alice@example.test',
      subject: 'DMP Tool - Reset Your Password',
      html: expect.stringContaining('https://app.example.test/login/reset-password?token=reset-token'),
    }));
  });

  it('accepts SMTP responses without a message ID', async () => {
    process.env.NODE_ENV = 'production';
    sendMail.mockResolvedValueOnce(undefined as never);

    await expect(sendResetPasswordEmail(config, emailer, 'alice@example.test', 'reset-token')).resolves.toBe(true);
  });

  it('logs reset emails instead of sending them in development', async () => {
    process.env.NODE_ENV = 'development';

    await expect(sendResetPasswordEmail(config, emailer, 'alice@example.test', 'reset-token')).resolves.toBe(true);

    expect(sendMail).not.toHaveBeenCalled();
    expect(logger.info).toHaveBeenCalledWith(
      expect.objectContaining({ toAddresses: ['alice@example.test'] }),
      expect.stringContaining("Logging email notification of type 'ResetPassword'"),
    );
  });

  it('sends reset emails when NODE_ENV is not configured', async () => {
    delete process.env.NODE_ENV;

    await expect(sendResetPasswordEmail(config, emailer, 'alice@example.test', 'reset-token')).resolves.toBe(true);

    expect(sendMail).toHaveBeenCalled();
  });

  it('returns false when delivery fails or no recipient is supplied', async () => {
    process.env.NODE_ENV = 'production';
    sendMail.mockRejectedValueOnce(new Error('SMTP unavailable'));

    await expect(sendResetPasswordEmail(config, emailer, 'alice@example.test', 'reset-token')).resolves.toBe(false);
    await expect(sendResetPasswordEmail(config, emailer, '', 'reset-token')).resolves.toBe(false);
    expect(logger.error).toHaveBeenCalled();
  });
});
