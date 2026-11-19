import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import type { Logger } from 'pino';
import type { Config } from '../types.js';

const createTransport = jest.fn();
jest.unstable_mockModule('nodemailer', () => ({
  createTransport,
  default: { createTransport },
}));

const {
  initializeEmailTransporter,
  sendAccountLockedEmail,
  sendEmailConfirmationEmail,
  sendResetPasswordEmail,
} = await import('../email.js');

const environment = { ...process.env };
const logger = {
  debug: jest.fn(),
  error: jest.fn(),
  info: jest.fn(),
} as unknown as Logger;
const sendMail = jest.fn<(message: { html?: string }) => Promise<{ messageId?: string } | undefined>>();
const emailer = { sendMail } as unknown as Parameters<typeof sendResetPasswordEmail>[1];

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
  audienceAPI: 'my-api',
  audienceUI: 'my-ui',
  tokens: {
    access: 'access',
    refresh: 'refresh',
    ssoPending: 'sso-pending',
    validAudiences: ['my-ui', 'my-api'],
    keyRotationSeconds: 60 * 60 * 24 * 30,
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
    emailConfirmation: 86400,
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

  it('sends an email confirmation email with the confirmation link', async () => {
    process.env.NODE_ENV = 'production';

    await expect(sendEmailConfirmationEmail(config, emailer, '42', 'alias@example.test', 'abc_123-XYZ'))
      .resolves.toBe(true);

    expect(sendMail).toHaveBeenCalledWith(expect.objectContaining({
      to: 'alias@example.test',
      subject: 'DMP Tool - Please confirm your email address',
      html: expect.stringContaining('href="https://app.example.test/email/confirm-email/abc_123-XYZ"'),
    }));
    const html = sendMail.mock.calls[0]?.[0]?.html ?? '';
    expect(html).toContain('This link expires in 24 hours and can only be used once.');
    expect(html).toContain('To confirm that this is your email address, open the link below.</p>');
    // An unconfirmed alias can't be used to sign in yet, so the email says which address to sign in with
    expect(html).toContain("If you're asked to sign in, use the email address you normally sign in with, not this one.");
  });

  it('escapes the email address and token in the email confirmation email', async () => {
    process.env.NODE_ENV = 'production';

    await sendEmailConfirmationEmail(
      { ...config, ttl: { ...config.ttl, emailConfirmation: 3600 } },
      emailer,
      '42',
      '"<b>x</b>"@example.test',
      'a/b?c',
    );

    const html = sendMail.mock.calls[0]?.[0]?.html ?? '';
    expect(html).toContain('&quot;&lt;b&gt;x&lt;/b&gt;&quot;@example.test');
    expect(html).not.toContain('<b>x</b>');
    expect(html).toContain('/email/confirm-email/a%2Fb%3Fc');
    expect(html).toContain('This link expires in 1 hour and can only be used once.');
  });

  it('adds a protocol to the confirmation link only when DOMAIN does not include one', async () => {
    process.env.NODE_ENV = 'production';
    await sendEmailConfirmationEmail({ ...config, domain: 'http://localhost:3000/' }, emailer, '42', 'a@example.test', 't');
    await sendEmailConfirmationEmail({ ...config, domain: 'app.example.test' }, emailer, '42', 'a@example.test', 't');

    expect(sendMail.mock.calls[0]?.[0]?.html).toContain('href="http://localhost:3000/email/confirm-email/t"');
    expect(sendMail.mock.calls[1]?.[0]?.html).toContain('href="https://app.example.test/email/confirm-email/t"');
  });

  it('uses an http confirmation link and logs the email instead of sending it in development', async () => {
    process.env.NODE_ENV = 'development';

    await expect(sendEmailConfirmationEmail({ ...config, domain: 'app.example.test' }, emailer, '42', 'alias@example.test', 'token'))
      .resolves.toBe(true);

    expect(sendMail).not.toHaveBeenCalled();
    expect(logger.info).toHaveBeenCalledWith(
      expect.objectContaining({ message: expect.stringContaining('href="http://app.example.test/email/confirm-email/token"') }),
      expect.stringContaining("Logging email notification of type 'EmailConfirmation'"),
    );
  });

  it('does not send an email confirmation email without an email address', async () => {
    await expect(sendEmailConfirmationEmail(config, emailer, '42', '', 'token')).resolves.toBe(false);
    expect(sendMail).not.toHaveBeenCalled();
    expect(logger.error).toHaveBeenCalledWith({ userId: '42' }, expect.stringContaining('No email address'));
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

  it('sends account-lock emails and rejects missing recipients', async () => {
    process.env.NODE_ENV = 'production';

    await expect(sendAccountLockedEmail(config, emailer, 'alice@example.test')).resolves.toBe(true);
    expect(sendMail).toHaveBeenCalledWith(expect.objectContaining({
      subject: 'DMP Tool - Your account has been locked',
      html: expect.stringContaining('too many failed login attempts'),
    }));

    await expect(sendAccountLockedEmail(config, emailer, '')).resolves.toBe(false);
    expect(logger.error).toHaveBeenCalled();
  });
});
