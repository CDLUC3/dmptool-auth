import { describe, expect, it, jest } from '@jest/globals';
import type { Config, PublicUser } from '../types.js';

const Provider = jest.fn();
const createAdapter = jest.fn();

jest.unstable_mockModule('oidc-provider', () => ({ default: Provider }));
jest.unstable_mockModule('../models/oidcStore.js', () => ({ createAdapter }));

const { createProvider } = await import('../oidc.js');

const logger = { warn: jest.fn() };
const config = {
  issuer: 'https://auth.example.test',
  oidcClients: [],
  logger,
  ttl: {
    oidcAccess: 900,
    oidcCode: 120,
    oidcRefresh: 604800,
    oidcGrant: 120,
    oidcIdToken: 600,
    oidcInteraction: 600,
  },
} as unknown as Config;

const user: PublicUser = {
  id: 'user-1',
  email: 'user@example.test',
  givenName: 'User',
  surName: 'Example',
  role: 'RESEARCHER',
  affiliationId: 'affiliation-1',
  languageId: 'en',
  tokenVersion: 0,
  acceptedTerms: true,
  failed_sign_in_attempts: 0,
};

describe('OIDC provider configuration', () => {
  it('configures private signing keys and exposes complete account claims', async () => {
    const users = { findById: jest.fn().mockResolvedValue(user as never) };
    const keys = {
      jwks: {
        keys: [
          { kty: 'RSA', kid: 'private', d: 'private-material' },
          { kty: 'RSA', kid: 'public' },
        ],
      },
    };

    createProvider(config, {} as never, users as never, keys as never);

    const configuration = Provider.mock.calls[0]?.[1] as {
      jwks: { keys: Array<{ kid: string }> };
      findAccount: (_context: unknown, accountId: string) => Promise<{
        accountId: string;
        claims: () => Record<string, unknown>;
      } | undefined>;
    };
    expect(Provider).toHaveBeenCalledWith(config.issuer, expect.any(Object));
    expect(createAdapter).toHaveBeenCalledWith(config, expect.anything());
    expect(configuration.jwks.keys).toEqual([{ kty: 'RSA', kid: 'private', d: 'private-material' }]);

    const account = await configuration.findAccount({}, user.id);
    expect(account?.accountId).toBe(user.id);
    expect(account?.claims()).toMatchObject({
      sub: user.id,
      email: user.email,
      email_verified: true,
      given_name: user.givenName,
      family_name: user.surName,
      role: user.role,
    });
  });

  it('handles absent accounts, renders safe errors, and selects the configured interaction URL', async () => {
    const users = { findById: jest.fn().mockResolvedValue(undefined as never) };
    const keys = { jwks: { keys: [] } };
    const previousSignInUrl = process.env.OAUTH2_SIGN_IN_URL;
    process.env.OAUTH2_SIGN_IN_URL = 'https://login.example.test/authorize';

    try {
      createProvider(config, {} as never, users as never, keys as never);
      const configuration = Provider.mock.calls[1]?.[1] as {
        findAccount: (_context: unknown, accountId: string) => Promise<undefined>;
        interactions: { url: (_context: unknown, interaction: { uid: string }) => string };
        renderError: (context: { type?: string; body?: string }, output: { error: string }) => void;
      };
      const context: { type?: string; body?: string } = {};

      await expect(configuration.findAccount({}, 'missing')).resolves.toBeUndefined();
      expect(configuration.interactions.url({}, { uid: 'interaction id' }))
        .toBe('https://login.example.test/authorize?uid=interaction%20id');
      configuration.renderError(context, { error: 'invalid_request' });
      expect(context).toEqual(expect.objectContaining({
        type: 'html',
        body: expect.stringContaining('Authentication request could not be completed'),
      }));
      expect(logger.warn).toHaveBeenCalledWith({ error: 'invalid_request' }, 'OIDC request rejected');

      delete process.env.OAUTH2_SIGN_IN_URL;
      expect(configuration.interactions.url({}, { uid: 'local-id' })).toBe('/interaction/local-id');
    } finally {
      if (previousSignInUrl === undefined) delete process.env.OAUTH2_SIGN_IN_URL;
      else process.env.OAUTH2_SIGN_IN_URL = previousSignInUrl;
    }
  });
});
