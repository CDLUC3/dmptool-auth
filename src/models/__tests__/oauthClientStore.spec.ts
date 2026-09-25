import { beforeEach, describe, expect, it, jest } from '@jest/globals';

const queryTable = jest.fn<(config: unknown, sql: string, values?: unknown[]) => Promise<unknown>>();
jest.unstable_mockModule('@dmptool/utils', () => ({ queryTable }));
const { OauthClientStore } = await import('../oauthClientStore.js');

const config = { database: {}, logger: {} };

beforeEach(() => {
  queryTable.mockReset();
});

describe('OauthClientStore', () => {
  it('loads active client metadata and normalized redirect URIs', async () => {
    queryTable.mockResolvedValueOnce({
      results: [{
        clientId: 'web',
        clientSecret: 'secret',
        clientName: 'DMP UI',
        applicationType: 'web',
        tokenEndpointAuthMethod: 'client_secret_basic',
        grantTypes: ['authorization_code', 'refresh_token'],
        responseTypes: ['code'],
        requirePkce: 1,
        clientMetadata: { post_logout_redirect_uris: ['https://app.example.test/logout'] },
        redirectUris: 'https://app.example.test/callback,https://app.example.test/alternate-callback',
      }],
      fields: [],
    });

    await expect(new OauthClientStore().listActive(config as never)).resolves.toEqual([{
      client_id: 'web',
      client_secret: 'secret',
      client_name: 'DMP UI',
      application_type: 'web',
      token_endpoint_auth_method: 'client_secret_basic',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      require_pkce: true,
      client_metadata: { post_logout_redirect_uris: ['https://app.example.test/logout'] },
      redirect_uris: ['https://app.example.test/callback', 'https://app.example.test/alternate-callback'],
    }]);
  });

  it('returns no registrations when the query has no rows', async () => {
    queryTable.mockResolvedValueOnce({ results: [], fields: [] });
    await expect(new OauthClientStore().listActive(config as never)).resolves.toEqual([]);
  });

  it.each([
    undefined,
    { results: undefined, fields: [] },
    { results: {}, fields: [] },
  ])('returns no registrations for an unusable query result', async (response) => {
    queryTable.mockResolvedValueOnce(response);
    await expect(new OauthClientStore().listActive(config as never)).resolves.toEqual([]);
  });

  it('preserves false PKCE and maps a missing redirect URI list to an empty list', async () => {
    queryTable.mockResolvedValueOnce({
      results: [{
        clientId: 'native',
        clientSecret: null,
        clientName: null,
        applicationType: 'native',
        tokenEndpointAuthMethod: 'none',
        grantTypes: ['authorization_code'],
        responseTypes: ['code'],
        requirePkce: 0,
        clientMetadata: null,
        redirectUris: '',
      }],
      fields: [],
    });

    await expect(new OauthClientStore().listActive(config as never)).resolves.toEqual([
      expect.objectContaining({ client_id: 'native', require_pkce: false, redirect_uris: [] }),
    ]);
  });

  it('finds one active client by ID for on-demand provider resolution', async () => {
    queryTable.mockResolvedValueOnce({
      results: [{
        clientId: 'external',
        clientSecret: 'secret',
        clientName: 'External integration',
        applicationType: 'web',
        tokenEndpointAuthMethod: 'client_secret_basic',
        grantTypes: ['authorization_code'],
        responseTypes: ['code'],
        requirePkce: 0,
        clientMetadata: null,
        redirectUris: 'https://external.example.test/callback',
      }],
      fields: [],
    });

    await expect(new OauthClientStore().findActive(config as never, 'external')).resolves.toEqual(
      expect.objectContaining({
        client_id: 'external',
        redirect_uris: ['https://external.example.test/callback'],
      }),
    );
    expect(queryTable.mock.calls[0]![1]).toContain('c.active = TRUE AND c.clientId = ?');
    expect(queryTable.mock.calls[0]![2]).toEqual(['external']);
  });

  it('returns undefined when an active client is not found', async () => {
    queryTable.mockResolvedValueOnce({ results: [], fields: [] });

    await expect(new OauthClientStore().findActive(config as never, 'missing')).resolves.toBeUndefined();
  });
});
