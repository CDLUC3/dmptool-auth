import { queryTable } from '@dmptool/utils';
import type { Config, dbQueryResponse, OAuthClient, OAuthClientRow } from "../types.js";

const clientsTable: string = process.env.DB_OAUTH_CLIENTS_TABLE || 'oauth_clients';
const redirectUrisTable: string = process.env.DB_OAUTH_CLIENT_REDIRECT_URIS_TABLE || 'oauth_client_redirect_uris';

/**
 * Loads OAuth client registrations and their redirect URIs for oidc-provider.
 */
export class OauthClientStore {
  constructor() {}

  /**
   * Finds one active client when oidc-provider receives an authorization or token request.
   */
  async findActive(config: Config, clientId: string): Promise<OAuthClient | undefined> {
    const response: dbQueryResponse = await queryTable(
      { ...config.database, logger: config.logger },
      `SELECT c.clientId, c.clientSecret, c.clientName, c.applicationType,
              c.tokenEndpointAuthMethod, c.grantTypes, c.responseTypes, c.requirePkce,
              c.clientMetadata,
              GROUP_CONCAT(r.redirect_uri, SEPARATOR ',') as redirectUris
       FROM ${clientsTable} c
       LEFT JOIN ${redirectUrisTable} r ON r.client_id = c.client_id
       WHERE c.active = TRUE AND c.clientId = ?
       ORDER BY c.id, r.id`,
      [clientId],
    );
    if (!response || !Array.isArray(response.results) || !response.results[0]) return undefined;
    return this.toClient(response.results[0] as OAuthClientRow);
  }

  async listActive(config: Config): Promise<OAuthClient[]> {
    const response: dbQueryResponse = await queryTable(
      { ...config.database, logger: config.logger },
      `SELECT c.clientId, c.clientSecret, c.clientName, c.applicationType,
              c.tokenEndpointAuthMethod, c.grantTypes, c.responseTypes, c.requirePkce,
              c.clientMetadata,
              GROUP_CONCAT(r.redirect_uri, SEPARATOR ',') as redirectUris
       FROM ${clientsTable} c
       LEFT JOIN ${redirectUrisTable} r ON r.client_id = c.client_id
       WHERE c.active = TRUE
       ORDER BY c.id, r.id`,
    );

    if (response && Array.isArray(response.results) && response.results.length > 0) {
      return response.results.map((row: unknown): OAuthClient => this.toClient(row as OAuthClientRow));
    }
    return [];
  }

  private toClient(client: OAuthClientRow): OAuthClient {
    return {
      client_id: client.clientId,
      client_secret: client.clientSecret,
      client_name: client.clientName,
      application_type: client.applicationType,
      token_endpoint_auth_method: client.tokenEndpointAuthMethod,
      grant_types: client.grantTypes,
      response_types: client.responseTypes,
      require_pkce: !!client.requirePkce,
      client_metadata: client.clientMetadata,
      redirect_uris: client.redirectUris ? (client.redirectUris as string).split(',') : [],
    };
  }
}
