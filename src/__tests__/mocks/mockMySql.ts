import type { ResultSetHeader } from 'mysql2';
import type { AdapterPayload } from 'oidc-provider';
import type { OAuthClient } from '../../types.js';

interface UserRecord {
  id: number;
  password: string;
  role: string;
  givenName: string | null;
  surName: string | null;
  affiliationId: string | null;
  acceptedTerms: boolean;
  languageId: string | null;
  ssoId: string | null;
  active: boolean;
  locked: boolean;
  tokenVersion: number;
  email?: string;
}

export interface PersistedUser {
  id: number;
  email: string;
  role: string;
  givenName: string | null;
  surName: string | null;
  affiliationId: string | null;
  acceptedTerms: boolean;
  languageId: string | null;
  ssoId: string | null;
  tokenVersion: number;
}

interface OidcRecord {
  model: string;
  id: string;
  payload: AdapterPayload;
  grantId?: string | null;
  uid?: string | null;
  userCode?: string | null;
  expiresAt?: Date | null;
}

interface ClientRecord {
  active: boolean;
  client: OAuthClient;
}

const result = (affectedRows: number, insertId = 0): { results: ResultSetHeader; fields: [] } => ({
  results: { affectedRows, insertId } as ResultSetHeader,
  fields: [],
});

/**
 * An in-memory implementation of the SQL statements issued by the auth service.
 * It intentionally mirrors queryTable's currently mixed response shapes: UserStore
 * consumes SELECT rows directly, while the other stores consume a response wrapper.
 */
export class MockMySqlStore {
  private nextUserId = 1;
  private readonly users = new Map<number, UserRecord>();
  private readonly authKeys = new Map<string, string>();
  private readonly oidcRecords = new Map<string, OidcRecord>();
  private readonly oauthClients = new Map<string, ClientRecord>();

  async query(_config: unknown, statement: string, values: unknown[] = []): Promise<unknown> {
    const sql = statement.replace(/\s+/g, ' ').trim();

    if (sql.startsWith('SELECT jwks FROM auth_keys')) {
      const jwks = this.authKeys.get(String(values[0]));
      return { results: jwks ? [{ jwks }] : [], fields: [] };
    }
    if (sql.startsWith('INSERT INTO auth_keys')) {
      this.authKeys.set(String(values[0]), String(values[1]));
      return result(1, 1);
    }

    if (sql.startsWith('INSERT INTO users ')) {
      const [password, role, givenName, surName, affiliationId, acceptedTerms, languageId, ssoId] = values;
      const id = this.nextUserId++;
      this.users.set(id, {
        id,
        password: String(password),
        role: String(role),
        givenName: nullableString(givenName),
        surName: nullableString(surName),
        affiliationId: nullableString(affiliationId),
        acceptedTerms: Boolean(acceptedTerms),
        languageId: nullableString(languageId),
        ssoId: nullableString(ssoId),
        active: true,
        locked: false,
        tokenVersion: 0,
      });
      return result(1, id);
    }
    if (sql.startsWith('INSERT INTO user_emails')) {
      const user = this.users.get(Number(values[0]));
      if (!user) return result(0);
      user.email = String(values[1]);
      return result(1, user.id);
    }
    if (sql.startsWith('SELECT u.id, u.password') && sql.includes('WHERE u.id = ?')) {
      return this.userRows((user) => user.id === Number(values[0]));
    }
    if (sql.startsWith('SELECT u.id, u.password') && sql.includes('LOWER(ue.email) = ?')) {
      const email = String(values[0]).toLowerCase();
      return this.userRows((user) => user.email?.toLowerCase() === email);
    }
    if (sql.startsWith('SELECT u.id, u.password') && sql.includes('WHERE u.ssoId = ?')) {
      return this.userRows((user) => user.ssoId === values[0]);
    }
    if (sql.startsWith('UPDATE users SET password = ?')) {
      const user = this.users.get(Number(values[1]));
      if (!user || !user.active || user.locked) return result(0);
      user.password = String(values[0]);
      return result(1);
    }
    if (sql.startsWith('UPDATE users ') || sql.startsWith('UPDATE template_collaborators ') || sql.startsWith('UPDATE project_collaborators ')) {
      return result(1);
    }

    if (sql.startsWith('INSERT INTO oidc_records')) {
      const [model, id, payload, grantId, uid, userCode, expiresAt] = values;
      this.oidcRecords.set(`${model}:${id}`, {
        model: String(model),
        id: String(id),
        payload: JSON.parse(String(payload)) as AdapterPayload,
        grantId: nullableString(grantId),
        uid: nullableString(uid),
        userCode: nullableString(userCode),
        expiresAt: expiresAt instanceof Date ? expiresAt : null,
      });
      return result(1);
    }
    if (sql.startsWith('SELECT payload FROM oidc_records')) {
      const [model, lookup] = values;
      const record = [...this.oidcRecords.values()].find((candidate) =>
        candidate.model === model
        && (sql.includes('WHERE model = ? AND id = ?') ? candidate.id === lookup
          : sql.includes('WHERE model = ? AND uid = ?') ? candidate.uid === lookup
            : candidate.userCode === lookup)
        && (!candidate.expiresAt || candidate.expiresAt > new Date()),
      );
      return { results: record ? [{ payload: record.payload }] : [], fields: [] };
    }
    if (sql.startsWith('DELETE FROM oidc_records')) {
      const [model, lookup] = values;
      const records = [...this.oidcRecords.values()].filter((candidate) =>
        candidate.model === model
        && (sql.includes('WHERE model = ? AND id = ?') ? candidate.id === lookup : candidate.grantId === lookup),
      );
      records.forEach((record) => this.oidcRecords.delete(`${record.model}:${record.id}`));
      return result(records.length);
    }

    if (sql.startsWith('SELECT c.clientId')) {
      const clientId = sql.includes('c.clientId = ?') ? String(values[0]) : undefined;
      const clients = [...this.oauthClients.values()]
        .filter((record) => record.active && (!clientId || record.client.client_id === clientId))
        .map(({ client }) => ({
          clientId: client.client_id,
          clientSecret: client.client_secret,
          clientName: client.client_name,
          applicationType: client.application_type,
          tokenEndpointAuthMethod: client.token_endpoint_auth_method,
          grantTypes: client.grant_types,
          responseTypes: client.response_types,
          requirePkce: client.require_pkce ? 1 : 0,
          clientMetadata: client.client_metadata,
          redirectUris: client.redirect_uris.join(','),
        }));
      return { results: clients, fields: [] };
    }
    throw new Error(`MockMySqlStore does not support query: ${sql}`);
  }

  findUserByEmail(email: string): PersistedUser | undefined {
    const user = [...this.users.values()].find((candidate) => candidate.email?.toLowerCase() === email.toLowerCase());
    if (!user?.email) return undefined;
    return {
      id: user.id,
      email: user.email,
      role: user.role,
      givenName: user.givenName,
      surName: user.surName,
      affiliationId: user.affiliationId,
      acceptedTerms: user.acceptedTerms,
      languageId: user.languageId,
      ssoId: user.ssoId,
      tokenVersion: user.tokenVersion,
    };
  }

  addOauthClient(client: OAuthClient): void {
    this.oauthClients.set(client.client_id, { active: true, client });
  }

  setOauthClientActive(clientId: string, active: boolean): void {
    const record = this.oauthClients.get(clientId);
    if (record) record.active = active;
  }

  private userRows(predicate: (user: UserRecord) => boolean): UserRecord[] {
    return [...this.users.values()]
      .filter((user) => user.active && !user.locked && user.email && predicate(user))
      .map((user) => ({ ...user }));
  }
}

const nullableString = (value: unknown): string | null =>
  value === null || value === undefined ? null : String(value);
