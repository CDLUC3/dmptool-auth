import type { JWK } from "jose";
import Provider, { type Configuration, type Interaction, type KoaContextWithOIDC } from 'oidc-provider';
import type { CacheInterface } from './cache.js';
import type { Config, OAuthClient, PublicUser } from "./types.js";
import { createAdapter } from './models/oidcStore.js';
import type { KeyStore } from './models/keyStore.js';
import type { UserStore } from './models/userStore.js';

/**
 * Create an OIDC provider instance with the given configuration, user store and key store.
 *
 * @param config The configuration object containing OIDC client settings and issuer URL.
 * @param cache The Valkey cache used for refresh tokens.
 * @param users The user repository used for finding user accounts based on account IDs.
 * @param keys The key store containing the signing keys for JWTs.
 * @param clients An optional array of OIDC client configurations. If not provided, the
 * clients from the config will be used.
 * @returns A new instance of the OIDC provider.
 */
export const createProvider = (
  config: Config,
  cache: CacheInterface,
  users: UserStore,
  keys: KeyStore,
  clients: OAuthClient[] = config.oidcClients,
): Provider => {
  const configuration: Configuration = {
    adapter: createAdapter(config, cache),
    clients: clients as unknown as Configuration['clients'],
    jwks: { keys: keys.jwks.keys.filter((key:JWK): boolean => key.d !== undefined) },
    claims: {
      openid: ['sub'],
      profile: ['given_name', 'family_name'],
      email: ['email', 'email_verified'],
      dmp: ['id', 'givenName', 'surName', 'role', 'affiliationId', 'languageId'],
    },
    features: {
      devInteractions: { enabled: false },
      resourceIndicators: { enabled: true },
      jwtResponseModes: { enabled: true },
    },
    ttl: {
      AccessToken: config.ttl.oidcAccess,
      AuthorizationCode: config.ttl.oidcCode,
      RefreshToken: config.ttl.oidcRefresh,
      Session: config.ttl.oidcRefresh,
      Grant: config.ttl.oidcGrant,
      IdToken: config.ttl.oidcIdToken,
      Interaction: config.ttl.oidcInteraction,
    },
    rotateRefreshToken: true,
    renderError: (ctx, out): void => {
      config.logger.warn({ error: out.error }, 'OIDC request rejected');
      ctx.type = 'html';
      ctx.body = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Authentication request failed</title>
  </head>
  <body>
    <main>
      <h1>Authentication request could not be completed</h1>
      <p>Please return to the application and try again.</p>
    </main>
  </body>
</html>`;
    },
    interactions: {
      url: (_ctx: KoaContextWithOIDC, interaction: Interaction): string => {
        return process.env.OAUTH2_SIGN_IN_URL
          ? `${process.env.OAUTH2_SIGN_IN_URL}?uid=${encodeURIComponent(interaction.uid)}`
          : `/interaction/${interaction.uid}`;
      },
    },
    findAccount: async (_ctx: KoaContextWithOIDC, accountId: string) => {
      const user: PublicUser | undefined = await users.findById(accountId);
      if (!user) return undefined;
      return {
        accountId: user.id,
        claims: () => ({
          sub: user.id,
          email: user.email,
          email_verified: true,
          given_name: user.givenName,
          family_name: user.surName,
          id: user.id,
          givenName: user.givenName,
          surName: user.surName,
          role: user.role,
          affiliationId: user.affiliationId,
          languageId: user.languageId,
        }),
      };
    },
  };

  return new Provider(config.issuer, configuration);
};
