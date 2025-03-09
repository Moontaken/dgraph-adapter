/**
 * <div style={{display: "flex", justifyContent: "space-between", alignItems: "center", padding: "16px"}}>
 *  <p style={{fontWeight: "normal"}}>Official <a href="https://dgraph.io/docs">Dgraph</a> adapter for Auth.js / NextAuth.js.</p>
 *  <a href="https://dgraph.io/">
 *   <img style={{display: "block"}} src="https://authjs.dev/img/adapters/dgraph.svg" width="100"/>
 *  </a>
 * </div>
 *
 * ## Installation
 *
 * ```bash npm2yarn
 * npm install next-auth @auth/dgraph-adapter
 * ```
 *
 * @module @auth/dgraph-adapter
 */
import { client as dgraphClient } from "./lib/client.js";
import { isDate } from "@auth/core/adapters";
import * as defaultFragments from "./lib/graphql/fragments.js";
export function DgraphAdapter(client, options) {
  const c = dgraphClient(client);
  const fragments = { ...defaultFragments, ...options?.fragments };
  return {
    async createUser(input) {
      const result = await c.run(
            /* GraphQL */ `
          mutation ($input: [AddUserInput!]!) {
            addUser(input: $input) {
              user {
                ...UserFragment
              }
            }
          }
          ${fragments.User}
        `, { input });
      return format.from(result?.user[0]);
    },
    async getUser(id) {
      const result = await c.run(
            /* GraphQL */ `
          query ($id: ID!) {
            getUser(id: $id) {
              ...UserFragment
            }
          }
          ${fragments.User}
        `, { id });
      return format.from(result);
    },
    async getUserByEmail(email) {
      const [user] = await c.run(
            /* GraphQL */ `
          query ($email: String = "") {
            queryUser(filter: { email: { eq: $email } }) {
              ...UserFragment
            }
          }
          ${fragments.User}
        `, { email });
      return format.from(user);
    },
    async getUserByAccount(provider_providerAccountId) {
      const [account] = await c.run(
            /* GraphQL */ `
          query ($providerAccountId: String = "", $provider: String = "") {
            queryAccount(
              filter: {
                and: {
                  providerAccountId: { eq: $providerAccountId }
                  provider: { eq: $provider }
                }
              }
            ) {
              user {
                ...UserFragment
              }
              id
            }
          }
          ${fragments.User}
        `, provider_providerAccountId);
      return format.from(account?.user);
    },
    async updateUser({ id, ...input }) {
      const result = await c.run(
            /* GraphQL */ `
          mutation ($id: String!, $input: UserPatch) {
            updateUser(input: { filter: { id: {eq: $id} }, set: $input }) {
              user {
                ...UserFragment
              }
            }
          }
          ${fragments.User}
        `, { id, input });
      return format.from(result.user[0]);
    },
    async deleteUser(id) {
      const result = await c.run(
            /* GraphQL */ `
          mutation ($id: String!) {
            deleteUser(filter: { id: {eq: $id} }) {
              numUids
              user {
                accounts {
                  id
                }
                sessions {
                  id
                }
              }
            }
          }
        `, { id });
      const deletedUser = format.from(result.user[0]);
      await c.run(
            /* GraphQL */ `
          mutation ($accounts: [ID!], $sessions: [ID!]) {
            deleteAccount(filter: { id: $accounts }) {
              numUids
            }
            deleteSession(filter: { id: $sessions }) {
              numUids
            }
          }
        `, {
        sessions: deletedUser.sessions.map((x) => x.id),
        accounts: deletedUser.accounts.map((x) => x.id),
      });
      return deletedUser;
    },
    async linkAccount(data) {
      const { userId, ...input } = data;
      await c.run(
            /* GraphQL */ `
          mutation ($input: [AddAccountInput!]!) {
            addAccount(input: $input) {
              account {
                ...AccountFragment
              }
            }
          }
          ${fragments.Account}
        `, { input: { ...input, user: { id: userId } } });
      return data;
    },
    async unlinkAccount(provider_providerAccountId) {
      await c.run(
            /* GraphQL */ `
          mutation ($providerAccountId: String = "", $provider: String = "") {
            deleteAccount(
              filter: {
                and: {
                  providerAccountId: { eq: $providerAccountId }
                  provider: { eq: $provider }
                }
              }
            ) {
              numUids
            }
          }
        `, provider_providerAccountId);
    },
    async getSessionAndUser(sessionToken) {
      const [sessionAndUser] = await c.run(
            /* GraphQL */ `
          query ($sessionToken: String = "") {
            querySession(filter: { sessionToken: { eq: $sessionToken } }) {
              ...SessionFragment
              user {
                ...UserFragment
              }
            }
          }
          ${fragments.User}
          ${fragments.Session}
        `, { sessionToken });
      if (!sessionAndUser)
        return null;
      const { user, ...session } = sessionAndUser;
      return {
        user: format.from(user),
        session: { ...format.from(session), userId: user.id },
      };
    },
    async createSession(data) {
      const { userId, ...input } = data;
      await c.run(
            /* GraphQL */ `
          mutation ($input: [AddSessionInput!]!) {
            addSession(input: $input) {
              session {
                ...SessionFragment
              }
            }
          }
          ${fragments.Session}
        `, { input: { ...input, user: { id: userId } } });
      return data;
    },
    async updateSession({ sessionToken, ...input }) {
      const result = await c.run(
            /* GraphQL */ `
          mutation ($input: SessionPatch = {}, $sessionToken: String) {
            updateSession(
              input: {
                filter: { sessionToken: { eq: $sessionToken } }
                set: $input
              }
            ) {
              session {
                ...SessionFragment
                user {
                  id
                }
              }
            }
          }
          ${fragments.Session}
        `, { sessionToken, input });
      const session = format.from(result.session[0]);
      if (!session?.user?.id)
        return null;
      return { ...session, userId: session.user.id };
    },
    async deleteSession(sessionToken) {
      await c.run(
            /* GraphQL */ `
          mutation ($sessionToken: String = "") {
            deleteSession(filter: { sessionToken: { eq: $sessionToken } }) {
              numUids
            }
          }
        `, { sessionToken });
    },
    async createVerificationToken(input) {
      const result = await c.run(
            /* GraphQL */ `
          mutation ($input: [AddVerificationTokenInput!]!) {
            addVerificationToken(input: $input) {
              numUids
            }
          }
        `, { input });
      return format.from(result);
    },
    async useVerificationToken(params) {
      const result = await c.run(
            /* GraphQL */ `
          mutation ($token: String = "", $identifier: String = "") {
            deleteVerificationToken(
              filter: {
                and: { token: { eq: $token }, identifier: { eq: $identifier } }
              }
            ) {
              verificationToken {
                ...VerificationTokenFragment
              }
            }
          }
          ${fragments.VerificationToken}
        `, params);
      return format.from(result.verificationToken[0]);
    },
  };
}
export const format = {
  from(object) {
    const newObject = {};
    if (!object)
      return null;
    for (const key in object) {
      const value = object[key];
      if (isDate(value)) {
        newObject[key] = new Date(value);
      }
      else {
        newObject[key] = value;
      }
    }
    return newObject;
  },
};
