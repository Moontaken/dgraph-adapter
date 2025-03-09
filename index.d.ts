import { type Adapter } from "@auth/core/adapters";
import type { DgraphClientParams } from "./lib/client.js";
export type { DgraphClientParams, DgraphClientError } from "./lib/client.js";
/** This is the interface of the Dgraph adapter options. */
export interface DgraphAdapterOptions {
    /**
     * The GraphQL {@link https://dgraph.io/docs/query-language/fragments/ Fragments} you can supply to the adapter
     * to define how the shapes of the `user`, `account`, `session`, `verificationToken` entities look.
     *
     * By default the adapter will uses the [default defined fragments](https://github.com/nextauthjs/next-auth/blob/main/packages/adapter-dgraph/src/lib/graphql/fragments.ts)
     * , this config option allows to extend them.
     */
    fragments?: {
        User?: string;
        Account?: string;
        Session?: string;
        VerificationToken?: string;
    };
}
export declare function DgraphAdapter(client: DgraphClientParams, options?: DgraphAdapterOptions): Adapter;
export declare const format: {
    from<T>(object?: Record<string, any>): T | null;
};
//# sourceMappingURL=index.d.ts.map