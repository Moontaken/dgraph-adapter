export interface DgraphClientParams {
    endpoint: string;
    /**
     * `X-Auth-Token` header value
     *
     * [Dgraph Cloud Authentication](https://dgraph.io/docs/cloud/cloud-api/overview/#dgraph-cloud-authentication)
     */
    authToken: string;
    /** [Using JWT and authorization claims](https://dgraph.io/docs/graphql/authorization/authorization-overview#using-jwts-and-authorization-claims) */
    jwtSecret?: string;
    /**
     * @default "RS256"
     *
     * [Using JWT and authorization claims](https://dgraph.io/docs/graphql/authorization/authorization-overview#using-jwts-and-authorization-claims)
     */
    jwtAlgorithm?: "HS256" | "RS256";
    /**
     * @default "Authorization"
     *
     * [Using JWT and authorization claims](https://dgraph.io/docs/graphql/authorization/authorization-overview#using-jwts-and-authorization-claims)
     */
    authHeader?: string;
}
export declare class DgraphClientError extends Error {
    name: string;
    constructor(errors: any[], query: string, variables: any);
}
export declare function client(params: DgraphClientParams): {
    run<T>(query: string, variables?: Record<string, any>): Promise<T | null>;
};
//# sourceMappingURL=client.d.ts.map