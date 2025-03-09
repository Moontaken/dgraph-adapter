import * as jwt from "jsonwebtoken";
export class DgraphClientError extends Error {
    constructor(errors, query, variables) {
        super(errors.map((error) => error.message).join("\n"));
        this.name = "DgraphClientError";
        console.error({ query, variables });
    }
}
export function client(params) {
    if (!params.authToken) {
        throw new Error("Dgraph client error: Please provide an API key");
    }
    if (!params.endpoint) {
        throw new Error("Dgraph client error: Please provide a valid GraphQL endpoint");
    }
    const { endpoint, authToken, jwtSecret, jwtAlgorithm = "HS256", authHeader = "Authorization", } = params;
    const headers = {
        "Content-Type": "application/json",
        "X-Auth-Token": authToken,
    };
    if (authHeader && jwtSecret) {
        headers[authHeader] = jwt.sign({ nextAuth: true }, jwtSecret, {
            algorithm: jwtAlgorithm,
        });
    }
    return {
        async run(query, variables) {
            const response = await fetch(endpoint, {
                method: "POST",
                headers,
                body: JSON.stringify({ query, variables }),
            });
            const { data = {}, errors } = await response.json();
            if (errors?.length) {
                throw new DgraphClientError(errors, query, variables);
            }
            return Object.values(data)[0];
        },
    };
}
