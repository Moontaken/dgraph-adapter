import * as jose from "jose";

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

    const {
        endpoint,
        authToken,
        jwtSecret,
        jwtAlgorithm = "HS256",
        authHeader = "Authorization",
    } = params;

    const headers = {
        "Content-Type": "application/json",
        "X-Auth-Token": authToken,
    };

    return {
        async graphql(token, query, variables) {
            headers[authHeader] = token
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
        async run(query, variables) {
            // Generate JWT if needed
            if (authHeader && jwtSecret && !headers[authHeader]) {
                try {
                    if (jwtAlgorithm === "HS256") {
                        const secretKey = new TextEncoder().encode(jwtSecret);
                        headers[authHeader] = await new jose.SignJWT({ nextAuth: true })
                            .setProtectedHeader({ alg: 'HS256' })
                            .sign(secretKey);
                    } else if (jwtAlgorithm === "RS256") {
                        console.log(jwtSecret)
                        const privateKey = await jose.importPKCS8(jwtSecret, jwtAlgorithm);
                        headers[authHeader] = await new jose.SignJWT({ nextAuth: true })
                            .setProtectedHeader({ alg: 'RS256' })
                            .sign(privateKey);
                    } else {
                        throw new Error(`Unsupported JWT algorithm: ${jwtAlgorithm}`);
                    }
                } catch (error) {
                    console.error("JWT creation error:", error);
                }
            }

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