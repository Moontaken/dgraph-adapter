import * as jose from "jose"

export interface DgraphClientParams {
  endpoint: string
  /**
   * `X-Auth-Token` header value
   *
   * [Dgraph Cloud Authentication](https://dgraph.io/docs/cloud/cloud-api/overview/#dgraph-cloud-authentication)
   */
  authToken: string
  /** [Using JWT and authorization claims](https://dgraph.io/docs/graphql/authorization/authorization-overview#using-jwts-and-authorization-claims) */
  jwtSecret?: string
  /**
   * @default "RS256"
   *
   * [Using JWT and authorization claims](https://dgraph.io/docs/graphql/authorization/authorization-overview#using-jwts-and-authorization-claims)
   */
  jwtAlgorithm?: "HS256" | "RS256"
  /**
   * @default "Authorization"
   *
   * [Using JWT and authorization claims](https://dgraph.io/docs/graphql/authorization/authorization-overview#using-jwts-and-authorization-claims)
   */
  authHeader?: string
}

export class DgraphClientError extends Error {
  name = "DgraphClientError"
  constructor(errors: any[], query: string, variables: any) {
    super(errors.map((error) => error.message).join("\n"))
    console.error({ query, variables })
  }
}

export function client(params: DgraphClientParams) {
  if (!params.authToken) {
    throw new Error("Dgraph client error: Please provide an API key")
  }
  if (!params.endpoint) {
    throw new Error(
      "Dgraph client error: Please provide a valid GraphQL endpoint"
    )
  }

  const {
    endpoint,
    authToken,
    jwtSecret,
    jwtAlgorithm = "HS256",
    authHeader = "Authorization",
  } = params
  const headers: HeadersInit = {
    "Content-Type": "application/json",
    "X-Auth-Token": authToken,
  }

  if (authHeader && jwtSecret) {
    const createJWT = async () => {
      let token: string

      if (jwtAlgorithm === "HS256") {
        // For HS256, use a symmetric key
        const secretKey = new TextEncoder().encode(jwtSecret)
        token = await new jose.SignJWT({ nextAuth: true })
          .setProtectedHeader({ alg: 'HS256' })
          .sign(secretKey)
      } else if (jwtAlgorithm === "RS256") {
        // For RS256, the secret should be a private key
        // Note: In a real implementation, you might need to handle PEM formatting
        try {
          const privateKey = await jose.importPKCS8(jwtSecret, jwtAlgorithm)
          token = await new jose.SignJWT({ nextAuth: true })
            .setProtectedHeader({ alg: 'RS256' })
            .sign(privateKey)
        } catch (error) {
          throw new Error(`Invalid private key for RS256 algorithm: ${error.message}`)
        }
      } else {
        throw new Error(`Unsupported JWT algorithm: ${jwtAlgorithm}`)
      }

      return token
    }

    // Create and set the token
    createJWT()
      .then(token => {
        headers[authHeader] = token
      })
      .catch(error => {
        console.error("JWT creation error:", error)
      })
  }

  return {
    async run<T>(
      query: string,
      variables?: Record<string, any>
    ): Promise<T | null> {
      // Ensure the JWT is set before making the request if jwtSecret is provided
      if (authHeader && jwtSecret && !headers[authHeader]) {
        try {
          if (jwtAlgorithm === "HS256") {
            const secretKey = new TextEncoder().encode(jwtSecret)
            headers[authHeader] = await new jose.SignJWT({ nextAuth: true })
              .setProtectedHeader({ alg: 'HS256' })
              .sign(secretKey)
          } else if (jwtAlgorithm === "RS256") {
            const privateKey = await jose.importPKCS8(jwtSecret, jwtAlgorithm)
            headers[authHeader] = await new jose.SignJWT({ nextAuth: true })
              .setProtectedHeader({ alg: 'RS256' })
              .sign(privateKey)
          }
        } catch (error) {
          console.error("JWT creation error:", error)
        }
      }

      const response = await fetch(endpoint, {
        method: "POST",
        headers,
        body: JSON.stringify({ query, variables }),
      })

      const { data = {}, errors } = await response.json()
      if (errors?.length) {
        throw new DgraphClientError(errors, query, variables)
      }
      return Object.values(data)[0] as any
    },
  }
}