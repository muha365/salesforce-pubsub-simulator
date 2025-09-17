import jwt, { JwtPayload } from "jsonwebtoken";

export interface IssueTokenParams {
  clientId: string;
  clientSecret: string;
  scope: string;
}

export interface OAuthTokenResponse {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  scope: string;
}

interface RegisteredClient {
  secret: string;
  scopes: Set<string>;
}

export interface TokenVerifier {
  verify(token: string): JwtPayload & { scope?: string[] | string };
}

export interface MockOAuthServerOptions {
  signingSecret?: string;
  tokenLifetimeSeconds?: number;
}

export class MockOAuthServer implements TokenVerifier {
  private readonly signingSecret: string;
  private readonly tokenLifetimeSeconds: number;
  private readonly clients = new Map<string, RegisteredClient>();

  constructor(options: MockOAuthServerOptions = {}) {
    const { signingSecret = "mock-oauth-signing-secret", tokenLifetimeSeconds = 300 } = options;
    this.signingSecret = signingSecret;
    this.tokenLifetimeSeconds = tokenLifetimeSeconds;
  }

  registerClient(clientId: string, clientSecret: string, scopes: string[] = []): void {
    if (!clientId || !clientSecret) {
      throw new Error("clientId and clientSecret are required");
    }
    this.clients.set(clientId, {
      secret: clientSecret,
      scopes: new Set(scopes),
    });
  }

  issueToken(params: IssueTokenParams): OAuthTokenResponse {
    const { clientId, clientSecret, scope } = params;
    const client = this.clients.get(clientId);

    if (!client || client.secret !== clientSecret) {
      const error = new Error("invalid_client");
      (error as NodeJS.ErrnoException).code = "invalid_client";
      throw error;
    }

    const requestedScopes = scope
      .split(/\s+/)
      .map((scopePart) => scopePart.trim())
      .filter(Boolean);

    if (requestedScopes.length === 0) {
      const error = new Error("invalid_scope");
      (error as NodeJS.ErrnoException).code = "invalid_scope";
      throw error;
    }

    for (const requestedScope of requestedScopes) {
      if (!client.scopes.has(requestedScope)) {
        const error = new Error("invalid_scope");
        (error as NodeJS.ErrnoException).code = "invalid_scope";
        throw error;
      }
    }

    const payload: JwtPayload & { scope: string[] } = {
      sub: clientId,
      scope: requestedScopes,
      iss: "mock-oauth",
    };

    const token = jwt.sign(payload, this.signingSecret, {
      audience: "https://eventbus.salesforce.com",
      expiresIn: this.tokenLifetimeSeconds,
    });

    return {
      access_token: token,
      token_type: "Bearer",
      expires_in: this.tokenLifetimeSeconds,
      scope: requestedScopes.join(" "),
    };
  }

  verify(token: string): JwtPayload & { scope?: string[] | string } {
    if (!token) {
      const error = new Error("Token missing");
      (error as NodeJS.ErrnoException).code = "invalid_token";
      throw error;
    }

    try {
      return jwt.verify(token, this.signingSecret, {
        audience: "https://eventbus.salesforce.com",
        issuer: "mock-oauth",
      }) as JwtPayload & { scope?: string[] | string };
    } catch (err) {
      const error = new Error("invalid_token");
      (error as NodeJS.ErrnoException).code = "invalid_token";
      (error as NodeJS.ErrnoException).message = err instanceof Error ? err.message : String(err);
      throw error;
    }
  }
}
