const jwt = require("jsonwebtoken");

class MockOAuthServer {
  constructor(options = {}) {
    const {
      signingSecret = "mock-oauth-signing-secret",
      tokenLifetimeSeconds = 300,
    } = options;

    this.signingSecret = signingSecret;
    this.tokenLifetimeSeconds = tokenLifetimeSeconds;
    this.clients = new Map();
  }

  registerClient(clientId, clientSecret, scopes = []) {
    if (!clientId || !clientSecret) {
      throw new Error("clientId and clientSecret are required");
    }
    this.clients.set(clientId, {
      secret: clientSecret,
      scopes: new Set(scopes),
    });
  }

  issueToken({ clientId, clientSecret, scope }) {
    const client = this.clients.get(clientId);
    if (!client || client.secret !== clientSecret) {
      const error = new Error("invalid_client");
      error.code = "invalid_client";
      throw error;
    }

    const requestedScopes = new Set((scope || "").split(/\s+/).filter(Boolean));
    if (requestedScopes.size === 0) {
      const error = new Error("invalid_scope");
      error.code = "invalid_scope";
      throw error;
    }

    for (const requestedScope of requestedScopes) {
      if (!client.scopes.has(requestedScope)) {
        const error = new Error("invalid_scope");
        error.code = "invalid_scope";
        throw error;
      }
    }

    const payload = {
      sub: clientId,
      scope: Array.from(requestedScopes),
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
      scope: Array.from(requestedScopes).join(" "),
    };
  }

  verify(token) {
    if (!token) {
      const error = new Error("Token missing");
      error.code = "invalid_token";
      throw error;
    }

    try {
      return jwt.verify(token, this.signingSecret, {
        audience: "https://eventbus.salesforce.com",
        issuer: "mock-oauth",
      });
    } catch (error) {
      const err = new Error("invalid_token");
      err.code = "invalid_token";
      err.details = error.message;
      throw err;
    }
  }
}

module.exports = {
  MockOAuthServer,
};
