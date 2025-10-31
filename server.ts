// server.ts
import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { createRemoteJWKSet, jwtVerify, JWTPayload } from "jose";
import { randomBytes, createHash } from "crypto";
import { AsyncLocalStorage } from "async_hooks";

// ----------------- env -----------------
const PORT = parseInt(process.env.PORT || "3000");
const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL!; // e.g. https://airtable-mcp.automation.engineer
const AUTH0_DOMAIN = process.env.AUTH0_DOMAIN!; // e.g. your-tenant.us.auth0.com
const AUTH0_ISSUER = `https://${AUTH0_DOMAIN}/`;
const AUTH0_AUDIENCE = process.env.AUTH0_AUDIENCE!; // e.g. https://airtable-mcp.automation.engineer
const AIRTABLE_CLIENT_ID = process.env.AIRTABLE_CLIENT_ID!;
const AIRTABLE_CLIENT_SECRET = process.env.AIRTABLE_CLIENT_SECRET!;
const AIRTABLE_OAUTH_REDIRECT =
  process.env.AIRTABLE_OAUTH_REDIRECT || `${PUBLIC_BASE_URL}/airtable/oauth/callback`;

// ----------------- oauth state & storage -----------------
interface UserTokens {
  accessToken: string;
  refreshToken: string;
  expiresAt: number;
}

const airtableTokens = new Map<string, UserTokens>();
const oauthStates = new Map<string, { codeVerifier: string; sub: string }>();

function generateCodeVerifier() {
  return randomBytes(32).toString("base64url");
}

function generateCodeChallenge(verifier: string) {
  return createHash("sha256").update(verifier).digest("base64url");
}

function computeExpiry(expiresIn: unknown) {
  const seconds = typeof expiresIn === "number" && Number.isFinite(expiresIn) ? expiresIn : 3600;
  return Date.now() + Math.max(30, seconds - 30) * 1000; // keep a small buffer
}

async function exchangeToken(params: URLSearchParams) {
  const response = await fetch("https://airtable.com/oauth2/v1/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: params,
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Airtable token exchange failed (${response.status}): ${text}`);
  }
  return response.json();
}

async function refreshAirtableTokens(existing: UserTokens): Promise<UserTokens> {
  const params = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: existing.refreshToken,
    client_id: AIRTABLE_CLIENT_ID,
    client_secret: AIRTABLE_CLIENT_SECRET,
  });
  const data = await exchangeToken(params);
  if (typeof data.access_token !== "string" || data.access_token.length === 0) {
    throw new Error("Airtable refresh response missing access_token");
  }
  const newRefresh = typeof data.refresh_token === "string" && data.refresh_token.length > 0
    ? data.refresh_token
    : existing.refreshToken;
  return {
    accessToken: data.access_token,
    refreshToken: newRefresh,
    expiresAt: computeExpiry(data.expires_in),
  };
}

async function getAirtableAccessTokenForSub(sub: string): Promise<string | null> {
  const existing = airtableTokens.get(sub);
  if (!existing) return null;
  if (existing.expiresAt > Date.now()) {
    return existing.accessToken;
  }
  try {
    const refreshed = await refreshAirtableTokens(existing);
    airtableTokens.set(sub, refreshed);
    return refreshed.accessToken;
  } catch (err) {
    console.error(`Failed to refresh Airtable token for ${sub}:`, err);
    airtableTokens.delete(sub);
    return null;
  }
}

// ----------------- auth helpers -----------------
const JWKS = createRemoteJWKSet(new URL(`${AUTH0_ISSUER}.well-known/jwks.json`));

interface Access {
  sub: string;
  scopes: string[];
  permissions: string[];
}

async function verifyBearer(token?: string): Promise<Access> {
  if (!token) throw new Error("missing");
  const { payload } = await jwtVerify(token, JWKS, {
    issuer: AUTH0_ISSUER,
    audience: AUTH0_AUDIENCE,
  });
  const permissions = (payload as JWTPayload & { permissions?: string[] }).permissions || [];
  const scopeString = (payload.scope as string) || "";
  const scopes = scopeString.split(" ").filter(Boolean);
  return { sub: payload.sub as string, scopes, permissions };
}

function requirePermission(a: Access, p: string) {
  if (!a.permissions.includes(p)) throw new Error(`forbidden:${p}`);
}

const accessStorage = new AsyncLocalStorage<Access | undefined>();

function buildLinkMessage(): { content: { type: "text"; text: string }[] } {
  return {
    content: [
      {
        type: "text",
        text: `Your Airtable account is not linked yet. Please visit ${PUBLIC_BASE_URL}/airtable/oauth/start to authorize access and then try again.`,
      },
    ],
  };
}

// ----------------- MCP server -----------------
const server = new McpServer({ name: "airtable-mcp", version: "1.0.0" });

// List records tool
server.registerTool(
  "airtable_list_records",
  {
    title: "List Airtable records",
    description: "Lists records from a base/table.",
    inputSchema: {
      type: "object",
      properties: {
        baseId: { type: "string" },
        table: { type: "string" },
        pageSize: { type: "number", minimum: 1, maximum: 100, default: 50 },
      },
      required: ["baseId", "table"],
    },
    securitySchemes: [{ type: "oauth2", scopes: ["airtable.read"] }],
  },
  async ({ input }) => {
    const access = accessStorage.getStore();
    if (!access) {
      return buildLinkMessage();
    }
    const token = await getAirtableAccessTokenForSub(access.sub);
    if (!token) {
      return buildLinkMessage();
    }
    const url = new URL(
      `https://api.airtable.com/v0/${encodeURIComponent(input.baseId)}/${encodeURIComponent(input.table)}`
    );
    url.searchParams.set("pageSize", String(input.pageSize ?? 50));
    const r = await fetch(url, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (r.status === 401) {
      airtableTokens.delete(access.sub);
      return buildLinkMessage();
    }
    if (!r.ok) {
      const t = await r.text();
      throw new Error(`Airtable error ${r.status}: ${t}`);
    }
    const data = await r.json();
    const sample = Array.isArray(data.records) ? data.records.slice(0, 10) : data;
    return {
      content: [{ type: "text", text: `Fetched ${sample.length ?? "some"} records.` }],
      structuredContent: { records: sample },
    };
  }
);

// Create record tool
server.registerTool(
  "airtable_create_record",
  {
    title: "Create Airtable record",
    description: "Creates a single record in a base/table.",
    inputSchema: {
      type: "object",
      properties: {
        baseId: { type: "string" },
        table: { type: "string" },
        fields: { type: "object" },
      },
      required: ["baseId", "table", "fields"],
    },
    securitySchemes: [{ type: "oauth2", scopes: ["airtable.write"] }],
  },
  async ({ input }) => {
    const access = accessStorage.getStore();
    if (!access) {
      return buildLinkMessage();
    }
    const token = await getAirtableAccessTokenForSub(access.sub);
    if (!token) {
      return buildLinkMessage();
    }
    const r = await fetch(
      `https://api.airtable.com/v0/${encodeURIComponent(input.baseId)}/${encodeURIComponent(input.table)}`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ fields: input.fields }),
      }
    );
    if (r.status === 401) {
      airtableTokens.delete(access.sub);
      return buildLinkMessage();
    }
    if (!r.ok) {
      const t = await r.text();
      throw new Error(`Airtable error ${r.status}: ${t}`);
    }
    const data = await r.json();
    return {
      content: [{ type: "text", text: `Created record ${data?.id ?? ""}` }],
      structuredContent: { record: data },
    };
  }
);

// ----------------- HTTP wiring + auth gate -----------------
const app = express();
app.use(express.json());

// Protected Resource Metadata (PRM)
app.get("/.well-known/oauth-protected-resource", (_req, res) => {
  res.json({
    resource: `${PUBLIC_BASE_URL}`,
    authorization_servers: [`${AUTH0_ISSUER}`.replace(/\/$/, "")],
    bearer_methods_supported: ["header"],
    scopes_supported: ["airtable.read", "airtable.write"],
  });
});

app.get("/airtable/oauth/start", async (req, res) => {
  try {
    const header = req.header("authorization") || "";
    const token = header.replace(/^Bearer\s+/i, "");
    const access = await verifyBearer(token);
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);
    const state = randomBytes(16).toString("base64url");
    oauthStates.set(state, { codeVerifier, sub: access.sub });

    const authorizeUrl = new URL("https://airtable.com/oauth2/v1/authorize");
    authorizeUrl.searchParams.set("client_id", AIRTABLE_CLIENT_ID);
    authorizeUrl.searchParams.set("redirect_uri", AIRTABLE_OAUTH_REDIRECT);
    authorizeUrl.searchParams.set("response_type", "code");
    authorizeUrl.searchParams.set("code_challenge", codeChallenge);
    authorizeUrl.searchParams.set("code_challenge_method", "S256");
    authorizeUrl.searchParams.set("state", state);
    authorizeUrl.searchParams.set("scope", "data.records:read data.records:write");

    res.redirect(authorizeUrl.toString());
  } catch (err) {
    console.error("Failed to initiate Airtable OAuth:", err);
    res.status(401).json({ error: "unauthorized" });
  }
});

app.get("/airtable/oauth/callback", async (req, res) => {
  const code = req.query.code;
  const state = req.query.state;
  if (typeof code !== "string" || typeof state !== "string") {
    res.status(400).send("Missing authorization code or state");
    return;
  }
  const saved = oauthStates.get(state);
  if (!saved) {
    res.status(400).send("Invalid or expired OAuth state");
    return;
  }
  oauthStates.delete(state);

  try {
    const params = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      client_id: AIRTABLE_CLIENT_ID,
      client_secret: AIRTABLE_CLIENT_SECRET,
      redirect_uri: AIRTABLE_OAUTH_REDIRECT,
      code_verifier: saved.codeVerifier,
    });
    const data = await exchangeToken(params);
    if (typeof data.access_token !== "string" || data.access_token.length === 0) {
      throw new Error("Airtable response missing access_token");
    }
    if (typeof data.refresh_token !== "string" || data.refresh_token.length === 0) {
      throw new Error("Airtable response missing refresh_token");
    }
    const tokens: UserTokens = {
      accessToken: data.access_token,
      refreshToken: data.refresh_token,
      expiresAt: computeExpiry(data.expires_in),
    };
    airtableTokens.set(saved.sub, tokens);
    res.send("Airtable account linked successfully. You can return to ChatGPT.");
  } catch (err) {
    console.error("Failed to complete Airtable OAuth callback:", err);
    res.status(500).send("Failed to exchange authorization code. Please try again.");
  }
});

// Main MCP endpoint
app.post("/mcp", async (req, res) => {
  let access: Access | undefined;
  try {
    const method = req.body?.method;
    const isToolCall = method === "call_tool";
    if (isToolCall) {
      const header = req.header("authorization") || "";
      const token = header.replace(/^Bearer\s+/i, "");
      access = await verifyBearer(token);
      const tool = req.body?.params?.name as string | undefined;
      if (tool === "airtable_list_records") requirePermission(access, "airtable.read");
      if (tool === "airtable_create_record") requirePermission(access, "airtable.write");
    }
    const transport = new StreamableHTTPServerTransport({ enableJsonResponse: true });
    res.on("close", () => transport.close());
    await accessStorage.run(access, async () => {
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    });
  } catch (e: any) {
    res.set(
      "WWW-Authenticate",
      `Bearer error="invalid_token", resource="${PUBLIC_BASE_URL}", as_uri="${PUBLIC_BASE_URL}/.well-known/oauth-protected-resource"`
    );
    res
      .status(e?.message?.startsWith("forbidden:") ? 403 : 401)
      .json({ error: e?.message || "unauthorized" });
  }
});

app.listen(PORT, () => {
  console.log(`MCP on ${PUBLIC_BASE_URL}/mcp`);
});
