// server.ts
import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import { createRemoteJWKSet, jwtVerify, JWTPayload } from "jose";

// ----------------- env -----------------
const PORT = parseInt(process.env.PORT || "3000");
const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL!;   // e.g. https://airtable-mcp.automation.engineer
const AUTH0_DOMAIN = process.env.AUTH0_DOMAIN!;         // e.g. your-tenant.us.auth0.com
const AUTH0_ISSUER = `https://${AUTH0_DOMAIN}/`;
const AUTH0_AUDIENCE = process.env.AUTH0_AUDIENCE!;     // e.g. https://airtable-mcp.automation.engineer
const AIRTABLE_PAT = process.env.AIRTABLE_PAT || "";    // optional PAT if using service auth

// ----------------- auth helpers -----------------
const JWKS = createRemoteJWKSet(new URL(`${AUTH0_ISSUER}.well-known/jwks.json`));

type Access = {
  sub: string;
  scopes: string[];
  permissions: string[];
};

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
    if (!AIRTABLE_PAT) {
      return { content: [{ type: "text", text: "Server not configured with AIRTABLE_PAT." }] };
    }
    const url = new URL(
      `https://api.airtable.com/v0/${encodeURIComponent(input.baseId)}/${encodeURIComponent(input.table)}`
    );
    url.searchParams.set("pageSize", String(input.pageSize ?? 50));
    const r = await fetch(url, {
      headers: { Authorization: `Bearer ${AIRTABLE_PAT}` },
    });
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
    if (!AIRTABLE_PAT) {
      return { content: [{ type: "text", text: "Server not configured with AIRTABLE_PAT." }] };
    }
    const r = await fetch(
      `https://api.airtable.com/v0/${encodeURIComponent(input.baseId)}/${encodeURIComponent(input.table)}`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${AIRTABLE_PAT}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ fields: input.fields }),
      }
    );
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
    resource: `${PUBLIC_BASE_URL}/mcp`,
    authorization_servers: [`${AUTH0_ISSUER}`.replace(/\/$/, "")],
    bearer_methods_supported: ["header"],
    scopes_supported: ["airtable.read", "airtable.write"],
  });
});

// Main MCP endpoint
app.post("/mcp", async (req, res) => {
  try {
    const method = req.body?.method;
    const isToolCall = method === "call_tool";
    if (isToolCall) {
      const header = req.header("authorization") || "";
      const token = header.replace(/^Bearer\s+/i, "");
      const access = await verifyBearer(token);
      const tool = req.body?.params?.name as string | undefined;
      if (tool === "airtable_list_records") requirePermission(access, "airtable.read");
      if (tool === "airtable_create_record") requirePermission(access, "airtable.write");
    }
    const transport = new StreamableHTTPServerTransport({ enableJsonResponse: true });
    res.on("close", () => transport.close());
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (e: any) {
    res.set(
      "WWW-Authenticate",
      `Bearer error="invalid_token", resource="${PUBLIC_BASE_URL}/mcp", as_uri="${PUBLIC_BASE_URL}/.well-known/oauth-protected-resource"`
    );
    res.status(e?.message?.startsWith("forbidden:") ? 403 : 401).json({ error: e?.message || "unauthorized" });
  }
});

app.listen(PORT, () => {
  console.log(`MCP on ${PUBLIC_BASE_URL}/mcp`);
});
