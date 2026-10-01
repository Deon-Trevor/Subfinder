import assert from "node:assert/strict";
import { test } from "node:test";

import { clientIdentity } from "../src/client-auth.js";

const env = { CLIENT_IP_HEADER_HOSTNAME: "subfinder.syncpundit.io" };

test("production accepts only the hostname-scoped transformed IP header", async () => {
  const headers = { "X-Subfinder-Client-IP": "192.0.2.10" };
  const production = new Request("https://subfinder.syncpundit.io/v1/search", { headers });
  const identity = await clientIdentity(production, env);
  assert.equal(identity.subject, "ip:192.0.2.10");

  const preview = new Request("https://preview.example.net/v1/search", { headers });
  await assert.rejects(clientIdentity(preview, env), /client IP is unavailable/);
  await assert.rejects(clientIdentity(production, {}), /client IP is unavailable/);
});

test("Cloudflare's standard client IP takes precedence", async () => {
  const request = new Request("https://subfinder.syncpundit.io/v1/search", {
    headers: {
      "CF-Connecting-IP": "2001:db8::10",
      "X-Subfinder-Client-IP": "192.0.2.10",
    },
  });
  const identity = await clientIdentity(request, env);
  assert.equal(identity.subject, "ip:2001:db8::10");
});
