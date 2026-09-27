const encoder = new TextEncoder();


async function sha256Hex(value) {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}


function constantTimeEqual(left, right) {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }
  return difference === 0;
}


function positiveInteger(value, fallback) {
  const parsed = Number(value ?? fallback);
  if (!Number.isInteger(parsed) || parsed < 1) {
    throw new Error("request limit configuration must be a positive integer");
  }
  return parsed;
}


function configuredTokens(env) {
  if (!env.CLIENT_TOKENS) return [];
  let parsed;
  try {
    parsed = JSON.parse(env.CLIENT_TOKENS);
  } catch {
    throw new Error("CLIENT_TOKENS must be valid JSON");
  }
  if (!Array.isArray(parsed)) throw new Error("CLIENT_TOKENS must be a JSON array");
  return parsed.map((entry) => {
    if (
      typeof entry?.id !== "string" ||
      !/^[A-Za-z0-9._-]{1,64}$/.test(entry.id) ||
      typeof entry?.sha256 !== "string" ||
      !/^[a-f0-9]{64}$/.test(entry.sha256)
    ) {
      throw new Error("CLIENT_TOKENS contains an invalid token entry");
    }
    return {
      id: entry.id,
      sha256: entry.sha256,
      limit: positiveInteger(entry.limit, env.TOKEN_REQUEST_LIMIT ?? 250000),
    };
  });
}


function bearerToken(request) {
  const authorization = request.headers.get("authorization");
  if (!authorization?.startsWith("Bearer ")) return null;
  return authorization.slice("Bearer ".length).trim() || null;
}


export async function clientIdentity(request, env) {
  const token = bearerToken(request);
  if (token !== null) {
    const digest = await sha256Hex(token);
    for (const configured of configuredTokens(env)) {
      if (constantTimeEqual(digest, configured.sha256)) {
        return {
          authenticated: true,
          clientId: configured.id,
          limit: configured.limit,
          subject: `token:${digest}`,
        };
      }
    }
  }
  const address = request.headers.get("CF-Connecting-IP") || env.LOCAL_CLIENT_IP;
  if (!address) throw new Error("client IP is unavailable");
  return {
    authenticated: false,
    clientId: null,
    limit: positiveInteger(env.PUBLIC_REQUEST_LIMIT, 1000),
    subject: `ip:${address}`,
  };
}


export async function requireClient(request, env) {
  const identity = await clientIdentity(request, env);
  if (!identity.authenticated) {
    const error = new Error("a valid service token is required");
    error.status = 401;
    throw error;
  }
  return identity;
}
