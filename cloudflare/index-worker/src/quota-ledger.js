function json(value, status = 200) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json" },
  });
}


export function utcWindow(now = Date.now()) {
  const date = new Date(now);
  const day = date.toISOString().slice(0, 10);
  const resetAt = Date.UTC(
    date.getUTCFullYear(),
    date.getUTCMonth(),
    date.getUTCDate() + 1,
  ) / 1000;
  return { day, resetAt };
}


export class QuotaLedger {
  constructor(ctx) {
    this.ctx = ctx;
    this.sql = ctx.storage.sql;
    ctx.blockConcurrencyWhile(async () => {
      this.sql.exec(`
        CREATE TABLE IF NOT EXISTS request_counts (
          day TEXT NOT NULL,
          subject TEXT NOT NULL,
          used INTEGER NOT NULL,
          PRIMARY KEY (day, subject)
        ) WITHOUT ROWID
      `);
    });
  }

  async fetch(request) {
    if (request.method !== "POST" || new URL(request.url).pathname !== "/admit") {
      return json({ detail: "not found" }, 404);
    }
    let input;
    try {
      input = await request.json();
    } catch {
      return json({ detail: "invalid admission request" }, 400);
    }
    const { subject } = input;
    const units = Number(input.units ?? 1);
    const limit = Number(input.limit);
    if (
      typeof subject !== "string" ||
      subject.length < 1 ||
      subject.length > 160 ||
      !Number.isSafeInteger(units) ||
      units < 1 ||
      !Number.isSafeInteger(limit) ||
      limit < 1
    ) {
      return json({ detail: "invalid admission request" }, 400);
    }
    const { day, resetAt } = utcWindow();
    const result = this.ctx.storage.transactionSync(() => {
      this.sql.exec("DELETE FROM request_counts WHERE day < ?", day);
      const row = this.sql
        .exec(
          "SELECT used FROM request_counts WHERE day = ? AND subject = ?",
          day,
          subject,
        )
        .toArray()[0];
      const used = Number(row?.used ?? 0);
      if (used + units > limit) {
        return { admitted: false, used };
      }
      const next = used + units;
      this.sql.exec(
        `INSERT INTO request_counts(day, subject, used) VALUES (?, ?, ?)
         ON CONFLICT(day, subject) DO UPDATE SET used = excluded.used`,
        day,
        subject,
        next,
      );
      return { admitted: true, used: next };
    });
    return json({
      admitted: result.admitted,
      limit,
      remaining: Math.max(0, limit - result.used),
      reset_at: resetAt,
    }, result.admitted ? 200 : 429);
  }
}


export async function subjectShard(subject) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(subject),
  );
  return new Uint8Array(digest)[0].toString(16).padStart(2, "0");
}


export async function admitQuota(env, identity, units = 1) {
  const id = env.QUOTA_LEDGER.idFromName(await subjectShard(identity.subject));
  const response = await env.QUOTA_LEDGER.get(id).fetch("https://quota/admit", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      subject: identity.subject,
      limit: identity.limit,
      units,
    }),
  });
  const quota = await response.json();
  if (!response.ok) {
    const error = new Error("daily request limit exceeded");
    error.status = response.status;
    error.quota = quota;
    throw error;
  }
  return quota;
}


export function quotaHeaders(quota) {
  return {
    "X-RateLimit-Limit": String(quota.limit),
    "X-RateLimit-Remaining": String(quota.remaining),
    "X-RateLimit-Reset": String(quota.reset_at),
  };
}
