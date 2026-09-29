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
      this.sql.exec(`
        CREATE TABLE IF NOT EXISTS admission_keys (
          day TEXT NOT NULL,
          subject TEXT NOT NULL,
          key TEXT NOT NULL,
          fingerprint TEXT NOT NULL,
          units INTEGER NOT NULL,
          PRIMARY KEY (day, subject, key)
        ) WITHOUT ROWID
      `);
    });
  }

  async fetch(request) {
    const path = new URL(request.url).pathname;
    if (request.method !== "POST" || !["/admit", "/release"].includes(path)) {
      return json({ detail: "not found" }, 404);
    }
    let input;
    try {
      input = await request.json();
    } catch {
      return json({ detail: "invalid admission request" }, 400);
    }
    const { subject, key, fingerprint } = input;
    const units = Number(input.units ?? 1);
    const limit = Number(input.limit);
    if (
      typeof subject !== "string" ||
      subject.length < 1 ||
      subject.length > 160 ||
      !Number.isSafeInteger(units) ||
      units < 1 ||
      !Number.isSafeInteger(limit) ||
      limit < 1 ||
      (key !== undefined && (
        typeof key !== "string" || key.length < 1 || key.length > 256 ||
        typeof fingerprint !== "string" || fingerprint.length < 1 || fingerprint.length > 256
      )) ||
      (path === "/release" && key === undefined)
    ) {
      return json({ detail: "invalid admission request" }, 400);
    }
    const { day, resetAt } = utcWindow();
    const result = this.ctx.storage.transactionSync(() => {
      this.sql.exec("DELETE FROM request_counts WHERE day < ?", day);
      this.sql.exec("DELETE FROM admission_keys WHERE day < ?", day);
      const row = this.sql
        .exec(
          "SELECT used FROM request_counts WHERE day = ? AND subject = ?",
          day,
          subject,
        )
        .toArray()[0];
      const used = Number(row?.used ?? 0);
      if (key !== undefined) {
        const previous = this.sql.exec(
          "SELECT fingerprint, units FROM admission_keys WHERE day = ? AND subject = ? AND key = ?",
          day, subject, key,
        ).toArray()[0];
        if (previous) {
          if (previous.fingerprint !== fingerprint) return { conflict: true, used };
          if (path === "/release") {
            this.sql.exec("DELETE FROM admission_keys WHERE day = ? AND subject = ? AND key = ?", day, subject, key);
            const next = Math.max(0, used - Number(previous.units));
            this.sql.exec("UPDATE request_counts SET used = ? WHERE day = ? AND subject = ?", next, day, subject);
            return { admitted: true, used: next, released: true };
          }
          return { admitted: true, used, replay: true };
        }
      }
      if (path === "/release") return { admitted: true, used, released: false };
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
      if (key !== undefined) {
        this.sql.exec(
          "INSERT INTO admission_keys(day, subject, key, fingerprint, units) VALUES (?, ?, ?, ?, ?)",
          day, subject, key, fingerprint, units,
        );
      }
      return { admitted: true, used: next };
    });
    return json({
      admitted: result.admitted,
      replay: result.replay === true,
      released: result.released === true,
      limit,
      remaining: Math.max(0, limit - result.used),
      reset_at: resetAt,
    }, result.conflict ? 409 : result.admitted ? 200 : 429);
  }
}


export async function subjectShard(subject) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(subject),
  );
  return new Uint8Array(digest)[0].toString(16).padStart(2, "0");
}


export async function admitQuota(env, identity, units = 1, key, fingerprint) {
  const id = env.QUOTA_LEDGER.idFromName(await subjectShard(identity.subject));
  const response = await env.QUOTA_LEDGER.get(id).fetch("https://quota/admit", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      subject: identity.subject,
      limit: identity.limit,
      units,
      ...(key === undefined ? {} : { key, fingerprint }),
    }),
  });
  const quota = await response.json();
  if (!response.ok) {
    const error = new Error(response.status === 409
      ? "idempotency key was already used for another request"
      : "daily request limit exceeded");
    error.status = response.status;
    error.quota = quota;
    throw error;
  }
  return quota;
}


export async function releaseQuota(env, identity, key, fingerprint) {
  const id = env.QUOTA_LEDGER.idFromName(await subjectShard(identity.subject));
  const response = await env.QUOTA_LEDGER.get(id).fetch("https://quota/release", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ subject: identity.subject, limit: identity.limit,
      units: 1, key, fingerprint }),
  });
  if (!response.ok) throw new Error("quota release failed");
  return await response.json();
}


export function quotaHeaders(quota) {
  return {
    "X-RateLimit-Limit": String(quota.limit),
    "X-RateLimit-Remaining": String(quota.remaining),
    "X-RateLimit-Reset": String(quota.reset_at),
  };
}
