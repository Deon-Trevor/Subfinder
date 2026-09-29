import { WorkflowEntrypoint } from "cloudflare:workers";
import { Container, ContainerProxy } from "@cloudflare/containers";

import {
  appendCzdsChunk,
  beginCzdsArtifact,
  claimCzdsJob,
  completeCzdsArtifact,
  czdsJobUsesContainer,
  failCzdsJob,
  finishCzdsWorkflow,
  inspectCzdsContainerJob,
  scheduleCzds,
  stageCzdsJob,
  startCzdsContainerJob,
} from "./core.js";

export { ContainerProxy };


export class CzdsParser extends Container {
  defaultPort = 8080;
  sleepAfter = "5m";

  onStop({ exitCode, reason }) {
    console.error("CZDS Container stopped", { exitCode, reason });
  }
}


CzdsParser.outboundByHost = {
  "czds.internal": async (request, env) => {
    if (request.method !== "POST") return new Response("method not allowed", { status: 405 });
    const url = new URL(request.url);
    const body = await request.json();
    try {
      if (url.pathname === "/begin") {
        await beginCzdsArtifact(env, body.job_id, body.fingerprint);
      } else if (url.pathname === "/chunk") {
        await appendCzdsChunk(env, body.job_id, body.chunk_index, body.records);
      } else if (url.pathname === "/complete") {
        return Response.json(await completeCzdsArtifact(
          env, body.job_id, body.chunk_count, body.hostname_count,
        ));
      } else {
        return new Response("not found", { status: 404 });
      }
      return Response.json({ ok: true });
    } catch (error) {
      const detail = String(error);
      const status = detail.startsWith("Error: CZDS ") ? 409 : 503;
      console.error("CZDS parser callback failed", url.pathname, status, detail);
      return Response.json({ detail }, { status });
    }
  },
};


async function stageInContainer(env, step, jobId) {
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const launched = await step.do(`start CZDS parser ${attempt}`, async () => (
      await startCzdsContainerJob(env, jobId)
    ));
    if (launched.state === "staged" || launched.state === "complete") return launched;
    for (let poll = 0; poll < 720; poll += 1) {
      await step.sleep(`wait for CZDS parser ${attempt}-${poll}`, "1 minute");
      const status = await step.do(`inspect CZDS parser ${attempt}-${poll}`, async () => (
        await inspectCzdsContainerJob(env, jobId)
      ));
      if (status.state === "staged") return status;
      if (status.state === "failed" || status.state === "idle") break;
      if (status.state !== "running") throw new Error("CZDS parser returned an invalid state");
    }
  }
  throw new Error("CZDS parser did not complete after three attempts");
}


export class CzdsIngestionWorkflow extends WorkflowEntrypoint {
  async run(event, step) {
    const jobId = event.payload?.job_id;
    try {
      const claim = await step.do("claim CZDS job", async () => (
        await claimCzdsJob(this.env, jobId)
      ));
      if (claim.state === "complete") return claim;
      if (await step.do("select CZDS parser", async () => (
        await czdsJobUsesContainer(this.env, jobId)
      ))) {
        await stageInContainer(this.env, step, jobId);
      } else {
        await step.do(
          "download and stage CZDS deltas",
          {
            retries: { limit: 3, delay: "1 minute", backoff: "exponential" },
            timeout: "30 minutes",
          },
          async () => await stageCzdsJob(this.env, jobId),
        );
      }
      return await step.do(
        "finish CZDS deltas",
        async () => await finishCzdsWorkflow(this.env, jobId),
      );
    } catch (error) {
      await step.do("record CZDS failure", async () => {
        await failCzdsJob(this.env, jobId, error);
      });
      throw error;
    }
  }
}


export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/health") {
      return new Response("ok");
    }
    return Response.json({ detail: "not found" }, { status: 404 });
  },

  async scheduled(_controller, env) {
    await scheduleCzds(env);
  },
};
