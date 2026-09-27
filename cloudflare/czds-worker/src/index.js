import { WorkflowEntrypoint } from "cloudflare:workers";

import {
  claimCzdsJob,
  failCzdsJob,
  publishCzdsJob,
  scheduleCzds,
  stageCzdsJob,
} from "./core.js";


export class CzdsIngestionWorkflow extends WorkflowEntrypoint {
  async run(event, step) {
    const jobId = event.payload?.job_id;
    try {
      const claim = await step.do("claim CZDS job", async () => (
        await claimCzdsJob(this.env, jobId)
      ));
      if (claim.state === "complete") return claim;
      await step.do(
        "download and stage CZDS deltas",
        {
          retries: { limit: 3, delay: "1 minute", backoff: "exponential" },
          timeout: "30 minutes",
        },
        async () => await stageCzdsJob(this.env, jobId),
      );
      return await step.do(
        "publish CZDS deltas",
        async () => await publishCzdsJob(this.env, jobId),
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
