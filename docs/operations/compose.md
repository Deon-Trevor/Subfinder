# Operate the Compose service

Use these limits and proxy settings when operating the Compose deployment.
The [getting-started guide](/getting-started) covers initial setup.

## Bound request load

The Compose edge admits an initial global burst of 80 public requests, then
limits sustained traffic to 10 requests per second. It also applies an
80-request per-client burst with a 10 request-per-second sustained rate and
bounds active proxied requests to 96 globally and 80 per client. Excess edge
traffic returns `503`, `Retry-After: 1`, and
`X-Overload-Reason: edge-capacity`. `/health` bypasses these public limits but
is available only to direct local probes; a request carrying the sanitized
client header from host NGINX receives `404`. The limits live in
`deploy/nginx.conf`; keep the host NGINX connection and request limits as an
additional outer boundary.

Behind that edge, the API accepts at most 80 public requests and 16 requests
with a valid service token at one time. These limits cover the complete
response, including a streamed response. A full class returns `503`,
`Retry-After: 1`, and
`X-Overload-Reason: public-capacity` or `service-capacity`. A request rejected
at this boundary does not consume quota. Quota exhaustion remains a distinct
`429` response with the exact limit, remaining count, reset time, and retry
time.

Set `CTLOGS_PUBLIC_INFLIGHT_LIMIT` and `CTLOGS_SERVICE_INFLIGHT_LIMIT` to
change the two limits. The default catalog concurrency is one. Local burst
tests show that 70 reads take about 55 ms sequentially and about 379 ms with
eight reader threads. Keep `CTLOGS_CATALOG_CONCURRENCY=1` unless a benchmark
on the deployment host proves that a different value is faster.

Concurrent quota checks wait 2 ms so the control database can commit them in
one ordered transaction. `CTLOGS_CONTROL_BATCH_WINDOW_SECONDS` changes that
window. The 80-public and 16-service request limits bound the batch queue.
Canceled requests leave the batch before transaction selection. After a
request enters a control transaction, its exact quota outcome is final even if
the client disconnects before it receives the response.

Run one Uvicorn worker. The in-process request limits apply per worker. Keep
`/health` outside public edge limits so an overloaded instance remains
observable. uMzingeli should call `http://subfinder-index:8200` over the
private data network with its service token; it must not loop through the
public edge, where public DoS protection sheds excess traffic.

## Configure trusted client addresses

NGINX must replace client-supplied forwarding headers. Do not append an
untrusted chain.

```nginx
proxy_set_header Forwarded "";
proxy_set_header X-Forwarded-For $remote_addr;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-Proto $scheme;
```

The Compose API has no published host port, so its default
`CTLOGS_FORWARDED_ALLOW_IPS=*` trusts the edge and other private-network peers.
Only trusted services may join those networks. When the deployment assigns a
stable edge address or subnet, set `CTLOGS_FORWARDED_ALLOW_IPS` to that narrower
value. Do not use the wildcard if any untrusted container can reach port 8200;
it could forge a public client address and avoid its quota.

If a CDN connects to NGINX, configure the NGINX real-IP module with only the
CDN's published address ranges. NGINX must resolve the client address before
it sets `X-Forwarded-For` for Subfinder.
