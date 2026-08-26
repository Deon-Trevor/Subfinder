# LLM Council transcript: Subfinder burst hardening

Timestamp: 2026-08-26T15:08:35Z

## Original request

The user asked for three local load scenarios with more than 70 simultaneous
users, including Threat Hunter background traffic: repeated apexes, 70 distinct
popular apexes, and staggered bursts. The follow-up work had to continue until
the service handled bursts and protected itself from denial-of-service traffic
and abuse.

## Workspace context scanned

- `src/ctlogs/app.py`: request admission, quota identity, catalog lanes, and API routes.
- `src/ctlogs/control.py`: exact SQLite quotas and refresh deduplication.
- `src/ctlogs/database.py`: read-only catalog queries.
- `docker-compose.yml` and `Dockerfile`: loopback bind, private network, and Uvicorn process shape.
- `README.md`: existing proxy, quota, and deployment contracts.
- `tests/test_api.py` and `tests/test_control.py`: lock, quota, and failure behavior.
- Local baseline artifacts under `.codex/evidence/task-subfinder-burst-hardening/`.

## Framed question

## Question

How should the local Subfinder FastAPI/SQLite service be hardened so it can serve a supported synchronized burst of 70 public `/v1/search` requests plus 10 token-authenticated Threat Hunter `/v1/records` requests, while rejecting abusive overload predictably and preserving fair service traffic behind host NGINX and Docker?

Measured facts: 70+10 synchronized same-apex succeeds but public p95 is 652 ms; distinct-apex p95 is 608 ms; seven staggered bursts of 10 pass at 79 ms p95. Health p99 stays under 35 ms. An abusive 500 public + 20 service synchronized load is not bounded: every request is accepted, public p95 reaches 6.7 s, service p95 2.08 s, health p99 409 ms/max 1.43 s, and maximum RSS reaches 153 MB. At synchronization, serialized exact quota/refresh admission reaches 221 ms and the eight-slot read-only catalog lane reaches 409 ms. Same-apex refresh requests dedupe but identical catalog reads do not. Semaphores bound active DB calls but their wait queues and wait times are unbounded. Daily public quota is persistent SQLite per `request.client.host`; bearer tokens get a separate quota. Docker binds port 8200 to loopback and NGINX proxies to it, but trustworthy real-client identity and service fairness must be explicit.

Constraints: keep SQLite unless evidence forces replacement; do not load-test production; preserve exact quota semantics, passive behavior, API response contracts, and current Threat Hunter integration. The design must specify overload status/headers, limits/deadlines, identity trust boundary, and deployment defaults.

## Response A

Adopt three explicit lanes in one Uvicorn process:

- Admission: separate bounded queues for public and token traffic. Reserve 16 token slots and allow 96 public waiters. A single control-DB worker should drain admission requests in micro-batches under one transaction while assigning each request its exact sequential quota result. Reject before quota consumption when the lane is full.
- Catalog: use 16 read-only workers, a 750 ms queue deadline, and per-apex singleflight. Seventy synchronized `zerofox.com` requests should perform one catalog read but retain independent quota and response headers. Do not add a TTL cache; singleflight preserves snapshot semantics without staleness.
- Refresh: retain per-apex deduplication, cap concurrent refresh scheduling at two, and never let refresh delay catalog delivery.

Return 429 only for exhausted daily quota. Return 503 with `Retry-After: 1`, `X-Subfinder-Overload: public|service|catalog`, and existing quota headers where admission already occurred. Set an end-to-end server deadline of 1.5 seconds. Health bypasses every lane.

Make NGINX the sole identity boundary. Bind Docker to loopback, delete incoming forwarding headers, then set them from `$remote_addr`. Configure FastAPI to trust proxy headers only from loopback. Bearer-authenticated Threat Hunter traffic enters the reserved service lane; invalid bearer traffic remains public. Run one application worker so semaphores and singleflight are authoritative.

Deployment defaults should include NGINX connection limits, a per-IP burst of at least 80, upstream timeouts slightly above 1.5 seconds, and structured metrics for lane depth, rejection reason, admission latency, catalog wait, singleflight followers, and identity source.

## Response B

Do not fix this by enlarging semaphores. That converts overload into a bigger unbounded waiting room.

Add class-aware admission before quota or catalog work:

- Public: shared catalog capacity 6, queue cap 80, total deadline 900 ms.
- Threat Hunter: 2 reserved catalog slots plus borrowing from the shared 6, queue cap 16, deadline 500 ms.
- Reject queue-full or deadline-expired requests with 503, `Retry-After: 1`, and `X-Overload-Reason: queue-full|deadline`.
- Return quota exhaustion as 429 with `Retry-After` and exact limit/remaining/reset headers.

Replace individually committed quota admissions with a bounded single-writer control channel that group-commits requests arriving within 2-5 ms in one SQLite transaction, preserving arrival order, exact counters, refresh deduplication, and individual outcomes. Cap the channel; never let senders wait indefinitely.

Do not implement same-apex read singleflight yet. Same- and distinct-apex results are similarly slow, proving admission and lane waiting dominate. Singleflight also becomes dangerous when one shared result is a 7 MB response. Reconsider it only for bounded pages.

NGINX must discard client-supplied forwarding headers and set client identity from `$remote_addr`. Uvicorn should trust proxy headers only from loopback or the exact private NGINX address. If a CDN precedes NGINX, configure NGINX real-IP with that provider's published CIDRs; never trust arbitrary chains.

Set NGINX per-location connection limits and a public burst of at least 70, while reserving `/v1/records` upstream capacity. Test supported burst, queue saturation, slow clients, forged forwarding headers, and quota correctness across restart.

## Response C

Treat 80 synchronized requests as the explicit supported burst, not as an incidental success. Put bounded admission in front of every unbounded semaphore queue: separate public-search and authenticated-records queues/pools, with reserved service capacity. Once a queue is full, reject immediately with 503 and `Retry-After`; use 429 only for actual quota exhaustion. Include rate-limit headers on quota responses and `Retry-After` on both classes of rejection.

Set short, test-derived queue deadlines: public requests must fail before they can damage health or service traffic; authenticated records receive a larger reserved queue and deadline. Bound concurrent refresh/quota mutation work separately from the read-only catalog lane. The eight-slot catalog lane's synchronization result means its queue also needs a fixed maximum; deduplicate identical catalog reads just as refreshes are deduplicated. Do not collapse public and service admission into one fair pool—under overload that merely lets public traffic consume service latency.

Keep SQLite. The evidence shows admission and waiting, not SQLite failure. Preserve exact persistent quota by allowing only a bounded number of requests to wait for serialized quota/refresh admission; rejected requests must not consume quota.

Make client identity a deployment boundary: have NGINX strip inbound forwarding headers, set them itself, and configure the app to trust forwarded identity only from the loopback NGINX peer. Otherwise quotas are neither per-client nor trustworthy. Token identity remains a distinct quota key.

Ship conservative defaults: loopback-only Docker bind, NGINX request/body/time limits, app concurrency/queue caps, health excluded from expensive admission, structured overload logs/metrics, and local/container burst tests for 70+10 plus 500+20 rejection behavior.

## Response D

Capacity, not SQLite, is the problem. Build two bounded admission classes before quota or catalog work: public queue capacity 80 and service queue capacity 16. Give public at most six catalog slots, service at most four, and retain a global limit of eight so public traffic always leaves two slots available for Threat Hunter. Set queue-acquisition deadlines to 750 ms and total request deadlines to 1.5 seconds.

Single-flight identical catalog reads by normalized `(apex, dates, pagination)` key and retain results in a small bounded TTL cache. This removes redundant same-apex reads without weakening distinct-apex behavior. Keep exact public quota increments serialized in the control SQLite database, but bound its queue to 80 and deadline to 500 ms. Refresh enqueue remains idempotent and deduplicated. Authenticate service traffic before public admission and account token quotas by token identity, never client IP.

Return 429 plus rate-limit and retry headers for exhausted quotas. Return 503 plus `Retry-After: 1` and `X-Overload-Reason: admission-capacity|admission-timeout` when bounded capacity is unavailable. Never allow semaphore waiters to accumulate without a cap or deadline.

NGINX must overwrite client identity headers. Configure trusted proxy CIDRs explicitly, derive the canonical client address with `real_ip`, and send only that value upstream. FastAPI must honor forwarded identity only when the socket peer is the configured loopback/private Docker proxy. Keep port 8200 loopback-only.

Deployment defaults: queues 80/16, class concurrency 6/4, global catalog concurrency 8, 750 ms admission deadline, 1.5-second application deadline, and NGINX timeout above that boundary.

## Response E

Put a bounded admission gate in front of every request before quota/refresh/catalog work. Use separate FIFO queues and reserved concurrency: public (for example 80 queued, 32 admitted) and authenticated service (20 queued, 10 admitted), with no borrowing from the service reservation. If a queue is full, return 429 immediately with `Retry-After: 1` and rate-limit headers where applicable. This converts the abusive burst into predictable shedding and protects `/health` by handling it outside these gates.

Inside the admitted request path, retain the existing serialized SQLite quota operation so quota remains exact. Add a strict admission deadline (for example 250 ms) covering quota/refresh admission and catalog-lane acquisition. On expiry, return 503 with `Retry-After: 1`; do not consume quota unless the exact quota transaction completed. Keep the catalog lane at eight active reads, but make its queue bounded and deduplicate identical catalog reads by normalized request key, just as refreshes are deduplicated.

Set end-to-end request deadlines (for example 1.5 seconds public, 2 seconds service), cancel pending work on disconnect, and expose counters for rejected-full, rejected-deadline, queue depth, and lane wait time. Validate this only in local/container tests with synchronized 70+10 and abusive 500+20 cases.

Trust identity only from NGINX: bind Uvicorn to loopback, have NGINX overwrite and forward a single client-IP header, and configure the app to honor it only when the peer is loopback. Apply NGINX request/body/header limits and an outer per-IP connection/rate limit, but leave application quota authoritative.

## Anonymization mapping

- Response A: The Expansionist
- Response B: The Contrarian
- Response C: The Outsider
- Response D: The First Principles Thinker
- Response E: The Executor

## Peer review 1

1. Response B is strongest. It best follows the measurements: it bounds every
wait, reserves service capacity, proposes exact micro-batched quota commits,
and correctly rejects same-apex singleflight because distinct-apex latency is
nearly identical and shared 7 MB results create memory risk. Its proxy trust
boundary is also the most complete.

2. Response E has the biggest blind spot. Its 250 ms admission deadline is
below the measured 409 ms catalog wait for the supported burst, so it would
reject legitimate 70+10 traffic. It also uses `429` for queue saturation and
admits 32 public requests into an eight-reader lane without a queue cap.

3. All five miss end-to-end fairness during serialization and response egress.
Reserved catalog slots do not protect service traffic if slow public downloads
hold CPU, memory, Uvicorn connections, or NGINX upstream sockets.

## Peer review 2

1. Response B is strongest. It treats overload as bounded admission, reserves
service capacity with controlled borrowing, preserves exact quota through
ordered commits, uses the correct `429` and `503` meanings, and avoids
premature singleflight.

2. Response E has the biggest blind spot. It returns `429` for queue saturation
and proposes a deadline below the measured supported-burst wait.

3. All five miss the timeout and commit race. A request can time out while a
SQLite operation continues and commits, which can charge quota for a `503`.
They also under-specify response backpressure for slow clients.

## Peer review 3

1. Response B is strongest. It targets the measured bottleneck, preserves exact
quotas, reserves service capacity, uses correct status semantics, and rejects
premature singleflight.

2. Response E has the biggest blind spot. It retains individual serialized
quota admission, sets a combined 250 ms deadline, and calls queue saturation a
`429`.

3. All five miss the deadline and commit race. The design needs explicit rules
for cancellation before transaction selection, the irrevocable commit point,
and disconnects after commit.

## Peer review 4

1. Response B is strongest because every control maps to an observed failure:
bounded class admission, reserved service capacity, bounded quota work, and
explicit rejection.

2. Response A has the biggest blind spot. It raises catalog concurrency to 16
and allows 96 public waiters without evidence that SQLite or memory can sustain
them.

3. All five miss a precise supported-service contract. They need to state which
requests the 70+10 burst must admit, the latency target for each class, and how
quota outcomes behave across timeout, cancellation, and transaction completion.

## Peer review 5

1. Response A is strongest. It specifies class-separated admission, quota
outcomes, catalog singleflight, proxy trust, one worker, and observability in
one implementable design.

2. Response E has the biggest blind spot because it uses `429` for capacity
overload.

3. All five miss the quota rule for a request that passes quota admission but
later fails in the catalog lane. The implementation must preserve and test that
rule.

## Where the Council Agrees

Every advisor requires bounded public and authenticated-service capacity. They
agree that health must bypass expensive work, quota exhaustion must remain
`429`, capacity overload must be explicit, and NGINX must replace untrusted
forwarding headers. No advisor found evidence that justified replacing SQLite.

## Where the Council Clashes

The advisors disagree about group commits, singleflight, and reader count.
Responses A and D add singleflight. Response B rejects it until bounded pages
prove a need. Responses A and B propose quota micro-batching, while Responses C
and E retain the current exact transaction. Catalog recommendations range from
one implied bounded lane to 16 readers.

## Blind Spots the Council Caught

The reviews caught three missing contracts. Limits must cover response egress,
not only database work. A timed-out synchronous thread can still commit quota.
The supported 70+10 burst needs an exact status and latency gate, separate from
the expected rejection behavior above the limit.

## The Recommendation

Use separate total in-flight limits of 80 public and 16 authenticated-service
requests. Count each request until its response completes. Reject excess work
before quota admission with `503`, `Retry-After: 1`, and a class-specific
`X-Overload-Reason`. Keep `429` only for an exhausted exact daily quota.

Keep one catalog worker. The council did not have the later disconfirming
benchmark: 70 direct catalog reads took about 55 ms sequentially and about 379
ms with eight threads. A one-reader experiment reduced synchronized distinct-
apex public p95 from 608 ms to 233 ms without a cache or group commits. That
measurement overrules proposals to add readers, micro-batches, or singleflight.

Bound lane acquisition, but do not abandon a synchronous SQLite operation
after it starts. The existing SQLite busy timeouts bound lock waits. Preserve
the current quota rule: a request consumes quota after the control transaction
commits, even if a later catalog failure prevents delivery. NGINX must overwrite
forwarding headers, and Uvicorn must trust only the exact NGINX socket peer.

## The One Thing to Do First

Change the default catalog concurrency from eight to one, then rerun the
synchronized distinct-apex gate before adding any cache or batch worker.
