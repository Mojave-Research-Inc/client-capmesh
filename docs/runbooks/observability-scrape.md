# Observability Scrape Runbook (CM-13)

Entity: ASI | Scope: Multi | [INTERNAL] | [DRAFT — REQUIRES HUMAN REVIEW — v2026-07-27]

Operational runbook for the CM-13 observability surface wired into the
asg-capmesh server: the `GET /metrics` Prometheus scrape endpoint, the
`capmesh_<gate>.<outcome>` gate counters, and the single-line structured JSON
log lines emitted by the gate runner, HTTP handler, and router. This is the
contract an on-call operator needs to scrape, alert, and correlate — nothing
more.

## 1. Scraping `/metrics`

The scrape endpoint is live in `capmesh/server.py` (`do_GET`, `parsed.path ==
"/metrics"`). It is a **public, read-only Prometheus scrape endpoint**: no
service token (`CAPMESH_BEARER_TOKEN`), no `CAPMESH_METRICS_TOKEN`, no proxy
token, and no mutating-route gate is required. The `/metrics` branch is
evaluated *before* the `if not self.authorized(token)` check, so a Prometheus
scraper that sends no bearer is accepted. It is a `GET` only; the mutating
gate (`mutating_route_authorized`) applies to `POST`/`PATCH`/`PUT`/`DELETE`.

| Property      | Value                                            |
|---------------|--------------------------------------------------|
| Path          | `/metrics`                                       |
| Method        | `GET`                                            |
| Content-Type  | `text/plain; version=0.0.4`                      |
| Auth          | None (public read-only scrape)                   |
| Body (empty)  | `""` (HTTP 200)                                  |
| Body (error)  | `capmesh_metrics_render_failed 1\n` (HTTP 500)    |

The body is produced by `render_metrics_endpoint()` in `server.py`, which
calls `render_prometheus(GATE_METRICS)` from `capmesh/metrics_export.py` on
the module-level `GATE_METRICS` registry from `capmesh/lifecycle.py`. An
empty registry renders `""` (no lines) with HTTP 200. A rendering exception
is swallowed and a minimal `capmesh_metrics_render_failed 1\n` body is
returned with HTTP 500 so a scrape never crashes the server.

Example scrape:

```bash
curl -sS http://127.0.0.1:8181/metrics
```

Example output (a few `capmesh_gate_*` lines after at least one gate run):

```
# HELP capmesh_gate_sourceIntegrity_passed capmesh counter
# TYPE capmesh_gate_sourceIntegrity_passed counter
capmesh_gate_sourceIntegrity_passed 3
# HELP capmesh_gate_signature_passed capmesh counter
# TYPE capmesh_gate_signature_passed counter
capmesh_gate_signature_passed 3
# HELP capmesh_gate_provenance_skipped capmesh counter
# TYPE capmesh_gate_provenance_skipped counter
capmesh_gate_provenance_skipped 2
```

Each counter is emitted as a three-line Prometheus exposition block
(`# HELP`, `# TYPE`, one sample line) by `render_counter()`. Blocks are
newline-separated and the body ends with a single trailing newline. An empty
registry (no gate run yet in this process) returns `""` with HTTP 200 — that
is expected, not a bug.

Note: this `/metrics` endpoint renders **only** the gate-runner registry
(`GATE_METRICS`). The worker-level counters (`requests_total`,
`errors_total`, `router_errors_total`, `capmesh_uptime_seconds`,
`capmesh_catalog_*` gauges) are rendered by a separate
`prometheus_metrics_payload()` path used elsewhere and are not part of the
`/metrics` gate scrape surface.

## 2. Metric taxonomy

Counter names are produced in `capmesh/lifecycle.py` as
`f"gate.{_gate_name}.{_gate_outcome}"` and then normalized by
`sanitize_metric_name()` in `capmesh/metrics_export.py` for export. The
outcome (gate state) is one of `passed`, `failed`, or `skipped` (see
`GateDecision` in `capmesh/observability.py`); `unknown` is used as a
defensive fallback when the state field is missing.

`sanitize_metric_name(name)` is deterministic and idempotent:

1. Every character outside `[a-zA-Z0-9_:]` becomes `_`, so dots collapse to
   underscores: `gate.sourceIntegrity.passed` →
   `gate_sourceIntegrity_passed`.
2. If the result does not already start with `METRIC_PREFIX` (`capmesh_`) or
   `_`, prepend `capmesh_`. A name that already carries the prefix is not
   prefixed again (idempotent).
3. As a final guard, if the result would still start with a digit, prepend
   `capmesh_` once more (a Prometheus metric name must begin with a letter or
   underscore).

So the in-memory counter `gate.sourceIntegrity.passed` is exported as
`capmesh_gate_sourceIntegrity_passed`. The exported counter scheme is
`capmesh_<gate>.<outcome>` where `<outcome>` ∈ {`passed`, `failed`,
`skipped`}.

The seven gate counters (one per gate in `REQUIRED_GATES`, in declaration
order):

| Counter (in-memory)                          | Exported metric name                                  |
|----------------------------------------------|-------------------------------------------------------|
| `gate.sourceIntegrity.passed`                 | `capmesh_gate_sourceIntegrity_passed`                  |
| `gate.tests.passed`                           | `capmesh_gate_tests_passed`                            |
| `gate.retrievalEvals.passed`                  | `capmesh_gate_retrievalEvals_passed`                   |
| `gate.signature.passed`                      | `capmesh_gate_signature_passed`                        |
| `gate.provenance.passed`                      | `capmesh_gate_provenance_passed`                       |
| `gate.promptInjectionScan.passed`             | `capmesh_gate_promptInjectionScan_passed`              |
| `gate.riskTierPolicy.passed`                  | `capmesh_gate_riskTierPolicy_passed`                   |

Each of the seven gates also emits a `..._failed` and (for `provenance`) a
`..._skipped` counter on those outcomes. The full set of observable counters
is therefore `capmesh_gate_{sourceIntegrity,tests,retrievalEvals,signature,
provenance,promptInjectionScan,riskTierPolicy}_{passed,failed,skipped}`,
populated lazily as each outcome occurs (counters are created on first
`increment` and never removed).

Structured-logging counters from the server and router are **not** registered
in `GATE_METRICS` and do not appear on `/metrics`. The HTTP handler and
router emit log lines only (see section 3); they do not currently increment
`GATE_METRICS`. `MetricsRegistry` exposes `.increment(name, by=1)`,
`.get(name)`, and `.snapshot()` (sorted-by-name dict) for ops/test access.

## 3. Structured log schema

`log_event(logger, event_type, **fields)` in `capmesh/observability.py` emits
one structured line via `logger.info`:

```
capmesh.<event_type> <json>
```

where `<json>` is `json.dumps(redact(fields), sort_keys=True,
separators=(",", ":"))` — a single-line, compact JSON payload with sorted
keys. If a value is not JSON-serializable, the call retries with
`default=str` so the value is stringified rather than crashing the caller.
Control characters in string values are escaped by `json.dumps`, so the
payload never contains embedded newlines.

Documented event types and their fields:

| Event type     | Emitted by                          | Fields (sorted)                                                              |
|----------------|-------------------------------------|------------------------------------------------------------------------------|
| `gate.eval`    | `capmesh/lifecycle.py` `review_capability` | `capabilityUri`, `gateName`, `outcome`, `requestId`, `reason`                |
| `http.request` | `capmesh/server.py` `do_GET`/`do_POST`    | `method`, `path`, `request_id`                                               |
| `request`      | `capmesh/router.py` `CapabilityRouter.call` | `request_id`, `subject`, `tenant`, `tool`, `verb`                            |

Field-name detail (grounded in source):

- `gate.eval` (from `format_gate_decision(GateDecision(...))`): `gateName`,
  `capabilityUri`, `outcome` (`passed`/`failed`/`skipped`), `requestId`
  (currently always `None` — see section 5), `reason` (the gate evidence
  `code`, e.g. `source_hash_verified`).
- `http.request`: `request_id` (from `_http_request_id()`, may be `""`),
  `method` (`GET`/`POST`), `path` (parsed path component only).
- `request`: `request_id` (the router `rid`), `verb` (the cap verb, e.g.
  `search`), `subject` (principal subject), `tenant` (principal tenant id),
  `tool` (e.g. `cap.search`).

These log lines are **best-effort**. Every call site is wrapped in
`try: ... except Exception: pass` (see section 7), so a logging failure never
breaks the gate runner or the request path. A misconfigured logger does not
take down promotion or dispatch.

Loggers used: `capmesh.lifecycle`, `capmesh.server`, `capmesh.router` (see
`_OBS_LOGGER` in each module). Configure handlers at the process level to
capture these; the library does not configure handlers itself.

## 4. Request-ID correlation

The correlation chain is:

```
X-Request-Id / X-Correlation-Id (HTTP header)
  -> Handler._http_request_id()        (server.py)
  -> router.call(request_id=...)       (server.py -> router.py)
  -> CapabilityRouter.call rid        (router.py: rid = request_id or uuid.uuid4().hex)
  -> "request" log line field request_id
```

`_http_request_id()` returns `(X-Request-Id or X-Correlation-Id or "").strip()`.
The empty string is passed through; `CapabilityRouter.call` generates a fresh
`uuid.uuid4().hex` for any falsy/empty value (`rid = request_id or
uuid.uuid4().hex`), so every dispatch is traceable even without an upstream
header. The same `rid` is logged in the `request` event.

The HTTP response also carries an `X-Request-Id` response header
(`_send_common_headers` → `self.request_id()`), which echoes a valid
incoming header or synthesizes `req_<hex_ts>_<thread_id>` — note the
synthesized response header id is **not** the same as the router `rid`
(see `_http_request_id` docstring). To follow one request across logs,
filter on the `request_id` value you sent in `X-Request-Id`.

Known gap: `gate.eval` events currently hardcode `request_id=None` in
`review_capability` (lifecycle.py), so the `requestId` field in `gate.eval`
lines is always `null` today — gate-eval events are correlated to a
capability URI and reason, not to an HTTP request id. The router `request`
event does carry the `rid`. Operators correlating a promotion run to an HTTP
request should correlate on `capabilityUri`/`reason` until the gate runner is
threaded with the request id.

How to follow one request:

```bash
# 1. Send a request with a known id.
curl -H 'X-Request-Id: op-debug-001' http://127.0.0.1:8181/mcp ...

# 2. Find the HTTP line, then the router dispatch line, by that id.
grep 'op-debug-001' /var/log/capmesh/server.log
# capmesh.http.request {"method":"POST","path":"/mcp","request_id":"op-debug-001"}
# capmesh.request {"request_id":"op-debug-001","subject":"...","tenant":"asg","tool":"cap.search","verb":"search"}
```

## 5. Redaction guarantees

`redact(fields, sensitive_keys=SENSITIVE_KEYS)` masks sensitive values in
**every** structured log line — `log_event` always calls `redact` before
serializing. Matching is case-insensitive (keys are lowercased before
comparison) and any key whose lowercased form is in `SENSITIVE_KEYS` has its
value replaced by the literal string `"[REDACTED]"`.

`SENSITIVE_KEYS` (from `capmesh/observability.py`):

- `token`
- `secret`
- `password`
- `api_key`
- `authorization`
- `cookie`

Redaction is **shallow**. `redact` returns a shallow copy of `fields`;
values are copied by reference, not deep-copied, and nested dict values are
**not** recursed. A secret placed under a nested key (e.g.
`{"headers": {"authorization": "Bearer ...}}`) will **not** be masked
because the top-level key `headers` is not sensitive. Operators and callers
must not place secrets in nested fields expecting redaction — keep sensitive
material at the top level under one of the listed key names. Non-string keys
never match `SENSITIVE_KEYS` (they are lowercased-string-compared) and pass
through unchanged.

## 6. Best-effort contract

Observability is best-effort and never breaks the gate runner or request
handling. Concretely, in the source:

- `capmesh/lifecycle.py` `review_capability`: each `log_event(...)` and each
  `GATE_METRICS.increment(...)` call is wrapped in its own
  `try: ... except Exception: pass` (the comment above states "a logging or
  metric failure is swallowed and never breaks the gate runner").
- `capmesh/server.py` `do_GET`/`do_POST`: the `log_event("http.request", ...)`
  call is wrapped in `try: ... except Exception: pass` ("Failure here must
  never break request handling or change status").
- `capmesh/router.py` `CapabilityRouter.call`: the `log_event("request", ...)`
  call is wrapped in `try: ... except Exception: pass`.
- `capmesh/server.py` `render_metrics_endpoint()`: any rendering exception is
  swallowed and a `capmesh_metrics_render_failed 1\n` body with HTTP 500 is
  returned instead of raising.

Operational implication: a metrics outage (registry corruption, rendering
bug, logger misconfiguration) does **not** take down promotion or dispatch.
Gate evaluation, approval, and the request path continue to work even if
`/metrics` returns 500 or the structured logger is broken. Conversely, a
silent loss of metrics/logs is not a signal of a gate-runner outage — verify
the gate runner independently (e.g. `/health/ready` `gateRunner` check,
which is itself a WARNING excluded from the readiness aggregate).

## 7. Operational checklist

1. **Verify `/metrics` is up.**

   ```bash
   curl -sS -o /tmp/metrics.txt -w '%{http_code} %{content_type}\n' \
     http://127.0.0.1:8181/metrics
   # Expect: 200 text/plain; version=0.0.4
   wc -c /tmp/metrics.txt   # 0 is fine before any gate has run
   ```

   An empty body (`Content-Length: 0`) with HTTP 200 means the registry is
   empty — no gate has run in this process yet. Run a review/promotion and
   scrape again.

2. **Check gate counts.**

   ```bash
   # All gate counters currently exported, with values.
   grep '^capmesh_gate_' /tmp/metrics.txt
   # A specific gate's pass/fail/skipped counts.
   grep '^capmesh_gate_signature_' /tmp/metrics.txt
   ```

   Counters appear lazily — a counter that has never incremented is absent
   from the output. `capmesh_gate_provenance_skipped` is expected for
   capabilities with no git source commit (`source_commit="unknown"`); see
   `_provenance_gate` in `lifecycle.py`.

3. **Grep logs for a request_id.**

   ```bash
   grep 'op-debug-001' /var/log/capmesh/server.log
   # Should show capmesh.http.request and capmesh.request lines.
   # gate.eval lines will NOT carry this id today (requestId is null).
   ```

   To correlate a gate run to a capability, grep by `capabilityUri`:

   ```bash
   grep 'gate.eval' /var/log/capmesh/server.log | grep '<capability-uri>'
   ```

4. **Confirm redaction is working.**

   Send a request whose arguments would otherwise carry a sensitive key at the
   top level (e.g. a tool call with `token` in arguments) and verify the log
   line masks it:

   ```bash
   grep 'capmesh.request' /var/log/capmesh/server.log | grep -o '"token":"[^"]*"'
   # Expect: "token":"[REDACTED]"
   ```

   Then confirm a **nested** sensitive value is NOT redacted (shallow
   redaction contract): if `{"headers":{"authorization":"Bearer x"}}` is
   logged, the `Bearer x` value is present because the top-level key
   `headers` is not sensitive. This is expected behavior, not a bug.

5. **Confirm a metrics outage does not break promotion.** Force a render
   failure (e.g. by patching `render_prometheus` to raise in a test) and
   verify `/metrics` returns HTTP 500 with body
   `capmesh_metrics_render_failed 1\n` while `POST /api/v1/approve` and
   `POST /mcp` continue to succeed. (This is a test-only verification; the
   production path swallows the exception.)

## 8. OTel trace foundation (CM-13-full)

CM-13-full adds OpenTelemetry-style distributed trace spans on top of the
structured-logging + Prometheus-metrics surface in sections 1–7. The
**foundation modules and the gate-runner span emission are landed and
tested on disk**; the HTTP traceparent propagation and the OTLP exporter
resource-envelope/flush are in-flight wiring (see the "In flight" note at
the end of this section). This section documents only what is on disk
today so an operator is not misled about what is already observable.

### Span model — `capmesh/tracing.py`

A pure-stdlib in-process tracer (no `opentelemetry` dependency). `Tracer`
produces `Span` objects; each span carries a `SpanContext`
(`trace_id`/`span_id`/`trace_flags`/`trace_state`). IDs are 32-hex (trace)
and 16-hex (span) from `os.urandom`. W3C traceparent round-trips via
`format_traceparent(ctx)` / `parse_traceparent(s)` (strict version `"00"`).
`Span.set_attribute`, `Span.add_event`, `Span.set_status`, and `Span.end`
are idempotent; `Span.end` is a no-op if called twice and records
`duration_ns`. `Tracer.ended_spans()` returns the list of ended spans for
test/flush access. Verified by `tests/test_tracing.py` (8 tests).

### Gate-runner span emission — `capmesh/lifecycle.py`

`review_capability` (the per-gate loop) emits **one OTel span per
evaluated gate** via the module-level `TRACER = Tracer()` (`lifecycle.py:39`):

- span name: `gate.<gateName>` (e.g. `gate.sourceIntegrity`)
- attributes: `gate.name`, `gate.outcome`, `capability.uri` (and
  `gate.reason` when a reason is present)
- status: `ok` for `passed`, `error` for `failed`, `unset` otherwise
- `start_time_ns`/end are taken from the gate result's `startedAtNs`/
  `endedAtNs` when present

The entire span block is wrapped in `try: ... except Exception: pass`
(the same best-effort contract as the `gate.eval` log + `GATE_METRICS`
counter in section 6), so a tracing failure never breaks the gate runner.
Locked by `tests/test_lifecycle_span_emission.py` (6 tests): the span
count grows per gate, the span name matches `gate.<one of the 7 gates>`,
attributes are set, `passed→ok` / `failed→error`, and patching
`TRACER.start_span` to raise does **not** propagate out of
`review_capability`.

### OTLP/HTTP export — `capmesh/otlp_exporter.py`

`OtlpExporter(endpoint, timeout).export(spans) -> bool` encodes spans to
the OTLP/JSON `resourceSpans` envelope and POSTs to the OTLP/HTTP traces
endpoint (default `http://127.0.0.1:4318/v1/traces`) via `urllib.request`.
`export` **never raises** — `URLError` and broad `Exception` are caught
and it returns `False`. `_value_to_otlp` emits booleans before ints
(OTLP `AnyValue` is oneof). `span_to_otlp` omits `parentSpanId` when the
span has no parent. Verified by `tests/test_otlp_exporter.py` (7 tests).

### OTel Resource — `capmesh/otel_resource.py`

`create_resource()` builds the OTel `Resource` (service.name etc.) from
defaults < explicit args < `OTEL_RESOURCE_ATTRIBUTES` <
`OTEL_SERVICE_NAME`. `Resource.to_otlp_attributes()` returns the sorted
attribute list for the `resourceSpans.resource.attributes` envelope.
`EMPTY_RESOURCE` is the zero-attribute resource. Verified by
`tests/test_otel_resource.py` (9 tests).

### Landed (verified on disk 2026-07-27)

- **OTLP Resource envelope + tracer flush** (`capmesh/otlp_exporter.py`):
  `encode_batch(spans, resource=None)` fills
  `resourceSpans[0].resource.attributes` via
  `resource.to_otlp_attributes()`; the no-resource-arg default is
  `EMPTY_RESOURCE` (empty attributes — backward-compatible). A
  module-level `DEFAULT_RESOURCE = create_resource()` carries the
  service identity. `OtlpExporter.export(spans, resource=None)` threads
  the resource (default `DEFAULT_RESOURCE`) through `encode_batch`.
  `OtlpExporter.flush_tracer(tracer) -> bool` sends a `Tracer`'s
  `ended_spans()` in one batch — `True` without network when the tracer
  is empty, otherwise the `export` result, and never raises. Verified by
  `tests/test_otlp_exporter.py` (14 tests: 7 original + 7 new); ruff
  clean; no runtime import cycle (`otel_resource` is stdlib-only,
  `.tracing` stays under `TYPE_CHECKING`).

### Landed (verified on disk 2026-07-27)

- **HTTP traceparent propagation** (`server.py` + `router.py`): the
  HTTP handler parses an inbound `traceparent` header
  (`_inbound_trace_context()`), threads the raw header into all three
  `router.call` sites (`/cap/search`, `/mcp` via `handle_jsonrpc`,
  `/tools/call`+`/cap/call`), and echoes a `traceparent` response header
  on every response (inbound context when present, else a freshly
  synthesized `SpanContext`). `CapabilityRouter.call(..., traceparent=…,
  start_time_ns=…)` parses the inbound header as the parent context and
  starts a `"request"` span as its child (attributes `verb`/`subject`/
  `tenant`/`tool`/`request_id`), setting `ok`/`error` status and ending
  the span in a `finally`. Best-effort throughout; no status code or
  return value changed. Verified by
  `tests/test_request_span_wiring.py` (9 tests) + the existing
  server/router/metrics/readiness suites.

- **In-process e2e trace export** (`lifecycle.TRACER` →
  `OtlpExporter.flush_tracer` → OTLP/HTTP POST): driving
  `review_capability` populates gate spans in `lifecycle.TRACER`;
  `flush_tracer` encodes them as an OTLP `resourceSpans` envelope
  carrying `DEFAULT_RESOURCE` and POSTs it to the OTLP endpoint.
  Verified by `tests/test_trace_export_integration.py` (5 tests):
  gate spans flushed with `service.name=capmesh` resource attrs;
  empty tracer → `True` without network; `URLError` → `False` never
  raises; passing-cap span `status=OK`, failed-source span
  `status=ERROR`.

- **Traceparent + parent-child span contract**: W3C traceparent
  round-trip, parse rejections (version/length/hex/case),
  `Tracer.start_span` parent-context/parent-span-id semantics, and
  `encode_batch` `parentSpanId` omission-when-None / preservation-when-set.
  Verified by `tests/test_traceparent_propagation_contract.py` (11
  tests).

### Architectural note (honest)

The HTTP `request` span is a child of the inbound trace, but the
gate-runner spans emitted by `lifecycle.review_capability` are
**independent root spans** today — each gets a fresh `trace_id` —
because `review_capability` calls the module-level `TRACER.start_span`
with no `parent_context`. Linking gate spans into the request trace
would require threading the request span's `SpanContext` into
`review_capability` (a future lifecycle wiring, deliberately out of
this slice). The two export paths are therefore independent today:
the HTTP `request` span exports via the router's `REQUEST_TRACER`, and
the gate spans export via `lifecycle.TRACER` through `flush_tracer` —
both carrying the `DEFAULT_RESOURCE` envelope.

## Source references

- `capmesh/observability.py` — `SENSITIVE_KEYS`, `redact`, `log_event`,
  `GateDecision`, `format_gate_decision`, `MetricsRegistry`.
- `capmesh/metrics_export.py` — `METRIC_PREFIX`, `sanitize_metric_name`,
  `render_counter`, `render_prometheus`.
- `capmesh/tracing.py` — `Tracer`, `Span`, `SpanContext`,
  `format_traceparent`, `parse_traceparent`, `generate_trace_id`,
  `generate_span_id` (CM-13-full foundation).
- `capmesh/otlp_exporter.py` — `OtlpExporter`, `encode_batch`,
  `span_to_otlp`, `_value_to_otlp` (CM-13-full foundation).
- `capmesh/otel_resource.py` — `Resource`, `create_resource`,
  `EMPTY_RESOURCE`, `to_otlp_attributes` (CM-13-full foundation).
- `capmesh/lifecycle.py` — `GATE_METRICS` (module-level), `TRACER`
  (module-level), `REQUIRED_GATES`, `review_capability` gate.eval logging,
  counter increments, and gate-span emission.
- `capmesh/server.py` — `/metrics` GET handler, `render_metrics_endpoint`,
  `_http_request_id`, `do_GET`/`do_POST` `http.request` logging.
- `capmesh/router.py` — `CapabilityRouter.call` `request` logging and
  `request_id` resolution.
