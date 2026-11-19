# SOC triage agent

This package implements Elasticsearch alert retrieval, bounded read-only
investigation tools, and a bounded OpenAI Responses API investigation loop. It
does not modify Elastic Security alerts.

## Setup

```bash
cd soc-triage-agent
python3.11 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
cp .env.example .env
```

Set `ELASTIC_API_KEY`, `OPENAI_API_KEY`, and `OPENAI_MODEL`. When TLS uses a
private CA, set `ELASTIC_CA_CERT`. The `.env` file is ignored by Git.
Configuration rejects invalid URLs, index patterns, limits, and log levels.

LLM-related settings are:

* `PROMPT_INSPECTION_MODE`: `off`, `log`, or interactive `pause`.
* `LOG_LLM_REQUESTS`, `LOG_LLM_RESPONSES`, `LOG_TOOL_CALLS`,
  `LOG_TOOL_RESULTS`, and `LOG_TRIAGE_RESULTS`.
* `MAX_TOOL_CALLS` and `MAX_MODEL_REQUESTS` bound each investigation.
* `MAX_ALERT_FIELD_TEXT_LENGTH` and `MAX_ALERT_EVIDENCE_FIELDS` bound generic
  ECS and custom field evidence included in the initial alert context.

Prompt logging shows the sanitized payload passed to the SDK. `pause` requires
a TTY and prints the exact payload passed to the SDK before every model
request, including follow-ups. Log output redacts API keys, authorization
values, cookies, passwords, tokens, and secrets.

## Commands

```bash
.venv/bin/python -m src.main check
.venv/bin/python -m src.main investigate --alert-id <ALERT_ID>
.venv/bin/python -m src.main triage --alert-id <ALERT_ID>
```

`investigate` only retrieves and normalizes an alert, so it does not spend
OpenAI credits. `triage` sends a compact alert context to the configured
model: alert identity, rule details, timestamp, severity, source IP, bounded
detection evidence, and normalized telemetry provenance when available
(`event.dataset`, `data_stream.dataset`, and originating alert index). It does
not send the original alert document, Elastic rule documentation, or full
detection queries. The model is instructed to start with known originating
telemetry while retaining the ability to select other authorized datasets for
correlation.
The model may request only `discover_fields` and `search_elasticsearch`;
Python validates each request, executes a bounded query, and sends the bounded
result back in a follow-up Responses API call using the Responses conversation
state and matching function-call IDs. Arbitrary Elasticsearch DSL and shell
execution are not available; generic Query DSL is accepted only through the
validated read-only search tool.

For general investigations the model can use `discover_fields` followed by
`search_elasticsearch`. Field discovery accepts prefixes or wildcard patterns,
excludes internal metadata fields by default, preserves conflicting mappings as
separate compact table rows, supports continuation with `after_field`, and
caches field capabilities for the investigation. Field count and serialized
byte limits are enforced, with total, returned, omitted, and continuation
metadata reported accurately. The latter accepts read-only Query DSL, selected
source fields, sorting, and aggregations; Python validates allowed indices,
rejects unsafe/resource-intensive features, applies the Elasticsearch timeout,
and bounds the serialized result with `MAX_TOOL_RESULT_BYTES`.

SIEM tool results are normalized before they reach the model. Retrieved
documents use compact `columns` and `rows` tables, with repeated values moved
to optional `common_fields`; aggregations remain server-side and are returned
in compact form. Retrieval uses source filtering and bounded limits, and each
result declares sampled or omitted information. Full Elasticsearch documents
remain unchanged in Elasticsearch.

The final model assessment is validated with Pydantic and application code
derives `ESCALATE` or `CLOSE`. Failures and exhausted budgets safely become
`uncertain`/`ESCALATE` with `execution_status=failed`; only a parsed final
assessment is marked `execution_status=completed`. The configured request and
tool budgets prevent unbounded API usage.

The `check` command performs a zero-result `match_all` search against
`ELASTIC_ALERT_INDEX`, so the API key only needs read access to that index; it
does not call the cluster-level `ping` endpoint. Authentication (401),
authorization (403), and connection/TLS failures are reported separately.

The initial homelab validation used the fuzzing alert and matched a manual
Elasticsearch query: 623 requests, 615 unique URLs, and status counts of
404=600, 200=18, and 302=5. Actual LLM usage incurs model token and API costs,
so use `investigate`, mocked tests, or `PROMPT_INSPECTION_MODE=pause` before
experiments.

## Investigation tools

The generic search tool accepts caller-supplied read-only Query DSL only after
validation, and restricts searches to the configured telemetry or Elastic
Security alert indices. It preserves explicit source filtering, bounded result
sizes, result-byte limits, and observability.
Concrete index names matching a configured wildcard pattern are authorized;
other index expressions are rejected with the permitted patterns listed.

Run tests with:

```bash
.venv/bin/python -m pytest -q
```
