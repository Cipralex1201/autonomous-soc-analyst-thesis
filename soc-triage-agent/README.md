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
For statistical questions, the model is encouraged to use aggregations with
`size=0`; when representative documents are useful, it should prefer a small
bounded sample. Larger raw-event retrieval should answer a concrete question
that aggregations cannot resolve, without restricting the model's choice of
investigation criteria.

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
derives `ESCALATE` or `CLOSE`. The final configured model request is reserved
for a no-tools assessment when investigation reaches a budget, producing a
provisional `execution_status=partial` report with collected tool results and
human-review guidance. Normal validated assessments are `completed`; technical
failures are `failed` while preserving any collected evidence and errors.
Configured request and tool budgets prevent unbounded API usage.

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

## Structured investigation tracing

Set `INVESTIGATION_TRACING_ENABLED=true` to write one JSONL record per line to
`logs/investigations/<investigation_id>.jsonl` (or
`INVESTIGATION_TRACE_DIRECTORY`). Tracing is independent of console logging and
prompt-inspection mode. Every rerun gets a new UUID, while the alert ID remains
the correlation key.

Each JSONL file contains chronological `investigation.started`, `llm.request`,
`llm.response`, `tool.called`, `tool.completed` or `tool.failed`, and final
investigation events. Requests include exact Responses API parameters,
including `previous_response_id`; responses retain output items, function-call
arguments, response metadata, usage, and latency without duplicating the full
SDK response or storing opaque `encrypted_content` reasoning payloads. Tool
events retain original and validated arguments, the actual bounded Elasticsearch
request, compact results, errors, and final verdicts. API keys and authorization
values are never included in trace configuration.

Elasticsearch persistence uses `soc-triage-traces-v1` for events and
`soc-triage-results-v1` for one final document per investigation. The writer
uses an explicit `ELASTIC_WRITER_API_KEY` when configured; otherwise it falls
back to `ELASTIC_API_KEY`. Trace document IDs are
`<investigation_id>:<sequence>` and result IDs are `<investigation_id>`, making
retries idempotent. Elasticsearch failures are logged but do not invalidate or
erase the local JSONL archive.

Create a writer API key with these privileges:

* `manage` on `soc-triage-traces-v1` so existing trace indices can receive
  additive searchable-field mappings
* `create_index`, `create_doc`, and `index` or `all` on those two indices
* no read or write access to alert or telemetry indices is needed beyond the
  existing read credential

Trace mapping updates add explicitly typed root-level metric fields to the
existing versioned index; they do not delete, reindex, or replace existing
investigation records. Nested Query DSL and result content remain disabled for
dynamic indexing.

In Kibana Stack Management, create data views named
`SOC triage traces` for `soc-triage-traces-v1` and `SOC triage results` for
`soc-triage-results-v1`, using `@timestamp` as the time field. Restrict the
data-view role to these indices and use Discover.

```esql
FROM soc-triage-traces-v1
| WHERE investigation_id == "<INVESTIGATION_ID>"
| SORT sequence ASC
| KEEP @timestamp, sequence, event_type, call_id, response_id, tool, status, duration_seconds
```

```esql
FROM soc-triage-traces-v1
| WHERE alert_id == "<ALERT_ID>"
| SORT investigation_id ASC, sequence ASC
| KEEP investigation_id, sequence, @timestamp, event_type, model_request_number
```

```esql
FROM soc-triage-traces-v1
| WHERE event_type == "tool.failed"
| KEEP @timestamp, investigation_id, alert_id, call_id, tool_call_number,
    tool_name, tool_status, failure_category, error
| SORT @timestamp DESC
```

Compare request tokens and latency by investigation:

```esql
FROM soc-triage-traces-v1
| WHERE event_type == "llm.response"
| STATS requests = COUNT(*), input_tokens = SUM(input_tokens),
    output_tokens = SUM(output_tokens), cached_tokens = SUM(cached_input_tokens),
    reasoning_tokens = SUM(reasoning_output_tokens),
    avg_latency_seconds = AVG(api_latency_seconds) BY investigation_id
| SORT avg_latency_seconds DESC
```

Compare search result efficiency and truncation:

```esql
FROM soc-triage-traces-v1
| WHERE event_type == "tool.completed" AND tool_name == "search_elasticsearch"
| STATS searches = COUNT(*), matched_hits = SUM(total_hits),
    returned_hits = SUM(returned_hits), result_bytes = SUM(result_size_bytes),
    truncated_searches = COUNT_IF(truncated), sampled_searches = COUNT_IF(sampled)
    BY investigation_id
| SORT result_bytes DESC
```

```esql
FROM soc-triage-results-v1
| WHERE experiment_id == "<EXPERIMENT_ID>"
| KEEP investigation_id, alert_id, assessment, severity, confidence, model_request_count,
    tool_call_count, processing_duration_seconds, token_usage
| SORT processing_duration_seconds ASC
```
