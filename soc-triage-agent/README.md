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
model: alert identity, rule details, timestamp, severity, source IP, and
bounded detection evidence. It does not send the original alert document,
Elastic rule documentation, or full detection queries.
The model may request `get_source_activity`, `get_http_statistics`, or
`get_related_alerts`; Python validates each request, executes a bounded query,
and sends the bounded result back in a follow-up Responses API call using the
Responses conversation state and matching function-call IDs. Query windows are
limited by `MAX_QUERY_WINDOW_MINUTES`; rejected arguments are returned to the
model so it can retry within that limit. Arbitrary Elasticsearch DSL and shell
execution are not available.

SIEM tool results are normalized before they reach the model. Telemetry uses
common ECS fields plus bounded detection-specific evidence; HTTP statistics
contain counts, top paths, status/user-agent distributions, and time buckets;
related alerts contain identifiers, rule names, timestamps, severities, and
key evidence only. Retrieval uses source filtering and deterministic limits,
and each result declares sampled or omitted information. Full Elasticsearch
documents remain unchanged in Elasticsearch.

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

The tools use explicit time ranges, exact IP filters, configured index
patterns, bounded result sizes, and no caller-supplied Elasticsearch DSL.
HTTP statistics aggregates `url.original`, `http.response.status_code`,
`user_agent.original`, and request counts over time. Missing optional alert
fields remain optional.

Run tests with:

```bash
.venv/bin/python -m pytest -q
```
