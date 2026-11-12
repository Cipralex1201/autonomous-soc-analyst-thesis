# SOC triage agent

This package currently implements Milestones 1 and 2: Elasticsearch connectivity,
alert normalization, and bounded read-only investigation tools. It does not modify
Elastic Security alerts and does not yet include the OpenAI orchestration loop.

## Setup

```bash
cd soc-triage-agent
python3.11 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
cp .env.example .env
```

Set `ELASTIC_API_KEY` (or use the configured Elasticsearch authentication) and,
when TLS uses a private CA, set `ELASTIC_CA_CERT`. The `.env` file is ignored by
Git. Configuration rejects invalid URLs, index patterns, limits, and log levels.

## Commands

```bash
.venv/bin/python -m src.main check
.venv/bin/python -m src.main investigate --alert-id <ALERT_ID>
```

The manual command retrieves an alert by ID regardless of its age and prints a
normalized, JSON-safe context. It does not alter any polling state.

The tools `get_source_activity`, `get_http_statistics`, and `get_related_alerts`
use explicit time ranges, exact IP filters, configured index patterns, bounded
result sizes, and no caller-supplied Elasticsearch DSL. HTTP statistics returns
the aggregations supplied by Elasticsearch; aggregation field mappings can be
extended when the telemetry schema is confirmed.

Run tests with:

```bash
.venv/bin/python -m pytest -q
```
