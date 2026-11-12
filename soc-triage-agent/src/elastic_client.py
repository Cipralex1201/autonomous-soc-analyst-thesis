"""Small, explicit Elasticsearch adapter used by the first milestones."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from elasticsearch import Elasticsearch
from elastic_transport import ApiError, TransportError

from .config import Settings
from .schemas import AlertContext


def _nested(source: Mapping[str, Any], *path: str) -> Any:
    value: Any = source
    for key in path:
        if not isinstance(value, Mapping):
            return None
        value = value.get(key)
    return value


def _field(source: Mapping[str, Any], *path: str) -> Any:
    """Read ECS fields whether Elasticsearch returned dotted or nested keys."""
    dotted = ".".join(path)
    if dotted in source:
        return source[dotted]
    return _nested(source, *path)


class ElasticClient:
    """Authorized access to alerts and read-only telemetry queries."""

    def __init__(self, settings: Settings, client: Elasticsearch | None = None) -> None:
        self.settings = settings
        self.client = client or self._build_client(settings)

    @staticmethod
    def _build_client(settings: Settings) -> Elasticsearch:
        kwargs: dict[str, Any] = {"hosts": [settings.elastic_url]}
        if settings.elastic_api_key:
            kwargs["api_key"] = settings.elastic_api_key
        if settings.elastic_ca_cert:
            kwargs["ca_certs"] = settings.elastic_ca_cert
        return Elasticsearch(**kwargs)

    def check_read_access(self) -> None:
        """Validate read access without requiring cluster-level privileges."""
        try:
            self.client.search(
                index=self.settings.elastic_alert_index,
                query={"match_all": {}},
                size=0,
                track_total_hits=False,
            )
        except ApiError as exc:
            status = exc.meta.status
            if status == 401:
                raise ElasticAccessError("authentication", "Elasticsearch authentication failed (HTTP 401)") from exc
            if status == 403:
                raise ElasticAccessError("authorization", "Elasticsearch alert-index access denied (HTTP 403)") from exc
            raise ElasticAccessError("elasticsearch", f"Elasticsearch returned HTTP {status}") from exc
        except TransportError as exc:
            raise ElasticAccessError("connection", f"Elasticsearch connection/TLS failure: {exc}") from exc

    def get_alert(self, alert_id: str) -> AlertContext:
        response = self.client.get(index=self.settings.elastic_alert_index, id=alert_id)
        return self.normalize_alert(response.get("_id", alert_id), response.get("_source", {}))

    def search_alerts(self, *, query: Mapping[str, Any], size: int = 100) -> list[AlertContext]:
        response = self.client.search(
            index=self.settings.elastic_alert_index,
            query=dict(query),
            sort=[{"kibana.alert.original_time": "asc"}, {"_id": "asc"}],
            size=min(size, 1000),
        )
        return [
            self.normalize_alert(hit.get("_id", ""), hit.get("_source", {}))
            for hit in response.get("hits", {}).get("hits", [])
        ]

    @staticmethod
    def normalize_alert(alert_id: str, source: Mapping[str, Any]) -> AlertContext:
        """Normalize optional Elastic alert fields without assuming an HTTP schema."""
        event_ids = source.get("event", {}).get("id", []) if isinstance(source.get("event"), Mapping) else []
        if isinstance(event_ids, str):
            event_ids = [event_ids]
        return AlertContext(
            alert_id=alert_id,
            rule_name=_field(source, "kibana", "alert", "rule", "name")
            or _field(source, "kibana", "alert", "rule", "rule_name"),
            rule_description=_field(source, "kibana", "alert", "rule", "description"),
            detected_at=source.get("@timestamp") or _field(source, "kibana", "alert", "original_time"),
            severity=_field(source, "kibana", "alert", "severity"),
            risk_score=_field(source, "kibana", "alert", "risk_score"),
            source_ip=_field(source, "source", "ip"),
            destination_ip=_field(source, "destination", "ip"),
            host_name=_field(source, "host", "name"),
            user_name=_field(source, "user", "name"),
            event_ids=list(event_ids),
            metadata={
                "event_kind": _field(source, "event", "kind"),
                "original": source,
            },
        )

    def search(
        self,
        *,
        index: str,
        query: Mapping[str, Any],
        size: int,
        aggregations: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute an application-built query against an explicitly configured index."""
        if index not in {
            self.settings.elastic_telemetry_indices,
            self.settings.elastic_nginx_index,
            self.settings.elastic_alert_index,
        }:
            raise ValueError("index is not configured for this application")
        request: dict[str, Any] = {
            "index": index,
            "query": dict(query),
            "size": min(size, 1000),
            "track_total_hits": True,
        }
        if aggregations:
            request["aggregations"] = dict(aggregations)
        response = self.client.search(
            **request,
        )
        return dict(response)


class ElasticAccessError(RuntimeError):
    """A categorized failure while validating Elasticsearch read access."""

    def __init__(self, category: str, message: str) -> None:
        super().__init__(message)
        self.category = category
