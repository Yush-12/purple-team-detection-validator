"""
detection/siem_query.py
------------------------
Queries your SIEM after each technique simulation to determine
whether the corresponding detection rule fired.

Currently supports: Elasticsearch 8.x
Planned: Splunk (see SplunkQuery stub below)

How it works:
    After a simulation runs, we search the SIEM index for documents
    containing the technique's expected_alert_keywords within a
    short lookback window. If any matching documents are found,
    the alert is considered "fired."

    This is intentionally simple — a real production implementation
    would query the SIEM's alert/detection API rather than raw logs.
    For a lab context, raw log matching is sufficient and avoids
    requiring paid SIEM alert tiers.
"""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional

from techniques.base import SimulationResult

logger = logging.getLogger(__name__)

LOOKBACK_MINUTES = 5


@dataclass
class DetectionOutcome:
    technique_id: str
    alert_fired: bool
    matched_keywords: list[str]
    matched_doc_count: int
    query_timestamp: datetime
    raw_hits: list[dict] = field(default_factory=list)
    notes: str = ""


class SiemQuery(ABC):
    """Abstract base — implement for Elastic, Splunk, etc."""

    @abstractmethod
    def check_detection(self, result: SimulationResult) -> DetectionOutcome:
        ...


class ElasticSiemQuery(SiemQuery):
    """
    Queries Elasticsearch for log artifacts matching a simulation result.

    Args:
        host:          Elasticsearch base URL (e.g. http://localhost:9200)
        index_pattern: Index pattern to search (e.g. "logs-*")
        api_key:       Optional API key (preferred over user/pass)
        username:      Optional basic auth username
        password:      Optional basic auth password
    """

    def __init__(
        self,
        host: str = "http://localhost:9200",
        index_pattern: str = "logs-*",
        api_key: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
    ):
        # Import here so missing elasticsearch package gives a clear error
        try:
            from elasticsearch import Elasticsearch
        except ImportError:
            logger.error("Elasticsearch client not installed. Run 'pip install elasticsearch'")
            raise

        auth_kwargs = {}
        if api_key:
            auth_kwargs["api_key"] = api_key
        elif username and password:
            auth_kwargs["basic_auth"] = (username, password)

        self.client = Elasticsearch(host, **auth_kwargs)
        self.index_pattern = index_pattern

    def check_detection(self, result: SimulationResult) -> DetectionOutcome:
        since = (
            datetime.now(timezone.utc) - timedelta(minutes=LOOKBACK_MINUTES)
        ).isoformat()

        # Build a multi-match query across all expected keywords
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": since}}},
                    ],
                    "should": [
                        {"multi_match": {
                            "query": kw,
                            "fields": ["message", "event.*", "process.*", "file.*"],
                        }}
                        for kw in result.expected_alert_keywords
                    ],
                    "minimum_should_match": 1,
                }
            },
            "size": 10,
        }

        logger.debug(f"[ELASTIC] Querying {self.index_pattern} for {result.technique_id}")

        try:
            response = self.client.search(index=self.index_pattern, body=query)
            hits = response["hits"]["hits"]
            matched_keywords = [
                kw for kw in result.expected_alert_keywords
                if any(kw.lower() in str(hit).lower() for hit in hits)
            ]
            return DetectionOutcome(
                technique_id=result.technique_id,
                alert_fired=len(hits) > 0,
                matched_keywords=matched_keywords,
                matched_doc_count=len(hits),
                query_timestamp=datetime.now(timezone.utc),
                raw_hits=hits,
            )
        except Exception as exc:
            logger.error(f"[ELASTIC] Query failed for {result.technique_id}: {exc}")
            return DetectionOutcome(
                technique_id=result.technique_id,
                alert_fired=False,
                matched_keywords=[],
                matched_doc_count=0,
                query_timestamp=datetime.now(timezone.utc),
                notes=f"Query error: {exc}",
            )


class MockSiemQuery(SiemQuery):
    """
    No-SIEM stub for local development and CI testing.
    Returns a configurable outcome without touching any SIEM.
    """

    def __init__(self, always_detected: bool = False):
        self.always_detected = always_detected

    def check_detection(self, result: SimulationResult) -> DetectionOutcome:
        logger.info(
            f"[MOCK SIEM] Returning always_detected={self.always_detected} "
            f"for {result.technique_id}"
        )
        return DetectionOutcome(
            technique_id=result.technique_id,
            alert_fired=self.always_detected,
            matched_keywords=result.expected_alert_keywords if self.always_detected else [],
            matched_doc_count=1 if self.always_detected else 0,
            query_timestamp=datetime.now(timezone.utc),
            notes="MockSiemQuery — no real SIEM queried",
        )


# ── Splunk stub (implement when adding Splunk support) ─────────────────────

class SplunkSiemQuery(SiemQuery):
    """
    TODO: Implement Splunk HEC / REST API query.
    Use the splunk-sdk package and query via saved search or ad-hoc SPL.
    """

    def check_detection(self, result: SimulationResult) -> DetectionOutcome:
        raise NotImplementedError("Splunk support not yet implemented.")
