"""
siem_querier.py — Elasticsearch query engine for detection validation.
"""

import logging
import requests
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

from technique_schema import Technique

logger = logging.getLogger(__name__)

INDEX_MAP: Dict[str, str] = {
    "purpleteam-events": "purpleteam-*",
    "system-auth": "filebeat-*",
}


@dataclass
class DetectionResult:
    technique_id: str
    technique_name: str
    tactic: str
    log_source_checked: str
    raw_log_visible: bool
    matching_doc_count: int
    detection_status: str
    query_used: Dict[str, Any]
    execution_time: datetime
    query_time: datetime


class SIEMQuerier:
    def __init__(self, es_url: str = "http://localhost:9200", time_window_seconds: int = 120):
        self.es_url = es_url.rstrip("/")
        self.time_window_seconds = time_window_seconds

    def check_visibility(self, technique: Technique, execution_time: datetime) -> DetectionResult:
        """Query Elasticsearch for matching documents within the time window. Never raises."""
        query_time = datetime.now(timezone.utc)
        index = self._get_index(technique.log_source)
        query_body = self._build_query(technique.expected_fields, execution_time)
        url = f"{self.es_url}/{index}/_search"

        logger.info(
            "[SIEM] Querying %s for technique %s (%s)",
            index,
            technique.technique_id,
            technique.name,
        )

        try:
            response = requests.post(
                url,
                json=query_body,
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            response.raise_for_status()
            data = response.json()

            total_hits = data.get("hits", {}).get("total", {}).get("value", 0)
            raw_log_visible = total_hits > 0

            if raw_log_visible:
                detection_status = "DETECTED"
            else:
                detection_status = "NOT_DETECTED"

            logger.info(
                "[SIEM] %s — %s (matched %d document(s))",
                technique.technique_id,
                detection_status,
                total_hits,
            )

            return DetectionResult(
                technique_id=technique.technique_id,
                technique_name=technique.name,
                tactic=technique.tactic,
                log_source_checked=index,
                raw_log_visible=raw_log_visible,
                matching_doc_count=total_hits,
                detection_status=detection_status,
                query_used=query_body,
                execution_time=execution_time,
                query_time=query_time,
            )

        except requests.exceptions.ConnectionError:
            logger.error("[SIEM] Connection refused — is Elasticsearch running at %s?", self.es_url)
            return self._error_result(technique, query_body, execution_time, query_time)

        except requests.exceptions.Timeout:
            logger.error("[SIEM] Request timed out querying %s", url)
            return self._error_result(technique, query_body, execution_time, query_time)

        except requests.exceptions.JSONDecodeError:
            logger.error("[SIEM] Failed to decode JSON response from %s", url)
            return self._error_result(technique, query_body, execution_time, query_time)

        except requests.exceptions.HTTPError as e:
            logger.error("[SIEM] HTTP error from Elasticsearch: %s", e)
            return self._error_result(technique, query_body, execution_time, query_time)

        except Exception as e:
            logger.error("[SIEM] Unexpected error: %s", e)
            return self._error_result(technique, query_body, execution_time, query_time)

    def _build_query(self, expected_fields: Dict[str, Any], execution_time: datetime) -> Dict[str, Any]:
        """Build a bool query with must clauses for each expected field and a time range filter."""
        must_clauses = []

        for field_key, field_value in expected_fields.items():
            must_clauses.append({"match": {field_key: field_value}})

        time_from = execution_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        time_to = (execution_time + timedelta(seconds=self.time_window_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")

        must_clauses.append({
            "range": {
                "@timestamp": {
                    "gte": time_from,
                    "lte": time_to,
                }
            }
        })

        return {
            "size": 0,
            "query": {
                "bool": {
                    "must": must_clauses,
                }
            },
        }

    def _get_index(self, log_source: str) -> str:
        """Map a technique's log_source to the corresponding Elasticsearch index pattern."""
        return INDEX_MAP.get(log_source, "purpleteam-*")

    def _error_result(
        self,
        technique: Technique,
        query_body: Dict[str, Any],
        execution_time: datetime,
        query_time: datetime,
    ) -> DetectionResult:
        """Build a DetectionResult for pipeline/connection errors."""
        return DetectionResult(
            technique_id=technique.technique_id,
            technique_name=technique.name,
            tactic=technique.tactic,
            log_source_checked=self._get_index(technique.log_source),
            raw_log_visible=False,
            matching_doc_count=0,
            detection_status="LOG_PIPELINE_ERROR",
            query_used=query_body,
            execution_time=execution_time,
            query_time=query_time,
        )
