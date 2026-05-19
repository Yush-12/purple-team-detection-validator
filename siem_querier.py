import os
import logging
import requests
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List

logger = logging.getLogger(__name__)

class SiemQuerier:
    def __init__(self, config: dict):
        self.config = config.get("siem", {})
        self.host = self.config.get("host", "http://localhost:9200")
        self.kibana_host = self.config.get("kibana_host", "http://localhost:5601")
        self.index_pattern = self.config.get("index_pattern", "logs-*")
        
        self.username = self.config.get("username")
        self.password = self.config.get("password")
        self.api_key = self.config.get("api_key")

        # Initialize ES Python client
        self.client = None
        self._init_es_client()

    def _init_es_client(self):
        try:
            from elasticsearch import Elasticsearch
            
            auth_kwargs = {}
            if self.api_key:
                auth_kwargs["api_key"] = self.api_key
            elif self.username and self.password:
                auth_kwargs["basic_auth"] = (self.username, self.password)
                
            # Disable SSL verification warnings if using self-signed certs
            self.client = Elasticsearch(
                self.host,
                verify_certs=False,
                ssl_show_warn=False,
                **auth_kwargs
            )
            logger.info(f"[SIEM] Elasticsearch client initialized targeting: {self.host}")
        except Exception as e:
            logger.error(f"[SIEM] Failed to initialize Elasticsearch client: {e}")

    def test_connection(self) -> bool:
        """Test connections to Elasticsearch and Kibana endpoints."""
        es_ok = False
        kibana_ok = False

        if self.client:
            try:
                info = self.client.info()
                logger.info(f"[SIEM] ES Connection successful. Cluster name: {info.get('cluster_name')}")
                es_ok = True
            except Exception as e:
                logger.warning(f"[SIEM] ES Connection check failed: {e}")

        # Check Kibana API
        try:
            headers = {"kbn-xsrf": "true"}
            auth = None
            if self.username and self.password:
                auth = (self.username, self.password)
            elif self.api_key:
                headers["Authorization"] = f"ApiKey {self.api_key}"

            res = requests.get(f"{self.kibana_host}/api/status", headers=headers, auth=auth, timeout=5)
            if res.status_code == 200:
                logger.info(f"[SIEM] Kibana Connection successful targeting: {self.kibana_host}")
                kibana_ok = True
            else:
                logger.warning(f"[SIEM] Kibana Connection check returned HTTP {res.status_code}")
        except Exception as e:
            logger.warning(f"[SIEM] Kibana Connection check failed: {e}")

        return es_ok

    def provision_rules(self, techniques: List[dict]) -> None:
        """Programmatically provisions detection rules in Kibana."""
        logger.info("[SIEM] Starting Kibana Detection Rule provisioning...")
        
        headers = {
            "kbn-xsrf": "true",
            "Content-Type": "application/json"
        }
        
        auth = None
        if self.username and self.password:
            auth = (self.username, self.password)
        elif self.api_key:
            headers["Authorization"] = f"ApiKey {self.api_key}"

        for tech in techniques:
            tech_id = tech["id"]
            rule_id = f"rule-{tech_id.lower().replace('.', '_')}"
            
            # 1. Check if rule exists
            # We list rules and look for rule_id
            find_url = f"{self.kibana_host}/api/detection_engine/rules/_find?rule_id={rule_id}"
            
            try:
                res = requests.get(find_url, headers=headers, auth=auth, timeout=10)
                
                # If Kibana Detection Engine is not available, fail gracefully and log a warning
                if res.status_code == 403 or res.status_code == 404:
                    logger.warning(f"[SIEM] Kibana Detection Engine API is not enabled/available. Skipping automatic rule provisioning.")
                    return
                
                rule_exists = False
                if res.status_code == 200:
                    data = res.json()
                    if data.get("total", 0) > 0:
                        rule_exists = True
                
                rule_payload = {
                    "rule_id": rule_id,
                    "name": f"PT-Validator: {tech_id} - {tech['name']}",
                    "type": "query",
                    "query": tech["kql_rule"],
                    "severity": "medium",
                    "risk_score": 50,
                    "index": [self.index_pattern],
                    "interval": "5m",
                    "from": "now-6m",
                    "enabled": True,
                    "language": "kuery",
                    "description": f"Automated detection validation rule for MITRE technique {tech_id}.",
                    "tags": ["purple-team", tech_id]
                }
                
                if rule_exists:
                    logger.info(f"[SIEM] Kibana detection rule '{rule_id}' already exists. Skipping creation.")
                else:
                    create_url = f"{self.kibana_host}/api/detection_engine/rules"
                    c_res = requests.post(create_url, json=rule_payload, headers=headers, auth=auth, timeout=10)
                    
                    if c_res.status_code == 200:
                        logger.info(f"[SIEM] Programmatically created Kibana detection rule '{rule_id}' [OK]")
                    else:
                        logger.warning(f"[SIEM] Failed to create Kibana rule '{rule_id}': HTTP {c_res.status_code} - {c_res.text}")
            
            except Exception as e:
                logger.error(f"[SIEM] Error provisioning Kibana rule for {tech_id}: {e}")

    def query_verification(self, tech: dict, execution_timestamp: str) -> dict:
        """
        Queries Elasticsearch to check if the generated telemetry log is:
        1. Visible (Ingested)
        2. Detection Fired (Matches KQL Query)
        """
        # Convert timestamp to datetime and look back a few minutes
        exec_dt = datetime.fromisoformat(execution_timestamp)
        since = (exec_dt - timedelta(minutes=2)).isoformat()
        
        outcome = {
            "technique_id": tech["id"],
            "log_visible": False,
            "detection_fired": False,
            "matched_docs": 0,
            "notes": ""
        }

        if not self.client:
            outcome["notes"] = "Elasticsearch client is offline. Verification skipped."
            return outcome

        # Query 1: Log Visibility Check (Searches logs-* for any expected keywords)
        logger.info(f"[SIEM] Checking visibility for technique {tech['id']} since {since}...")
        
        # Build query for matching any expected keywords in system or custom event log fields
        keywords_str = " OR ".join([f'"{kw}"' for kw in tech["expected_keywords"]])
        
        visibility_query = {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": since}}},
                    {"query_string": {
                        "query": keywords_str,
                        "fields": ["message", "event.action", "process.name", "process.command_line", "file.path"]
                    }}
                ]
            }
        }

        try:
            res = self.client.search(
                index=self.index_pattern,
                query=visibility_query,
                size=5
            )
            hits = res["hits"]["hits"]
            outcome["matched_docs"] = len(hits)
            
            if len(hits) > 0:
                outcome["log_visible"] = True
                logger.info(f"[SIEM] Log Visibility [OK]: Found {len(hits)} matching events in Elasticsearch.")
                
                # Query 2: Detection Rule Fire Check
                # Run the exact KQL rule as an Elasticsearch query_string search to see if it triggers
                logger.info(f"[SIEM] Verifying KQL detection rule query: '{tech['kql_rule']}'")
                
                detection_query = {
                    "bool": {
                        "must": [
                            {"range": {"@timestamp": {"gte": since}}},
                            {"query_string": {
                                "query": tech["kql_rule"],
                                "default_field": "message" # query_string fallback
                            }}
                        ]
                    }
                }
                
                det_res = self.client.search(
                    index=self.index_pattern,
                    query=detection_query,
                    size=5
                )
                
                if len(det_res["hits"]["hits"]) > 0:
                    outcome["detection_fired"] = True
                    logger.info(f"[SIEM] Detection Alert [OK]: Rule query successfully matched active logs.")
                else:
                    outcome["notes"] = "Telemetry is visible in Elasticsearch, but KQL detection rule query did not match."
                    logger.warning(f"[SIEM] Detection Alert [GAP]: Rule query did not match raw telemetry.")
            else:
                outcome["notes"] = "No matching raw telemetry logs found in Elasticsearch."
                logger.warning(f"[SIEM] Log Visibility [GAP]: Telemetry logs are missing in Elasticsearch.")
                
        except Exception as e:
            outcome["notes"] = f"SIEM search query failed: {e}"
            logger.error(f"[SIEM] Search query failed: {e}")
            
        return outcome
