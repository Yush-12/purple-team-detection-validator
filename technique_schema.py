"""
technique_schema.py — Dataclass schema and YAML loaders for technique definitions.
"""

import os
import yaml
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Any


@dataclass
class Technique:
    technique_id: str
    name: str
    tactic: str
    description: str
    commands: List[str]
    cleanup_commands: List[str]
    log_source: str
    detection_query: str
    expected_fields: Dict[str, Any]


def load_technique(filepath: str) -> Technique:
    """Load a single technique definition from a YAML file."""
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Technique file not found: {filepath}")

    with open(path, "r", encoding="utf-8") as f:
        data: Dict[str, Any] = yaml.safe_load(f)

    return Technique(
        technique_id=data["technique_id"],
        name=data["name"],
        tactic=data["tactic"],
        description=data["description"],
        commands=data.get("commands", []),
        cleanup_commands=data.get("cleanup_commands", []),
        log_source=data.get("log_source", "purpleteam-events"),
        detection_query=data["detection_query"],
        expected_fields=data.get("expected_fields", {}),
    )


def load_all_techniques(directory: str) -> List[Technique]:
    """Load all technique YAML files from a directory, sorted by technique_id."""
    dir_path = Path(directory)
    if not dir_path.is_dir():
        raise NotADirectoryError(f"Techniques directory not found: {directory}")

    techniques: List[Technique] = []
    for yaml_file in sorted(dir_path.glob("*.yaml")):
        techniques.append(load_technique(str(yaml_file)))

    return techniques
