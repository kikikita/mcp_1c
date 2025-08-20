import json
import logging
import os
from fnmatch import fnmatchcase
from typing import Any, Dict, List, Optional, Set, Union

logger = logging.getLogger(__name__)

_ALLOWED_EXACT: Dict[str, Set[str]] = {}
_WILDCARD_PATTERNS: List[tuple[str, Set[str], int]] = []
_ENTITY_ALIASES: Dict[str, List[str]] = {}
_ALIAS_TARGETS: Dict[str, List[str]] = {}
_ALL_FIELDS: Set[str] = set()


def _load_configs() -> None:
    global _ALLOWED_EXACT, _WILDCARD_PATTERNS, _ENTITY_ALIASES, _ALIAS_TARGETS, _ALL_FIELDS
    base_dir = os.path.dirname(__file__)
    allow_path = os.getenv(
        "MCP_ALLOWED_FIELDS_FILE", os.path.join(base_dir, "odata_field_allowlist.json")
    )
    alias_path = os.getenv(
        "MCP_ENTITY_ALIASES_FILE", os.path.join(base_dir, "odata_entity_aliases.json")
    )
    try:
        with open(allow_path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        _ALLOWED_EXACT = {}
        _WILDCARD_PATTERNS = []
        _ALL_FIELDS = set()
        for key, fields in raw.items():
            field_set = set(fields)
            _ALL_FIELDS.update(field_set)
            if "*" in key:
                fixed = key.split("*", 1)[0]
                _WILDCARD_PATTERNS.append((key, field_set, len(fixed)))
            else:
                _ALLOWED_EXACT[key] = field_set
        _WILDCARD_PATTERNS.sort(key=lambda x: x[2], reverse=True)
    except Exception as e:
        logger.warning(
            "Allow-list not loaded (%s): %s. Field filtering disabled.", allow_path, e
        )
        _ALLOWED_EXACT = {}
        _WILDCARD_PATTERNS = []
        _ALL_FIELDS = set()
    try:
        with open(alias_path, "r", encoding="utf-8") as f:
            _ENTITY_ALIASES = json.load(f)
        _ALIAS_TARGETS = {}
        for canonical, names in _ENTITY_ALIASES.items():
            for name in names:
                _ALIAS_TARGETS.setdefault(name, []).append(canonical)
    except Exception as e:
        logger.warning(
            "Entity aliases not loaded (%s): %s. Aliases disabled.", alias_path, e
        )
        _ENTITY_ALIASES = {}
        _ALIAS_TARGETS = {}


_load_configs()


def resolve_allowed_fields(entity_name: str, _visited: Optional[Set[str]] = None) -> Optional[Set[str]]:
    if not entity_name:
        return None
    if _visited is None:
        _visited = set()
    if entity_name in _visited:
        return None
    _visited.add(entity_name)

    if entity_name in _ALLOWED_EXACT:
        return _ALLOWED_EXACT[entity_name]

    if entity_name in _ENTITY_ALIASES:
        combined: Set[str] = set()
        for target in _ENTITY_ALIASES[entity_name]:
            resolved = resolve_allowed_fields(target, _visited)
            if resolved:
                combined.update(resolved)
        return combined if combined else None

    if entity_name in _ALIAS_TARGETS:
        combined = set()
        for canonical in _ALIAS_TARGETS[entity_name]:
            resolved = resolve_allowed_fields(canonical, _visited)
            if resolved:
                combined.update(resolved)
        return combined if combined else None

    for pattern, fields, _fixed_len in _WILDCARD_PATTERNS:
        if fnmatchcase(entity_name, pattern):
            return fields
    return None


Payload = Union[Dict[str, Any], List[Dict[str, Any]], None]


def filter_fields(entity_name: str, payload: Payload) -> Payload:
    allowed = resolve_allowed_fields(entity_name)
    if not allowed or payload is None:
        return payload
    if isinstance(payload, dict):
        return {k: v for k, v in payload.items() if k in allowed}
    if isinstance(payload, list):
        return [{k: v for k, v in row.items() if k in allowed} for row in payload]
    return payload
