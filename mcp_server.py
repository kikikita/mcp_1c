# mcp_server.py
from __future__ import annotations

import asyncio
import os
import re
from typing import Any, Dict, List, Optional, Union, Tuple
import logging
import json
import functools
from datetime import datetime
from typing import Annotated
from pydantic import Field
from mcp.server.fastmcp import FastMCP
from odata_client import ODataClient, _is_guid
from log_config import setup_logging
from field_filter import filter_fields, resolve_allowed_fields

setup_logging()
logger = logging.getLogger(__name__)


# Heuristic to detect if a string already looks like an OData filter
FILTER_TOKEN_RE = re.compile(
    r"\b(eq|ne|gt|lt|ge|le|and|or|not|substringof|startswith|endswith)\b",
    re.IGNORECASE,
)


def _json_ready(x: Any) -> Any:
    """Convert dataclasses/pydantic/objects to JSON-serialisable structures."""
    if x is None or isinstance(x, (str, int, float, bool)):
        return x
    if isinstance(x, (list, tuple)):
        return [_json_ready(i) for i in x]
    if isinstance(x, dict):
        return {k: _json_ready(v) for k, v in x.items()}
    if hasattr(x, "model_dump"):
        try:
            return _json_ready(x.model_dump())
        except Exception:
            pass
    try:
        from dataclasses import is_dataclass, asdict

        if is_dataclass(x):
            return _json_ready(asdict(x))
    except Exception:
        pass
    if hasattr(x, "dict") and callable(getattr(x, "dict")):
        try:
            return _json_ready(x.dict())
        except Exception:
            pass
    if hasattr(x, "__dict__"):
        try:
            return _json_ready(vars(x))
        except Exception:
            pass
    return repr(x)


def _shorten(data: Any, limit: int = 500) -> str:
    try:
        txt = json.dumps(_json_ready(data), ensure_ascii=False)
    except Exception:
        txt = repr(data)
    if len(txt) > limit:
        return txt[:limit] + "..."
    return txt


def _unescape_strings(obj: Any) -> Any:
    """Recursively remove escape backslashes from string values."""
    if isinstance(obj, str):
        return obj.replace("\\'", "'").replace('\\"', '"')
    if isinstance(obj, dict):
        return {k: _unescape_strings(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_unescape_strings(v) for v in obj]
    return obj


def logged_tool(func):
    """Decorator to log tool calls and results."""
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        logger.info(
            "MCP tool %s called with %s",
            func.__name__,
            _shorten({"args": args, "kwargs": kwargs}),
        )
        res = await func(*args, **kwargs)
        logger.info("MCP tool %s result %s", func.__name__, _shorten(res))
        return res

    return wrapper


class MCPServer:
    """Business layer on top of ODataClient with improved heuristics."""

    ENTITY_TYPE_PREFIX: Dict[str, str] = {
        # Catalogues
        "справочник": "Catalog_",
        "справочники": "Catalog_",
        "catalog": "Catalog_",
        "catalogs": "Catalog_",
        "каталог": "Catalog_",
        "каталоги": "Catalog_",
        # Documents
        "document": "Document_",
        "documents": "Document_",
        "документ": "Document_",
        "документы": "Document_",
        "журнал": "DocumentJournal_",
        "журналы": "DocumentJournal_",
        # Constants
        "constant": "Constant_",
        "constants": "Constant_",
        "константа": "Constant_",
        "константы": "Constant_",
        # Registers
        "план обмена": "ExchangePlan_",
        "планы обмена": "ExchangePlan_",
        "exchangeplan": "ExchangePlan_",
        "chart of accounts": "ChartOfAccounts_",
        "план счетов": "ChartOfAccounts_",
        "планы счетов": "ChartOfAccounts_",
        "chartofcalculationtypes": "ChartOfCalculationTypes_",
        "план видов расчета": "ChartOfCalculationTypes_",
        "планы видов расчета": "ChartOfCalculationTypes_",
        "chartofcharacteristictypes": "ChartOfCharacteristicTypes_",
        "план видов характеристик": "ChartOfCharacteristicTypes_",
        "регистр сведений": "InformationRegister_",
        "регистры сведений": "InformationRegister_",
        "informationregister": "InformationRegister_",
        "регистр накопления": "AccumulationRegister_",
        "регистры накопления": "AccumulationRegister_",
        "accumulationregister": "AccumulationRegister_",
        "регистр расчета": "CalculationRegister_",
        "регистры расчета": "CalculationRegister_",
        "calculationregister": "CalculationRegister_",
        "регистр бухгалтерии": "AccountingRegister_",
        "регистры бухгалтерии": "AccountingRegister_",
        "accountingregister": "AccountingRegister_",
        "бизнес процесс": "BusinessProcess_",
        "бизнес процессы": "BusinessProcess_",
        "businessprocess": "BusinessProcess_",
        "задача": "Task_",
        "задачи": "Task_",
        "task": "Task_",
        "tasks": "Task_",
    }

    FIELD_SYNONYMS: Dict[str, List[str]] = {
        "наименование": ["Description", "Наименование", "Name"],
        "имя": ["Description", "Name", "Наименование"],
        "описание": ["Description", "Наименование"],
        "code": ["Code", "Код"],
        "код": ["Code", "Код"],
        "артикул": ["Артикул", "SKU", "Code"],
        "инн": ["ИНН", "Inn", "INN"],
        "номер": ["Номер", "Number", "НомерДокумента", "DocumentNumber"],
        "ид": ["Ref_Key", "ID", "RefKey"],
        "guid": ["Ref_Key"],
        "гид": ["Ref_Key"],
        "количество": ["Количество", "Quantity"],
        "цена": ["Цена", "Price"],
        "сумма": ["Сумма", "Amount"],
        "стоимость": ["Сумма", "Amount", "Цена"],
        "дата": ["Дата", "Date", "ДатаДокумента"],
        "дата документа": ["Дата", "ДатаДокумента", "Date"],
        "формат": ["Формат", "Format"],
    }

    def __init__(
        self,
        base_url: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        timeout: int = 30,
        verify_ssl: bool = False,
    ) -> None:
        self.client = ODataClient(
            base_url, username=username, password=password, timeout=timeout, verify_ssl=verify_ssl
        )
        # Warm up metadata cache early to stabilise subsequent calls
        try:
            self.client.get_metadata()
            logger.info("1C OData metadata cache warmed up successfully")
        except Exception as e:
            logger.warning("Metadata warmup failed: %s", e)

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    @staticmethod
    def _build_filter(filters: Union[Dict[str, Any], List[str], str, None]) -> Optional[str]:
        """Build $filter from dict/list/str."""
        if filters is None:
            return None
        if isinstance(filters, str):
            return filters
        if isinstance(filters, list):
            return " and ".join([f for f in filters if f])
        if isinstance(filters, dict):
            exprs: List[str] = []
            for key, value in filters.items():
                if value is None:
                    exprs.append(f"{key} eq null")
                elif isinstance(value, bool):
                    exprs.append(f"{key} eq {'true' if value else 'false'}")
                elif isinstance(value, (int, float)):
                    exprs.append(f"{key} eq {value}")
                elif isinstance(value, str):
                    if re.search(r"\s(and|or|eq|ne|gt|lt|ge|le)\s", value, re.IGNORECASE):
                        exprs.append(f"{key} {value}")
                    elif re.fullmatch(r"guid'[0-9a-fA-F-]{36}'", value):
                        exprs.append(f"{key} eq {value}")
                    elif _is_guid(value):
                        exprs.append(f"{key} eq guid'{value}'")
                    else:
                        safe = value.replace("'", "''")
                        exprs.append(f"{key} eq '{safe}'")
                else:
                    safe = str(value).replace("'", "''")
                    exprs.append(f"{key} eq '{safe}'")
            return " and ".join(exprs)
        return None

    @staticmethod
    def _result_from_response(
        response, client: ODataClient, object_name: Optional[str] = None
    ) -> Dict[str, Any]:
        data = response.values() if hasattr(response, "values") else None
        if object_name:
            data = filter_fields(object_name, data)
        return {
            "http_code": client.get_http_code(),
            "http_message": client.get_http_message(),
            "odata_error_code": client.get_error_code(),
            "odata_error_message": client.get_error_message(),
            "last_id": client.get_last_id(),
            "data": _json_ready(data),
        }

    # ------------------------------------------------------------------
    # Metadata & resolvers
    # ------------------------------------------------------------------
    def get_server_entity_sets(self) -> Dict[str, Any]:
        try:
            meta = self.client.get_metadata()
        except Exception as e:
            logger.warning("Failed to fetch metadata: %s", e)
            return {
                "http_code": self.client.get_http_code(),
                "http_message": str(e),
                "entity_sets": [],
            }
        return {
            "http_code": self.client.get_http_code(),
            "http_message": self.client.get_http_message(),
            "entity_sets": list((meta or {}).keys()),
        }

    def get_server_metadata(self) -> Dict[str, Any]:
        try:
            meta = self.client.get_metadata()
        except Exception as e:
            logger.warning("Failed to fetch metadata: %s", e)
            return {
                "http_code": self.client.get_http_code(),
                "http_message": str(e),
                "entity_sets": {},
            }
        # simplify properties to just a list of field names
        simplified: Dict[str, Dict[str, Any]] = {}
        for name, info in (meta or {}).items():
            props = info.get("properties", {})
            allowed = resolve_allowed_fields(name)
            if allowed:
                props = {k: v for k, v in props.items() if k in allowed}
            simplified[name] = {
                "entity_type": info.get("entity_type"),
                "properties": list(props.keys()),
            }

        return {
            "http_code": self.client.get_http_code(),
            "http_message": self.client.get_http_message(),
            "entity_sets": simplified,
        }

    def get_entity_schema(self, object_name: str) -> Optional[Dict[str, Any]]:
        try:
            meta = self.client.get_metadata()
        except Exception as e:
            logger.warning("Failed to fetch metadata: %s", e)
            return None
        schema = (meta or {}).get(object_name)
        if not schema:
            return None
        props = schema.get("properties", {})
        nav_props = schema.get("navigation_properties", {})
        allowed = resolve_allowed_fields(object_name)
        if allowed:
            props = {k: v for k, v in props.items() if k in allowed}
            nav_props = {k: v for k, v in nav_props.items() if k in allowed}
        schema = dict(schema)
        schema["properties"] = props
        schema["navigation_properties"] = nav_props
        return schema

    def resolve_entity_name(self, user_entity: str, user_type: Optional[str] = None) -> Optional[str]:
        if not user_entity:
            return None
        normalized = re.sub(r"\s+", "", user_entity).lower()
        prefixes: List[str] = []
        if user_type:
            pfx = self.ENTITY_TYPE_PREFIX.get(user_type.strip().lower())
            if pfx:
                prefixes = [pfx]
        if not prefixes:
            prefixes = list(set(self.ENTITY_TYPE_PREFIX.values()))
            prefixes.append("")
        try:
            meta = self.client.get_metadata()
        except Exception as e:
            logger.warning("Failed to fetch metadata: %s", e)
            return None
        entity_sets = list((meta or {}).keys())
        candidates: List[Tuple[str, str, int]] = []
        for es in entity_sets:
            for p in prefixes:
                if p and not es.startswith(p):
                    continue
                suffix = es[len(p):] if p else es
                s_norm = re.sub(r"\s+", "", suffix).lower()
                if s_norm == normalized:
                    return es
                if normalized in s_norm:
                    candidates.append((es, p, abs(len(s_norm) - len(normalized))))
        if not candidates and user_type:
            for es in entity_sets:
                suffix = es
                s_norm = re.sub(r"\s+", "", suffix).lower()
                if s_norm == normalized:
                    return es
                if normalized in s_norm:
                    candidates.append((es, "", abs(len(s_norm) - len(normalized))))
        if candidates:
            candidates.sort(key=lambda x: (1 if not x[1] else 0, x[2], x[0]))
            return candidates[0][0]
        return None

    def resolve_field_name(
        self,
        object_name: str,
        user_field: str,
        *,
        fallback: bool = True,
    ) -> Optional[str]:
        """Resolve a human readable field name to the exact OData property name.

        Parameters
        ----------
        object_name: str
            Exact name of the EntitySet.
        user_field: str
            Human readable field name provided by the user.
        fallback: bool, default True
            Whether to fall back to a default text field (``Description``/
            ``Наименование``/``Name``) when no direct match is found.  When
            ``False`` the function returns ``None`` if the field cannot be
            resolved, allowing the caller to keep the original field name and
            avoid accidental overwrites of unrelated properties.
        """
        if not user_field:
            return None
        schema = self.get_entity_schema(object_name)
        if not schema:
            return None
        props: Dict[str, Dict[str, Any]] = schema.get("properties", {})
        keys = list(props.keys())
        key_lower = user_field.strip().lower()
        if key_lower in self.FIELD_SYNONYMS:
            for cand in self.FIELD_SYNONYMS[key_lower]:
                if cand in props:
                    return cand
        for p in keys:
            if p.lower() == key_lower:
                return p
        for p in keys:
            pl = p.lower()
            if key_lower in pl or pl in key_lower:
                return p
        if fallback:
            for default_field in ["Description", "Наименование", "Name"]:
                if default_field in props:
                    return default_field
        return None

    # ------------------------------------------------------------------
    # Internal helpers for progressive search
    # ------------------------------------------------------------------
    def _resolve_reference(self, ref_spec: Any) -> Optional[str]:
        if not isinstance(ref_spec, dict):
            return None
        utype = ref_spec.get("user_type")
        uent = ref_spec.get("user_entity")
        ufilters = ref_spec.get("filters")
        top = ref_spec.get("top", 1)
        if not (utype and uent):
            return None
        found = self.search_object(utype, uent, ufilters, top=top)
        data = found.get("data")
        if isinstance(data, dict):
            return data.get("Ref_Key")
        if isinstance(data, list) and data:
            return data[0].get("Ref_Key")
        return None

    def _resolve_refs_in_payload(self, object_name: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        _ = self.get_entity_schema(object_name)
        out: Dict[str, Any] = {}
        for k, v in (payload or {}).items():
            fld = self.resolve_field_name(object_name, k, fallback=False) or k
            if (fld.endswith("_Key") or fld.endswith("Key")) and isinstance(v, dict):
                guid = self._resolve_reference(v)
                out[fld] = guid or v
            else:
                out[fld] = v
        return out

    def _validate_expand(self, object_name: str, expand: Optional[str]) -> Optional[str]:
        if not expand:
            return None
        schema = self.get_entity_schema(object_name) or {}
        nav_props = schema.get("navigation_properties") or {}
        nav_names = set(nav_props.keys()) if isinstance(nav_props, dict) else set(nav_props or [])
        valid: List[str] = []
        for segment in expand.split(","):
            seg = segment.strip()
            if not seg:
                continue
            root = seg.split("/", 1)[0]
            resolved = self.resolve_field_name(object_name, root, fallback=False) or root
            if resolved in nav_names:
                if resolved != root:
                    seg = seg.replace(root, resolved, 1)
                valid.append(seg)
            else:
                logger.warning(
                    "Navigation property '%s' not found for %s; skipping from expand",
                    root,
                    object_name,
                )
        return ",".join(valid) if valid else None

    def _exec_get(
        self, object_name: str, flt: Optional[str], top: Optional[int], expand: Optional[str]
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        builder = getattr(self.client, object_name)
        expand = self._validate_expand(object_name, expand)
        if expand:
            builder = builder.expand(expand)
        if top is not None:
            builder = builder.top(int(top))
        if flt:
            builder = builder.filter(flt)
        try:
            resp = builder.get()
        except Exception as e:
            logger.warning("GET failed for %s with %s", object_name, e)
            return [], {
                "http_code": self.client.get_http_code(),
                "http_message": self.client.get_http_message() or str(e),
                "odata_error_code": self.client.get_error_code(),
                "odata_error_message": self.client.get_error_message(),
                "last_id": self.client.get_last_id(),
                "data": None,
            }
        vals = resp.values() or []
        vals = filter_fields(object_name, vals)
        return vals, self._result_from_response(resp, self.client, object_name)

    def _has_isfolder(self, object_name: str) -> bool:
        schema = self.get_entity_schema(object_name) or {}
        props = (schema.get("properties") or {})
        return "IsFolder" in props

    def _default_text_field(self, object_name: str) -> Optional[str]:
        # prefer Description/Наименование/Name or first string property
        for cand in ["Description", "Наименование", "Name"]:
            fld = self.resolve_field_name(object_name, cand)
            if fld:
                return fld
        schema = self.get_entity_schema(object_name) or {}
        props: Dict[str, Dict[str, Any]] = schema.get("properties", {}) or {}
        for pname, pinfo in props.items():
            if (pinfo or {}).get("type", "").endswith("String"):
                return pname
        return (props and list(props.keys())[0]) or None

    def _looks_like_filter(self, expr: str) -> bool:
        """Return True if the string resembles a ready OData filter expression."""
        if not isinstance(expr, str):
            return False
        return bool(FILTER_TOKEN_RE.search(expr))

    def _compose_expr_eq(self, field: str, value: str) -> str:
        safe = (value or "").replace("'", "''")
        return f"{field} eq '{safe}'"

    def _compose_expr_substr(self, field: str, value: Any) -> str:
        safe = str(value or "").replace("'", "''")
        return f"substringof('{safe}', {field})"

    def _compose_expr_substr_ci(self, field: str, value: Any) -> str:
        safe = str(value or "").lower().replace("'", "''")
        return f"substringof('{safe}', tolower({field}))"

    def _progressive_attempts_for_string(
        self, object_name: str, field: str, value: str, include_only_elements: bool
    ) -> List[str]:
        attempts = [self._compose_expr_eq(field, value)]
        schema = self.get_entity_schema(object_name) or {}
        props: Dict[str, Dict[str, Any]] = schema.get("properties", {}) or {}
        if props.get(field, {}).get("type") == "Edm.String":
            attempts.extend(
                [
                    self._compose_expr_substr(field, value),
                    self._compose_expr_substr_ci(field, value),
                ]
            )
        if include_only_elements and self._has_isfolder(object_name):
            attempts = [f"{a} and IsFolder eq false" for a in attempts]
        return attempts

    def _progressive_attempts_for_dict(
        self, object_name: str, filters: Dict[str, Any], include_only_elements: bool
    ) -> List[str]:
        """
        Сначала точные eq для всех полей.
        Потом — для КАЖДОГО строкового поля делаем варианты substringof/substringof+tolower,
        прочие поля оставляем как eq. Собираем AND.
        """
        # 0) точный матч целиком
        base_eq = self._build_filter(filters) or ""
        attempts = [base_eq] if base_eq else []

        # Определим строковые поля по типу из схемы
        schema = self.get_entity_schema(object_name) or {}
        props: Dict[str, Dict[str, Any]] = schema.get("properties", {}) or {}
        string_fields: List[Tuple[str, Any]] = []
        for k, v in filters.items():
            if props.get(k, {}).get("type") == "Edm.String":
                string_fields.append((k, v))

        # 1) substringof для каждого строкового поля поверх eq остальных
        for fld, val in string_fields:
            parts: List[str] = []
            for k, v in filters.items():
                if k == fld:
                    parts.append(self._compose_expr_substr(k, v))
                else:
                    parts.append(self._build_filter({k: v}) or "")
            attempts.append(" and ".join([p for p in parts if p]))

        # 2) substringof+tolower для каждого строкового поля
        for fld, val in string_fields:
            parts: List[str] = []
            for k, v in filters.items():
                if k == fld:
                    parts.append(self._compose_expr_substr_ci(k, v))
                else:
                    parts.append(self._build_filter({k: v}) or "")
            attempts.append(" and ".join([p for p in parts if p]))

        # + IsFolder eq false
        if include_only_elements and self._has_isfolder(object_name):
            attempts = [f"{a} and IsFolder eq false" if a else "IsFolder eq false" for a in attempts]

        # Удалим пустые/дубликаты, сохранив порядок
        seen = set()
        uniq: List[str] = []
        for a in attempts:
            a = a.strip()
            if not a or a in seen:
                continue
            seen.add(a)
            uniq.append(a)
        return uniq

    # ------------------------------------------------------------------
    # CRUD / actions
    # ------------------------------------------------------------------
    def list_objects(
        self,
        object_name: str,
        filters: Optional[Union[str, Dict[str, Any], List[str]]] = None,
        top: Optional[int] = None,
        expand: Optional[str] = None,
    ) -> Dict[str, Any]:
        builder = getattr(self.client, object_name)
        expand = self._validate_expand(object_name, expand)
        if expand:
            builder = builder.expand(expand)
        if top is not None:
            builder = builder.top(int(top))
        if filters:
            flt = self._build_filter(filters)
            if flt:
                builder = builder.filter(flt)
        try:
            response = builder.get()
        except Exception as e:
            logger.warning("Failed to list objects for %s: %s", object_name, e)
            self.client.http_code = None
            self.client.http_message = str(e)
            self.client.odata_code = None
            self.client.odata_message = None
            return {
                "http_code": None,
                "http_message": str(e),
                "odata_error_code": None,
                "odata_error_message": None,
                "last_id": None,
                "data": None,
            }
        return self._result_from_response(response, self.client, object_name)

    def find_object(
        self,
        object_name: str,
        filters: Optional[Union[str, Dict[str, Any], List[str]]] = None,
        expand: Optional[str] = None,
    ) -> Dict[str, Any]:
        builder = getattr(self.client, object_name)
        expand = self._validate_expand(object_name, expand)
        if expand:
            builder = builder.expand(expand)
        if filters:
            flt = self._build_filter(filters)
            if flt:
                builder = builder.filter(flt)
        builder = builder.top(1)
        try:
            response = builder.get()
        except Exception as e:
            logger.warning("Failed to find object for %s: %s", object_name, e)
            self.client.http_code = None
            self.client.http_message = str(e)
            self.client.odata_code = None
            self.client.odata_message = None
            return {
                "http_code": None,
                "http_message": str(e),
                "odata_error_code": None,
                "odata_error_message": None,
                "last_id": None,
                "data": None,
            }
        res = self._result_from_response(response, self.client, object_name)
        items = res.get("data") or []
        res["data"] = items[0] if items else None
        return res

    def create_object(
        self,
        object_name: str,
        data: Dict[str, Any],
        expand: Optional[str] = None,
    ) -> Dict[str, Any]:
        builder = getattr(self.client, object_name)
        expand = self._validate_expand(object_name, expand)
        if expand:
            builder = builder.expand(expand)
        resolved = self._resolve_refs_in_payload(object_name, data or {})
        try:
            response = builder.create(resolved)
        except Exception as e:
            logger.warning("Failed to create object %s: %s", object_name, e)
            self.client.http_code = None
            self.client.http_message = str(e)
            self.client.odata_code = None
            self.client.odata_message = None
            return {
                "http_code": None,
                "http_message": str(e),
                "odata_error_code": None,
                "odata_error_message": None,
                "last_id": None,
                "data": None,
            }
        return self._result_from_response(response, self.client, object_name)

    def update_object(
        self,
        object_name: str,
        object_id: Union[str, Dict[str, str]],
        data: Dict[str, Any],
        expand: Optional[str] = None,
    ) -> Dict[str, Any]:
        builder = getattr(self.client, object_name).id(object_id)
        expand = self._validate_expand(object_name, expand)
        if expand:
            builder = builder.expand(expand)
        resolved = self._resolve_refs_in_payload(object_name, data or {})
        try:
            response = builder.update(data=resolved)
        except Exception as e:
            logger.warning("Failed to update object %s: %s", object_name, e)
            self.client.http_code = None
            self.client.http_message = str(e)
            self.client.odata_code = None
            self.client.odata_message = None
            return {
                "http_code": None,
                "http_message": str(e),
                "odata_error_code": None,
                "odata_error_message": None,
                "last_id": None,
                "data": None,
            }
        return self._result_from_response(response, self.client, object_name)

    def delete_object(
        self,
        object_name: str,
        object_id: Union[str, Dict[str, str]],
        physical_delete: bool = False,
    ) -> Dict[str, Any]:
        if physical_delete:
            builder = getattr(self.client, object_name).id(object_id)
            try:
                response = builder.delete()
            except Exception as e:
                logger.warning("Failed to physically delete object %s: %s", object_name, e)
                self.client.http_code = None
                self.client.http_message = str(e)
                self.client.odata_code = None
                self.client.odata_message = None
                return {
                    "http_code": None,
                    "http_message": str(e),
                    "odata_error_code": None,
                    "odata_error_message": None,
                    "last_id": None,
                    "data": None,
                }
            return self._result_from_response(response, self.client, object_name)
        return self.update_object(object_name, object_id, {"DeletionMark": True})

    def post_document(self, object_name: str, object_id: Union[str, Dict[str, str]]) -> Dict[str, Any]:
        builder = getattr(self.client, object_name).id(object_id)
        try:
            response = builder("Post")
        except Exception as e:
            logger.warning("Failed to post document %s: %s", object_name, e)
            self.client.http_code = None
            self.client.http_message = str(e)
            self.client.odata_code = None
            self.client.odata_message = None
            return {
                "http_code": None,
                "http_message": str(e),
                "odata_error_code": None,
                "odata_error_message": None,
                "last_id": None,
                "data": None,
            }
        return self._result_from_response(response, self.client, object_name)

    def unpost_document(self, object_name: str, object_id: Union[str, Dict[str, str]]) -> Dict[str, Any]:
        builder = getattr(self.client, object_name).id(object_id)
        try:
            response = builder("Unpost")
        except Exception as e:
            logger.warning("Failed to unpost document %s: %s", object_name, e)
            self.client.http_code = None
            self.client.http_message = str(e)
            self.client.odata_code = None
            self.client.odata_message = None
            return {
                "http_code": None,
                "http_message": str(e),
                "odata_error_code": None,
                "odata_error_message": None,
                "last_id": None,
                "data": None,
            }
        return self._result_from_response(response, self.client, object_name)

    def get_schema(self, object_name: str) -> Dict[str, Any]:
        meta = None
        try:
            meta = _server.client.get_metadata()
        except Exception as e:
            return {
                "http_code": _server.client.get_http_code(),
                "http_message": str(e),
                "odata_error_code": _server.client.get_error_code(),
                "odata_error_message": _server.client.get_error_message(),
                "fields": [],
            }
        schema = (meta or {}).get(object_name, {}) or {}
        props = schema.get("properties") or {}
        allowed = resolve_allowed_fields(object_name)
        if allowed:
            props = {k: v for k, v in props.items() if k in allowed}
        fields = list(props.keys())
        return {
            "http_code": _server.client.get_http_code(),
            "http_message": _server.client.get_http_message(),
            "odata_error_code": _server.client.get_error_code(),
            "odata_error_message": _server.client.get_error_message(),
            "fields": fields,
        }

    # ------------------------------------------------------------------
    # High level operations
    # ------------------------------------------------------------------
    def search_object(
        self,
        user_type: str,
        user_entity: str,
        user_filters: Optional[Union[str, Dict[str, Any], List[str]]] = None,
        top: Optional[int] = 1,
        expand: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Прогрессивный поиск.

        - filters=str:
            * если строка похожа на готовый OData `$filter`, он выполняется как есть;
            * иначе ищем по основному текстовому полю (eq → substringof → substringof(tolower),
              затем варианты с `IsFolder eq false`, если есть).
        - filters=dict: сначала точные `eq`, затем для строковых полей
          `substringof/substringof+tolower` (остальные остаются `eq`), плюс
          попытки с `IsFolder eq false`.

        Возвращает первый непустой результат (учитывая `top`).
        """
        object_name = self.resolve_entity_name(user_entity, user_type)
        if not object_name:
            return {
                "http_code": None,
                "http_message": None,
                "odata_error_code": None,
                "odata_error_message": f"Could not resolve entity '{user_entity}' of type '{user_type}'",
                "last_id": None,
                "data": None,
            }

        # ----- Построим список попыток -----
        attempts: List[str] = []

        def exec_attempts(attempt_list: List[str]) -> Dict[str, Any]:
            nonlocal top, expand, object_name
            res: Dict[str, Any] = {}
            for flt in attempt_list:
                vals, res = self._exec_get(object_name, flt, top, expand)
                if vals:
                    # Если top<=1 — вернуть одиночный объект, иначе список
                    if top is not None and int(top) <= 1:
                        res["data"] = vals[0]
                    else:
                        res["data"] = vals
                    return res
                if res.get("http_code") == 400 and res.get("odata_error_code") == 21:
                    continue
            # если все пусто — вернём последний res (или “пусто”)
            if attempt_list:
                return res
            # вообще без попыток — как list_objects без фильтра
            return self.list_objects(object_name, filters=None, top=top, expand=expand)

        # Словарные фильтры: сначала нормализуем имена полей
        if isinstance(user_filters, dict):
            normalized: Dict[str, Any] = {}
            for k, v in user_filters.items():
                field = self.resolve_field_name(object_name, k) or k
                normalized[field] = v
            # 1-я волна: точные eq
            attempts = [self._build_filter(normalized) or ""]
            # 2-я волна: для каждого строкового поля — substringof / substringof+tolower
            attempts += self._progressive_attempts_for_dict(object_name, normalized, include_only_elements=False)
            # Пробуем
            res = exec_attempts([a for a in attempts if a])
            if res.get("data"):
                return res
            # Если пусто — добавим «только элементы»
            if self._has_isfolder(object_name):
                attempts_is = self._progressive_attempts_for_dict(
                    object_name, normalized, include_only_elements=True
                )
                res = exec_attempts(attempts_is)
                return res

            return res  # пусто

        # Строковый поиск или готовый фильтр
        if isinstance(user_filters, str) and user_filters:
            # Если строка похожа на готовое OData-выражение — используем её напрямую
            if self._looks_like_filter(user_filters):
                if top is not None and int(top) <= 1:
                    return self.find_object(object_name, filters=user_filters, expand=expand)
                return self.list_objects(object_name, filters=user_filters, top=top, expand=expand)

            # Иначе считаем, что это текст для поиска по основному полю
            fld = self._default_text_field(object_name)
            if not fld:
                # Как fallback — просто top(1) без фильтра
                return self.find_object(object_name, filters=None, expand=expand)
            # 1-я волна: eq → substr → substr_ci
            attempts = self._progressive_attempts_for_string(
                object_name, fld, user_filters, include_only_elements=False
            )
            res = exec_attempts(attempts)
            if res.get("data"):
                return res
            # 2-я волна: повтор с IsFolder eq false (если поле есть в схеме)
            if self._has_isfolder(object_name):
                attempts2 = self._progressive_attempts_for_string(
                    object_name, fld, user_filters, include_only_elements=True
                )
                res = exec_attempts(attempts2)
                return res
            return res

        # Иначе — как обычный вызов
        if top is not None and int(top) <= 1:
            return self.find_object(object_name, filters=user_filters, expand=expand)
        return self.list_objects(object_name, filters=user_filters, top=top, expand=expand)

    def ensure_entity(
        self,
        user_type: str,
        user_entity: str,
        data_or_filters: Union[Dict[str, Any], str],
        expand: Optional[str] = None,
    ) -> Dict[str, Any]:
        object_name = self.resolve_entity_name(user_entity, user_type)
        if not object_name:
            return {"http_code": None, "odata_error_message": f"Unknown entity {user_entity}", "data": None}
        filters = data_or_filters
        found = self.find_object(object_name, filters=filters, expand=expand)
        if found.get("data"):
            return found
        data = data_or_filters if isinstance(data_or_filters, dict) else {}
        created = self.create_object(object_name, data, expand=expand)
        return created

    def create_document_with_rows(
        self,
        object_name: str,
        header: Dict[str, Any],
        rows: Optional[Dict[str, List[Dict[str, Any]]]] = None,
        post: bool = False,
    ) -> Dict[str, Any]:
        created = self.create_object(object_name, header or {})
        if not (200 <= (created.get("http_code") or 0) < 300) or not created.get("last_id"):
            return {"step": "create_header", **created}
        doc_id = created["last_id"]
        result: Dict[str, Any] = {"header": created, "table_parts": {}}
        if rows:
            for tp_name, tp_rows in (rows or {}).items():
                builder = getattr(self.client, object_name).id(doc_id)
                tp_endpoint = getattr(builder, tp_name)
                tp_results: List[Dict[str, Any]] = []
                for row in (tp_rows or []):
                    resolved_row = self._resolve_refs_in_payload(f"{object_name}_{tp_name}", row)
                    try:
                        resp = tp_endpoint.create(resolved_row)
                    except Exception as e:
                        logger.warning("Failed to add row to %s: %s", tp_name, e)
                        tp_results.append(
                            {
                                "http_code": None,
                                "http_message": str(e),
                                "odata_error_code": None,
                                "odata_error_message": None,
                                "data": None,
                            }
                        )
                        continue
                    tp_results.append(
                        self._result_from_response(
                            resp, self.client, f"{object_name}_{tp_name}"
                        )
                    )
                result["table_parts"][tp_name] = tp_results
        if post:
            result["post"] = self.post_document(object_name, doc_id)
        return _json_ready(result)


# ------------------------------------------------------------------
# FastMCP tools
# ------------------------------------------------------------------

BASE_URL = os.getenv("MCP_1C_BASE", "")
USERNAME = os.getenv("ONEC_USERNAME")
PASSWORD = os.getenv("ONEC_PASSWORD")
VERIFY_SSL = os.getenv("ONEC_VERIFY_SSL", "false").lower() not in {"false", "0", "no"}

if "_server_instance" not in globals():
    _server_instance = MCPServer(base_url=BASE_URL,
                                 username=USERNAME,
                                 password=PASSWORD,
                                 verify_ssl=VERIFY_SSL)
_server = _server_instance
mcp = FastMCP("mcp_1c_improved")


@logged_tool
@mcp.tool()
async def mcp_tool_entity_sets() -> Dict[str, Any]:
    """
    Получает список всех доступных наборов сущностей (EntitySets) из OData сервиса 1С.
    Наборы сущностей представляют собой коллекции данных, доступные для чтения/записи через OData API.
    Например: справочники (Catalog_*), документы (Document_*), регистры сведений и т.д.
    Args:
      Нет
    Returns:
      Dict с следующими полями:
        - http_code (int|null): HTTP статус код последнего запроса
        - http_message (str|null): Текстовое описание HTTP статуса  
        - odata_error_code (str|null): Код ошибки OData, если произошла ошибка
        - odata_error_message (str|null): Детальное сообщение об ошибке OData
        - entity_sets (list[str]): Список имен доступных коллекций данных
    """
    data = await asyncio.to_thread(_server.get_server_entity_sets)
    return _json_ready(data)


@logged_tool
@mcp.tool()
async def get_schema(
    object_name: Annotated[str,
                           Field(description="Точное имя набора сущности (EntitySet) из OData сервиса 1С",
                                 examples=["Catalog_Контрагенты", "Document_ПлатежноеПоручение", "Catalog_Номенклатура"],
                                 max_length=256)]
) -> Dict[str, Any]:
    """
    Возвращает схему полей для указанного набора сущностей OData 1С.
    Схема содержит информацию о всех доступных полях объекта.
    
    Args:
      object_name: Точное имя набора сущностей (EntitySet), полученное из функции mcp_tool_entity_sets()
    
    Returns:
      Dict с следующими полями:
        - http_code (int|null): HTTP статус код запроса метаданных
        - http_message (str|null): Текстовое описание HTTP статуса
        - odata_error_code (str|null): Код ошибки OData, если произошла ошибка
        - odata_error_message (str|null): Детальное сообщение об ошибке OData
        - fields (list|null): Список с именами свойств сущности (например: "Ref_Key", "Description", "Code")

    Примеры использования:
        - Получить схему сущности Catalog_Контрагенты: get_schema("Catalog_Контрагенты")
        - Получить схему платежного поручения: get_schema("Document_ПлатежноеПоручение")
    """
    data = await asyncio.to_thread(_server.get_schema, object_name)
    return _json_ready(data)


@logged_tool
@mcp.tool()
async def mcp_tool_metadata() -> Dict[str, Any]:
    """
    Получить полные метаданные OData сервиса 1С.
    Возвращает разобранную информацию о всех доступных наборах сущностей и их структуре.
    
    Args:
      Нет
    
    Returns:
      Dict с следующими полями:
        - http_code (int|null): HTTP статус код запроса метаданных
        - http_message (str|null): Текстовое описание HTTP статуса
        - odata_error_code (str|null): Код ошибки OData, если произошла ошибка
        - odata_error_message (str|null): Детальное сообщение об ошибке OData
        - entity_sets (dict|null): Словарь с метаданными всех наборов сущностей, где:
            - Ключи - имена EntitySet (например: "Catalog_Контрагенты")
            - Значения - словари с описанием набора сущностей:
              - entity_type (str|None): Тип сущности в формате OData
              - properties (list): Список имен свойств сущности (например: ["Ref_Key", "Description", "Code"])
    """
    data = await asyncio.to_thread(_server.get_server_metadata)
    return _json_ready(data)


@logged_tool
@mcp.tool()
async def resolve_entity_name(
    user_entity: Annotated[str, Field(
        description="Название сущности на русском языке",
        examples=["Контрагенты", "Платежное поручение", "Номенклатура"],
        max_length=256)],
    user_type: Annotated[str, Field(
        description="Подсказка типа для уточнения поиска",
        examples=["справочник", "документ", "регистр", "константа"],
        max_length=256)] = None
) -> Dict[str, Any]:
    """
    Нормализует человеческое название сущности в точное техническое имя EntitySet OData.
    Используется для преобразования понятных пользователю названий в формальные имена,
    необходимые для работы с API 1С через OData.
    Функция выполняет поиск по уже загруженным метаданным OData,
    поэтому требует предварительного вызова mcp_tool_metadata() или mcp_tool_entity_sets()
    
    Args:
      user_entity: Название сущности на русском языке (например: "Контрагенты", "Платежное поручение")
      user_type: Опциональная подсказка типа сущности для уточнения поиска 
                (например: "справочник", "документ", "регистр")
    
    Returns:
      Dict с следующими полями:
        - resolved (str|null): Найденное точное имя EntitySet в формате OData 
                        (например: "Catalog_Контрагенты", "Document_ПлатежноеПоручение")
                        или None, если совпадение не найдено
        - http_code (int|null): HTTP статус код запроса метаданных
        - http_message (str|null): Текстовое описание HTTP статуса
        - odata_error_code (str|null): Код ошибки OData, если произошла ошибка
        - odata_error_message (str|null): Детальное сообщение об ошибке OData

    Примеры использования:
        - Найти каталог контрагентов: resolve_entity_name("Контрагенты", "каталог")
        - Найти сущность платежного поручения в 1С: resolve_entity_name("Платежное поручение")
    """
    resolved = await asyncio.to_thread(_server.resolve_entity_name, user_entity, user_type)
    return _json_ready(
        {
            "resolved": resolved,
            "http_code": _server.client.get_http_code(),
            "http_message": _server.client.get_http_message(),
            "odata_error_code": _server.client.get_error_code(),
            "odata_error_message": _server.client.get_error_message(),
        }
    )


@logged_tool
@mcp.tool()
async def resolve_field_name(
    object_name: Annotated[str, Field(
        description="Точное имя набора сущностей (EntitySet) из OData сервиса 1С",
        examples=["Catalog_Контрагенты", "Document_ПлатежноеПоручение", "Catalog_Номенклатура"],
        max_length=256
    )],
    user_field: Annotated[str, Field(
        description="Название поля на русском языке или общепринятое обозначение",
        examples=["Наименование", "ИНН", "Дата", "Код", "Сумма", "Номер"],
        max_length=256
    )]
) -> Dict[str, Any]:
    """
    Нормализует человеческое название поля в точное техническое имя свойства OData.
    Учитывает синонимы и общепринятые названия полей в системе 1С.
    Функция использует заранее загруженные метаданные OData,
    поэтому требует предварительного вызова mcp_tool_metadata() или get_schema()
    
    Args:
      object_name: Точное имя набора сущностей (EntitySet), полученное из resolve_entity_name()
      user_field: Название поля на русском языке или общепринятое обозначение
                 (например: "Наименование", "ИНН", "Дата", "Код")
    
    Returns:
      Dict с следующими полями:
        - resolved (str|null): Найденное точное имя свойства в формате OData
                        (например: "Description", "ИНН", "Date", "Code")
                        или None, если совпадение не найдено
        - http_code (int|null): HTTP статус код запроса метаданных
        - http_message (str|null): Текстовое описание HTTP статуса
        - odata_error_code (str|null): Код ошибки OData, если произошла ошибка
        - odata_error_message (str|null): Детальное сообщение об ошибке OData
    
    Примеры использования:
        - Получить название поля, содержащего наименование контрагента: resolve_field_name("Catalog_Контрагенты", "Наименование")
        - Узнать, в каком поле сущности платежного поручения хранится джата создания платежного поручения: resolve_field_name("Document_ПлатежноеПоручение", "Дата")
    """
    resolved = await asyncio.to_thread(_server.resolve_field_name, object_name, user_field)
    return _json_ready(
        {
            "resolved": resolved,
            "http_code": _server.client.get_http_code(),
            "http_message": _server.client.get_http_message(),
            "odata_error_code": _server.client.get_error_code(),
            "odata_error_message": _server.client.get_error_message(),
        }
    )


@logged_tool
@mcp.tool()
async def list_objects(
    object_name: Annotated[str, Field(
        description="Точное имя набора сущностей (EntitySet) из OData сервиса 1С",
        examples=["Catalog_Контрагенты", "Document_ПлатежноеПоручение", "Catalog_Номенклатура"],
        max_length=256
    )],
    filters: Annotated[Union[str, Dict[str, Any], List[str]], Field(
        description="Условия фильтрации записей. Может быть: "
                   "1) Строка с выражением $filter (например: \"Description eq 'Поставщик'\") "
                   "2) Словарь {поле: значение} (строковые значения автоматически экранируются) "
                   "3) Список выражений, которые объединяются через AND",
        examples=[
            "Description eq 'Поставщик'",
            {"Description": "Поставщик", "DeletionMark": False},
            ["Description eq 'Поставщик'", "Code gt '1000'"]
        ]
    )] = None,
    top: Annotated[int, Field(
        description="Ограничение количества возвращаемых записей (OData $top)",
        examples=[10, 50, 100],
        ge=1
    )] = None,
    expand: Annotated[str, Field(
        description="Поля для расширения связанных данных (OData $expand). "
                   "Указываются через запятую",
        examples=["Контрагент", "Склад,Номенклатура", "Владелец"]
    )] = None
) -> Dict[str, Any]:
    """
    Получает список записей из указанного набора сущностей с возможностью фильтрации, 
    ограничения количества и расширения связанных данных.
    Поддерживает все основные параметры OData запроса: $filter, $top, $expand.
    Для сложных фильтров рекомендуется использовать строковый формат с синтаксисом OData $filter
    
    Args:
      object_name: Точное имя набора сущностей (EntitySet), полученное из resolve_entity_name()
      filters: Условия фильтрации записей. Поддерживает различные форматы:
              - Строка с выражением OData $filter
              - Словарь {имя_поля: значение} для простых равенств
              - Список выражений для объединения через AND
      top: Максимальное количество возвращаемых записей
      expand: Поля для включения связанных данных (разделитель - запятая)
    
    Returns:
      Dict с следующими полями:
        - http_code (int|null): HTTP статус код запроса
        - http_message (str|null): Текстовое описание HTTP статуса
        - odata_error_code (str|null): Код ошибки OData, если произошла ошибка
        - odata_error_message (str|null): Детальное сообщение об ошибке OData
        - data (list[dict]|null): Список записей с данными объектов или None при ошибке

    Примеры использования:
      - Получить первых 10 контрагентов:
        list_objects("Catalog_Контрагенты", top=10)
      - Найти контрагентов с наименованием "Поставщик": 
        list_objects("Catalog_Контрагенты", filters={"Description": "Поставщик"})
      - Получить платежные поручения с расширением данных контрагента:
        list_objects("Document_ПлатежноеПоручение", expand="Контрагент")
    """
    data = await asyncio.to_thread(_server.list_objects, object_name, filters, top, expand)
    return _json_ready(data)


@logged_tool
@mcp.tool()
async def find_object(
    object_name: Annotated[str, Field(
        description="Точное имя набора сущностей (EntitySet) из OData сервиса 1С",
        examples=["Catalog_Контрагенты", "Document_ПлатежноеПоручение", "Catalog_Номенклатура"],
        max_length=256
    )],
    filters: Annotated[Union[str, Dict[str, Any], List[str]], Field(
        description="Условия фильтрации для поиска записи. Может быть: "
                   "1) Строка с выражением $filter (например: \"Code eq 'БП-000001'\") "
                   "2) Словарь поле: значение (строковые значения автоматически экранируются) "
                   "3) Список выражений, которые объединяются через AND",
        examples=[
            "Code eq 'БП-000001'",
            {"Code": "БП-000001", "DeletionMark": False},
            ["Code eq 'БП-000001'", "Description ne ''"]
        ]
    )] = None,
    expand: Annotated[str, Field(
        description="Поля для расширения связанных данных (OData $expand). "
                   "Указываются через запятую",
        examples=["Контрагент", "Склад,Номенклатура", "Владелец"]
    )] = None
) -> Dict[str, Any]:
    """
    Находит первую запись в указанном наборе сущностей, соответствующую условиям фильтрации.
    Эквивалентно вызову list_objects(..., top=1) с возвратом одной записи вместо списка.
    Функция полезна для поиска конкретного объекта по уникальным характеристикам 
    (коду, наименованию, идентификатору) когда ожидается только один результат.
    Если требуется получить несколько записей, следует использовать функцию list_objects вместо find_object.
    
    Args:
      object_name: Точное имя набора сущностей (EntitySet), полученное из resolve_entity_name()
      filters: Условия фильтрации для поиска записи. Поддерживает различные форматы:
              - Строка с выражением OData $filter
              - Словарь {имя_поля: значение} для простых равенств
              - Список выражений для объединения через AND
      expand: Поля для включения связанных данных (разделитель - запятая)
    
    Returns:
      Dict с следующими полями:
        - http_code (int|null): HTTP статус код запроса
        - http_message (str|null): Текстовое описание HTTP статуса
        - odata_error_code (str|null): Код ошибки OData, если произошла ошибка
        - odata_error_message (str|null): Детальное сообщение об ошибке OData
        - data (dict|null): Найденная запись в виде словаря или None, если ничего не найдено

    Примеры использования:
        - Найти контрагента с кодом "БП-000001": 
          find_object("Catalog_Контрагенты", filters={"Code": "БП-000001"})
        - Найти незаполненное платежное поручение: 
          find_object("Document_ПлатежноеПоручение", filters={"Posted": False})
        - Найти номенклатуру с расширением данных единицы измерения:
          find_object("Catalog_Номенклатура", filters={"Description": "Техническая поддержка ПО"}, expand="ЕдиницаИзмерения")
    """
    data = await asyncio.to_thread(_server.find_object, object_name, filters, expand)
    return _json_ready(data)


@logged_tool
@mcp.tool()
async def create_object(
    object_name: Annotated[str, Field(
        description="Точное имя набора сущностей (EntitySet) из OData сервиса 1С",
        examples=["Catalog_Контрагенты", "Document_ПлатежноеПоручение", "Catalog_Номенклатура"],
        max_length=256
    )],
    data: Annotated[Dict[str, Any], Field(
        description="Данные для создания новой записи в виде словаря поле: значение",
        examples=[
            {"Description": "Новый контрагент", "Code": "БП-000001", "ИНН": "1234567890"},
            {"Date": "2024-01-15", "Number": "00002", "Организация_Key": "00000000-0000-0000-0000-000000000000"}
        ]
    )],
    expand: Annotated[str, Field(
        description="Поля для расширения связанных данных (OData $expand). "
                   "Указываются через запятую",
        examples=["Контрагент", "Склад,Номенклатура", "Организация"]
    )] = None,
) -> Dict[str, Any]:
    """
    Создает новую запись в указанном наборе сущностей с поддержкой автоматического
    разрешения ссылочных полей и расширения связанных данных.

    Args:
      object_name: Точное имя набора сущностей (EntitySet), полученное из resolve_entity_name()
      data: Данные для создания записи.
      expand: Поля для включения связанных данных в ответ (разделитель - запятая)

    Returns:
      Dict с следующими полями:
        - http_code (int|null): HTTP статус код запроса
        - http_message (str|null): Текстовое описание HTTP статуса
        - odata_error_code (str|null): Код ошибки OData, если произошла ошибка
        - odata_error_message (str|null): Детальное сообщение об ошибке OData
        - data (list|dict|null): Созданная запись с расширенными данными или None при ошибке
        - last_id (str|null): Ref_Key созданного объекта (уникальный идентификатор в 1С)

    Примеры использования:
      - Создать нового контрагента:
        create_object("Catalog_Контрагенты", {"Description": "ООО Ромашка", "Code": "БП-00100"})
      - Создать документ платежное поручение с известным контрагентом:
        create_object("Document_ПлатежноеПоручение", {"Date": "2024-01-15", "Контрагент": "00000000-0000-0000-0000-000000000000"})
      - Создать номенклатуру с расширением данных единицы измерения:
        create_object("Catalog_Номенклатура", {"Description": "Новый товар"}, expand="ЕдиницаИзмерения")
    """
    clean_data = _unescape_strings(data)
    res = await asyncio.to_thread(_server.create_object, object_name, clean_data, expand)
    return _json_ready(res)


@logged_tool
@mcp.tool()
async def update_object(
    object_name: Annotated[str, Field(
        description="Точное имя набора сущностей (EntitySet) из OData сервиса 1С",
        examples=["Catalog_Контрагенты", "Document_ПлатежноеПоручение", "Catalog_Номенклатура"],
        max_length=256
    )],
    object_id: Annotated[Union[str, Dict[str, str]], Field(
        description="Идентификатор объекта для обновления. Это может быть: Ref_Key объекта в формате GUID, либо словарь с составным ключом для объектов с композитными идентификаторами",
        examples=[
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            {"Ref_Key": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
            {"Code": "00001", "Вид": "Основной"}
        ]
    )],
    data: Annotated[Dict[str, Any], Field(
        description="Поля для обновления в виде словаря поле: новое_значение",
        examples=[
            {"Description": "Новое наименование", "ИНН": "0987654321"},
            {"Контрагент": "00000000-0000-0000-0000-000000000000", "Сумма": 1000.50}
        ]
    )],
    expand: Annotated[str, Field(
        description="Поля для расширения связанных данных (OData $expand). "
                   "Указываются через запятую",
        examples=["Контрагент", "Склад,Номенклатура", "Организация"]
    )] = None,
) -> Dict[str, Any]:
    """
    Обновляет существующую запись в указанном наборе сущностей по идентификатору.
    Функция позволяет частично обновлять объекты, изменяя только указанные поля.
    
    Args:
      object_name: Точное имя набора сущностей (EntitySet), полученное из resolve_entity_name()
      object_id: Идентификатор обновляемого объекта. Для объектов с составными ключами 
                передается словарь с параметрами идентификации
      data: Поля для обновления
      expand: Поля для включения связанных данных в ответ (разделитель - запятая)
    
    Returns:
      Dict с следующими полями:
        - http_code (int|null): HTTP статус код запроса
        - http_message (str|null): Текстовое описание HTTP статуса
        - odata_error_code (str|null): Код ошибки OData, если произошла ошибка
        - odata_error_message (str|null): Детальное сообщение об ошибке OData
        - data (dict|null): Обновленная запись с расширенными данными или None при ошибке

    Примеры использования:
        - Обновить наименование контрагента:
          update_object("Catalog_Контрагенты", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", {"Description": "Новое описание"})
        - Изменить контрагента в документе с автоматическим поиском:
          update_object("Document_ПлатежноеПоручение", "bbbbbbbb-cccc-dddd-eeee-ffffffffffff", {"Контрагент_Key": "00000000-0000-0000-0000-000000000000"})
        - Обновить несколько полей с расширением данных:
          update_object("Catalog_Номенклатура", "cccccccc-dddd-eeee-ffff-gggggggggggg", {"Description": "Новое описание", "Цена": 150.75}, expand="ЕдиницаИзмерения")
    """
    clean_data = _unescape_strings(data)
    res = await asyncio.to_thread(_server.update_object, object_name, object_id, clean_data, expand)
    return _json_ready(res)


@logged_tool
@mcp.tool()
async def delete_object(
    object_name: Annotated[str, Field(
        description="Точное имя набора сущностей (EntitySet) из OData сервиса 1С",
        examples=["Catalog_Контрагенты", "Document_ПлатежноеПоручение", "Catalog_Номенклатура"],
        max_length=256
    )],
    object_id: Annotated[Union[str, Dict[str, str]], Field(
        description="Идентификатор объекта для удаления. Это может быть Ref_Key объекта в формате GUID либо словарь с составным ключом для объектов с композитными идентификаторами",
        examples=[
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            {"Ref_Key": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
            {"Code": "БП-00001", "Вид": "Основной"}
        ]
    )],
    physical_delete: Annotated[bool, Field(
        description="Тип удаления: "
                   "False - пометить на удаление (установить флаг DeletionMark) "
                   "True - физическое удаление из базы данных",
        examples=[False, True]
    )] = False,
) -> Dict[str, Any]:
    """
    Выполняет пометку на удаление или физическое удаление записи из указанного набора сущностей.
    По умолчанию используется мягкое удаление (пометка на удаление), 
    которое позволяет восстановить объекты. Физическое удаление безвозвратно удаляет 
    данные из базы и должно использоваться с осторожностью.
    
    Args:
      object_name: Точное имя набора сущностей (EntitySet), полученное из resolve_entity_name()
      object_id: Идентификатор удаляемого объекта. Для объектов с составными ключами 
                передается словарь с параметрами идентификации
      physical_delete: Определяет тип операции удаления. По умолчанию False - пометка на удаление
    
    Returns:
      Dict с следующими полями:
        - http_code (int|null): HTTP статус код запроса
        - http_message (str|null): Текстовое описание HTTP статуса
        - odata_error_code (str|null): Код ошибки OData, если произошла ошибка
        - odata_error_message (str|null): Детальное сообщение об ошибке OData
        - data (dict|null): Ответ сервера 1С или None при ошибке
    
    Примеры использования:
        - Пометить контрагента на удаление: 
          delete_object("Catalog_Контрагенты", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        - Физически удалить документ: 
          delete_object("Document_ПлатежноеПоручение", "bbbbbbbb-cccc-dddd-eeee-ffffffffffff", True)
        - Удалить объект с составным ключом: 
          delete_object("Catalog_ДополнительныеРеквизиты", {"Code": "БП-00001", "Вид": "Основной"})
    """
    res = await asyncio.to_thread(_server.delete_object, object_name, object_id, physical_delete)
    return _json_ready(res)


@logged_tool
@mcp.tool()
async def post_document(
    object_name: Annotated[str, Field(
        description="Точное имя набора сущностей документа (Document_*) из OData сервиса 1С",
        examples=["Document_ПлатежноеПоручение", "Document_ПоступлениеТоваров", "Document_РеализацияТоваров"],
        max_length=256
    )],
    object_id: Annotated[Union[str, Dict[str, str]], Field(
        description="Идентификатор документа для проведения. Это может быть Ref_Key документа в формате GUID, либо словарь с составным ключом для документов с идентификатором",
        examples=[
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            {"Ref_Key": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}
        ]
    )],
) -> Dict[str, Any]:
    """
    Выполняет проведение документа в системе 1С через вызов метода OData /Post.
    Документ должен быть корректно заполнен перед проведением.
    
    Args:
      object_name: Точное имя набора сущностей документа, полученное из resolve_entity_name()
      object_id: Идентификатор проводимого документа.
    
    Returns:
      Dict с следующими полями:
        - http_code (int|null): HTTP статус код запроса
        - http_message (str|null): Текстовое описание HTTP статуса
        - odata_error_code (str|null): Код ошибки OData, если произошла ошибка
        - odata_error_message (str|null): Детальное сообщение об ошибке OData
        - last_id (str|null): Ref_Key документа или None при ошибке
        - data (dict|null): Ответ сервера 1С с результатом проведения или None при ошибке

    Примеры использования:
        - Провести платежное поручение: 
        post_document("Document_ПлатежноеПоручение", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        - Провести документ поступления: 
        post_document("Document_ПоступлениеТоваров", "bbbbbbbb-cccc-dddd-eeee-ffffffffffff")
    """
    res = await asyncio.to_thread(_server.post_document, object_name, object_id)
    return _json_ready(res)


@logged_tool
@mcp.tool()
async def unpost_document(
    object_name: Annotated[str, Field(
        description="Точное имя набора сущностей документа из OData сервиса 1С",
        examples=["Document_ПлатежноеПоручение", "Document_ПоступлениеТоваров", "Document_РеализацияТоваров"],
        max_length=256
    )],
    object_id: Annotated[Union[str, Dict[str, str]], Field(
        description="Идентификатор документа для отмены проведения. Это может быть Ref_Key документа в формате GUID, либо словарь с составным ключом для документов с идентификатором",
        examples=[
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            {"Ref_Key": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}
        ]
    )],
) -> Dict[str, Any]:
    """
    Выполняет отмену проведения документа в системе 1С через вызов метода OData /Unpost.
    После отмены проведения документ снова становится доступным для редактирования.
    
    Args:
      object_name: Точное имя набора сущностей документа, полученное из resolve_entity_name()
      object_id: Идентификатор документа для отмены проведения.
    
    Returns:
      Dict с следующими полями:
        - http_code (int|null): HTTP статус код запроса
        - http_message (str|null): Текстовое описание HTTP статуса
        - odata_error_code (str|null): Код ошибки OData, если произошла ошибка
        - odata_error_message (str|null): Детальное сообщение об ошибке OData
        - last_id (str|null): Ref_Key документа или None при ошибке
        - data (dict|null): Ответ сервера 1С с результатом отмены проведения или None при ошибке

    Примеры использования:
        - Отменить проведение платежного поручения: 
        unpost_document("Document_ПлатежноеПоручение", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        - Отменить проведение документа поступления: 
        unpost_document("Document_ПоступлениеТоваров", "bbbbbbbb-cccc-dddd-eeee-ffffffffffff")
    """
    res = await asyncio.to_thread(_server.unpost_document, object_name, object_id)
    return _json_ready(res)


@logged_tool
@mcp.tool()
async def search_object(
    user_type: Annotated[str, Field(
        description="Тип сущности для поиска",
        examples=["справочник", "документ", "регистр", "константа"],
        max_length=256
    )],
    user_entity: Annotated[str, Field(
        description="Название сущности на русском языке",
        examples=["Контрагенты", "Платежное поручение", "Номенклатура", "Валюты"],
        max_length=256
    )],
    user_filters: Annotated[Optional[Union[str, Dict[str, Any], List[str]]], Field(
        description="Условия поиска. Допустимые варианты:" \
                   "1) Строка - текст для поиска по основному полю. " \
                   "Если содержит ключевые слова OData (eq, ge, и т.д.), будет " \
                   "использована как готовый `$filter`." \
                   "2) Словарь поле: значение. Строковые значения ищутся " \
                   "прогрессивно, числа и даты передаются как есть." \
                   "3) Список - набор готовых выражений, объединяемых через AND." \
                   "4) None - возврат первых записей без фильтра",
        examples=[
            "ООО Ромашка",
            {"Номер": "123", "СуммаДокумента": 1000},
            ["Date eq datetime'2024-01-19T00:00:00'", "СуммаДокумента ge 1000"],
        ]
    )] = None,
    top: Annotated[int, Field(
        description="Ограничение количества возвращаемых записей",
        examples=[1, 5, 10],
        ge=1
    )] = 1,
    expand: Annotated[str, Field(
        description="Поля для расширения связанных данных (через запятую)",
        examples=["Контрагент", "Склад,Номенклатура", "Владелец"]
    )] = None
) -> Dict[str, Any]:
    """
    Выполняет интеллектуальный поиск по сущности с автоматическим разрешением имен
    и прогрессивной стратегией поиска для повышения вероятности нахождения результатов.
    Функция автоматически определяет оптимальные поля для текстового поиска и
    последовательно применяет стратегии: точное совпадение → частичное совпадение →
    регистронезависимый поиск → исключение папок (если применимо).
    Если фильтр передан готовым выражением OData, он используется напрямую.
    Имена полей нормализуются автоматически.
    
    Args:
      user_type: Тип сущности для уточнения поиска (например: "справочник", "документ")
      user_entity: Название сущности на русском языке
      user_filters: Условия поиска. Может быть:
                   - Строка: текст либо готовое OData-выражение
                   - Словарь: {поле: значение} с автоматической подстановкой типов
                   - Список: выражения для объединения через AND
                   - None: возврат первых записей без фильтра
      top: Максимальное количество возвращаемых записей
      expand: Поля для включения связанных данных
    
    Returns:
      Dict с следующими полями:
        - http_code (int|null): HTTP статус код запроса
        - http_message (str|null): Текстовое описание HTTP статуса
        - odata_error_code (str|null): Код ошибки OData, если произошла ошибка
        - odata_error_message (str|null): Детальное сообщение об ошибке OData
        - data (dict|list|null): Найденные данные. При top=1 возвращает один объект, 
                                при top>1 возвращает список объектов
    
    Примеры использования:
      - Найти контрагента по наименованию:
        search_object("справочник", "Контрагенты", "ООО Ромашка")
      - Найти документ по номеру:
        search_object("документ", "Платежное поручение", {"Number": "00003"})
      - Найти документы по дате и сумме:
        search_object(
            "документ", "Платежное поручение",
            ["Date eq datetime'2024-01-19T00:00:00'", "СуммаДокумента ge 1000"],
            top=10
        )
      - Найти несколько номенклатур:
        search_object("справочник", "Номенклатура", "товар", top=5)
    """
    res = await asyncio.to_thread(_server.search_object, user_type, user_entity, user_filters, top, expand)
    return _json_ready(res)


@logged_tool
@mcp.tool()
async def ensure_entity(
    user_type: Annotated[str, Field(
        description="Тип сущности",
        examples=["справочник", "документ", "регистр", "константа"],
        max_length=256
    )],
    user_entity: Annotated[str, Field(
        description="Название сущности на русском языке",
        examples=["Контрагенты", "Номенклатура", "Валюты", "Склады"],
        max_length=256
    )],
    data_or_filters: Annotated[Union[Dict[str, Any], str], Field(
        description="Данные для операции upsert. Может быть: "
                   "1) Словарь с фильтром для поиска существующей записи "
                   "2) Словарь с данными для создания новой записи "
                   "3) Строка для поиска по основному текстовому полю",
        examples=[
            {"Code": "БП-00001"},
            {"Description": "ООО Ромашка", "ИНН": "1234567890"},
            "ООО Ромашка"
        ]
    )],
    expand: Annotated[str, Field(
        description="Поля для расширения связанных данных (через запятую)",
        examples=["Контрагент", "Склад,Номенклатура", "Организация"]
    )] = None
) -> Dict[str, Any]:
    """
    Выполняет операцию upsert (update или insert) для сущности: ищет запись по фильтру 
    и если не находит - создает новую запись с переданными данными.
    Паттерн "ensure" обеспечивает атомарность операции поиска-создания и полезен 
    для гарантированного получения объекта без дублирования кода проверки существования.
    Для сложных объектов с автоматическим разрешением ссылок рекомендуется 
    использовать отдельные вызовы find_object и create_object для большего контроля.
    
    Args:
      user_type: Тип сущности для уточнения поиска
      user_entity: Название сущности на русском языке
      data_or_filters: Данные для операции upsert. Если передается словарь, используется 
                      как фильтр для поиска, и если поиск не дал результатов - как данные для создания.
                      Если передается строка - выполняется поиск по основному текстовому полю.
      expand: Поля для включения связанных данных
    
    Returns:
      Dict с следующими полями:
        - http_code (int|null): HTTP статус код последней операции
        - http_message (str|null): Текстовое описание HTTP статуса
        - odata_error_code (str|null): Код ошибки OData, если произошла ошибка
        - odata_error_message (str|null): Детальное сообщение об ошибке OData
        - data (dict|null): Найденная или созданная запись
        - last_id (str|null): Ref_Key объекта (особенно полезно при создании)
    
    Примеры использования:
      - Найти или создать контрагента по коду: 
        ensure_entity("справочник", "Контрагенты", {
            "Code": "00100", 
            "Description": "ООО Ромашка",
            "ИНН": "1234567890"
        })
      - Найти или создать по наименованию: 
        ensure_entity("справочник", "Номенклатура", "Новый товар")
    """
    res = await asyncio.to_thread(_server.ensure_entity, user_type, user_entity, data_or_filters, expand)
    return _json_ready(res)


@logged_tool
@mcp.tool()
async def create_document(
    object_name: Annotated[str, Field(
        description="Точное имя набора сущностей документа из OData сервиса 1С",
        examples=["Document_ПоступлениеТоваровУслуг", "Document_ПлатежноеПоручение"],
        max_length=256
    )],
    header: Annotated[Dict[str, Any], Field(
        description="Данные для шапки документа в виде словаря поле: значение",
        examples=[
            {"Date": "2024-01-16T23:59:59", "Number": "124", "Ref_Key": "xxxxxxxxxx-xxxx-xxxx-xxxx"},
            {"Date": "2024-01-15T18:00:00", "Number": "123", "Контрагент": "xxxxxxxxxx-xxxx-xxxx-xxxx", "Контрагент_Type": "StandardODATA.Catalog_Контрагенты"},
        ]
    )],
    rows: Annotated[Dict[str, List[Dict[str, Any]]], Field(
        description="Данные для табличных частей документа. Ключ - точное имя табличной части, "
                   "значение - список строк в виде словарей поле: значение, где каждой строке соответсвует один словарь",
        examples=[
            {"Товары": [{"Ref_Key": "xxxxxxxxxx-xxxx-xxxx-xxxx", "Номенклатура_Key": "xxxxxxxxxx-xxxx-xxxx-xxxx", "Количество": 10, "Цена": 100.50, "СтавкаНДС": "БезНДС"}]},
            {"Услуги": [{"Ref_Key": "xxxxxxxxxx-xxxx-xxxx-xxxx", "Номенклатура_Key": "xxxxxxxxxx-xxxx-xxxx-xxxx", "Сумма": 250.75, "СтавкаНДС": "НДС20"}]}
        ]
    )] = None,
    post: Annotated[bool, Field(
        description="Автоматически провести документ после создания",
        examples=[True, False]
    )] = False,
) -> Dict[str, Any]:
    """
    Создает документ с шапкой и табличными частями с возможностью автоматического проведения.
    
    Args:
      object_name: Точное имя набора сущностей документа, полученное из resolve_entity_name()
      header: Данные для шапки документа. Поддерживает сложные объекты для автоматического 
             разрешения ссылок на связанные объекты. Для платежного поручения поле "Контрагент_Type" обязательно для заполнения
      rows: Данные для табличных частей документа. Каждая табличная часть должна быть 
            указана под своим точным именем с списком строк.
      post: Флаг автоматического проведения документа после успешного создания
    
    Returns:
      Dict с следующими полями:
        - http_code (int|null): HTTP статус код основной операции
        - http_message (str|null): Текстовое описание HTTP статуса
        - odata_error_code (str|null): Код ошибки OData, если произошла ошибка
        - odata_error_message (str|null): Детальное сообщение об ошибке OData
        - header (dict): Результат создания шапки документа со стандартными полями
        - table_parts (dict): Результаты добавления строк табличных частей в формате:
                             {имя_тч: [результат_строки1, результат_строки2, ...]}
        - post (dict|null): Результат проведения документа, если post=True
    
    Примеры использования:
      - Создать документ поступления без проведения: 
        create_document("Document_ПоступлениеТоваровУслуг", 
                       {"Date": "2024-01-15T17:00:00", "Контрагент": "xxxxxxxxxx-xxxx-xxxx-xxxx"},
                       {"Товары": [{"Номенклатура_Key": "xxxxxxxxxx-xxxx-xxxx-xxxx", "Количество": 10}]})
      - Создать и провести платежное поручение: 
        create_document("Document_ПлатежноеПоручение", 
                       {"Ref_Key": "xxxxxxxxxx-xxxx-xxxx-xxxx", "Date": "2024-01-15T15:00:00", "СуммаДокумента": 1000, "Контрагент_Type": "StandardODATA.Catalog_Контрагенты"},
                       post=True)
    """
    res = await asyncio.to_thread(_server.create_document_with_rows, object_name, header, rows, post)
    return _json_ready(res)


# ------------------------------------------------------------------
# Convenience tools — now using ONLY the shared _server.client
# ------------------------------------------------------------------


@logged_tool
@mcp.tool()
async def get_first_records(
    entity_name: Annotated[str, Field(
        description="Точное имя набора сущностей (EntitySet) из OData сервиса 1С",
        examples=["Catalog_Контрагенты", "Document_ПлатежноеПоручение", "Catalog_Номенклатура"],
        max_length=256
    )],
    n: Annotated[int, Field(
        description="Количество записей для получения. Положительное целое число",
        examples=[1, 3, 5]
    )] = 1
) -> Dict[str, Any]:
    """
    Получает первые несколько записей из указанного набора сущностей для ознакомления со структурой данных.
    Функция предназначена для получения примеров записей и их структуры. Для документов 
    "Document_ПоступлениеТоваровУслуг" автоматически исключает тяжелые табличные части 
    "Товары" и "Услуги" для оптимизации производительности.
    Функция полезна для анализа структуры данных перед выполнением запросов для выполнения операций с записями (создание, изменение и т.д.).
    Для "Document_ПоступлениеТоваровУслуг" автоматически удаляются табличные части 
    "Товары" и "Услуги" для избежания передачи больших объемов данных
    
    Args:
      entity_name: Точное имя набора сущностей, полученное из resolve_entity_name()
      n: Количество возвращаемых записей (положительное целое число)
    
    Returns:
      Dict с следующими полями:
        - http_code (int|null): HTTP статус код запроса
        - http_message (str|null): Текстовое описание HTTP статуса
        - odata_error_code (str|null): Код ошибки OData, если произошла ошибка
        - odata_error_message (str|null): Детальное сообщение об ошибке OData
        - record (list): Список записей. Может быть пустым если данных нет или произошла ошибка
    
    Примеры использования:
        - Получить пример контрагента: 
        get_first_records("Catalog_Контрагенты", 1)
        - Получить 3 примерa номенклатуры: 
        get_first_records("Catalog_Номенклатура", 3)
        - Получить пример документа поступления (без табличных частей): 
        get_first_records("Document_ПоступлениеТоваровУслуг", 1)
    """
    def _sync() -> Dict[str, Any]:
        try:
            entity = getattr(_server.client, entity_name)
        except Exception:
            return {
                "http_code": None,
                "http_message": f"Unknown entity {entity_name}",
                "odata_error_code": None,
                "odata_error_message": None,
                "record": [],
            }
        try:
            sample = entity.top(n).get().values()
        except Exception as e:
            return {
                "http_code": _server.client.get_http_code(),
                "http_message": str(e),
                "odata_error_code": _server.client.get_error_code(),
                "odata_error_message": _server.client.get_error_message(),
                "record": [],
            }
        if sample:
            recs = []
            for i in range(len(sample)):
                rec = sample[i]
                if entity_name == "Document_ПоступлениеТоваровУслуг":
                    rec = dict(rec)
                    rec.pop("Товары", None)
                    rec.pop("Услуги", None)
                recs.append(rec)
            recs = filter_fields(entity_name, recs)
            return {
                "http_code": _server.client.get_http_code(),
                "http_message": _server.client.get_http_message(),
                "odata_error_code": _server.client.get_error_code(),
                "odata_error_message": _server.client.get_error_message(),
                "record": recs,
            }
        else:
            return {
                "http_code": _server.client.get_http_code(),
                "http_message": _server.client.get_http_message(),
                "odata_error_code": _server.client.get_error_code(),
                "odata_error_message": _server.client.get_error_message(),
                "record": [],
            }

    data = await asyncio.to_thread(_sync)
    return _json_ready(data)


@logged_tool
@mcp.tool()
async def find_record(
    entity_name: Annotated[str, Field(
        description="Точное имя набора сущностей (EntitySet) из OData сервиса 1С",
        examples=["Catalog_Контрагенты", "Document_ПлатежноеПоручение", "Catalog_Номенклатура"],
        max_length=256
    )],
    field: Annotated[str, Field(
        description="Имя поля для фильтрации. Должно быть точным именем свойства OData",
        examples=["Code", "НаименованиеПолное", "Ref_Key", "ИНН"],
        max_length=256
    )],
    value: Annotated[str, Field(
        description="Значение для поиска по строгому равенству. Строка автоматически экранируется",
        examples=["БП-00001", "ООО Ромашка", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "00000000"],
        max_length=256
    )]
) -> Dict[str, Any]:
    """
    Находит первую запись в указанном наборе сущностей по условию строгого равенства поля значению.
    Функция выполняет точный поиск по формату `field eq 'value'` с автоматическим 
    экранированием специальных символов в значении. Возвращает первую найденную запись 
    или пустой объект если совпадений не найдено.
    Для нечеткого поиска или поиска по частичному совпадению лучше использовать функцию 
    search_object с прогрессивной стратегией поиска.
    
    Args:
      entity_name: Точное имя набора сущностей, полученное из resolve_entity_name()
      field: Имя поля для поиска. Должно быть точным именем свойства в формате OData
      value: Значение для поиска. Строковые значения автоматически экранируются
    
    Returns:
      Dict с следующими полями:
        - http_code (int|null): HTTP статус код запроса
        - http_message (str|null): Текстовое описание HTTP статуса
        - odata_error_code (str|null): Код ошибки OData, если произошла ошибка
        - odata_error_message (str|null): Детальное сообщение об ошибке OData
        - record (dict): Найденная запись или пустой словарь если не найдено
    
    Примеры использования:
      - Найти контрагента по коду: 
        find_record("Catalog_Контрагенты", "Code", "БП-00001")
      - Найти номенклатуру по наименованию: 
        find_record("Catalog_Номенклатура", "Description", "Товар 1")
      - Найти документ по Ref_Key: 
        find_record("Document_ПлатежноеПоручение", "Ref_Key", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
    """
    def _sync() -> Dict[str, Any]:
        try:
            entity = getattr(_server.client, entity_name)
        except Exception:
            return {
                "http_code": None,
                "http_message": f"Unknown entity {entity_name}",
                "odata_error_code": None,
                "odata_error_message": None,
                "record": {},
            }
        try:
            safe = value.replace("'", "''")
            expr = f"{field} eq '{safe}'"
            sample = entity.filter(expr).top(1).get().values()
        except Exception as e:
            return {
                "http_code": _server.client.get_http_code(),
                "http_message": str(e),
                "odata_error_code": _server.client.get_error_code(),
                "odata_error_message": _server.client.get_error_message(),
                "record": {},
            }
        rec = sample[0] if sample else {}
        rec = filter_fields(entity_name, rec)
        return {
            "http_code": _server.client.get_http_code(),
            "http_message": _server.client.get_http_message(),
            "odata_error_code": _server.client.get_error_code(),
            "odata_error_message": _server.client.get_error_message(),
            "record": rec,
        }

    data = await asyncio.to_thread(_sync)
    return _json_ready(data)


@logged_tool
@mcp.tool()
async def create_record(
    entity_name: Annotated[str, Field(
        description="Точное имя набора сущностей (EntitySet) из OData сервиса 1С",
        examples=["Catalog_Контрагенты", "Document_ПлатежноеПоручение", "Catalog_Номенклатура"],
        max_length=256
    )],
    record: Annotated[Dict[str, Any], Field(
        description="Данные для создания записи в виде словаря поле: значение. "
                   "Требуется точное соответствие структуре данных сущности",
        examples=[
            {"Code": "БП-00100", "Description": "Новый контрагент"},
            {"Number": "123456", "Date": "2024-01-15", "Сумма": 1000.50}
        ]
    )]
) -> Dict[str, Any]:
    """
    Быстрое создание записи в указанном наборе сущностей без автоматического разрешения ссылок.
    Функция выполняет прямое создание объекта с переданными данными. В отличие от create_object, 
    не поддерживает автоматическое разрешение ссылочных полей - все значения должны быть 
    переданы в окончательном формате, готовом для сохранения в базу.
    Особенности и ограничения:
      - Не поддерживает автоматическое разрешение ссылок (*_Key поля должны содержать готовые Ref_Key)
      - Требует точного соответствия структуры данных схеме сущности
      - Не выполняет дополнительных преобразований или валидаций
    
    Args:
      entity_name: Точное имя набора сущностей, полученное из resolve_entity_name()
      record: Данные для создания записи. Должны точно соответствовать структуре, 
             определенной в схеме сущности (get_schema). Ссылочные поля должны содержать 
             готовые значения Ref_Key в правильном формате.
    
    Returns:
      Dict с следующими полями:
        - http_code (int|null): HTTP статус код запроса
        - http_message (str|null): Текстовое описание HTTP статуса
        - odata_error_code (str|null): Код ошибки OData, если произошла ошибка
        - odata_error_message (str|null): Детальное сообщение об ошибке OData
        - record (dict|null): Созданная запись или None при ошибке
        - error (str|null): Дополнительное сообщение об ошибке
    
    Примеры использования:
        - Создать контрагента с готовыми данными: 
        create_record("Catalog_Контрагенты", {"Code": "БП-00100", "Description": "Прочие"})
        - Создать документ с прямыми ссылками: 
        create_record("Document_ПлатежноеПоручение", {
            "Number": "123456", 
            "Date": "2024-01-15T00:00:00",
            "Контрагент": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        })
    """
    def _sync() -> Dict[str, Any]:
        try:
            entity = getattr(_server.client, entity_name)
        except Exception:
            return {
                "http_code": None,
                "http_message": f"Unknown entity {entity_name}",
                "odata_error_code": None,
                "odata_error_message": None,
                "error": f"Unknown entity {entity_name}",
            }
        try:
            created = entity.create(record)
            vals = created.values()
            first = vals[0] if vals else {}
            first = filter_fields(entity_name, first)
        except Exception as e:
            return {
                "http_code": _server.client.get_http_code(),
                "http_message": str(e),
                "odata_error_code": _server.client.get_error_code(),
                "odata_error_message": _server.client.get_error_message(),
                "error": f"Ошибка при создании записи: {str(e)}",
            }
        return {
            "http_code": _server.client.get_http_code(),
            "http_message": _server.client.get_http_message(),
            "odata_error_code": _server.client.get_error_code(),
            "odata_error_message": _server.client.get_error_message(),
            "record": first,
        }

    data = await asyncio.to_thread(_sync)
    return _json_ready(data)


@logged_tool
@mcp.tool()
async def post_record(
    entity_name: Annotated[str, Field(
        description="Точное имя набора сущностей документа (Document_*) из OData сервиса 1С",
        examples=["Document_ПлатежноеПоручение", "Document_ПоступлениеТоваровУслуг"],
        max_length=256
    )],
    ref_key: Annotated[str, Field(
        description="Ref_Key документа в формате GUID для проведения",
        examples=["aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"],
        max_length=256
    )]
) -> Dict[str, Any]:
    """
    Проводит документ по его Ref_Key через вызов метода OData /Post.
    Упрощенный алиас для функции post_document когда известно точное имя сущности.
    Особенности:
      - Упрощенный интерфейс по сравнению с post_document
      - Требует точного знания имени сущности документа
      - Работает только с документами (сущностями типа Document_*)
      - Автоматически определяет успешность операции по HTTP статусу
    
    Args:
      entity_name: Точное имя набора сущностей документа, полученное из resolve_entity_name()
      ref_key: Ref_Key документа в формате GUID для проведения
    
    Returns:
      Dict с следующими полями:
        - http_code (int|null): HTTP статус код запроса
        - http_message (str|null): Текстовое описание HTTP статуса
        - odata_error_code (str|null): Код ошибки OData, если произошла ошибка
        - odata_error_message (str|null): Детальное сообщение об ошибке OData
        - success (bool): Флаг успешного выполнения операции
        - message (str): Текстовое описание результата операции или сообщение об ошибке
        - ref_key (str): Ref_Key проведенного документа (только если документ успешно проведен)
        - entity (str): Имя сущности документа (только если документ успешно проведен)
    
    Примеры использования:
        - Провести платежное поручение: 
        post_record("Document_ПлатежноеПоручение", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        - Провести документ поступления: 
        post_record("Document_ПоступлениеТоваровУслуг", "bbbbbbbb-cccc-dddd-eeee-ffffffffffff")
    """
    def _sync() -> Dict[str, Any]:
        try:
            _ = getattr(_server.client, entity_name).id(ref_key).Post()
        except Exception as e:
            return {
                "http_code": _server.client.get_http_code(),
                "http_message": str(e),
                "odata_error_code": _server.client.get_error_code(),
                "odata_error_message": _server.client.get_error_message(),
                "success": False,
                "message": f"Ошибка при проведении документа: {str(e)}",
            }
        ok = _server.client.is_ok()
        return {
            "http_code": _server.client.get_http_code(),
            "http_message": _server.client.get_http_message(),
            "odata_error_code": _server.client.get_error_code(),
            "odata_error_message": _server.client.get_error_message(),
            "success": ok,
            "message": "Документ успешно проведен" if ok else "Не удалось провести документ",
            "ref_key": ref_key,
            "entity": entity_name,
        }

    data = await asyncio.to_thread(_sync)
    return _json_ready(data)


@logged_tool
@mcp.tool()
async def add_product_service(
    type_of_good: Annotated[str, Field(
        description="Тип добавляемого элемента. Обязательно одно из значений: 'Товары' или 'Услуги'",
        examples=["Товары", "Услуги"],
        max_length=256
    )],
    waybill: Annotated[Dict[str, Any], Field(
        description="Словарь существующего документа-накладной, в который добавляются товары либо услуги. "
                   "Должен содержать соответствующую табличную часть, которая может быть пустой (в виде пустых списков)",
        examples=[
            {"Number": "123456", "Date": "2024-01-15T23:59:59", "Товары": [], "Услуги": []},
            {"Ref_Key": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "Товары": [{"Номенклатура_Key": "..."}]}
        ]
    )],
    product_or_service: Annotated[Dict[str, Any], Field(
        description="Данные строки табличной части в виде словаря {поле: значение}",
        examples=[
            {"Номенклатура_Key": "bbbbbbbb-cccc-dddd-eeee-ffffffffffff", "Количество": 10, "Цена": 100.50},
            {"Номенклатура_Key": "cccccccc-dddd-eeee-ffff-gggggggggggg", "Количество": 5, "Сумма": 250.75}
        ]
    )]
) -> Dict[str, Any]:
    """
    Добавляет товар или услугу в словарь документа-накладной.
    Вспомогательная функция для добпавления в накладную табличной части.
    
    Args:
      type_of_good: Тип добавляемого элемента - 'Товары' для товаров или 'Услуги' для услуг
      waybill: Словарь документа-накладной. Должен содержать соответствующую 
              табличную часть как список (может быть пустым, но обязательно должен быть записан в ключи "Товары" и "Услуги")
      product_or_service: Данные строки табличной части для добавления
    
    Returns:
      Dict с следующими полями:
        - success (bool): Флаг успешного выполнения операции
        - message (str|null): Текстовое описание результата операции
        - error (str|null): Сообщение об ошибке если операция не удалась
        - waybill (dict|null): Обновленный словарь документа с добавленной строкой
    
    Примеры использования:
       - Добавить товар в накладную: 
        add_product_service("Товары", waybill_dict, {"Номенклатура_Key": "...", "Количество": 10})
       - Добавить услугу в документ: 
        add_product_service("Услуги", waybill_dict, {"Номенклатура_Key": "...", "Сумма": 1000})
    """
    def _sync() -> Dict[str, Any]:
        try:
            if type_of_good not in waybill:
                return {"success": False, "error": f"Накладная не содержит таблицы {type_of_good}"}
            if waybill[type_of_good] is None:
                waybill[type_of_good] = []
            if not isinstance(waybill[type_of_good], list):
                return {"success": False, "error": f"Поле {type_of_good} должно быть списком"}
            waybill[type_of_good].append(product_or_service)
            return {"success": True, "message": "Товар или услуга успешно добавлен(а) в накладную", "waybill": waybill}
        except Exception as e:
            return {"success": False, "error": f"Произошла ошибка при добавлении товара или услуги: {str(e)}"}

    data = await asyncio.to_thread(_sync)
    return _json_ready(data)


@logged_tool
@mcp.tool()
async def get_records_by_date_range(
    entity_name: Annotated[str, Field(
        description="Точное имя набора сущностей (EntitySet) из OData сервиса 1С",
        examples=["Document_ПлатежноеПоручение", "Document_ПоступлениеТоваровУслуг"],
        max_length=256
    )],
    date_field: Annotated[str, Field(
        description="Имя поля с датой для фильтрации по диапазону",
        examples=["Date", "Дата", "ДатаСоздания"],
        max_length=256
    )] = "Date",
    start_date: Annotated[datetime, Field(
        description="Начальная дата диапазона (включительно). Если не указана, фильтр не применяется",
        examples=["2024-01-01", "2024-01-15T00:00:00"]
    )] = None,
    end_date: Annotated[datetime, Field(
        description="Конечная дата диапазона (включительно). Если не указана, фильтр не применяется",
        examples=["2024-01-31", "2024-01-15T23:59:59"]
    )] = None,
    additional_filters: Annotated[Dict[str, Any], Field(
        description="Дополнительные фильтры в виде словаря поле: значение. "
                   "Поддерживаются строковые, булевые и числовые значения",
        examples=[
            {"Posted": True, "Контрагент_Key": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
            {"DeletionMark": False, "Code": "БП-00001"}
        ]
    )] = None,
    top: Annotated[int, Field(
        description="Ограничение количества возвращаемых записей. "
                   "Если не указано, возвращаются все записи соответствующие фильтрам",
        examples=[5, 10, 50],
    )] = None
) -> Dict[str, Any]:
    """
    Выполняет выборку записей из указанного набора сущностей по диапазону дат 
    с возможностью дополнительной фильтрации и ограничения количества.
    Функция предназначена для получения исторических данных, отчетов и анализа 
    информации за определенный период времени с поддержкой сложных условий фильтрации.
    
    Args:
      entity_name: Точное имя набора сущностей, полученное из resolve_entity_name()
      date_field: Имя поля даты для фильтрации по диапазону
      start_date: Начальная дата диапазона (включительно)
      end_date: Конечная дата диапазона (включительно)
      additional_filters: Дополнительные условия фильтрации помимо дат
      top: Максимальное количество возвращаемых записей
    
    Returns:
      Dict с следующими полями:
        - http_code (int|null): HTTP статус код запроса
        - http_message (str|null): Текстовое описание HTTP статуса
        - odata_error_code (str|null): Код ошибки OData, если произошла ошибка
        - odata_error_message (str|null): Детальное сообщение об ошибке OData
        - success (bool): Флаг успешного выполнения запроса
        - data (list): Список записей, соответствующих условиям фильтрации
        - error (str|null): Сообщение об ошибке если запрос не удался
    
    Примеры использования:
      - Получить платежные поручения за январь 2024: 
        get_records_by_date_range("Document_ПлатежноеПоручение", "Date", 
                                 "2024-01-01T00:00:00", "2024-01-31T00:00:00")
      - Получить проведенные документы поступления за период: 
        get_records_by_date_range("Document_ПоступлениеТоваровУслуг", "Date",
                                 "2019-03-31T23:59:59", "2019-04-12T23:59:59",
                                 {"Posted": True})
    """
    def _sync() -> Dict[str, Any]:
        try:
            entity = getattr(_server.client, entity_name)
            
            # Формирование фильтров к запросу
            filters = []
            if start_date:
                filters.append(f"{date_field} ge datetime'{start_date.isoformat()}'")
            if end_date:
                filters.append(f"{date_field} le datetime'{end_date.isoformat()}'")
            
            if additional_filters:
                for field, value in additional_filters.items():
                    if isinstance(value, str):
                        filters.append(f"{field} eq '{value}'")
                    elif isinstance(value, bool):
                        filters.append(f"{field} eq {'true' if value else 'false'}")
                    else:
                        filters.append(f"{field} eq {value}")
            
            filter_str = " and ".join(filters) if filters else None
            
            query = entity
            if filter_str:
                query = query.filter(filter_str)
            if top:
                query = query.top(top)
            
            response = query.get()
            sample = response.values()

            if sample:
                result_dict = sample
            else:
                result_dict = []
            result_dict = filter_fields(entity_name, result_dict)

            return {
                "http_code": _server.client.get_http_code(),
                "http_message": _server.client.get_http_message(),
                "odata_error_code": _server.client.get_error_code(),
                "odata_error_message": _server.client.get_error_message(),
                "success": _server.client.is_ok(),
                "data": result_dict
            }
            
        except Exception as e:
            return {
                "http_code": _server.client.get_http_code(),
                "http_message": str(e),
                "odata_error_code": _server.client.get_error_code(),
                "odata_error_message": _server.client.get_error_message(),
                "success": False,
                "error": f"Ошибка при получении записей: {str(e)}"
            }

    data = await asyncio.to_thread(_sync)
    return _json_ready(data)


@logged_tool
@mcp.tool()
async def get_records_with_expand(
    entity_name: Annotated[str, Field(
        description="Точное имя набора сущностей (EntitySet) из OData сервиса 1С",
        examples=["Document_ПлатежноеПоручение", "Document_ПоступлениеТоваров", "Catalog_Номенклатура"],
        max_length=256
    )],
    expand_fields: Annotated[List[str], Field(
        description="Список имен связанных свойств для расширения (OData $expand). "
                   "Указываются имена свойств через запятую",
        examples=[["Контрагент"], ["Склад", "Номенклатура"]]
    )],
    filters: Annotated[Dict[str, Any], Field(
        description="Дополнительные фильтры в виде словаря поле: значение. "
                   "Поддерживаются строковые, булевые и числовые значения. "
                   "Все условия объединяются через логическое AND",
        examples=[
            {"Posted": True, "DeletionMark": False},
            {"Code": "БП-00001", "Description": "Прочие"}
        ]
    )] = None,
    order_by: Annotated[str, Field(
        description="Имя поля для сортировки результатов. "
                   "Если не указано, используется порядок по умолчанию 1С",
        examples=["Date", "Number", "Code", "Description"]
    )] = None,
    desc: Annotated[bool, Field(
        description="Направление сортировки: "
                   "False - по возрастанию (ascending), "
                   "True - по убыванию (descending)",
        examples=[False, True]
    )] = False
) -> Dict[str, Any]:
    """
    Выполняет выборку записей с расширением связанных сущностей через OData $expand.
    Функция позволяет получать данные основного объекта вместе с связанными данными 
    в одном запросе, что значительно уменьшает количество HTTP запросов к серверу.
    Чрезмерное использование $expand с большим количеством связанных данных 
    может значительно увеличить объем передаваемых данных и время выполнения запроса.
    Рекомендуется использовать только необходимые для задачи расширения.
    
    Args:
      entity_name: Точное имя набора сущностей, полученное из resolve_entity_name()
      expand_fields: Список имен связанных свойств для включения в результат
      filters: Дополнительные условия фильтрации помимо расширения
      order_by: Поле для сортировки результатов
      desc: Направление сортировки (по возрастанию/убыванию)
    
    Returns:
      Dict с следующими полями:
        - http_code (int|null): HTTP статус код запроса
        - http_message (str|null): Текстовое описание HTTP статуса
        - odata_error_code (str|null): Код ошибки OData, если произошла ошибка
        - odata_error_message (str|null): Детальное сообщение об ошибке OData
        - success (bool): Флаг успешного выполнения запроса
        - data (list): Список записей с расширенными связанными данными
        - error (str|null): Сообщение об ошибке если запрос не удался
    
    Примеры использования:
      - Получить платежные поручения с данными контрагента: 
        get_records_with_expand("Document_ПлатежноеПоручение", ["Контрагент"])
      - Получить номенклатуру с расширением единицы измерения и группы: 
        get_records_with_expand("Catalog_Номенклатура", ["ЕдиницаИзмерения", "НоменклатурнаяГруппа"])
      - Получить проведенные документы с сортировкой по дате: 
        get_records_with_expand("Document_ПоступлениеТоваровУслуг", ["Контрагент", "Склад"],
                               {"Posted": True}, "Date", True)
    """
    def _sync() -> Dict[str, Any]:
        try:
            entity = getattr(_server.client, entity_name)

            exp = _server._validate_expand(entity_name, ",".join(expand_fields))
            query = entity.expand(exp) if exp else entity
            
            if filters:
                filter_parts = []
                for field, value in filters.items():
                    if isinstance(value, str):
                        filter_parts.append(f"{field} eq '{value}'")
                    elif isinstance(value, bool):
                        filter_parts.append(f"{field} eq {'true' if value else 'false'}")
                    else:
                        filter_parts.append(f"{field} eq {value}")
                query = query.filter(" and ".join(filter_parts))
            
            if order_by:
                query = query.filter(f"$orderby={order_by}{' desc' if desc else ''}")
            
            response = query.get()
            sample = response.values()

            if sample:
                result_dict = sample
            else:
                result_dict = []
            result_dict = filter_fields(entity_name, result_dict)

            return {
                "http_code": _server.client.get_http_code(),
                "http_message": _server.client.get_http_message(),
                "odata_error_code": _server.client.get_error_code(),
                "odata_error_message": _server.client.get_error_message(),
                "success": _server.client.is_ok(),
                "data": result_dict
            }
            
        except Exception as e:
            return {
                "http_code": _server.client.get_http_code(),
                "http_message": str(e),
                "odata_error_code": _server.client.get_error_code(),
                "odata_error_message": _server.client.get_error_message(),
                "success": False,
                "error": f"Ошибка при получении записей: {str(e)}"
            }

    data = await asyncio.to_thread(_sync)
    return _json_ready(data)


@logged_tool
@mcp.tool()
async def get_aggregated_data(
    entity_name: Annotated[str, Field(
        description="Точное имя набора сущностей (EntitySet) из OData сервиса 1С",
        examples=["Document_ПлатежноеПоручение", "Document_ПоступлениеТоваров", "InformationRegister_КурсыВалют"],
        max_length=256
    )],
    group_by_field: Annotated[str, Field(
        description="Имя поля для группировки данных. Определяет категории для агрегации",
        examples=["Контрагент_Key", "Склад_Key", "Организация_Key"],
        max_length=256
    )],
    aggregate_field: Annotated[str, Field(
        description="Имя поля для агрегации. Должно содержать числовые значения",
        examples=["Сумма", "СуммаНДС", "Цена"],
        max_length=256
    )],
    aggregate_func: Annotated[str, Field(
        description="Функция агрегации для применения к значениям поля",
        examples=["sum", "avg", "min", "max", "count"],
        max_length=256
    )] = "sum",
    date_field: Annotated[str, Field(
        description="Имя поля с датой для фильтрации по диапазону",
        examples=["Date", "Дата"],
        max_length=256
    )] = "Date",
    start_date: Annotated[datetime, Field(
        description="Начальная дата диапазона для фильтрации. Если не указана, фильтр не применяется",
        examples=["2024-01-01", "2024-01-15T00:00:00"]
    )] = None,
    end_date: Annotated[datetime, Field(
        description="Конечная дата диапазона для фильтрации. Если не указана, фильтр не применяется",
        examples=["2024-01-31", "2024-01-15T23:59:59"]
    )] = None
) -> Dict[str, Any]:
    """
    Выполняет агрегацию данных по указанному полю группировки с применением функции агрегации.
    Функция позволяет получать сводные данные: суммы, средние значения, минимальные/максимальные 
    значения и количество записей по различным категориям с возможностью фильтрации по датам.
    
    Args:
      entity_name: Точное имя набора сущностей, полученное из resolve_entity_name()
      group_by_field: Поле для группировки данных (определяет категории)
      aggregate_field: Поле с числовыми значениями для агрегации
      aggregate_func: Функция агрегации: sum (сумма), avg (среднее), min (минимум), 
                     max (максимум), count (количество)
      date_field: Имя поля даты для фильтрации по диапазону
      start_date: Начальная дата диапазона (включительно)
      end_date: Конечная дата диапазона (включительно)
    
    Returns:
      Dict с следующими полями:
        - success (bool): Флаг успешного выполнения операции
        - data (dict|null): Словарь с агрегированными данными в формате {значение_группы: результат_агрегации}
        - error (str|null): Сообщение об ошибке если операция не удалась
    
    Примеры использования:
      - Получить общую сумму документов поступления по контрагентам за январь: 
        get_aggregated_data("Document_ПоступлениеТоваровУслуг", "Контрагент_Key", "СуммаДокумента", "sum", 
                           "Date", "2024-01-01T00:00:00", "2024-01-01T23:59:59")
      - Получить среднюю сумму НДС по организациям: 
        get_aggregated_data("Document_ПоступлениеТоваровУслуг", "Организация_Key", "СуммаНДС", "avg")
      - Получить количество документов по контрагентам: 
        get_aggregated_data("Document_ПоступлениеТоваровУслуг", "Контрагент_Key", "Ref_Key", "count")
    """
    def _sync() -> Dict[str, Any]:
        try:
            # Получаем записи через другую функцию
            records_response = get_records_by_date_range(
                entity_name=entity_name,
                date_field=date_field,
                start_date=start_date,
                end_date=end_date
            )
            
            if not records_response.get("success"):
                return records_response
                
            records = records_response.get("data", [])
            
            # Агрегируем данные
            result = {}
            for record in records:
                group_value = record.get(group_by_field)
                agg_value = record.get(aggregate_field, 0)
                
                if group_value not in result:
                    result[group_value] = []
                result[group_value].append(agg_value)
            
            if aggregate_func == "sum":
                aggregated = {k: sum(v) for k, v in result.items()}
            elif aggregate_func == "avg":
                aggregated = {k: sum(v)/len(v) for k, v in result.items()}
            elif aggregate_func == "min":
                aggregated = {k: min(v) for k, v in result.items()}
            elif aggregate_func == "max":
                aggregated = {k: max(v) for k, v in result.items()}
            elif aggregate_func == "count":
                aggregated = {k: len(v) for k, v in result.items()}
            else:
                return {
                    "success": False,
                    "error": f"Unsupported aggregate function: {aggregate_func}"
                }
            
            return {
                "success": True,
                "data": aggregated
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": f"Ошибка при агрегации данных: {str(e)}"
            }

    data = await asyncio.to_thread(_sync)
    return _json_ready(data)


# ASGI application for running with Uvicorn/gunicorn
app = mcp.streamable_http_app()

if __name__ == "__main__":
    mcp.run("streamable-http")
