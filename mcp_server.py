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

setup_logging()
logger = logging.getLogger(__name__)


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
    def _result_from_response(response, client: ODataClient) -> Dict[str, Any]:
        data = response.values() if hasattr(response, "values") else None
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
        return (meta or {}).get(object_name)

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

    def resolve_field_name(self, object_name: str, user_field: str) -> Optional[str]:
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
            fld = self.resolve_field_name(object_name, k) or k
            if (fld.endswith("_Key") or fld.endswith("Key")) and isinstance(v, dict):
                guid = self._resolve_reference(v)
                out[fld] = guid or v
            else:
                out[fld] = v
        return out

    def _exec_get(
        self, object_name: str, flt: Optional[str], top: Optional[int], expand: Optional[str]
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        builder = getattr(self.client, object_name)
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
            self.client.http_code = None
            self.client.http_message = str(e)
            self.client.odata_code = None
            self.client.odata_message = None
            return [], {
                "http_code": None,
                "http_message": str(e),
                "odata_error_code": None,
                "odata_error_message": None,
                "last_id": None,
                "data": None,
            }
        vals = resp.values() or []
        return vals, self._result_from_response(resp, self.client)

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

    def _compose_expr_eq(self, field: str, value: str) -> str:
        safe = (value or "").replace("'", "''")
        return f"{field} eq '{safe}'"

    def _compose_expr_substr(self, field: str, value: str) -> str:
        safe = (value or "").replace("'", "''")
        return f"substringof('{safe}', {field})"

    def _compose_expr_substr_ci(self, field: str, value: str) -> str:
        safe = (value or "").lower().replace("'", "''")
        return f"substringof('{safe}', tolower({field}))"

    def _progressive_attempts_for_string(
        self, object_name: str, field: str, value: str, include_only_elements: bool
    ) -> List[str]:
        attempts = [
            self._compose_expr_eq(field, value),
            self._compose_expr_substr(field, value),
            self._compose_expr_substr_ci(field, value),
        ]
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

        # строковые поля
        string_fields = []
        for k, v in filters.items():
            if isinstance(v, str):
                fld = k
                string_fields.append((fld, v))

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
        return self._result_from_response(response, self.client)

    def find_object(
        self,
        object_name: str,
        filters: Optional[Union[str, Dict[str, Any], List[str]]] = None,
        expand: Optional[str] = None,
    ) -> Dict[str, Any]:
        builder = getattr(self.client, object_name)
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
        res = self._result_from_response(response, self.client)
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
        return self._result_from_response(response, self.client)

    def update_object(
        self,
        object_name: str,
        object_id: Union[str, Dict[str, str]],
        data: Dict[str, Any],
        expand: Optional[str] = None,
    ) -> Dict[str, Any]:
        builder = getattr(self.client, object_name).id(object_id)
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
        return self._result_from_response(response, self.client)

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
            return self._result_from_response(response, self.client)
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
        return self._result_from_response(response, self.client)

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
        return self._result_from_response(response, self.client)

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
        Прогрессивный поиск:
          - если filters=str → field = best text field, попытки:
              eq → substringof → substringof(tolower), затем все 3 с добавкой IsFolder eq false (если есть).
          - если filters=dict → точные eq; если пусто:
              для строковых полей делаем substringof/substringof+tolower (остальные оставляем eq),
              затем варианты с IsFolder eq false (если есть).
        Возвращает первый непустой результат (учитывая top).
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
            for flt in attempt_list:
                vals, res = self._exec_get(object_name, flt, top, expand)
                if vals:
                    # Если top<=1 — вернуть одиночный объект, иначе список
                    if top is not None and int(top) <= 1:
                        res["data"] = vals[0]
                    else:
                        res["data"] = vals
                    return res
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

        # Строковый поиск: выберем поле
        if isinstance(user_filters, str) and user_filters:
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
                    tp_results.append(self._result_from_response(resp, self.client))
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
    Вернуть список доступных наборов сущностей (entity sets) сервиса OData 1С.
    Вход: нет.
    Выход (dict):
      - http_code:int|null, http_message:str|null
      - odata_error_code:str|null, odata_error_message:str|null
      - entity_sets:list[str] — имена наборов (например, "Catalog_Контрагенты", "Document_ПлатежноеПоручение").
    """
    data = await asyncio.to_thread(_server.get_server_entity_sets)
    return _json_ready(data)


@logged_tool
@mcp.tool()
async def get_schema(
    object_name: Annotated[str, Field(description="точное имя entity set", max_length=256)]
) -> Dict[str, Any]:
    """
    Получить список полей для заданного набора сущностей.
    Args:
      object_name:str — точное имя entity set (например, "Catalog_Контрагенты").
    Returns (dict):
      - http_code/http_message/odata_error_code/odata_error_message
      - schema:dict|null — описание полей (ключи — имена свойств).
    """
    data = await asyncio.to_thread(_server.get_schema, object_name)
    return _json_ready(data)


@logged_tool
@mcp.tool()
async def mcp_tool_metadata() -> Dict[str, Any]:
    """
    Получить полные метаданные OData: разобранные entity sets.
    Вход: нет.
    Выход (dict):
      - http_code/http_message
      - entity_sets:dict — имя -> {"entity_type": str|None, "properties": [field, ...]}.
    """
    data = await asyncio.to_thread(_server.get_server_metadata)
    return _json_ready(data)


@logged_tool
@mcp.tool()
async def resolve_entity_name(
    user_entity: Annotated[str, Field(description="Название сущности например, Контрагенты, Платежное поручение", max_length=256)],
    user_type: Annotated[str, Field(description="Подсказка типа: справочник/документ/регистр/константа и т.п.", max_length=256)] = None
) -> Dict[str, Any]:
    """
    Нормализовать «человеческое» имя сущности (и опциональный тип) в точное имя entity set.
    Args:
      user_entity:str — например, "Контрагенты", "Платежное поручение".
      user_type:str|None — подсказка типа: "справочник"/"документ"/"регистр"/"константа" и т. п.
    Returns (dict):
      - resolved:str|null — найденное имя (например, "Catalog_Контрагенты") либо null, если не найдено;
      - http_code/http_message/odata_error_code/odata_error_message.
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
    object_name: Annotated[str, Field(description="Название сущности", max_length=256)],
    user_field: Annotated[str, Field(description="Название поля, например, Наименование, ИНН, Дата", max_length=256)]
) -> Dict[str, Any]:
    """
    Нормализовать «человеческое» имя поля в точное имя свойства OData (с учётом синонимов).
    Args:
      object_name:str — entity set.
      user_field:str — например, "наименование", "ИНН", "Дата".
    Returns (dict):
      - resolved:str|null — точное имя свойства (например, "Description", "ИНН", "Date") либо null;
      - http_code/http_message/odata_error_code/odata_error_message.
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
    object_name: Annotated[str, Field(description="Название сущности", max_length=256)],
    filters: Annotated[Union[str, Dict[str, Any], List[str]], Field(description="выражение $filter или словарь поле:значение (строки экранируются), либо список выражений (объединяются через AND)", max_length=256)] = None,
    top: Annotated[int, Field(description="Ограничение записей ($top)", max_length=256)] = None,
    expand: Annotated[str, Field(description="Поля для $expand (через запятую)", max_length=256)] = None
) -> Dict[str, Any]:
    """
    Получить список записей набора сущностей с $filter/$top/$expand.
    Args:
      object_name:str — entity set.
      filters:str|dict|list|None — выражение $filter или словарь {поле:значение} (строки экранируются),
                                   либо список выражений (объединяются через AND).
      top:int|None — ограничение записей ($top).
      expand:str|None — поля для $expand (через запятую).
    Returns (dict): стандартный конверт + data:list[dict]|None.
    """
    data = await asyncio.to_thread(_server.list_objects, object_name, filters, top, expand)
    return _json_ready(data)


@logged_tool
@mcp.tool()
async def find_object(
    object_name: Annotated[str, Field(description="Название сущности", max_length=256)],
    filters: Annotated[Union[str, Dict[str, Any], List[str]], Field(description="выражение $filter или словарь поле:значение (строки экранируются), либо список выражений (объединяются через AND)", max_length=256)] = None,
    expand: Annotated[str, Field(description="Поля для $expand (через запятую)", max_length=256)] = None,
) -> Dict[str, Any]:
    """
    Найти первую запись (эквивалент list_objects(..., top=1)) по фильтру.
    Args:
      object_name:str;
      filters:str|dict|list|None;
      expand:str|None.
    Returns (dict): стандартный конверт + data:dict|null — найденная запись или null.
    """
    data = await asyncio.to_thread(_server.find_object, object_name, filters, expand)
    return _json_ready(data)


@logged_tool
@mcp.tool()
async def create_object(
    object_name: Annotated[str, Field(description="Название сущности", max_length=256)],
    data: Annotated[Dict[str, Any], Field(description="Тело записи", max_length=256)],
    expand: Annotated[str, Field(description="Поля для $expand (через запятую)", max_length=256)] = None,
) -> Dict[str, Any]:
    """
    Создать запись в наборе сущностей (с авто-разрешением ссылок *_Key при передаче спец-объектов).
    Args:
      object_name:str;
      data:dict — тело записи;
      expand:str|None.
    Returns (dict): стандартный конверт + data:list|dict|None; last_id:str|None — Ref_Key созданного объекта.
    """
    res = await asyncio.to_thread(_server.create_object, object_name, data, expand)
    return _json_ready(res)


@logged_tool
@mcp.tool()
async def update_object(
    object_name: Annotated[str, Field(description="Название сущности", max_length=256)],
    object_id: Annotated[Union[str, Dict[str, str]], Field(description="Идентификатор", max_length=256)],
    data: Annotated[Dict[str, Any], Field(description="Изменяемые поля", max_length=256)],
    expand: Annotated[str, Field(description="Поля для $expand (через запятую)", max_length=256)] = None,
) -> Dict[str, Any]:
    """
    Обновить запись по Ref_Key/ID.
    Args:
      object_name:str;
      object_id:str|dict — идентификатор;
      data:dict — изменяемые поля;
      expand:str|None.
    Returns (dict): стандартный конверт + data:ответ 1С.
    """
    res = await asyncio.to_thread(_server.update_object, object_name, object_id, data, expand)
    return _json_ready(res)


@logged_tool
@mcp.tool()
async def delete_object(
    object_name: Annotated[str, Field(description="Название сущности", max_length=256)],
    object_id: Annotated[Union[str, Dict[str, str]], Field(description="Идентификатор", max_length=256)],
    physical_delete: Annotated[bool, Field(description="True для физического удаления", max_length=256)] = False,
) -> Dict[str, Any]:
    """
    Пометить на удаление или физически удалить запись.
    Args:
      object_name:str;
      object_id:str|dict;
      physical_delete:bool — True для физического удаления.
    Returns (dict): стандартный конверт + data:ответ 1С.
    """
    res = await asyncio.to_thread(_server.delete_object, object_name, object_id, physical_delete)
    return _json_ready(res)


@logged_tool
@mcp.tool()
async def post_document(
    object_name: Annotated[str, Field(description="Название сущности", max_length=256)],
    object_id: Annotated[Union[str, Dict[str, str]], Field(description="Идентификатор", max_length=256)],
) -> Dict[str, Any]:
    """
    Провести документ (вызов /Post).
    Args:
      object_name:str — имя документа;
      object_id:str|dict — Ref_Key/ID.
    Returns (dict): стандартный конверт + data:ответ 1С.
    """
    res = await asyncio.to_thread(_server.post_document, object_name, object_id)
    return _json_ready(res)


@logged_tool
@mcp.tool()
async def unpost_document(
    object_name: Annotated[str, Field(description="Название сущности", max_length=256)],
    object_id: Annotated[Union[str, Dict[str, str]], Field(description="Идентификатор", max_length=256)],
) -> Dict[str, Any]:
    """
    Отменить проведение документа (вызов /Unpost).
    Args:
      object_name:str;
      object_id:str|dict.
    Returns (dict): стандартный конверт + data:ответ 1С.
    """
    res = await asyncio.to_thread(_server.unpost_document, object_name, object_id)
    return _json_ready(res)


@logged_tool
@mcp.tool()
async def search_object(
    user_type: Annotated[str, Field(description="тип (справочник/документ/...)", max_length=256)],
    user_entity: Annotated[str, Field(description="Имя сущности", max_length=256)],
    user_filters: Optional[Union[str, Dict[str, Any], List[str]]] = None,
    top: Annotated[int, Field(description="Ограничение записей ($top)", max_length=256)] = 1,
    expand: Annotated[str, Field(description="Поля для $expand (через запятую)", max_length=256)] = None
) -> Dict[str, Any]:
    """
    «Умный» поиск по сущности: сам резолвит entity/fields и пробует eq→substringof→tolower (+IsFolder=false при наличии).
    Args:
      user_type:str — тип ("справочник"/"документ"/...);
      user_entity:str — имя сущности;
      user_filters:str|dict|list|None — строка (по умолч. поиск по текстовому полю) или словарь {поле:значение};
      top:int|None; expand:str|None.
    Returns (dict): стандартный конверт + data:dict|list|None — одна запись при top<=1 или список.
    """
    res = await asyncio.to_thread(_server.search_object, user_type, user_entity, user_filters, top, expand)
    return _json_ready(res)


@logged_tool
@mcp.tool()
async def ensure_entity(
    user_type: Annotated[str, Field(description="тип (справочник/документ/...)", max_length=256)],
    user_entity: Annotated[str, Field(description="Имя сущности", max_length=256)],
    data_or_filters: Annotated[Union[Dict[str, Any], str], Field(description="фильтр для поиска ИЛИ тело для создания", max_length=256)],
    expand: Annotated[str, Field(description="Поля для $expand (через запятую)", max_length=256)] = None
) -> Dict[str, Any]:
    """
    Найти запись по фильтру; если не найдена — создать по переданным данным (upsert-паттерн).
    Args:
      user_type:str; user_entity:str; data_or_filters:dict|str — фильтр для поиска ИЛИ тело для создания.
    Returns (dict): стандартный конверт + data:созданная/найденная запись.
    """
    res = await asyncio.to_thread(_server.ensure_entity, user_type, user_entity, data_or_filters, expand)
    return _json_ready(res)


@logged_tool
@mcp.tool()
async def create_document(
    object_name: Annotated[str, Field(description="entity set документа (например, Document_ПоступлениеТоваровУслуг)", max_length=256)],
    header: Annotated[Dict[str, Any], Field(description="entity set документа (например, Document_ПоступлениеТоваровУслуг)", max_length=256)],
    rows: Annotated[Dict[str, List[Dict[str, Any]]], Field(description="Ключ - имя табличной части, значение - список словарей, в которых ключ - это строка", max_length=256)] = None,
    post: Annotated[bool, Field(description="Провести после создания", max_length=256)] = False,
) -> Dict[str, Any]:
    """
    Создать документ с табличными частями и, опционально, провести.
    Args:
      object_name:str — entity set документа (например, "Document_ПоступлениеТоваровУслуг");
      header:dict — поля «шапки» (ссылки *_Key можно передавать как спец-объекты для авто-резолва);
      rows:dict|None — {"ИмяТЧ":[{строка},...]};
      post:bool — провести после создания.
    Returns (dict): { header:..., table_parts:{ИмяТЧ:[...]} , post?:... } + стандартные http/odata поля.
    """
    res = await asyncio.to_thread(_server.create_document_with_rows, object_name, header, rows, post)
    return _json_ready(res)


# ------------------------------------------------------------------
# Convenience tools — now using ONLY the shared _server.client
# ------------------------------------------------------------------


@logged_tool
@mcp.tool()
async def get_first_records(
    entity_name: Annotated[str, Field(description="Имя сущности", max_length=256)],
    n: Annotated[int, Field(description="Количество записей, которые нужно получить", max_length=256)] = 1
) -> Dict[str, Any]:
    """
    Получить «пример» записи: первые n записей указанного набора (без тяжёлых ТЧ у поступлений).
    Args:
    entity_name:str
    n: int
    Returns: {http_*/odata_* , record:dict} — может быть пустым {}, если данных нет.
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
    entity_name: Annotated[str, Field(description="Имя сущности", max_length=256)],
    field: Annotated[str, Field(description="Имя поля для фильтрации (field eq value)", max_length=256)],
    value: Annotated[str, Field(description="Значение поля для фильтрации (field eq value)", max_length=256)]
) -> Dict[str, Any]:
    """
    Найти первую запись по условию `field eq 'value'` (строгое равенство).
    Args: entity_name:str; field:str; value:str.
    Returns: {http_*/odata_* , record:dict} — {} если не найдено.
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
    entity_name: Annotated[str, Field(description="Имя сущности", max_length=256)],
    record: Annotated[Dict[str, Any], Field(description="Запись в виде словаря", max_length=256)]
) -> Dict[str, Any]:
    """
    Быстрое создание записи (без авто-резолва ссылок). Убедитесь, что структура соответствует get_schema/get_record.
    Args: entity_name:str; record:dict.
    Returns: {http_*/odata_* , record:dict|None} — созданная запись (если сервер вернул).
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
    entity_name: Annotated[str, Field(description="Имя сущности", max_length=256)],
    ref_key: Annotated[str, Field(description="Ref_Key документа", max_length=256)]
) -> Dict[str, Any]:
    """
    Провести документ по его Ref_Key (короткий алиас post_document для известных entity_name).
    Args: entity_name:str; ref_key:str.
    Returns: {http_*/odata_* , success:bool, message:str, ref_key:str, entity:str} или ошибка.
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
                "error": f"Ошибка при проведении документа: {str(e)}",
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
    type_of_good: Annotated[str, Field(description="Обязательно принимает одно из двух значений - Товары или Услуги", max_length=256)],
    waybill: Annotated[Dict[str, Any], Field(description="словарь будущего документа (как из get_record/create_record)", max_length=256)],
    product_or_service: Annotated[Dict[str, Any], Field(description="строка товарной части", max_length=256)]
) -> Dict[str, Any]:
    """
    Добавить товар/услугу в подготовленный словарь накладной (in-memory; без запросов к 1С).
    Args:
      type_of_good:str — "Товары" или "Услуги";
      waybill:dict — словарь будущего документа (как из get_record/create_record);
      product_or_service:dict — строка ТЧ.
    Returns: {success:bool, message?:str, error?:str, waybill?:dict}.
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
    entity_name: Annotated[str, Field(description="Имя сущности", max_length=256)],
    date_field: Annotated[str, Field(description="Название поля с датой", max_length=256)] = "Date",
    start_date: Annotated[datetime, Field(description="Начальная дата", max_length=256)] = None,
    end_date: Annotated[datetime, Field(description="Конечная дата", max_length=256)] = None,
    additional_filters: Annotated[Dict[str, Any], Field(description="Ыильтры к записям в виде поле:значение", max_length=256)] = None,
    top: Annotated[int, Field(description="Количество записей для извлечения", max_length=256)] = None
) -> Dict[str, Any]:
    """
    Выборка по диапазону дат (+доп. фильтры) с поддержкой $top.
    Args:
      entity_name:str;
      date_field:str="Date"; start_date:datetime|None; end_date:datetime|None;
      additional_filters:dict|None — {поле:значение}; top:int|None.
    Returns: {http_*/odata_* , success:bool, data:list|[]|str} — список записей (см. примечание).
    Примечание: текущая реализация сериализует выборку в строку JSON при наличии записей (историческое поведение сервиса).
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
    entity_name: Annotated[str, Field(description="Имя сущности", max_length=256)],
    expand_fields: Annotated[List[str], Field(description="имена расширяемых свойств (через запятую внутри вызова)", max_length=256)],
    filters: Annotated[Dict[str, Any], Field(description="Фильтры для фильтрации записей в виде поле:значение → объединяются AND", max_length=256)] = None,
    order_by: Annotated[str, Field(description="имя поля сортировки", max_length=256)] = None,
    desc: Annotated[bool, Field(description="Сортировка по убыванию", max_length=256)] = False
) -> Dict[str, Any]:
    """
    Выборка с $expand связанных сущностей (+фильтры и простая сортировка).
    Args:
      entity_name:str; expand_fields:list[str] — имена расширяемых свойств (через запятую внутри вызова);
      filters:dict|None — {поле:значение} → объединяются AND; order_by:str|None — имя поля сортировки; desc:bool.
    Returns: {http_*/odata_* , success:bool, data:list|[]|str}.
    Примечание: сортировка реализована через добавление "$orderby=..." в выражение (зависит от клиента OData).
    """
    def _sync() -> Dict[str, Any]:
        try:
            entity = getattr(_server.client, entity_name)
            
            query = entity.expand(",".join(expand_fields))
            
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
    entity_name: Annotated[str, Field(description="Имя сущности", max_length=256)],
    group_by_field: Annotated[str, Field(description="Поле для группировки", max_length=256)],
    aggregate_field: Annotated[str, Field(description="Поле для агрегации", max_length=256)],
    aggregate_func: Annotated[str, Field(description="Функция агрегации - sum|avg|min|max|count", max_length=256)] = "sum",
    date_field: Annotated[str, Field(description="Имя поля с датой", max_length=256)] = "Date",
    start_date: Annotated[datetime, Field(description="Начальная дата", max_length=256)] = None,
    end_date: Annotated[datetime, Field(description="Конечная дата", max_length=256)] = None
) -> Dict[str, Any]:
    """
    Простейшая агрегация выборки по полю группировки (sum/avg/min/max/count) с опциональным ограничением по датам.
    Args:
      entity_name:str; group_by_field:str; aggregate_field:str; aggregate_func:str="sum"|"avg"|"min"|"max"|"count";
      date_field:str="Date"; start_date/end_date:datetime|None.
    Returns: {success:bool, data:dict|None} или {success:False, error:str}.
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
