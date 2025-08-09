# mcp_server.py
# -*- coding: utf-8 -*-
"""
Enhanced MCP server exposing 1C OData operations as callable tools for LLM agents.

Главные отличия:
- Все инструменты возвращают Result(data=...), чтобы оркестратор и модель получали нормальный JSON.
- Фильтры по GUID принимаются как в «сыром» виде, так и в виде строки OData guid'...'.
- Универсальные резолверы: имя сущности, имя поля, автоматическое сопоставление ссылок *_Key.
- Высокоуровневые операции: search_object, ensure_entity, create_document (с табличными частями).
"""

from __future__ import annotations

import asyncio
import os
import re
from typing import Any, Dict, List, Optional, Union, Tuple
import logging

from mcp.server.fastmcp import FastMCP, Result
from odata_client import ODataClient, _is_guid
from log_config import setup_logging

setup_logging()
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Бизнес-логика поверх ODataClient
# -----------------------------------------------------------------------------
class MCPServer:
    """Бизнес-уровень над ODataClient: резолв имён, синонимы полей, удобные фильтры."""

    # Человек → префикс сущности 1С
    ENTITY_TYPE_PREFIX: Dict[str, str] = {
        # справочники
        "справочник": "Catalog_",
        "справочники": "Catalog_",
        "catalog": "Catalog_",
        "catalogs": "Catalog_",
        "каталог": "Catalog_",
        "каталоги": "Catalog_",
        # документы
        "document": "Document_",
        "documents": "Document_",
        "документ": "Document_",
        "документы": "Document_",
        "журнал": "DocumentJournal_",
        "журналы": "DocumentJournal_",
        # константы
        "constant": "Constant_",
        "constants": "Constant_",
        "константа": "Constant_",
        "константы": "Constant_",
        # регистры и прочее
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

    # Синонимы полей (для сопоставления естественного языка к реальным свойствам)
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

    # --------------------------- Утилиты ---------------------------

    @staticmethod
    def _build_filter(filters: Union[Dict[str, Any], List[str], str, None]) -> Optional[str]:
        """Собрать OData $filter.

        Поддержка:
        - dict -> "Field eq value and Field2 gt 0 ..."
        - list[str] -> "expr1 and expr2 ..."
        - str -> вернуть как есть
        - GUID: можно передать «сырой» xxxxxxxx-... или уже `guid'...'\`
        """
        if filters is None:
            return None
        if isinstance(filters, str):
            # уже готовая строка $filter
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
                    # Если пользователь прислал готовый фрагмент сравнения (с операторами), не экранируем
                    if re.search(r"\s(and|or|eq|ne|gt|lt|ge|le)\s", value, re.IGNORECASE):
                        exprs.append(f"{key} {value}")
                    # Уже обёрнутый вид guid'...'
                    elif re.fullmatch(r"guid'[0-9a-fA-F-]{36}'", value):
                        exprs.append(f"{key} eq {value}")
                    # «сырой» GUID
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
        """Привести ODataResponse к унифицированному словарю."""
        data = response.values() if hasattr(response, "values") else None
        return {
            "http_code": client.get_http_code(),
            "http_message": client.get_http_message(),
            "odata_error_code": client.get_error_code(),
            "odata_error_message": client.get_error_message(),
            "last_id": client.get_last_id(),
            "data": data,
        }

    # --------------------- Метаданные и резолверы ---------------------

    def list_entity_sets(self) -> List[str]:
        meta = self.client.get_metadata()
        return list((meta.get("entity_sets") or {}).keys())

    def get_entity_schema(self, object_name: str) -> Optional[Dict[str, Any]]:
        meta = self.client.get_metadata()
        return (meta.get("entity_sets") or {}).get(object_name)

    def resolve_entity_name(self, user_entity: str, user_type: Optional[str] = None) -> Optional[str]:
        """«Номенклатура» + «справочник» -> Catalog_Номенклатура (с фуззи-поиском суффикса)."""
        if not user_entity:
            return None
        normalized = re.sub(r"\s+", "", user_entity).lower()

        if user_type:
            pfx = self.ENTITY_TYPE_PREFIX.get(user_type.strip().lower())
            prefixes = [pfx] if pfx else []
        else:
            prefixes = list(set(self.ENTITY_TYPE_PREFIX.values()))
        if not prefixes:
            prefixes = [""]

        meta = self.client.get_metadata()
        entity_sets = (meta.get("entity_sets") or {}).keys()
        candidates: List[str] = []

        for es in entity_sets:
            for p in prefixes:
                if p and not es.startswith(p):
                    continue
                suffix = es[len(p) :] if p else es
                s_norm = re.sub(r"\s+", "", suffix).lower()
                if s_norm == normalized:
                    return es
                if normalized in s_norm:
                    candidates.append(es)

        if candidates:
            def key(name: str) -> Tuple[int, str]:
                suf = name.split("_", 1)[-1]
                suf_norm = re.sub(r"\s+", "", suf).lower()
                overlap = len(os.path.commonprefix([suf_norm, normalized]))
                return (overlap, name)
            candidates.sort(key=key, reverse=True)
            return candidates[0]
        return None

    def resolve_field_name(self, object_name: str, user_field: str) -> Optional[str]:
        """Подобрать реальное свойство по «человеческому» названию/синониму."""
        if not user_field:
            return None
        schema = self.get_entity_schema(object_name)
        if not schema:
            return None
        props: Dict[str, Dict[str, Any]] = (schema.get("properties") or {})
        keys = list(props.keys())

        key_lower = user_field.strip().lower()
        # 1) словарь синонимов
        if key_lower in self.FIELD_SYNONYMS:
            for cand in self.FIELD_SYNONYMS[key_lower]:
                if cand in props:
                    return cand
        # 2) точное совпадение (без регистра)
        for p in keys:
            if p.lower() == key_lower:
                return p
        # 3) подстрока
        for p in keys:
            pl = p.lower()
            if key_lower in pl or pl in key_lower:
                return p
        # 4) дефолты
        if "Description" in props:
            return "Description"
        if "Наименование" in props:
            return "Наименование"
        return None

    # --------- Вспомогательные вещи для ссылок и полезной нагрузки ---------

    def _resolve_reference(self, ref_spec: Any) -> Optional[str]:
        """Если поле — спецификация ссылки {user_type,user_entity,filters,top} → вернуть Ref_Key найденного."""
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
        """Подставить GUID'ы в *_Key полях, если пришла спецификация ссылки."""
        schema = self.get_entity_schema(object_name) or {}
        props = (schema.get("properties") or {})
        out: Dict[str, Any] = {}

        for k, v in (payload or {}).items():
            fld = self.resolve_field_name(object_name, k) or k
            if (fld.endswith("_Key") or fld.endswith("Key")) and isinstance(v, dict):
                guid = self._resolve_reference(v)
                out[fld] = guid or v
            else:
                out[fld] = v
        return out

    # --------------------------- CRUD / действия ---------------------------

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
        response = builder.get()
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
        response = builder.get()
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
        # подставим ссылки, если нужно
        resolved = self._resolve_refs_in_payload(object_name, data or {})
        response = builder.create(resolved)
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
        response = builder.update(data=resolved)
        return self._result_from_response(response, self.client)

    def delete_object(
        self,
        object_name: str,
        object_id: Union[str, Dict[str, str]],
        physical_delete: bool = False,
    ) -> Dict[str, Any]:
        if physical_delete:
            builder = getattr(self.client, object_name).id(object_id)
            response = builder.delete()
            return self._result_from_response(response, self.client)
        return self.update_object(object_name, object_id, {"DeletionMark": True})

    def post_document(self, object_name: str, object_id: Union[str, Dict[str, str]]) -> Dict[str, Any]:
        builder = getattr(self.client, object_name).id(object_id)
        response = builder("Post")
        return self._result_from_response(response, self.client)

    def unpost_document(self, object_name: str, object_id: Union[str, Dict[str, str]]) -> Dict[str, Any]:
        builder = getattr(self.client, object_name).id(object_id)
        response = builder("Unpost")
        return self._result_from_response(response, self.client)

    def get_schema(self, object_name: str) -> Dict[str, Any]:
        meta = self.client.get_metadata()
        es = (meta.get("entity_sets") or {}).get(object_name)
        return {
            "http_code": self.client.get_http_code(),
            "http_message": self.client.get_http_message(),
            "odata_error_code": self.client.get_error_code(),
            "odata_error_message": self.client.get_error_message(),
            "schema": es,
        }

    # ----------------------- Высокоуровневые операции -----------------------

    def search_object(
        self,
        user_type: str,
        user_entity: str,
        user_filters: Optional[Union[str, Dict[str, Any], List[str]]] = None,
        top: Optional[int] = 1,
        expand: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Найти сущность с резолвом имени и синонимов полей."""
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

        resolved_filters: Union[str, Dict[str, Any], List[str], None] = None
        if isinstance(user_filters, dict):
            resolved_filters = {}
            for k, v in user_filters.items():
                field = self.resolve_field_name(object_name, k) or k
                resolved_filters[field] = v
        else:
            resolved_filters = user_filters

        if top is not None and int(top) <= 1:
            return self.find_object(object_name, filters=resolved_filters, expand=expand)
        return self.list_objects(object_name, filters=resolved_filters, top=top, expand=expand)

    def ensure_entity(
        self,
        user_type: str,
        user_entity: str,
        data_or_filters: Union[Dict[str, Any], str],
        expand: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Найти элемент; если не найден — создать (данные берутся из dict)."""
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
        """Создать документ + табличные части; опционально провести."""
        # 1) Шапка
        created = self.create_object(object_name, header or {})
        if not (200 <= (created.get("http_code") or 0) < 300) or not created.get("last_id"):
            return {"step": "create_header", **created}

        doc_id = created["last_id"]
        result: Dict[str, Any] = {"header": created, "table_parts": {}}

        # 2) Табличные части (каждая строка — POST в /<Document>(guid)/<ТЧ>)
        if rows:
            for tp_name, tp_rows in (rows or {}).items():
                builder = getattr(self.client, object_name).id(doc_id)
                tp_endpoint = getattr(builder, tp_name)
                tp_results: List[Dict[str, Any]] = []

                for row in (tp_rows or []):
                    resolved_row = self._resolve_refs_in_payload(f"{object_name}_{tp_name}", row)
                    resp = tp_endpoint.create(resolved_row)
                    tp_results.append(self._result_from_response(resp, self.client))

                result["table_parts"][tp_name] = tp_results

        # 3) Постинг
        if post:
            result["post"] = self.post_document(object_name, doc_id)

        return result


# -----------------------------------------------------------------------------
# FastMCP: определение инструментов (все возвращают Result(data=...))
# -----------------------------------------------------------------------------

BASE_URL = os.getenv("MCP_1C_BASE", "")
USERNAME = os.getenv("ONEC_USERNAME")
PASSWORD = os.getenv("ONEC_PASSWORD")
VERIFY_SSL = os.getenv("ONEC_VERIFY_SSL", "false").lower() not in {"false", "0", "no"}

_server = MCPServer(BASE_URL, username=USERNAME, password=PASSWORD, verify_ssl=VERIFY_SSL)
mcp = FastMCP("mcp_1c")


@mcp.tool()
async def list_entity_sets() -> Result:
    """Вернуть список всех сущностей (EntitySets)."""
    data = await asyncio.to_thread(_server.list_entity_sets)
    return Result(data={"entity_sets": data})


@mcp.tool()
async def get_schema(object_name: str) -> Result:
    """Вернуть схему (свойства и типы) указанной сущности."""
    data = await asyncio.to_thread(_server.get_schema, object_name)
    return Result(data=data)


@mcp.tool()
async def resolve_entity_name(user_entity: str, user_type: Optional[str] = None) -> Result:
    """Преобразовать «человеческое» имя + тип в имя сущности OData (например, Catalog_Номенклатура)."""
    data = await asyncio.to_thread(_server.resolve_entity_name, user_entity, user_type)
    return Result(data={"resolved": data})


@mcp.tool()
async def resolve_field_name(object_name: str, user_field: str) -> Result:
    """Преобразовать «человеческое» имя поля в реальное свойство сущности."""
    data = await asyncio.to_thread(_server.resolve_field_name, object_name, user_field)
    return Result(data={"resolved": data})


@mcp.tool()
async def list_objects(
    object_name: str,
    filters: Optional[Union[str, Dict[str, Any], List[str]]] = None,
    top: Optional[int] = None,
    expand: Optional[str] = None,
) -> Result:
    """Вернуть список объектов сущности (с фильтром/$top/$expand)."""
    data = await asyncio.to_thread(_server.list_objects, object_name, filters, top, expand)
    return Result(data=data)


@mcp.tool()
async def find_object(
    object_name: str,
    filters: Optional[Union[str, Dict[str, Any], List[str]]] = None,
    expand: Optional[str] = None,
) -> Result:
    """Вернуть первый объект сущности, соответствующий фильтру."""
    data = await asyncio.to_thread(_server.find_object, object_name, filters, expand)
    return Result(data=data)


@mcp.tool()
async def create_object(
    object_name: str,
    data: Dict[str, Any],
    expand: Optional[str] = None,
) -> Result:
    """Создать объект сущности."""
    res = await asyncio.to_thread(_server.create_object, object_name, data, expand)
    return Result(data=res)


@mcp.tool()
async def update_object(
    object_name: str,
    object_id: Union[str, Dict[str, str]],
    data: Dict[str, Any],
    expand: Optional[str] = None,
) -> Result:
    """Обновить существующий объект."""
    res = await asyncio.to_thread(_server.update_object, object_name, object_id, data, expand)
    return Result(data=res)


@mcp.tool()
async def delete_object(
    object_name: str,
    object_id: Union[str, Dict[str, str]],
    physical_delete: bool = False,
) -> Result:
    """Удалить объект (по умолчанию — логическое удаление через DeletionMark)."""
    res = await asyncio.to_thread(_server.delete_object, object_name, object_id, physical_delete)
    return Result(data=res)


@mcp.tool()
async def post_document(
    object_name: str,
    object_id: Union[str, Dict[str, str]],
) -> Result:
    """Провести документ."""
    res = await asyncio.to_thread(_server.post_document, object_name, object_id)
    return Result(data=res)


@mcp.tool()
async def unpost_document(
    object_name: str,
    object_id: Union[str, Dict[str, str]],
) -> Result:
    """Отменить проведение документа."""
    res = await asyncio.to_thread(_server.unpost_document, object_name, object_id)
    return Result(data=res)


@mcp.tool()
async def search_object(
    user_type: str,
    user_entity: str,
    user_filters: Optional[Union[str, Dict[str, Any], List[str]]] = None,
    top: Optional[int] = 1,
    expand: Optional[str] = None,
) -> Result:
    """Найти объект(ы) с резолвом имени сущности и синонимов полей."""
    res = await asyncio.to_thread(_server.search_object, user_type, user_entity, user_filters, top, expand)
    return Result(data=res)


@mcp.tool()
async def ensure_entity(
    user_type: str,
    user_entity: str,
    data_or_filters: Union[Dict[str, Any], str],
    expand: Optional[str] = None,
) -> Result:
    """Найти элемент, или создать при отсутствии (по dict-данным)."""
    res = await asyncio.to_thread(_server.ensure_entity, user_type, user_entity, data_or_filters, expand)
    return Result(data=res)


@mcp.tool()
async def create_document(
    object_name: str,
    header: Dict[str, Any],
    rows: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    post: bool = False,
) -> Result:
    """Создать документ; заполнить табличные части; при необходимости — провести."""
    res = await asyncio.to_thread(_server.create_document_with_rows, object_name, header, rows, post)
    return Result(data=res)


# ASGI-приложение
app = mcp.streamable_http_app()

if __name__ == "__main__":
    mcp.run("streamable-http")
