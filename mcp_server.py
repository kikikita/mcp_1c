"""Enhanced MCP server exposing 1C OData operations as callable tools for LLM agents.

This module extends the original MCP server by adding higher level helper
functions for discovering entity sets, resolving human readable names to
concrete OData entity set identifiers, inspecting schema metadata and
performing fuzzy field name matching.  These additions allow a language
model to translate natural language queries into proper OData calls
without hardcoding specific object names or property identifiers.  The
core CRUD operations remain unchanged; additional tools provide a more
ergonomic interface for typical business scenarios (e.g. searching
catalogues or documents by name or code, listing available entity sets).

Key improvements over the base implementation:

* A method to list all entity sets exposed by the 1C service.  This
  enables discovery of available catalogues, documents, registers, etc.
* Helpers to map a user‑supplied type name (e.g. "справочник") and
  entity name (e.g. "Номенклатура") to the proper OData entity set
  identifier (e.g. ``Catalog_Номенклатура``).  The mapping uses simple
  string normalisation and prefix matching against the service metadata.
* Helpers to map a human readable field name (e.g. "наименование") to
  the appropriate property defined on the entity set (e.g. ``Description``
  or ``Наименование``).  A small synonym dictionary is provided and the
  algorithm falls back to case‑insensitive matching.
* A high level search tool (`search_object`) which encapsulates the
  entity and field resolution logic.  It takes natural language type
  and name along with user supplied filters, resolves the correct
  entity set and property names and dispatches to either ``find_object``
  or ``list_objects`` depending on the desired number of results.

These additions are intended to be consumed by an LLM orchestrator.  The
language model can first list the available entity sets, inspect the
schema of a candidate entity, then construct the correct call
parameters without manual intervention by an engineer.
"""

from __future__ import annotations

import asyncio
import os
import json
import re
from typing import Any, Dict, List, Optional, Union, Tuple
import logging

from mcp.server.fastmcp import FastMCP
from odata_client import ODataClient, _is_guid
from log_config import setup_logging

setup_logging()
logger = logging.getLogger(__name__)


class MCPServer:
    """Encapsulates business level operations on top of the OData client.

    In addition to the basic CRUD methods exposed in the base version, this
    class now provides high level helpers for entity discovery and fuzzy
    matching of object and field names based on the service metadata.  See
    the accompanying tool functions for the asynchronous wrappers exposed to
    FastMCP.
    """

    # Mapping of Russian entity type words to OData prefixes.  Both
    # singular and plural forms are supported.  Feel free to extend this
    # dictionary with other languages or domain specific aliases as needed.
    ENTITY_TYPE_PREFIX: Dict[str, str] = {
        "справочник": "Catalog_",
        "справочники": "Catalog_",
        "catalog": "Catalog_",
        "catalogs": "Catalog_",
        "каталог": "Catalog_",
        "каталоги": "Catalog_",
        "document": "Document_",
        "documents": "Document_",
        "документ": "Document_",
        "документы": "Document_",
        "журнал": "DocumentJournal_",
        "журналы": "DocumentJournal_",
        "constant": "Constant_",
        "constants": "Constant_",
        "константа": "Constant_",
        "константы": "Constant_",
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

    # Synonyms for field names.  Keys are lowercased user supplied
    # descriptors; values are lists of property names to try in order.  This
    # mapping can be extended with additional synonyms specific to a
    # particular 1C configuration.  If a synonym is not found, the
    # resolution algorithm falls back to case insensitive matching and
    # finally to the Description field if present.
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

    def __init__(self, base_url: str, username: Optional[str] = None, password: Optional[str] = None,
                 timeout: int = 30, verify_ssl: bool = False) -> None:
        self.client = ODataClient(base_url, username=username, password=password,
                                  timeout=timeout, verify_ssl=verify_ssl)

    # ------------------------------------------------------------------
    # Helper methods for filter building and result parsing (unchanged)
    # ------------------------------------------------------------------

    @staticmethod
    def _build_filter(filters: Union[Dict[str, Any], List[str], None]) -> Optional[str]:
        """Convert a dictionary or list of conditions into an OData filter string.

        The simplest form accepts a mapping of field names to literal values and
        joins them with ``and``.  String values are quoted, GUIDs are wrapped
        using the ``guid'...'`` literal and numeric/boolean values are passed
        through.  You can also pass a list of raw filter expressions which
        will be joined with ``and`` verbatim.  If ``filters`` is already a
        string it is returned unchanged.
        """
        if filters is None:
            return None
        if isinstance(filters, str):
            return filters
        if isinstance(filters, list):
            return " and ".join(filt for filt in filters if filt)
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
                    elif _is_guid(value):
                        exprs.append(f"{key} eq guid'{value}'")
                    else:
                        safe = value.replace("'", "''")
                        exprs.append(f"{key} eq '{safe}'")
                else:
                    exprs.append(f"{key} eq '{value}'")
            return " and ".join(exprs)
        return None

    @staticmethod
    def _parse_result(response, client: ODataClient) -> Dict[str, Any]:
        """Return a unified result dictionary from an ODataResponse."""
        return {
            "http_code": client.get_http_code(),
            "http_message": client.get_http_message(),
            "odata_error_code": client.get_error_code(),
            "odata_error_message": client.get_error_message(),
            "last_id": client.get_last_id(),
            "data": response.values() if hasattr(response, "values") else None,
        }

    # ------------------------------------------------------------------
    # Metadata based helpers
    # ------------------------------------------------------------------
    def _resolve_reference(self, ref_spec: Any) -> Optional[str]:
        """
        Если значение поля — словарь вида:
            {"user_type": "...", "user_entity": "...", "filters": {...}, "top": 1}
        вернёт Ref_Key найденного объекта (или создаст при ensure_entity).
        """
        if not isinstance(ref_spec, dict):
            return None
        utype = ref_spec.get("user_type")
        uent = ref_spec.get("user_entity")
        ufilters = ref_spec.get("filters")
        top = ref_spec.get("top", 1)
        if not (utype and uent):
            return None
        res = self.search_object(utype, uent, ufilters, top=top)
        data = res.get("data")
        if isinstance(data, dict):
            return data.get("Ref_Key")
        if isinstance(data, list) and data:
            return data[0].get("Ref_Key")
        return None

    def _resolve_refs_in_payload(self, object_name: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Пройдёт по полям payload; если значение словарь-спецификация ссылки — подставит *_Key.
        """
        schema = self.get_entity_schema(object_name) or {}
        props = (schema.get("properties") or {})
        out = {}
        for k, v in (payload or {}).items():
            field = self.resolve_field_name(object_name, k) or k
            # Если это *_Key и значение-спецификация — резолвим
            if (field.endswith("_Key") or field.endswith("Key")) and isinstance(v, dict):
                guid = self._resolve_reference(v)
                out[field] = guid or v
            else:
                out[field] = v
        return out


    def ensure_entity(self, user_type: str, user_entity: str,
                      data_or_filters: Union[Dict[str, Any], str],
                      expand: Optional[str] = None) -> Dict[str, Any]:
        """
        Найти элемент по фильтрам; если не найден — создать.
        data_or_filters: если dict — используется и как фильтр, и как данные при создании.
                         если str — это готовый $filter.
        """
        object_name = self.resolve_entity_name(user_entity, user_type)
        if not object_name:
            return {"http_code": None, "odata_error_message": f"Unknown entity {user_entity}"}
        filters = data_or_filters
        # сначала ищем
        found = self.find_object(object_name, filters=filters, expand=expand)
        if found.get("data"):
            return found
        # создаём: маппим поля/синонимы
        data = data_or_filters if isinstance(data_or_filters, dict) else {}
        data = self._resolve_refs_in_payload(object_name, data)
        created = self.create_object(object_name, data, expand=expand)
        return created

    def create_document_with_rows(self, object_name: str, header: Dict[str, Any],
                                  rows: Optional[Dict[str, List[Dict[str, Any]]]] = None,
                                  post: bool = False) -> Dict[str, Any]:
        """
        Создать документ:
          - object_name: например, "Document_ПоступлениеТоваров"
          - header: поля шапки (могут содержать спецификации ссылок)
          - rows: {"Товары": [ {...}, ... ], "Услуги": [ ... ]} — имена ТЧ как в конфигурации
        """
        # 1) Шапка
        header_resolved = self._resolve_refs_in_payload(object_name, header or {})
        created = self.create_object(object_name, header_resolved)
        if not (200 <= (created.get("http_code") or 0) < 300):
            return {"step": "create", **created}

        doc_id = created.get("last_id")
        results = {"header": created, "table_parts": {}}

        # 2) Табличные части
        if rows:
            for tp_name, tp_rows in rows.items():
                # резолв ссылок и синонимов в строках
                normalized_rows = []
                for r in tp_rows or []:
                    r2 = self._resolve_refs_in_payload(object_name + "_" + tp_name, r)
                    normalized_rows.append(r2)
                posted = self.client.add_table_part_rows(object_name, doc_id, tp_name, normalized_rows)
                results["table_parts"][tp_name] = posted

        # 3) Постинг
        if post:
            posted = self.post_document(object_name, doc_id)
            results["post"] = posted
        return results

    def list_entity_sets(self) -> List[str]:
        """Return a list of all entity set names exposed by the OData service."""
        meta = self.client.get_metadata()
        return list(meta.get("entity_sets", {}).keys())

    def get_entity_schema(self, object_name: str) -> Optional[Dict[str, Any]]:
        """Return the schema (properties and types) for the given entity set."""
        meta = self.client.get_metadata()
        return meta.get("entity_sets", {}).get(object_name)

    def resolve_entity_name(self, user_entity: str, user_type: Optional[str] = None) -> Optional[str]:
        """Resolve a human readable entity name to a concrete OData entity set.

        The resolution algorithm is as follows:

        1. Normalise the user supplied entity name by removing whitespace and
           converting to lowercase.  For example, "Физические лица" becomes
           "физическиелица".
        2. If a user_type is provided (e.g. "справочник"), translate it to
           the appropriate prefix (e.g. ``Catalog_``) via
           :data:`ENTITY_TYPE_PREFIX`.  Only entity sets starting with that
           prefix will be considered.
        3. Iterate over all entity sets from the service metadata and find
           those whose suffix (the part after the prefix) matches the
           normalised user name.  The match is case insensitive and ignores
           whitespace.
        4. If exactly one match is found, return it.  If multiple matches
           exist, return the one with the longest common subsequence.  If
           no matches are found, return ``None``.

        :param user_entity: Raw name of the entity as provided by the user.
        :param user_type: Optional human readable type (e.g. "справочник").
        :returns: Name of the entity set (e.g. ``Catalog_Контрагенты``) or
            ``None`` if no reasonable match exists.
        """
        if not user_entity:
            return None
        # Normalise the entity name: remove spaces, lower case
        normalised = re.sub(r"\s+", "", user_entity).lower()
        # Determine candidate prefixes
        prefixes: List[str]
        if user_type:
            pfx = self.ENTITY_TYPE_PREFIX.get(user_type.strip().lower())
            prefixes = [pfx] if pfx else []
        else:
            # If no type provided search across all known prefixes
            prefixes = list(set(self.ENTITY_TYPE_PREFIX.values()))
        if not prefixes:
            # No prefix mapping found; fall back to all entity sets
            prefixes = [""]
        meta = self.client.get_metadata()
        candidates: List[str] = []
        entity_sets: Dict[str, Any] = meta.get("entity_sets", {})
        for es_name in entity_sets.keys():
            # Determine the prefix and suffix of this entity set
            for pfx in prefixes:
                if es_name.startswith(pfx):
                    suffix = es_name[len(pfx):]
                    # normalise suffix
                    suffix_norm = re.sub(r"\s+", "", suffix).lower()
                    if suffix_norm == normalised:
                        return es_name
                    if normalised in suffix_norm:
                        candidates.append(es_name)
        # If exact match not found, try fuzzy: choose the candidate with longest match
        if candidates:
            # sort by length of suffix match descending then alphabetically
            def sort_key(name: str) -> Tuple[int, str]:
                suffix = name.split("_", 1)[-1]
                suffix_norm = re.sub(r"\s+", "", suffix).lower()
                # compute overlap length
                overlap = len(os.path.commonprefix([suffix_norm, normalised]))
                return (overlap, name)
            candidates.sort(key=sort_key, reverse=True)
            return candidates[0]
        return None

    def resolve_field_name(self, object_name: str, user_field: str) -> Optional[str]:
        """Resolve a human readable field name to an actual property on an entity.

        The resolution algorithm uses the following steps:

        1. If the user_field (after lowercasing and stripping whitespace) is
           found in :data:`FIELD_SYNONYMS`, iterate through the list of
           preferred property names.  If one of those exists on the entity
           schema, return it.
        2. Perform a case insensitive exact match of the user_field against
           the available properties.  If a match is found, return it.
        3. Perform a case insensitive containment check: if the user_field
           appears as a substring of a property name or vice versa, return
           that property.
        4. If the entity defines a ``Description`` property, return it as a
           generic fallback since most catalogues use this for human
           readable names.  If ``Наименование`` is present, return it.
        5. Finally return ``None`` if no match can be determined.

        :param object_name: Resolved OData entity set name.
        :param user_field: Raw field name from the user query.
        :returns: Property name as defined in the entity schema or ``None``.
        """
        if not user_field:
            return None
        schema = self.get_entity_schema(object_name)
        if not schema:
            return None
        props: Dict[str, Dict[str, Any]] = schema.get("properties", {})
        keys = list(props.keys())
        # Step 1: check synonyms
        key_lower = user_field.strip().lower()
        if key_lower in self.FIELD_SYNONYMS:
            for candidate in self.FIELD_SYNONYMS[key_lower]:
                if candidate in props:
                    return candidate
        # Step 2: exact case insensitive match
        for prop in keys:
            if prop.lower() == key_lower:
                return prop
        # Step 3: substring match
        for prop in keys:
            pname = prop.lower()
            if key_lower in pname or pname in key_lower:
                return prop
        # Step 4: use common fields
        if "Description" in props:
            return "Description"
        if "Наименование" in props:
            return "Наименование"
        return None

    # ------------------------------------------------------------------
    # Core CRUD and business operations (mostly unchanged)
    # ------------------------------------------------------------------

    def list_objects(self, object_name: str, filters: Optional[Union[str, Dict[str, Any], List[str]]] = None,
                      top: Optional[int] = None, expand: Optional[str] = None) -> Dict[str, Any]:
        """Return a list of entities from the specified entity set.

        :param object_name: Name of the entity set (e.g. ``Catalog_Номенклатура``).
        :param filters: Optional filter specification.  See :meth:`_build_filter`.
        :param top: Optional maximum number of records to return.
        :param expand: Optional comma separated list of navigation properties to expand.
        :return: Dictionary containing metadata and the list under the ``data`` key.
        """
        builder = getattr(self.client, object_name)
        if expand:
            builder = builder.expand(expand)
        if top is not None:
            builder = builder.top(int(top))
        if filters:
            filt = self._build_filter(filters)
            if filt:
                builder = builder.filter(filt)
        response = builder.get()
        return self._parse_result(response, self.client)

    def find_object(self, object_name: str, filters: Optional[Union[str, Dict[str, Any], List[str]]] = None,
                    expand: Optional[str] = None) -> Dict[str, Any]:
        """Return the first entity that matches the given filter.

        :param object_name: Name of the entity set.
        :param filters: Filter specification.  See :meth:`_build_filter`.
        :param expand: Optional navigation properties to expand.
        :return: Result dictionary.  The ``data`` key will contain either a
            single record or be ``None`` if nothing matched.
        """
        builder = getattr(self.client, object_name)
        if expand:
            builder = builder.expand(expand)
        if filters:
            filt = self._build_filter(filters)
            if filt:
                builder = builder.filter(filt)
        builder = builder.top(1)
        response = builder.get()
        result = self._parse_result(response, self.client)
        vals = result.get("data") or []
        result["data"] = vals[0] if vals else None
        return result

    def create_object(self, object_name: str, data: Dict[str, Any], expand: Optional[str] = None) -> Dict[str, Any]:
        """Create a new entity and return its identifier.

        :param object_name: Name of the entity set.
        :param data: Dictionary of field names and values to populate on the new entity.
        :param expand: Optional navigation properties to expand in the returned payload.
        :return: Result dictionary.  ``last_id`` will contain the new Ref_Key.
        """
        builder = getattr(self.client, object_name)
        if expand:
            builder = builder.expand(expand)
        response = builder.create(data)
        return self._parse_result(response, self.client)

    def update_object(self, object_name: str, object_id: Union[str, Dict[str, str]], data: Dict[str, Any],
                      expand: Optional[str] = None) -> Dict[str, Any]:
        """Update an existing entity.

        :param object_name: Name of the entity set.
        :param object_id: GUID or composite key identifying the entity.
        :param data: Dictionary of fields to update.
        :param expand: Optional navigation properties to expand in the returned payload.
        :return: Result dictionary.
        """
        builder = getattr(self.client, object_name).id(object_id)
        if expand:
            builder = builder.expand(expand)
        response = builder.update(data=data)
        return self._parse_result(response, self.client)

    def delete_object(self, object_name: str, object_id: Union[str, Dict[str, str]],
                      physical_delete: bool = False) -> Dict[str, Any]:
        """Delete an entity by marking it or removing it entirely.

        :param object_name: Name of the entity set.
        :param object_id: GUID or composite key.
        :param physical_delete: If ``True`` perform a physical deletion via
            HTTP DELETE.  Otherwise perform a logical deletion by setting
            ``DeletionMark`` to ``true`` via :meth:`update_object`.
        :return: Result dictionary.
        """
        if physical_delete:
            builder = getattr(self.client, object_name).id(object_id)
            response = builder.delete()
            return self._parse_result(response, self.client)
        return self.update_object(object_name, object_id, {"DeletionMark": True})

    def post_document(self, object_name: str, object_id: Union[str, Dict[str, str]]) -> Dict[str, Any]:
        """Conduct (post) a document.

        :param object_name: Name of the document entity set (e.g. ``Document_ПлатежноеПоручение``).
        :param object_id: GUID identifying the document.
        :return: Result dictionary.
        """
        builder = getattr(self.client, object_name).id(object_id)
        response = builder("Post")
        return self._parse_result(response, self.client)

    def unpost_document(self, object_name: str, object_id: Union[str, Dict[str, str]]) -> Dict[str, Any]:
        """Reverse (unpost) a document.

        :param object_name: Name of the document entity set.
        :param object_id: GUID identifying the document.
        :return: Result dictionary.
        """
        builder = getattr(self.client, object_name).id(object_id)
        response = builder("Unpost")
        return self._parse_result(response, self.client)

    def get_schema(self, object_name: str) -> Dict[str, Any]:
        """Return the metadata for the specified entity set.

        The returned dictionary contains the entity type and a mapping of
        property names to their EDM types.
        """
        meta = self.client.get_metadata()
        es = meta.get("entity_sets", {}).get(object_name)
        return {
            "http_code": self.client.get_http_code(),
            "http_message": self.client.get_http_message(),
            "odata_error_code": self.client.get_error_code(),
            "odata_error_message": self.client.get_error_message(),
            "schema": es,
        }

    # ------------------------------------------------------------------
    # High level search helper
    # ------------------------------------------------------------------

    def search_object(self, user_type: str, user_entity: str,
                      user_filters: Optional[Union[str, Dict[str, Any], List[str]]] = None,
                      top: Optional[int] = 1, expand: Optional[str] = None) -> Dict[str, Any]:
        """Search an entity set using human friendly names and filters.

        This helper resolves the entity set and property names before
        delegating to :meth:`find_object` or :meth:`list_objects`.

        :param user_type: Human readable type (e.g. "справочник", "документ").
        :param user_entity: Name of the entity (e.g. "Номенклатура").
        :param user_filters: Filter criteria provided by the user.  When a
            dictionary is supplied the keys are assumed to be human
            friendly field names and will be resolved via
            :meth:`resolve_field_name`.  Raw strings or lists are
            forwarded unchanged.
        :param top: Maximum number of results.  Use 1 for a single entity.
        :param expand: Optional ``$expand`` parameter.
        :returns: Result dictionary similar to the CRUD methods.  If the
            entity set cannot be resolved an error will be returned in the
            ``odata_error_message`` field.
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
        # Map user_filters to actual property names if needed
        resolved_filters: Union[str, Dict[str, Any], List[str], None] = None
        if isinstance(user_filters, dict):
            resolved_filters = {}
            for k, v in user_filters.items():
                field_name = self.resolve_field_name(object_name, k)
                if field_name:
                    resolved_filters[field_name] = v
                else:
                    # use original key if resolution fails
                    resolved_filters[k] = v
        else:
            resolved_filters = user_filters
        # Dispatch to appropriate CRUD method
        if top is not None and int(top) <= 1:
            return self.find_object(object_name, filters=resolved_filters, expand=expand)
        return self.list_objects(object_name, filters=resolved_filters, top=top, expand=expand)


# ---------------------------------------------------------------------------
# FastMCP integration and tool definitions
# ---------------------------------------------------------------------------

# Configuration
BASE_URL = os.getenv("MCP_1C_BASE", "")
USERNAME = os.getenv("ONEC_USERNAME")
PASSWORD = os.getenv("ONEC_PASSWORD")
VERIFY_SSL = os.getenv("ONEC_VERIFY_SSL", "false").lower() not in {"false", "0", "no"}

_server = MCPServer(BASE_URL, username=USERNAME, password=PASSWORD, verify_ssl=VERIFY_SSL)

mcp = FastMCP("mcp_1c")


@mcp.tool()
async def resolve_entity_name(user_entity: str, user_type: Optional[str] = None) -> Dict[str, Any]:
    res = await asyncio.to_thread(_server.resolve_entity_name, user_entity, user_type)
    return {"resolved": res}


@mcp.tool()
async def resolve_field_name(object_name: str, user_field: str) -> Dict[str, Any]:
    res = await asyncio.to_thread(_server.resolve_field_name, object_name, user_field)
    return {"resolved": res}


@mcp.tool()
async def ensure_entity(
    user_type: str,
    user_entity: str,
    data_or_filters: Union[Dict[str, Any], str],
    expand: Optional[str] = None,
) -> Dict[str, Any]:
    res = await asyncio.to_thread(_server.ensure_entity, user_type, user_entity, data_or_filters, expand)
    return res


@mcp.tool()
async def create_document(
    object_name: str,
    header: Dict[str, Any],
    rows: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    post: bool = False,
) -> Dict[str, Any]:
    res = await asyncio.to_thread(_server.create_document_with_rows, object_name, header, rows, post)
    return res


@mcp.tool()
async def list_objects(
    object_name: str,
    filters: Optional[Union[str, Dict[str, Any], List[str]]] = None,
    top: Optional[int] = None,
    expand: Optional[str] = None,
) -> Dict[str, Any]:
    """Return a list of entities from the specified entity set.

    This function wraps :meth:`MCPServer.list_objects` and simply forwards
    its arguments.  Use this tool when you already know the exact name of
    the entity set (e.g. ``Catalog_Номенклатура``) and wish to apply an
    arbitrary filter or paging options.
    """
    logger.debug("list_objects called with object_name=%s filters=%s top=%s expand=%s", object_name, filters, top, expand)
    result = await asyncio.to_thread(_server.list_objects, object_name, filters, top, expand)
    logger.debug("list_objects result: %s", result)
    return result


@mcp.tool()
async def find_object(
    object_name: str,
    filters: Optional[Union[str, Dict[str, Any], List[str]]] = None,
    expand: Optional[str] = None,
) -> Dict[str, Any]:
    """Return the first entity matching the filter from the specified entity set."""
    logger.debug("find_object called with object_name=%s filters=%s expand=%s", object_name, filters, expand)
    result = await asyncio.to_thread(_server.find_object, object_name, filters, expand)
    logger.debug("find_object result: %s", result)
    return result


@mcp.tool()
async def create_object(
    object_name: str,
    data: Dict[str, Any],
    expand: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a new entity in the specified entity set."""
    logger.debug("create_object called with object_name=%s data=%s expand=%s", object_name, data, expand)
    result = await asyncio.to_thread(_server.create_object, object_name, data, expand)
    logger.debug("create_object result: %s", result)
    return result


@mcp.tool()
async def update_object(
    object_name: str,
    object_id: Union[str, Dict[str, str]],
    data: Dict[str, Any],
    expand: Optional[str] = None,
) -> Dict[str, Any]:
    """Update fields of an existing entity."""
    logger.debug("update_object called with object_name=%s object_id=%s data=%s expand=%s", object_name, object_id, data, expand)
    result = await asyncio.to_thread(_server.update_object, object_name, object_id, data, expand)
    logger.debug("update_object result: %s", result)
    return result


@mcp.tool()
async def delete_object(
    object_name: str,
    object_id: Union[str, Dict[str, str]],
    physical_delete: bool = False,
) -> Dict[str, Any]:
    """Delete an entity (logical by default)."""
    logger.debug("delete_object called with object_name=%s object_id=%s physical_delete=%s", object_name, object_id, physical_delete)
    result = await asyncio.to_thread(_server.delete_object, object_name, object_id, physical_delete)
    logger.debug("delete_object result: %s", result)
    return result


@mcp.tool()
async def post_document(
    object_name: str,
    object_id: Union[str, Dict[str, str]],
) -> Dict[str, Any]:
    """Conduct (post) a document."""
    logger.debug("post_document called with object_name=%s object_id=%s", object_name, object_id)
    result = await asyncio.to_thread(_server.post_document, object_name, object_id)
    logger.debug("post_document result: %s", result)
    return result


@mcp.tool()
async def unpost_document(
    object_name: str,
    object_id: Union[str, Dict[str, str]],
) -> Dict[str, Any]:
    """Reverse a previously posted document."""
    logger.debug("unpost_document called with object_name=%s object_id=%s", object_name, object_id)
    result = await asyncio.to_thread(_server.unpost_document, object_name, object_id)
    logger.debug("unpost_document result: %s", result)
    return result


@mcp.tool()
async def get_schema(object_name: str) -> Dict[str, Any]:
    """Retrieve metadata (properties and types) for the specified entity set."""
    logger.debug("get_schema called with object_name=%s", object_name)
    result = await asyncio.to_thread(_server.get_schema, object_name)
    logger.debug("get_schema result: %s", result)
    return result


@mcp.tool()
async def list_entity_sets() -> Dict[str, Any]:
    """Return the list of entity sets available on the 1C OData service."""
    logger.debug("list_entity_sets called")
    result = await asyncio.to_thread(_server.list_entity_sets)
    return {"entity_sets": result}


@mcp.tool()
async def search_object(
    user_type: str,
    user_entity: str,
    user_filters: Optional[Union[str, Dict[str, Any], List[str]]] = None,
    top: Optional[int] = 1,
    expand: Optional[str] = None,
) -> Dict[str, Any]:
    """Search an entity set using human friendly names and filters.

    This tool encapsulates the entity name and field name resolution logic.  It
    allows a language model to issue queries like "Найди контрагента по
    наименованию Тест" without having to know that the underlying entity set
    is ``Catalog_Контрагенты`` and the correct property is ``Description``.

    :param user_type: Human readable type of the entity (e.g. "справочник").
    :param user_entity: Human readable name of the catalogue or document.
    :param user_filters: Filter conditions using human readable field names.
    :param top: Maximum number of results to return; defaults to 1.
    :param expand: Optional ``$expand`` value to include related entities.
    :returns: A dictionary containing the HTTP and OData status along with the
        matching entities under the ``data`` key.
    """
    logger.debug(
        "search_object called with user_type=%s user_entity=%s user_filters=%s top=%s expand=%s",
        user_type, user_entity, user_filters, top, expand,
    )
    result = await asyncio.to_thread(_server.search_object, user_type, user_entity, user_filters, top, expand)
    logger.debug("search_object result: %s", result)
    return result


# Expose ASGI application for uvicorn/ASGI servers
app = mcp.streamable_http_app()

if __name__ == "__main__":
    mcp.run("streamable-http")
