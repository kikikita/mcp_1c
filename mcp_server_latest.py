"""
Universal Model Context Protocol (MCP) server for interacting with 1C via OData.

This module exposes a set of high‑level helper functions ("tools") that wrap
the underlying :class:`ODataClient` and provide a simple JSON interface to
typical 1C operations.  Each tool corresponds to an atomic action such as
listing entities, finding a specific entity, creating or updating records,
conducting documents and retrieving metadata.  By combining these tools a
language model can automate complex workflows without needing to know the
details of the 1C schema ahead of time.

Example usage:

    from mcp_server import MCPServer

    mcp = MCPServer(
        base_url="http://192.168.18.113/TEST19/odata/standard.odata",
        username="user",
        password="pass"
    )

    # List the first 5 contractors whose name contains "Элитан"
    result = mcp.list_objects("Catalog_Контрагенты", filters={"Description": "contains 'Элитан'"}, top=5)
    print(result)

Note:
    The tools defined in this module are designed to be serialised into
    machine‑readable JSON schemas for use with function calling APIs.  To that
    end there is a module level ``TOOLS`` list describing each tool.  See
    the bottom of this file for details.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Union

from odata_client import ODataClient, _is_guid


class MCPServer:
    """Encapsulates business level operations on top of the OData client."""

    def __init__(self, base_url: str, username: Optional[str] = None, password: Optional[str] = None,
                 timeout: int = 30, verify_ssl: bool = False) -> None:
        self.client = ODataClient(base_url, username=username, password=password,
                                  timeout=timeout, verify_ssl=verify_ssl)

    # ------------------------------------------------------------------
    # Helper methods
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
        # If user provides a string just return it
        if isinstance(filters, str):
            return filters
        # If a list is provided treat each element as a complete expression
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
                    # If the value looks like an expression (contains space or operator) then use as is
                    if re.search(r"\s(and|or|eq|ne|gt|lt|ge|le)\s", value, re.IGNORECASE):
                        exprs.append(f"{key} {value}")
                    elif _is_guid(value):
                        exprs.append(f"{key} eq guid'{value}'")
                    else:
                        # Escape single quotes by doubling them
                        safe = value.replace("'", "''")
                        exprs.append(f"{key} eq '{safe}'")
                else:
                    # Fallback to string conversion
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
    # Tool implementations
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
        # Apply query options
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
        # Only request one record by default
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
        # Logical delete
        return self.update_object(object_name, object_id, {"DeletionMark": True})

    def post_document(self, object_name: str, object_id: Union[str, Dict[str, str]]) -> Dict[str, Any]:
        """Conduct (post) a document.

        :param object_name: Name of the document entity set (e.g. ``Document_ПлатежноеПоручение``).
        :param object_id: GUID identifying the document.
        :return: Result dictionary.
        """
        builder = getattr(self.client, object_name).id(object_id)
        response = builder("Post")  # invoke Post action
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


# ----------------------------------------------------------------------
# Tool definitions for function calling APIs
#
# Each entry in ``TOOLS`` describes an MCP operation.  ``name`` is the
# externally visible identifier; ``func_name`` is the method on the
# :class:`MCPServer` instance; ``description`` should be clear and succinct;
# ``parameters`` defines the JSON schema for the tool's arguments.
# ----------------------------------------------------------------------

TOOLS = [
    {
        "name": "list_objects",
        "func_name": "list_objects",
        "description": "Retrieve a collection of entities from a specified 1C entity set.",
        "parameters": {
            "type": "object",
            "properties": {
                "object_name": {
                    "type": "string",
                    "description": "Name of the entity set (e.g., Catalog_Номенклатура, Document_ПоступлениеТоваров)."
                },
                "filters": {
                    "oneOf": [
                        {"type": "object", "description": "Mapping of field names to literal values.  Values may contain OData expressions."},
                        {"type": "string", "description": "Raw OData filter string."},
                        {"type": "array", "items": {"type": "string"}, "description": "List of raw filter expressions to be joined with 'and'."}
                    ],
                    "description": "Optional filter criteria."
                },
                "top": {
                    "type": "integer",
                    "description": "Maximum number of records to return.",
                    "minimum": 1
                },
                "expand": {
                    "type": "string",
                    "description": "Comma separated list of navigation properties to expand."
                }
            },
            "required": ["object_name"],
            "additionalProperties": False
        }
    },
    {
        "name": "find_object",
        "func_name": "find_object",
        "description": "Retrieve the first entity that matches the given filter from a specified entity set.",
        "parameters": {
            "type": "object",
            "properties": {
                "object_name": {"type": "string", "description": "Entity set name."},
                "filters": {
                    "oneOf": [
                        {"type": "object"},
                        {"type": "string"},
                        {"type": "array", "items": {"type": "string"}}
                    ],
                    "description": "Filter criteria."
                },
                "expand": {"type": "string", "description": "Navigation properties to expand."}
            },
            "required": ["object_name"],
            "additionalProperties": False
        }
    },
    {
        "name": "create_object",
        "func_name": "create_object",
        "description": "Create a new entity in the specified entity set.",
        "parameters": {
            "type": "object",
            "properties": {
                "object_name": {"type": "string", "description": "Entity set name."},
                "data": {"type": "object", "description": "Field values for the new entity."},
                "expand": {"type": "string", "description": "Navigation properties to expand."}
            },
            "required": ["object_name", "data"],
            "additionalProperties": False
        }
    },
    {
        "name": "update_object",
        "func_name": "update_object",
        "description": "Update an existing entity in the specified entity set.",
        "parameters": {
            "type": "object",
            "properties": {
                "object_name": {"type": "string", "description": "Entity set name."},
                "object_id": {
                    "oneOf": [
                        {"type": "string"},
                        {"type": "object"}
                    ],
                    "description": "GUID or composite key identifying the entity to update."
                },
                "data": {"type": "object", "description": "Fields to update."},
                "expand": {"type": "string", "description": "Navigation properties to expand."}
            },
            "required": ["object_name", "object_id", "data"],
            "additionalProperties": False
        }
    },
    {
        "name": "delete_object",
        "func_name": "delete_object",
        "description": "Delete an entity.  Performs a logical deletion by default.",
        "parameters": {
            "type": "object",
            "properties": {
                "object_name": {"type": "string"},
                "object_id": {
                    "oneOf": [
                        {"type": "string"},
                        {"type": "object"}
                    ]
                },
                "physical_delete": {"type": "boolean", "description": "If true perform a physical deletion via HTTP DELETE."}
            },
            "required": ["object_name", "object_id"],
            "additionalProperties": False
        }
    },
    {
        "name": "post_document",
        "func_name": "post_document",
        "description": "Conduct (post) a document in 1C.",
        "parameters": {
            "type": "object",
            "properties": {
                "object_name": {"type": "string", "description": "Document entity set name."},
                "object_id": {
                    "oneOf": [
                        {"type": "string"},
                        {"type": "object"}
                    ],
                    "description": "GUID identifying the document."}
            },
            "required": ["object_name", "object_id"],
            "additionalProperties": False
        }
    },
    {
        "name": "unpost_document",
        "func_name": "unpost_document",
        "description": "Reverse (unpost) a previously posted document.",
        "parameters": {
            "type": "object",
            "properties": {
                "object_name": {"type": "string"},
                "object_id": {
                    "oneOf": [
                        {"type": "string"},
                        {"type": "object"}
                    ]
                }
            },
            "required": ["object_name", "object_id"],
            "additionalProperties": False
        }
    },
    {
        "name": "get_schema",
        "func_name": "get_schema",
        "description": "Retrieve metadata (properties and types) for a specified entity set.",
        "parameters": {
            "type": "object",
            "properties": {
                "object_name": {"type": "string"}
            },
            "required": ["object_name"],
            "additionalProperties": False
        }
    }
]
