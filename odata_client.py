"""
Python OData client for interacting with 1C via its standard OData interface.

This module defines a lightweight, stateful client that mirrors much of the
behaviour found in the original PHP implementation (see `odata_php/OData/Client.php`).
It allows you to build requests dynamically by chaining attribute accessors
(e.g. ``client.Catalog_Номенклатура``) and then invoking one of the high level
methods such as ``get``, ``create``, ``update`` or ``delete``.  Query options
like ``$filter``, ``$expand`` and ``$top`` are supported via the corresponding
``filter``, ``expand`` and ``top`` methods.  Documents can be posted/unposted
through the ``__call__`` mechanism (e.g. ``client.Document_ПлатежноеПоручение.id(guid).Post()``).

The client uses the ``requests`` library under the hood and implements basic
error handling.  After each request the client captures HTTP and OData error
codes/messages which can be inspected via ``get_http_code()``,
``get_http_message()``, ``get_error_code()`` and ``get_error_message()``.  A
convenience method ``is_ok()`` is provided to quickly check if the previous
request succeeded.

Usage example:

    from odata_client import ODataClient

    client = ODataClient(
        base_url="http://192.168.18.113/TEST19/odata/standard.odata",
        username="user",
        password="pass"
    )

    # Fetch the first 10 items from the nomenclature catalog
    response = client.Catalog_Номенклатура.top(10).get()
    items = response.values()

    # Create a new item
    new_item = {
        "Description": "Test Item",
        "Артикул": "TEST-001"
    }
    result = client.Catalog_Номенклатура.create(new_item)
    if client.is_ok():
        print("Created Ref_Key:", client.get_last_id())
    else:
        print("Error creating item", client.get_http_code(), client.get_http_message(), client.get_error_message())

Notes:
    * The client is intentionally generic; it does not hard‑code object names.
      You can use it to interact with any catalog, document, register or
      enumeration exposed by the 1C OData endpoint by referencing the
      corresponding entity set name.
    * GUIDs should be passed as plain strings.  When used as keys they will
      automatically be wrapped with ``guid'...'``.
    * For security reasons you should always use HTTPS when exposing your
      endpoints outside of a trusted network.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

import requests


class ODataResponse:
    """Wrapper around ``requests.Response`` providing helper methods to work with 1C OData payloads.

    A successful response from 1C usually contains a JSON object with either
    a top level ``value`` array (for collections) or a number of keyed
    properties (for single entities).  This wrapper exposes convenience
    functions to extract those structures consistently.
    """

    def __init__(self, client: "ODataClient", response: requests.Response) -> None:
        self._client = client
        self._response = response
        self._json: Optional[Dict[str, Any]] = None

    @property
    def raw(self) -> requests.Response:
        """Return the underlying :class:`requests.Response` instance."""
        return self._response

    def to_array(self) -> Dict[str, Any]:
        """Deserialize the response body into a dictionary.

        The method caches the result to avoid repeated JSON decoding.  If
        decoding fails (e.g. when the response is not JSON) an empty dict is
        returned instead.
        """
        if self._json is None:
            try:
                self._json = self._response.json()
            except ValueError:
                self._json = {}
        return self._json

    def values(self) -> List[Dict[str, Any]]:
        """Return the list of records contained in the response.

        * If the payload has a top level ``value`` key (the usual case for
          collections) that list is returned.
        * If the payload contains a ``Ref_Key`` property (indicating a single
          entity) a list containing the single entity is returned.
        * Otherwise an empty list is returned.
        """
        data = self.to_array()
        if isinstance(data, dict) and "value" in data and isinstance(data["value"], list):
            return data["value"]
        # Single entity
        if isinstance(data, dict) and "Ref_Key" in data:
            return [data]
        return []

    def first(self) -> Optional[Dict[str, Any]]:
        """Return the first item in the response or ``None`` if empty."""
        vals = self.values()
        return vals[0] if vals else None


class _RequestState:
    """Mutable state shared between chained calls on a request builder.

    Instances of :class:`ODataEndpoint` contain a reference to this state so
    that call chains like ``client.Catalog_Nomenclature.filter(...).top(...).get()``
    share the same ``path``, ``id`` and ``query_params`` until a terminal
    method (such as ``get`` or ``create``) is invoked.
    """

    def __init__(self, segments: Optional[List[str]] = None) -> None:
        self.segments: List[str] = segments or []
        self.entity_id: Optional[Union[str, Dict[str, str]]] = None
        self.query_params: Dict[str, Any] = {}
        self.is_invocation: bool = False
        self.invocation_name: Optional[str] = None

    def clone(self) -> "_RequestState":
        new = _RequestState(self.segments.copy())
        new.entity_id = self.entity_id
        new.query_params = self.query_params.copy()
        new.is_invocation = self.is_invocation
        new.invocation_name = self.invocation_name
        return new


class ODataEndpoint:
    """Represents a specific OData entity set or path built from chained attributes.

    You should not instantiate this class directly.  Instances are created
    implicitly when you access attributes on :class:`ODataClient`.  For
    example, ``client.Catalog_Номенклатура`` returns an endpoint whose
    ``segments`` list contains ``["Catalog_Номенклатура"]``.
    """

    def __init__(self, client: "ODataClient", state: _RequestState) -> None:
        self._client = client
        self._state = state

    # ------------------------------------------------------------------
    # State‑building operations
    #
    # These methods mutate the internal request state and return ``self``
    # to allow fluent chaining.  They do not trigger network I/O.
    # ------------------------------------------------------------------

    def id(self, value: Optional[Union[str, Dict[str, str]]] = None) -> "ODataEndpoint":
        """Set the entity identifier for the request.

        You can pass either a GUID string or a mapping of key/value pairs
        representing a composite key.  When a dictionary is provided the
        resultant key string will be formatted as ``(Key1=Value1,Key2=Value2)``.
        GUID strings are automatically wrapped in ``guid'...'`` when
        constructing the request URI.
        """
        self._state.entity_id = value
        return self

    def expand(self, fields: str) -> "ODataEndpoint":
        """Specify an ``$expand`` query option to include related entities."""
        self._state.query_params["$expand"] = fields
        return self

    def top(self, count: int) -> "ODataEndpoint":
        """Specify an ``$top`` query option to limit the number of returned records."""
        self._state.query_params["$top"] = int(count)
        return self

    def filter(self, expression: str) -> "ODataEndpoint":
        """Specify an ``$filter`` query option.

        The expression should be a valid OData filter string, for example
        ``"Description eq 'Test' and Price gt 100"``.  Helper functions in
        :class:`ODataClient` may be used to build filter strings.
        """
        self._state.query_params["$filter"] = expression
        return self

    # ------------------------------------------------------------------
    # Terminal operations
    #
    # These methods perform network I/O.  They reset the internal state of
    # the underlying client (HTTP/ODATA status, last response etc.) prior to
    # making the request.
    # ------------------------------------------------------------------

    def get(self, id: Optional[Union[str, Dict[str, str]]] = None,
            filter: Optional[str] = None,
            options: Optional[Dict[str, Any]] = None) -> ODataResponse:
        """Perform a HTTP GET to retrieve one or more entities.

        :param id: Optional entity identifier.  If supplied this overrides
            any previously set identifier.  Can be a GUID string or a
            dictionary of key/value pairs.
        :param filter: Optional filter expression.  If supplied this overrides
            any previously set filter.
        :param options: Optional dictionary of additional request options
            (passed to ``requests``).  Supported keys include ``params`` and
            ``headers``.
        :return: :class:`ODataResponse` wrapping the HTTP response.
        """
        # Override id/filter if provided directly
        if id is not None:
            self._state.entity_id = id
        if filter is not None:
            self._state.query_params["$filter"] = filter
        return self._request("GET", options or {})

    def create(self, data: Dict[str, Any], options: Optional[Dict[str, Any]] = None) -> ODataResponse:
        """Create a new entity via HTTP POST.

        :param data: Dictionary of field names and values for the new entity.
        :param options: Additional request options (e.g. custom headers).
        :return: :class:`ODataResponse` wrapping the HTTP response.
        """
        return self.update(None, data, options or {})

    def update(self, id: Optional[Union[str, Dict[str, str]]] = None,
               data: Optional[Dict[str, Any]] = None,
               options: Optional[Dict[str, Any]] = None) -> ODataResponse:
        """Update an existing entity or create one if no ID is provided.

        When an ID is supplied the request will use HTTP PATCH and update
        only the supplied fields.  When no ID is present the request uses
        HTTP POST to create a new entity.

        :param id: Optional entity identifier (GUID or composite key).  If
            ``None`` the method behaves like :meth:`create`.
        :param data: Dictionary of field names and values to update.  If
            ``None`` the update will use any data provided via ``options``.
        :param options: Additional request options (e.g. custom headers or
            query parameters).  JSON payload supplied via ``options['json']``
            will override the ``data`` argument.
        :return: :class:`ODataResponse` wrapping the HTTP response.
        """
        # Determine method based on presence of id
        if id is not None:
            self._state.entity_id = id
        method = "PATCH" if self._state.entity_id else "POST"
        if options is None:
            options = {}
        if data is not None and "json" not in options:
            options = options.copy()
            options["json"] = data
        return self._request(method, options)

    def delete(self, id: Optional[Union[str, Dict[str, str]]] = None,
               filter: Optional[str] = None,
               options: Optional[Dict[str, Any]] = None) -> ODataResponse:
        """Delete an entity or collection of entities via HTTP DELETE.

        1C discourages physical deletion of business entities; instead the
        usual pattern is to set the ``DeletionMark`` property to ``true`` via
        :meth:`update`.  Nevertheless this method is provided for completeness.
        :param id: Optional entity identifier.  If omitted the deletion may
            operate on all entities matching the filter.
        :param filter: Optional filter expression.
        :param options: Additional request options.
        :return: :class:`ODataResponse` wrapping the HTTP response.
        """
        if id is not None:
            self._state.entity_id = id
        if filter is not None:
            self._state.query_params["$filter"] = filter
        return self._request("DELETE", options or {})

    # Invocation of OData actions/function imports
    def __call__(self, name: str) -> ODataResponse:
        """Invoke an unbound or bound function/action via HTTP POST.

        This is primarily used to post or unpost documents.  The passed
        ``name`` should correspond to the operation name supported by the
        endpoint (e.g. ``"Post"`` or ``"Unpost"``).  The entity ID must
        already be set via :meth:`id`.
        """
        # Mark invocation on the state so that the request builder knows
        # to append ``/<OperationName>`` instead of treating ``name`` as an
        # additional path segment.
        self._state.is_invocation = True
        self._state.invocation_name = name
        return self._request("POST", {})

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_path(self) -> str:
        """Construct the request path relative to the base URL.

        This takes into account any previously set entity ID and invocation.
        ``self._state.segments`` should always contain at least one element
        representing the entity set (e.g. ``Catalog_Номенклатура``).  If an
        ID is present it is formatted according to its type: GUID strings are
        wrapped in ``guid'...'`` whereas dictionaries are rendered as
        ``(Key1=Value1,Key2=Value2)``.  Invocations (such as ``Post``) append
        ``/<Invocation>`` to the path.
        """
        # Start with the entity set path
        parts: List[str] = self._state.segments.copy()
        # Append entity id if present
        if self._state.entity_id:
            if isinstance(self._state.entity_id, dict):
                # Composite key
                key_parts = []
                for k, v in self._state.entity_id.items():
                    if _is_guid(v):
                        key_parts.append(f"{k}=guid'{v}'")
                    else:
                        key_parts.append(f"{k}='{v}'")
                parts[-1] += "(" + ",".join(key_parts) + ")"
            else:
                # Single key
                v = self._state.entity_id
                if _is_guid(v):
                    parts[-1] += f"(guid'{v}')"
                else:
                    parts[-1] += f"('{v}')"
        # Append invocation name if any
        if self._state.is_invocation and self._state.invocation_name:
            parts.append(self._state.invocation_name)
        return "/".join(parts)

    def _request(self, method: str, options: Dict[str, Any]) -> ODataResponse:
        """Execute the HTTP request and reset client state accordingly."""
        # Reset error indicators on the client
        self._client._reset_state()
        # Compose URL
        path = self._build_path()
        url = f"{self._client.base_url}/{path}"
        # Merge query params
        params = self._state.query_params.copy()
        if "params" in options and options["params"]:
            # Merge user supplied params last so they override defaults
            params.update(options["params"])
        # Prepare request options for requests library
        req_options: Dict[str, Any] = {
            "params": params or None,
            "timeout": self._client.timeout,
            "verify": self._client.verify_ssl,
        }
        # Data / JSON / headers
        if "data" in options and options["data"] is not None:
            req_options["data"] = options["data"]
        if "json" in options and options["json"] is not None:
            req_options["json"] = options["json"]
        # Merge additional headers
        if "headers" in options and options["headers"]:
            headers = self._client.session.headers.copy()
            headers.update(options["headers"])
            req_options["headers"] = headers
        # Perform the request
        try:
            response = self._client.session.request(method, url, **req_options)
            self._client._record_response(response)
        except requests.RequestException as exc:
            # Network or protocol level error; populate HTTP code/message
            self._client.http_code = getattr(exc.response, "status_code", None) or 0
            self._client.http_message = str(exc)
            self._client.odata_code = None
            self._client.odata_message = None
            raise
        finally:
            # Reset invocation flag and query params for subsequent calls
            self._state.is_invocation = False
            self._state.invocation_name = None
            self._state.entity_id = None
            self._state.query_params = {}
        return ODataResponse(self._client, response)

    # Attribute access builds up the path segments
    def __getattr__(self, name: str) -> "ODataEndpoint":
        # Protect against access to internal attributes
        if name.startswith("_"):
            raise AttributeError(name)
        # Create a new state to avoid interfering with the current chain
        new_state = self._state.clone()
        new_state.segments.append(name)
        return ODataEndpoint(self._client, new_state)


def _is_guid(value: Any) -> bool:
    """Return ``True`` if ``value`` looks like a GUID string."""
    if not isinstance(value, str):
        return False
    return bool(re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", value))


class ODataClient:
    """Top level client object used to access entity sets exposed by the 1C OData endpoint."""

    def __init__(self, base_url: str,
                 username: Optional[str] = None,
                 password: Optional[str] = None,
                 timeout: int = 30,
                 verify_ssl: bool = False,
                 extra_headers: Optional[Dict[str, str]] = None) -> None:
        """
        :param base_url: Root of the OData service (without trailing slash).  For
            1C this is typically ``http://host/base/odata/standard.odata``.
        :param username: Optional username for basic authentication.
        :param password: Optional password for basic authentication.
        :param timeout: Timeout in seconds for HTTP requests.
        :param verify_ssl: If ``True`` SSL certificates will be verified.  Set
            to ``False`` when connecting to internal endpoints with self‑signed
            certificates.
        :param extra_headers: Additional HTTP headers to include on every
            request (e.g. custom ``User-Agent``).
        """
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        # Initialize session
        self.session = requests.Session()
        if username is not None and password is not None:
            self.session.auth = (username, password)
        # Default headers
        headers = {"Accept": "application/json"}
        if extra_headers:
            headers.update(extra_headers)
        self.session.headers.update(headers)
        # Tracking of last request state
        self.http_code: Optional[int] = None
        self.http_message: Optional[str] = None
        self.odata_code: Optional[str] = None
        self.odata_message: Optional[str] = None
        self._last_id: Optional[str] = None
        # Metadata cache
        self._metadata_cache: Optional[Dict[str, Any]] = None

    # ------------------------------------------------------------------
    # Internal helpers for request tracking
    # ------------------------------------------------------------------

    def _reset_state(self) -> None:
        self.http_code = None
        self.http_message = None
        self.odata_code = None
        self.odata_message = None
        self._last_id = None

    def _record_response(self, response: requests.Response) -> None:
        """Populate state based on the returned HTTP response."""
        self.http_code = response.status_code
        self.http_message = response.reason
        # Attempt to decode payload to extract OData error messages and the
        # identifier of newly created entities.  Errors from JSON parsing are
        # intentionally suppressed; failure to parse just means we cannot
        # populate the OData specific fields.
        try:
            data = response.json()
        except ValueError:
            data = None
        if isinstance(data, dict):
            # Extract errors
            err = data.get("odata.error") or data.get("error") or None
            if err:
                # The structure of error objects may vary; attempt to extract
                # both code and message if present
                code = err.get("code") or (err.get("error") if isinstance(err.get("error"), str) else None)
                message = None
                # The message can either be a string or nested under a
                # ``message`` key with a ``value`` field
                msg_obj = err.get("message") if isinstance(err, dict) else None
                if isinstance(msg_obj, dict):
                    message = msg_obj.get("value") or msg_obj.get("Message")
                elif isinstance(msg_obj, str):
                    message = msg_obj
                self.odata_code = code
                self.odata_message = message
            # Extract the key of a newly created entity if present
            # 1C usually returns an object with a ``Ref_Key`` property on
            # creation.  We store this value for later retrieval via
            # ``get_last_id``.
            if "Ref_Key" in data and isinstance(data["Ref_Key"], str):
                self._last_id = data["Ref_Key"]
            # For POST requests the Location header typically contains the
            # entity URI; attempt to parse the GUID from it as a fallback.
            loc = response.headers.get("Location")
            if not self._last_id and loc:
                m = re.search(r"\(guid'([0-9a-fA-F-]{36})'\)", loc)
                if m:
                    self._last_id = m.group(1)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def __getattr__(self, name: str) -> ODataEndpoint:
        """Start building a request against a specific entity set.

        Accessing an attribute on the client returns an :class:`ODataEndpoint`
        pointing at that entity set.  For example ``client.Catalog_Номенклатура``
        returns an endpoint whose internal path consists of just that segment.
        Subsequent attribute accessors append more segments.
        """
        if name.startswith("_"):
            raise AttributeError(name)
        state = _RequestState([name])
        return ODataEndpoint(self, state)

    def is_ok(self) -> bool:
        """Return ``True`` if the last request completed without HTTP or OData errors."""
        return (self.http_code is not None and 200 <= self.http_code < 300 and
                self.odata_code is None)

    def get_http_code(self) -> Optional[int]:
        return self.http_code

    def get_http_message(self) -> Optional[str]:
        return self.http_message

    def get_error_code(self) -> Optional[str]:
        return self.odata_code

    def get_error_message(self) -> Optional[str]:
        return self.odata_message

    def get_last_id(self) -> Optional[str]:
        """Return the Ref_Key of the last created entity if available."""
        return self._last_id

    # Metadata retrieval
    def get_metadata(self) -> Dict[str, Any]:
        """Retrieve and cache the OData metadata document.

        The 1C OData service exposes its EDMX metadata at ``$metadata``.
        Parsing this XML yields a description of all entity sets, their
        properties and relationships.  This helper fetches and caches the
        document on first use.  If parsing fails the raw XML text is stored
        under the ``"raw"`` key of the returned dictionary.
        """
        if self._metadata_cache is not None:
            return self._metadata_cache
        url = f"{self.base_url}/$metadata"
        try:
            resp = self.session.get(url, timeout=self.timeout, verify=self.verify_ssl)
        except requests.RequestException as exc:
            self.http_code = getattr(exc.response, "status_code", None) or 0
            self.http_message = str(exc)
            self.odata_code = None
            self.odata_message = None
            raise
        text = resp.text
        # Very simple XML parsing to extract entity sets and their properties.
        # We avoid heavy dependencies; for more complex scenarios you may wish
        # to use ``xml.etree.ElementTree`` or ``lxml``.
        metadata: Dict[str, Any] = {"raw": text, "entity_sets": {}}
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(text)
            ns = {
                "edmx": "http://docs.oasis-open.org/odata/ns/edmx",
                "edm": "http://docs.oasis-open.org/odata/ns/edm",
            }
            # EntitySets live under /edmx:Edmx/edmx:DataServices/edm:Schema/edm:EntityContainer
            for container in root.findall(".//edm:EntityContainer", ns):
                for es in container.findall("edm:EntitySet", ns):
                    name = es.get("Name")
                    etype = es.get("EntityType")
                    if not (name and etype):
                        continue
                    # Extract properties of the underlying EntityType
                    et_name = etype.split(".")[-1]
                    props: Dict[str, Dict[str, Any]] = {}
                    # Find the schema for this entity type
                    schema = root.find(f".//edm:Schema[edm:EntityType[@Name='{et_name}']]", ns)
                    if schema is not None:
                        et_el = schema.find(f"edm:EntityType[@Name='{et_name}']", ns)
                        if et_el is not None:
                            for prop in et_el.findall("edm:Property", ns):
                                pname = prop.get("Name")
                                ptype = prop.get("Type")
                                nullable = prop.get("Nullable", "true").lower() == "true"
                                props[pname] = {"type": ptype, "nullable": nullable}
                    metadata["entity_sets"][name] = {
                        "entity_type": etype,
                        "properties": props,
                    }
        except Exception:
            # Parsing failed; just return raw XML
            metadata["entity_sets"] = {}
        self._metadata_cache = metadata
        return metadata


    def _build_entity_uri(self, parent_name: str, parent_id: Union[str, Dict[str, str]]) -> str:
        if isinstance(parent_id, dict):
            key_parts = []
            for k, v in parent_id.items():
                if _is_guid(v):
                    key_parts.append(f"{k}=guid'{v}'")
                else:
                    key_parts.append(f"{k}='{v}'")
            key = "(" + ",".join(key_parts) + ")"
        else:
            key = f"(guid'{parent_id}')" if _is_guid(parent_id) else f"('{parent_id}')"
        return f"{self.base_url}/{parent_name}{key}"

    def add_table_part_rows(self, parent_name: str, parent_id: Union[str, Dict[str, str]],
                            table_name: str, rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        POST строки табличной части по пути:
            <base>/<parent_name>(...)/<table_name>
        Возвращает список кратких результатов по каждой строке.
        """
        uri = f"{self._build_entity_uri(parent_name, parent_id)}/{quote(table_name)}"
        results: List[Dict[str, Any]] = []
        for row in rows or []:
            try:
                r = self.session.post(uri, json=row, timeout=self.timeout, verify=self.verify_ssl,
                                      headers=self.session.headers)
                self._record_response(r)
                ok = 200 <= r.status_code < 300
                results.append({
                    "http_code": r.status_code,
                    "http_message": r.reason,
                    "ok": ok,
                    "row": row,
                })
            except requests.RequestException as exc:
                results.append({
                    "http_code": getattr(exc.response, "status_code", 0) or 0,
                    "http_message": str(exc),
                    "ok": False,
                    "row": row,
                })
        return results

    def get_table_part(self, parent_name: str, parent_id: Union[str, Dict[str, str]],
                       table_name: str, params: Optional[Dict[str, Any]] = None) -> ODataResponse:
        uri = f"{self._build_entity_uri(parent_name, parent_id)}/{quote(table_name)}"
        try:
            r = self.session.get(uri, params=params or None, timeout=self.timeout, verify=self.verify_ssl,
                                 headers=self.session.headers)
            self._record_response(r)
            return ODataResponse(self, r)
        finally:
            pass
