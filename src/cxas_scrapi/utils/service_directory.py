# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Service Directory mapping, resolution, and validation for CXAS resources."""

from __future__ import annotations

import json
import re
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

ENV_VAR_PLACEHOLDER = "$env_var"

SD_RESOURCE_RE = re.compile(
    r"^projects/([^/\s]+)/locations/([^/\s]+)"
    r"/namespaces/([^/\s]+)/services/([^/\s]+)$"
)
CONCRETE_REGION_RE = re.compile(r"^[a-z]+(?:-[a-z]+)+[0-9]+$")
FQDN_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)
SD_SUMMARY_LINE_RE = re.compile(
    r"^\s*([a-z0-9.-]+\.[a-z]{2,})\s*(?:\([^)]*\))?\s*(?:->|→|=)\s*"
    r"([^\s#]+)\s*(?:#.*)?$",
    re.IGNORECASE,
)
SD_RESOURCE_OVERRIDE_LINE_RE = re.compile(
    r"^\s*(toolsets|tools)[/.]([^\s=>→#]+)\s*(?:->|→|=)\s*"
    r"([^\s#]+)\s*(?:#.*)?$",
    re.IGNORECASE,
)
YAML_SERVER_RE = re.compile(
    r"^\s*-\s*url:\s*['\"]?([^\s#'\"]+)['\"]?\s*$",
    re.MULTILINE,
)
OPENAPI_V2_HOST_RE = re.compile(
    r"^\s*host:\s*['\"]?([^\s#'\"]+)['\"]?\s*$",
    re.MULTILINE,
)

DIRECT_EGRESS_DOMAINS: tuple[str, ...] = ("googleapis.com", "run.app")

TOOLSET_SD_COMPONENTS: tuple[str, ...] = (
    "openApiToolset",
    "open_api_toolset",
    "mcpToolset",
    "mcp_toolset",
)
TOOL_SD_COMPONENTS: tuple[str, ...] = (
    "openApiTool",
    "open_api_tool",
    "mcpTool",
    "mcp_tool",
)
UNSUPPORTED_SD_COMPONENTS: tuple[str, ...] = (
    "pythonFunction",
    "python_function",
)

_RESERVED_MAP_KEYS: frozenset[str] = frozenset(
    {
        "hosts",
        "fqdns",
        "toolsets",
        "tools",
        "project",
        "project_id",
        "projectId",
        "location",
        "region",
        "sd_region",
        "sdRegion",
        "namespace",
        "sd_namespace",
        "sdNamespace",
    }
)

_IGNORED_BANNER_PREFIXES: tuple[str, ...] = (
    "===",
    "---",
    "cx agent studio static egress",
    "project:",
    "static external ips",
    "servicedirectoryconfig.service per fqdn",
)
_IP_BULLET_RE = re.compile(r"^\s*-\s*\d{1,3}(?:\.\d{1,3}){3}\s*$")


@dataclass
class ServiceDirectoryMap:
    """Parsed Service Directory mapping rules and validation errors."""

    hosts: dict[str, str] = field(default_factory=dict)
    toolsets: dict[str, str] = field(default_factory=dict)
    tools: dict[str, str] = field(default_factory=dict)
    project: str | None = None
    location: str | None = None
    namespace: str | None = None
    errors: list[str] = field(default_factory=list)

    def lookup(
        self,
        kind: str,
        resource_id: str,
        display_name: str | None,
        fqdn: str,
    ) -> str | None:
        """Look up desired Service Directory service for a toolset or tool."""
        explicit = self.toolsets if kind == "toolsets" else self.tools
        if resource_id in explicit:
            return explicit[resource_id]
        if display_name and display_name in explicit:
            return explicit[display_name]
        if fqdn and fqdn in self.hosts:
            return self.hosts[fqdn]
        return None


@dataclass
class ServiceDirectoryInspection:
    """Inspection result for a single tool or toolset configuration."""

    kind: str
    resource_id: str
    display_name: str | None
    config_path: Path
    component_key: str | None
    fqdn: str
    has_sd_block: bool
    raw_service: Any
    env_service: str | None
    unsupported_sd_component: str | None = None


def validate_sd_resource_name(value: Any) -> str | None:
    """Validate a concrete Service Directory service resource string.

    Returns an error message if invalid, or None if valid.
    """
    if not isinstance(value, str) or not value.strip():
        return "must be a non-empty Service Directory resource string"

    cleaned = value.strip()
    match = SD_RESOURCE_RE.match(cleaned)
    if not match:
        return (
            f"invalid Service Directory resource '{cleaned}'; expected "
            "'projects/{project}/locations/{region}/namespaces/{namespace}"
            "/services/{service}'"
        )

    location = match.group(2)
    if not CONCRETE_REGION_RE.match(location):
        return (
            f"Service Directory location '{location}' in '{cleaned}' must be "
            "a concrete GCP region (e.g. 'us-central1'), not a multi-region "
            "or 'global'"
        )
    return None


def extract_fqdn(raw_url: str) -> str:
    """Extract normalized lowercase FQDN from a URL or hostname string."""
    cleaned = (raw_url or "").strip()
    if not cleaned or cleaned == ENV_VAR_PLACEHOLDER:
        return ""
    if "://" not in cleaned:
        cleaned = f"https://{cleaned}"
    try:
        parsed = urllib.parse.urlsplit(cleaned)
    except ValueError:
        return ""
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host or not FQDN_RE.match(host):
        return ""
    return host


def is_direct_egress_fqdn(fqdn: str) -> bool:
    """Return True if ``fqdn`` is a Google-managed direct-egress domain."""
    if not fqdn:
        return False
    lowered = fqdn.lower().rstrip(".")
    return any(
        lowered == dom or lowered.endswith(f".{dom}")
        for dom in DIRECT_EGRESS_DOMAINS
    )


def _substitute_openapi_server_vars(
    server_url: str, server_obj: dict[str, Any]
) -> str:
    variables = server_obj.get("variables")
    if not isinstance(variables, dict):
        return server_url
    resolved = server_url
    for var_name, var_spec in variables.items():
        if isinstance(var_spec, dict) and isinstance(
            var_spec.get("default"), str
        ):
            resolved = resolved.replace(f"{{{var_name}}}", var_spec["default"])
    return resolved


def extract_schema_fqdn(schema_text: str, env_url_override: str = "") -> str:
    """Extract target server FQDN from an OpenAPI 3.x or 2.0 schema."""
    raw = (schema_text or "").strip()
    if not raw:
        return ""

    doc: Any = None
    if raw.startswith("{"):
        try:
            doc = json.loads(raw)
        except json.JSONDecodeError:
            doc = None
    else:
        try:
            doc = yaml.safe_load(raw)
        except yaml.YAMLError:
            doc = None

    if isinstance(doc, dict):
        servers = doc.get("servers")
        if isinstance(servers, list) and servers:
            first = servers[0]
            if isinstance(first, dict) and first.get("url") is not None:
                raw_srv = _substitute_openapi_server_vars(
                    str(first["url"]).strip(), first
                )
                if raw_srv == ENV_VAR_PLACEHOLDER and env_url_override:
                    return extract_fqdn(env_url_override)
                fqdn = extract_fqdn(raw_srv)
                if fqdn:
                    return fqdn
        if doc.get("host"):
            fqdn = extract_fqdn(str(doc["host"]))
            if fqdn:
                return fqdn

    m_srv = YAML_SERVER_RE.search(raw)
    if m_srv:
        candidate = m_srv.group(1).strip()
        if candidate == ENV_VAR_PLACEHOLDER and env_url_override:
            return extract_fqdn(env_url_override)
        return extract_fqdn(candidate)

    m_host = OPENAPI_V2_HOST_RE.search(raw)
    if m_host:
        return extract_fqdn(m_host.group(1))
    return ""


def _load_config_file(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in (".yaml", ".yml"):
        return yaml.safe_load(text)
    return json.loads(text)


def _write_config_file(path: Path, data: dict[str, Any]) -> None:
    if path.suffix.lower() in (".yaml", ".yml"):
        path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    else:
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _extract_sd_string_from_mapping_entry(entry: Any) -> Any:
    """Unwrap nested Service Directory mapping shapes to the service string."""
    if isinstance(entry, str) or entry is None:
        return entry
    if not isinstance(entry, dict):
        return entry
    if "service" in entry:
        return entry["service"]
    for sd_key in ("serviceDirectoryConfig", "service_directory_config"):
        if isinstance(entry.get(sd_key), dict) and "service" in entry[sd_key]:
            return entry[sd_key]["service"]
    for comp_key in (*TOOLSET_SD_COMPONENTS, *TOOL_SD_COMPONENTS):
        comp = entry.get(comp_key)
        if isinstance(comp, dict):
            for sd_key in (
                "serviceDirectoryConfig",
                "service_directory_config",
            ):
                sd_cfg = comp.get(sd_key)
                if isinstance(sd_cfg, dict) and "service" in sd_cfg:
                    return sd_cfg["service"]
    return entry


def _expand_sd_service(
    raw_val: Any,
    project: str | None,
    location: str | None,
    namespace: str | None,
    label: str,
    errors: list[str],
) -> str | None:
    unwrapped = _extract_sd_string_from_mapping_entry(raw_val)
    if not isinstance(unwrapped, str) or not unwrapped.strip():
        errors.append(
            f"{label} must specify a non-empty Service Directory service string"
        )
        return None
    cleaned = unwrapped.strip()
    if cleaned == ENV_VAR_PLACEHOLDER:
        errors.append(
            f"{label} has unresolved '{ENV_VAR_PLACEHOLDER}' in mapping file"
        )
        return None
    if not cleaned.startswith("projects/"):
        if project and location and namespace and "/" not in cleaned:
            cleaned = (
                f"projects/{project}/locations/{location}"
                f"/namespaces/{namespace}/services/{cleaned}"
            )
        else:
            errors.append(
                f"{label} value '{cleaned}' must be a full resource name "
                "'projects/{project}/locations/{region}/namespaces/{namespace}"
                "/services/{service}' (or set top-level 'project', "
                "'location', and 'namespace' in the mapping file)"
            )
            return None

    err = validate_sd_resource_name(cleaned)
    if err:
        errors.append(f"{label}: {err}")
        return None
    return cleaned


def _register_host_mapping(
    result: ServiceDirectoryMap,
    sd_to_host: dict[str, str],
    raw_host: str,
    raw_sd: Any,
    label: str,
) -> None:
    fqdn = extract_fqdn(raw_host)
    if not fqdn:
        result.errors.append(f"Invalid FQDN '{raw_host}' in {label}")
        return
    expanded = _expand_sd_service(
        raw_sd,
        result.project,
        result.location,
        result.namespace,
        f"{label} ('{fqdn}')",
        result.errors,
    )
    if expanded is None:
        return
    if fqdn in result.hosts and result.hosts[fqdn] != expanded:
        result.errors.append(
            f"Conflicting Service Directory services for FQDN '{fqdn}': "
            f"'{result.hosts[fqdn]}' vs '{expanded}'"
        )
        return
    if expanded in sd_to_host and sd_to_host[expanded] != fqdn:
        result.errors.append(
            f"L4 invariant violation: Service Directory '{expanded}' mapped "
            f"to both '{sd_to_host[expanded]}' and '{fqdn}' "
            "(1 Service Directory service = 1 VIP = 1 FQDN)"
        )
        return
    result.hosts[fqdn] = expanded
    sd_to_host[expanded] = fqdn


def _parse_sd_map_dict(data: dict[str, Any]) -> ServiceDirectoryMap:
    result = ServiceDirectoryMap()
    sd_to_host: dict[str, str] = {}

    for k in ("project", "project_id", "projectId"):
        if isinstance(data.get(k), str) and data[k].strip():
            result.project = data[k].strip()
            break
    for k in ("location", "region", "sd_region", "sdRegion"):
        if isinstance(data.get(k), str) and data[k].strip():
            result.location = data[k].strip()
            break
    for k in ("namespace", "sd_namespace", "sdNamespace"):
        if isinstance(data.get(k), str) and data[k].strip():
            result.namespace = data[k].strip()
            break

    has_structured_keys = bool(_RESERVED_MAP_KEYS & data.keys())
    if not has_structured_keys:
        for raw_key, raw_val in data.items():
            key_str = str(raw_key).strip()
            if key_str.startswith(("toolsets/", "toolsets.")):
                ts_name = key_str.split("/", 1)[-1].split(".", 1)[-1].strip()
                expanded = _expand_sd_service(
                    raw_val,
                    result.project,
                    result.location,
                    result.namespace,
                    f"toolsets['{ts_name}']",
                    result.errors,
                )
                if expanded:
                    result.toolsets[ts_name] = expanded
            elif key_str.startswith(("tools/", "tools.")):
                t_name = key_str.split("/", 1)[-1].split(".", 1)[-1].strip()
                expanded = _expand_sd_service(
                    raw_val,
                    result.project,
                    result.location,
                    result.namespace,
                    f"tools['{t_name}']",
                    result.errors,
                )
                if expanded:
                    result.tools[t_name] = expanded
            else:
                _register_host_mapping(
                    result, sd_to_host, key_str, raw_val, "hosts"
                )
        return result

    for host_section_key in ("hosts", "fqdns"):
        if host_section_key not in data or data[host_section_key] is None:
            continue
        hosts_obj = data[host_section_key]
        if not isinstance(hosts_obj, dict):
            result.errors.append(
                f"Field '{host_section_key}' in Service Directory map must be "
                "an object/mapping"
            )
            continue
        for raw_host, raw_val in hosts_obj.items():
            _register_host_mapping(
                result, sd_to_host, str(raw_host), raw_val, host_section_key
            )

    for section_key, target_dict in (
        ("toolsets", result.toolsets),
        ("tools", result.tools),
    ):
        if section_key not in data or data[section_key] is None:
            continue
        sec_obj = data[section_key]
        if not isinstance(sec_obj, dict):
            result.errors.append(
                f"Field '{section_key}' in Service Directory map must be an "
                "object/mapping"
            )
            continue
        for raw_name, raw_val in sec_obj.items():
            res_name = str(raw_name).strip()
            if not res_name:
                result.errors.append(
                    f"Empty resource name in '{section_key}' mapping"
                )
                continue
            expanded = _expand_sd_service(
                raw_val,
                result.project,
                result.location,
                result.namespace,
                f"{section_key}['{res_name}']",
                result.errors,
            )
            if expanded:
                target_dict[res_name] = expanded

    unknown_keys = sorted(set(data.keys()) - _RESERVED_MAP_KEYS)
    for uk in unknown_keys:
        if uk == "app":
            continue
        result.errors.append(
            f"Unknown top-level key '{uk}' in Service Directory map; "
            "expected 'hosts', 'toolsets', 'tools', 'project', 'location', "
            "or 'namespace'"
        )
    return result


def _is_ignored_summary_line(stripped: str) -> bool:
    if not stripped or stripped.startswith("#"):
        return True
    lower = stripped.lower()
    if any(lower.startswith(p) for p in _IGNORED_BANNER_PREFIXES):
        return True
    return bool(_IP_BULLET_RE.match(stripped))


def _parse_sd_map_lines(text: str) -> ServiceDirectoryMap:
    result = ServiceDirectoryMap()
    sd_to_host: dict[str, str] = {}

    for line_no, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if _is_ignored_summary_line(stripped):
            continue

        m_res = SD_RESOURCE_OVERRIDE_LINE_RE.match(stripped)
        if m_res:
            kind = m_res.group(1).lower()
            res_name = m_res.group(2).strip()
            raw_sd = m_res.group(3).strip()
            expanded = _expand_sd_service(
                raw_sd,
                result.project,
                result.location,
                result.namespace,
                f"line {line_no} ({kind}/{res_name})",
                result.errors,
            )
            if expanded:
                target = result.toolsets if kind == "toolsets" else result.tools
                target[res_name] = expanded
            continue

        m_host = SD_SUMMARY_LINE_RE.match(stripped)
        if m_host:
            _register_host_mapping(
                result,
                sd_to_host,
                m_host.group(1),
                m_host.group(2),
                f"line {line_no}",
            )
            continue

        result.errors.append(
            f"Unrecognized Service Directory mapping at line {line_no}: "
            f"'{stripped}'"
        )

    return result


def parse_service_directory_map_text(
    text: str, suffix: str = ""
) -> ServiceDirectoryMap:
    """Parse Service Directory mapping content (JSON, YAML, or summary text)."""
    stripped = text.strip()
    if not stripped:
        return ServiceDirectoryMap()

    ext = suffix.lower()
    if ext == ".json":
        try:
            loaded = json.loads(stripped)
        except json.JSONDecodeError as e:
            res = ServiceDirectoryMap()
            res.errors.append(f"Invalid JSON in Service Directory map: {e}")
            return res
        if not isinstance(loaded, dict):
            res = ServiceDirectoryMap()
            res.errors.append(
                "Service Directory JSON map root must be an object"
            )
            return res
        return _parse_sd_map_dict(loaded)

    if ext in (".yaml", ".yml"):
        try:
            loaded = yaml.safe_load(stripped)
        except yaml.YAMLError as e:
            res = ServiceDirectoryMap()
            res.errors.append(f"Invalid YAML in Service Directory map: {e}")
            return res
        if loaded is None:
            return ServiceDirectoryMap()
        if isinstance(loaded, dict):
            return _parse_sd_map_dict(loaded)
        if isinstance(loaded, str):
            return _parse_sd_map_lines(stripped)
        res = ServiceDirectoryMap()
        res.errors.append("Service Directory YAML map root must be a mapping")
        return res

    if ext == ".txt":
        return _parse_sd_map_lines(stripped)

    if stripped.startswith("{"):
        try:
            loaded = json.loads(stripped)
        except json.JSONDecodeError as e:
            res = ServiceDirectoryMap()
            res.errors.append(f"Invalid JSON in Service Directory map: {e}")
            return res
        if isinstance(loaded, dict):
            return _parse_sd_map_dict(loaded)

    try:
        loaded = yaml.safe_load(stripped)
        if isinstance(loaded, dict):
            return _parse_sd_map_dict(loaded)
    except yaml.YAMLError:
        pass

    return _parse_sd_map_lines(stripped)


def load_service_directory_map(path: str | Path) -> ServiceDirectoryMap:
    """Load and validate a Service Directory mapping file from disk."""
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    return parse_service_directory_map_text(text, suffix=p.suffix)


def write_service_directory_map(
    path: str | Path, sd_map: ServiceDirectoryMap
) -> None:
    """Write a ``ServiceDirectoryMap`` to JSON, YAML, or text format."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    ext = p.suffix.lower()

    if ext == ".txt":
        lines: list[str] = []
        for fqdn in sorted(sd_map.hosts):
            lines.append(f"{fqdn} -> {sd_map.hosts[fqdn]}")
        for ts_name in sorted(sd_map.toolsets):
            lines.append(f"toolsets/{ts_name} -> {sd_map.toolsets[ts_name]}")
        for t_name in sorted(sd_map.tools):
            lines.append(f"tools/{t_name} -> {sd_map.tools[t_name]}")
        p.write_text(
            ("\n".join(lines) + "\n") if lines else "", encoding="utf-8"
        )
        return

    payload: dict[str, Any] = {}
    if sd_map.project:
        payload["project"] = sd_map.project
    if sd_map.location:
        payload["location"] = sd_map.location
    if sd_map.namespace:
        payload["namespace"] = sd_map.namespace
    payload["hosts"] = {
        fqdn: sd_map.hosts[fqdn] for fqdn in sorted(sd_map.hosts)
    }
    if sd_map.toolsets:
        payload["toolsets"] = {
            k: sd_map.toolsets[k] for k in sorted(sd_map.toolsets)
        }
    if sd_map.tools:
        payload["tools"] = {k: sd_map.tools[k] for k in sorted(sd_map.tools)}

    if ext in (".yaml", ".yml"):
        p.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    else:
        p.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _iter_resource_config_files(
    app_dir: Path, kind: str
) -> list[tuple[str, Path]]:
    parent = app_dir / kind
    if not parent.is_dir():
        return []
    found: list[tuple[str, Path]] = []
    for subdir in sorted(parent.iterdir()):
        if not subdir.is_dir():
            continue
        chosen: Path | None = None
        for ext in (".json", ".yaml", ".yml"):
            candidate = subdir / f"{subdir.name}{ext}"
            if candidate.is_file():
                chosen = candidate
                break
        if chosen is None:
            for ext in ("*.json", "*.yaml", "*.yml"):
                matches = sorted(subdir.glob(ext))
                if matches:
                    chosen = matches[0]
                    break
        if chosen is not None:
            found.append((subdir.name, chosen))
    return found


def _load_env_json(env_path: Path | None) -> dict[str, Any]:
    if env_path is None or not env_path.is_file():
        return {}
    try:
        loaded = json.loads(env_path.read_text(encoding="utf-8"))
        return loaded if isinstance(loaded, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def _find_env_resource_entry(
    env_data: dict[str, Any],
    kind: str,
    resource_id: str,
    display_name: str | None,
) -> dict[str, Any] | None:
    sec = env_data.get(kind)
    if not isinstance(sec, dict):
        return None
    if isinstance(sec.get(resource_id), dict):
        return sec[resource_id]
    if display_name and isinstance(sec.get(display_name), dict):
        return sec[display_name]
    return None


def _get_env_component_dict(
    env_entry: dict[str, Any] | None, component_key: str
) -> dict[str, Any] | None:
    if not isinstance(env_entry, dict):
        return None
    if isinstance(env_entry.get(component_key), dict):
        return env_entry[component_key]
    aliases = {
        "openApiToolset": "open_api_toolset",
        "open_api_toolset": "openApiToolset",
        "mcpToolset": "mcp_toolset",
        "mcp_toolset": "mcpToolset",
        "openApiTool": "open_api_tool",
        "open_api_tool": "openApiTool",
        "mcpTool": "mcp_tool",
        "mcp_tool": "mcpTool",
    }
    alt = aliases.get(component_key)
    if alt and isinstance(env_entry.get(alt), dict):
        return env_entry[alt]
    return None


def _extract_env_url_and_sd(
    env_data: dict[str, Any],
    kind: str,
    resource_id: str,
    display_name: str | None,
    component_key: str,
) -> tuple[str, str | None]:
    entry = _find_env_resource_entry(env_data, kind, resource_id, display_name)
    comp = _get_env_component_dict(entry, component_key)
    if not isinstance(comp, dict):
        return "", None

    env_url = ""
    for url_key in ("url", "serverAddress", "server_address"):
        val = comp.get(url_key)
        if isinstance(val, str) and val.strip() and val != ENV_VAR_PLACEHOLDER:
            env_url = val.strip()
            break

    env_sd: str | None = None
    for sd_key in ("serviceDirectoryConfig", "service_directory_config"):
        sd_cfg = comp.get(sd_key)
        if isinstance(sd_cfg, dict) and isinstance(sd_cfg.get("service"), str):
            env_sd = sd_cfg["service"].strip()
            break
    return env_url, env_sd


def _read_schema_text_from_ref(
    raw_schema: str, app_dir: Path, resource_dir: Path
) -> str:
    if "\n" in raw_schema or len(raw_schema) >= 1024:
        return raw_schema
    stripped = raw_schema.strip()
    if stripped.startswith("{"):
        return raw_schema
    for base in (app_dir, resource_dir):
        candidate = base / stripped
        if candidate.is_file():
            try:
                return candidate.read_text(encoding="utf-8")
            except OSError:
                return ""
    return raw_schema


def _resolve_component_fqdn(
    comp_dict: dict[str, Any],
    component_key: str,
    app_dir: Path,
    resource_dir: Path,
    env_url_override: str,
) -> str:
    if env_url_override:
        override_fqdn = extract_fqdn(env_url_override)
        if override_fqdn:
            return override_fqdn

    is_mcp = component_key in (
        "mcpToolset",
        "mcp_toolset",
        "mcpTool",
        "mcp_tool",
    )
    if is_mcp:
        raw_addr = (
            comp_dict.get("serverAddress")
            if "serverAddress" in comp_dict
            else comp_dict.get("server_address", "")
        )
        if isinstance(raw_addr, str) and raw_addr.strip():
            return extract_fqdn(raw_addr)
        return ""

    raw_url = comp_dict.get("url", "")
    if isinstance(raw_url, str) and raw_url.strip():
        fqdn = extract_fqdn(raw_url)
        if fqdn:
            return fqdn

    raw_schema = (
        comp_dict.get("openApiSchema")
        if "openApiSchema" in comp_dict
        else comp_dict.get("open_api_schema")
    )
    if isinstance(raw_schema, str) and raw_schema.strip():
        schema_text = _read_schema_text_from_ref(
            raw_schema, app_dir, resource_dir
        )
        fqdn = extract_schema_fqdn(schema_text, env_url_override)
        if fqdn:
            return fqdn

    sub_folder = (
        "open_api_toolset"
        if component_key in ("openApiToolset", "open_api_toolset")
        else "open_api_tool"
    )
    for fname in (
        "open_api_schema.yaml",
        "open_api_schema.json",
        "openapi.yaml",
    ):
        fallback = resource_dir / sub_folder / fname
        if not fallback.is_file():
            fallback = resource_dir / fname
        if fallback.is_file():
            try:
                fqdn = extract_schema_fqdn(
                    fallback.read_text(encoding="utf-8"), env_url_override
                )
                if fqdn:
                    return fqdn
            except OSError:
                pass
    return ""


def inspect_app_service_directories(
    app_dir: str | Path, env_file: str | Path | None = None
) -> list[ServiceDirectoryInspection]:
    """Inspect all tools and toolsets in ``app_dir`` for Service Directory."""
    root = Path(app_dir)
    env_path = (
        Path(env_file) if env_file is not None else (root / "environment.json")
    )
    env_data = _load_env_json(env_path)

    inspections: list[ServiceDirectoryInspection] = []
    for kind, supported_keys in (
        ("toolsets", TOOLSET_SD_COMPONENTS),
        ("tools", TOOL_SD_COMPONENTS),
    ):
        for res_id, cfg_path in _iter_resource_config_files(root, kind):
            try:
                data = _load_config_file(cfg_path)
            except (json.JSONDecodeError, yaml.YAMLError, OSError):
                continue
            if not isinstance(data, dict):
                continue

            display_name = (
                data.get("displayName")
                if isinstance(data.get("displayName"), str)
                else (
                    data.get("display_name")
                    if isinstance(data.get("display_name"), str)
                    else None
                )
            )

            unsupported_found: str | None = None
            if kind == "tools":
                for unsup_key in UNSUPPORTED_SD_COMPONENTS:
                    unsup_obj = data.get(unsup_key)
                    if isinstance(unsup_obj, dict) and (
                        "serviceDirectoryConfig" in unsup_obj
                        or "service_directory_config" in unsup_obj
                    ):
                        unsupported_found = unsup_key
                        break

            comp_key: str | None = None
            comp_dict: dict[str, Any] | None = None
            for k in supported_keys:
                if isinstance(data.get(k), dict):
                    comp_key = k
                    comp_dict = data[k]
                    break

            if comp_key is None or comp_dict is None:
                if unsupported_found is not None:
                    inspections.append(
                        ServiceDirectoryInspection(
                            kind=kind,
                            resource_id=res_id,
                            display_name=display_name,
                            config_path=cfg_path,
                            component_key=None,
                            fqdn="",
                            has_sd_block=True,
                            raw_service=None,
                            env_service=None,
                            unsupported_sd_component=unsupported_found,
                        )
                    )
                continue

            env_url, env_sd = _extract_env_url_and_sd(
                env_data, kind, res_id, display_name, comp_key
            )
            fqdn = _resolve_component_fqdn(
                comp_dict, comp_key, root, cfg_path.parent, env_url
            )

            has_sd = False
            raw_service: Any = None
            for sd_key in (
                "serviceDirectoryConfig",
                "service_directory_config",
            ):
                if sd_key in comp_dict:
                    sd_val = comp_dict[sd_key]
                    if sd_val is not None:
                        has_sd = True
                        if isinstance(sd_val, dict):
                            raw_service = sd_val.get("service")
                        else:
                            raw_service = sd_val
                    break

            inspections.append(
                ServiceDirectoryInspection(
                    kind=kind,
                    resource_id=res_id,
                    display_name=display_name,
                    config_path=cfg_path,
                    component_key=comp_key,
                    fqdn=fqdn,
                    has_sd_block=has_sd,
                    raw_service=raw_service,
                    env_service=env_sd,
                    unsupported_sd_component=unsupported_found,
                )
            )
    return inspections


def _set_component_sd_service(
    comp_dict: dict[str, Any], component_key: str, service_value: str
) -> None:
    if "service_directory_config" in comp_dict or "_" in component_key:
        sd_key = (
            "serviceDirectoryConfig"
            if "serviceDirectoryConfig" in comp_dict
            else "service_directory_config"
        )
    else:
        sd_key = "serviceDirectoryConfig"
    existing = comp_dict.get(sd_key)
    if isinstance(existing, dict):
        existing["service"] = service_value
    else:
        comp_dict[sd_key] = {"service": service_value}


def _upsert_env_json_sd_service(
    env_path: Path,
    kind: str,
    resource_id: str,
    component_key: str,
    service_value: str,
    only_if_entry_exists: bool = False,
) -> None:
    if only_if_entry_exists and not env_path.is_file():
        return

    env_data = _load_env_json(env_path)
    kind_sec = env_data.get(kind)
    if not isinstance(kind_sec, dict):
        if only_if_entry_exists:
            return
        kind_sec = {}
        env_data[kind] = kind_sec

    res_entry = kind_sec.get(resource_id)
    if not isinstance(res_entry, dict):
        if only_if_entry_exists:
            return
        res_entry = {}
        kind_sec[resource_id] = res_entry

    comp_entry = _get_env_component_dict(res_entry, component_key)
    if not isinstance(comp_entry, dict):
        if only_if_entry_exists:
            return
        comp_entry = {}
        res_entry[component_key] = comp_entry

    sd_key = (
        "service_directory_config"
        if "service_directory_config" in comp_entry
        and "serviceDirectoryConfig" not in comp_entry
        else "serviceDirectoryConfig"
    )
    if only_if_entry_exists and sd_key not in comp_entry:
        return

    sd_obj = comp_entry.get(sd_key)
    if not isinstance(sd_obj, dict):
        sd_obj = {}
        comp_entry[sd_key] = sd_obj
    sd_obj["service"] = service_value
    env_path.write_text(json.dumps(env_data, indent=2) + "\n", encoding="utf-8")


def collect_env_var_service_directory_targets(
    app_dir: str | Path,
) -> tuple[set[tuple[str, str]], dict[tuple[str, str], str]]:
    """Collect ``(kind, resource_id)`` targets using ``"$env_var"`` locally."""
    targets: set[tuple[str, str]] = set()
    env_defaults: dict[tuple[str, str], str] = {}
    for item in inspect_app_service_directories(app_dir):
        key = (item.kind, item.resource_id)
        if item.raw_service == ENV_VAR_PLACEHOLDER:
            targets.add(key)
        if (
            isinstance(item.env_service, str)
            and item.env_service
            and item.env_service != ENV_VAR_PLACEHOLDER
        ):
            env_defaults[key] = item.env_service
    return targets, env_defaults


def preserve_service_directory_placeholders_on_pull(
    app_dir: str | Path,
    previous_targets: set[tuple[str, str]],
    previous_env_defaults: dict[tuple[str, str], str] | None = None,
) -> list[str]:
    """Restore ``"$env_var"`` in pulled tool/toolset configs & sync env JSON."""
    if not previous_targets:
        return []

    root = Path(app_dir)
    env_path = root / "environment.json"
    fallbacks = previous_env_defaults or {}
    preserved: list[str] = []

    for item in inspect_app_service_directories(root):
        key = (item.kind, item.resource_id)
        if key not in previous_targets or item.component_key is None:
            continue
        if not item.has_sd_block:
            continue

        concrete: str | None = None
        if (
            isinstance(item.raw_service, str)
            and item.raw_service.strip()
            and item.raw_service.strip() != ENV_VAR_PLACEHOLDER
        ):
            concrete = item.raw_service.strip()
        elif (
            isinstance(item.env_service, str)
            and item.env_service.strip()
            and item.env_service.strip() != ENV_VAR_PLACEHOLDER
        ):
            concrete = item.env_service.strip()
        elif key in fallbacks:
            concrete = fallbacks[key]

        data = _load_config_file(item.config_path)
        if not isinstance(data, dict) or not isinstance(
            data.get(item.component_key), dict
        ):
            continue
        _set_component_sd_service(
            data[item.component_key], item.component_key, ENV_VAR_PLACEHOLDER
        )
        _write_config_file(item.config_path, data)

        if concrete:
            _upsert_env_json_sd_service(
                env_path,
                item.kind,
                item.resource_id,
                item.component_key,
                concrete,
                only_if_entry_exists=False,
            )
        preserved.append(f"{item.kind}/{item.resource_id}")

    return preserved


def record_and_placeholderize_service_directories_on_pull(
    app_dir: str | Path,
    map_path: str | Path,
    previous_env_defaults: dict[tuple[str, str], str] | None = None,
) -> list[str]:
    """Record pulled Service Directory bindings in map_path & set $env_var."""
    root = Path(app_dir)
    target_map_path = Path(map_path)
    fallbacks = previous_env_defaults or {}

    if target_map_path.is_file():
        sd_map = load_service_directory_map(target_map_path)
        if sd_map.errors:
            raise ValueError(
                f"Existing Service Directory map '{target_map_path}' has "
                f"errors: {'; '.join(sd_map.errors)}"
            )
    else:
        sd_map = ServiceDirectoryMap()

    sd_to_host = {sd: host for host, sd in sd_map.hosts.items()}
    recorded: list[str] = []
    env_path = root / "environment.json"

    for item in inspect_app_service_directories(root):
        if item.component_key is None:
            continue
        key = (item.kind, item.resource_id)
        concrete: str | None = None
        if (
            isinstance(item.raw_service, str)
            and item.raw_service.strip()
            and item.raw_service.strip() != ENV_VAR_PLACEHOLDER
        ):
            concrete = item.raw_service.strip()
        elif (
            isinstance(item.env_service, str)
            and item.env_service.strip()
            and item.env_service.strip() != ENV_VAR_PLACEHOLDER
        ):
            concrete = item.env_service.strip()
        elif item.has_sd_block and key in fallbacks:
            concrete = fallbacks[key]

        if not concrete:
            continue

        explicit_dict = (
            sd_map.toolsets if item.kind == "toolsets" else sd_map.tools
        )
        if item.fqdn:
            if concrete in sd_to_host and sd_to_host[concrete] != item.fqdn:
                raise ValueError(
                    f"L4 invariant violation while pulling: Service Directory "
                    f"'{concrete}' is bound to both '{sd_to_host[concrete]}' "
                    f"and '{item.fqdn}'"
                )
            sd_map.hosts[item.fqdn] = concrete
            sd_to_host[concrete] = item.fqdn
            if item.resource_id in explicit_dict:
                explicit_dict[item.resource_id] = concrete
        else:
            explicit_dict[item.resource_id] = concrete

        data = _load_config_file(item.config_path)
        if isinstance(data, dict) and isinstance(
            data.get(item.component_key), dict
        ):
            _set_component_sd_service(
                data[item.component_key],
                item.component_key,
                ENV_VAR_PLACEHOLDER,
            )
            _write_config_file(item.config_path, data)

        _upsert_env_json_sd_service(
            env_path,
            item.kind,
            item.resource_id,
            item.component_key,
            concrete,
            only_if_entry_exists=True,
        )
        recorded.append(f"{item.kind}/{item.resource_id}")

    write_service_directory_map(target_map_path, sd_map)
    return recorded


def resolve_service_directories_in_dir(
    app_dir: str | Path,
    map_path: str | Path | None = None,
) -> list[str]:
    """Resolve and inject concrete ``serviceDirectoryConfig`` in staged app_dir.

    Applies ``map_path`` (by explicit tool/toolset override or target FQDN) and
    resolves any remaining ``"$env_var"`` placeholders from ``environment.json``
    in ``app_dir``. Enforces resource format, concrete GCP region, and the
    1-SD-per-FQDN L4 invariant.
    """
    root = Path(app_dir)
    sd_map: ServiceDirectoryMap | None = None
    if map_path is not None:
        mp = Path(map_path)
        if not mp.is_file():
            raise FileNotFoundError(
                f"Service Directory mapping file '{map_path}' not found"
            )
        sd_map = load_service_directory_map(mp)
        if sd_map.errors:
            raise ValueError("; ".join(sd_map.errors))

    inspections = inspect_app_service_directories(root)
    errors: list[str] = []
    pending_writes: list[tuple[ServiceDirectoryInspection, str]] = []
    sd_to_fqdn: dict[str, tuple[str, str]] = {}

    for item in inspections:
        label = f"{item.kind}/{item.resource_id}"
        if item.unsupported_sd_component is not None:
            errors.append(
                f"{label} sets serviceDirectoryConfig on "
                f"'{item.unsupported_sd_component}', which does not support "
                "Service Directory Private Network Access"
            )
            if item.component_key is None:
                continue

        assert item.component_key is not None
        desired: str | None = None
        if sd_map is not None:
            desired = sd_map.lookup(
                item.kind, item.resource_id, item.display_name, item.fqdn
            )

        effective: str | None = desired
        should_write = desired is not None

        if effective is None and item.has_sd_block:
            if item.raw_service == ENV_VAR_PLACEHOLDER:
                if (
                    isinstance(item.env_service, str)
                    and item.env_service
                    and item.env_service != ENV_VAR_PLACEHOLDER
                ):
                    effective = item.env_service
                    should_write = True
                else:
                    errors.append(
                        f"{label} declares serviceDirectoryConfig.service="
                        f"'{ENV_VAR_PLACEHOLDER}', but no matching binding "
                        "was found in --service-directory-map or "
                        "environment.json"
                    )
                    continue
            else:
                effective_err = validate_sd_resource_name(item.raw_service)
                if effective_err:
                    errors.append(
                        f"{label} serviceDirectoryConfig.service "
                        f"{effective_err}"
                    )
                    continue
                effective = str(item.raw_service).strip()

        if effective is None:
            continue

        fmt_err = validate_sd_resource_name(effective)
        if fmt_err:
            errors.append(f"{label} serviceDirectoryConfig.service {fmt_err}")
            continue

        if item.fqdn:
            prev = sd_to_fqdn.get(effective)
            if prev is not None and prev[0] != item.fqdn:
                errors.append(
                    f"L4 invariant violation: Service Directory '{effective}' "
                    f"is bound to multiple distinct FQDNs ('{prev[0]}' on "
                    f"{prev[1]} and '{item.fqdn}' on {label}); 1 Service "
                    "Directory service = 1 VIP = 1 FQDN"
                )
                continue
            sd_to_fqdn[effective] = (item.fqdn, label)

        if should_write:
            pending_writes.append((item, effective))

    if errors:
        raise ValueError("; ".join(errors))

    env_path = root / "environment.json"
    updated_labels: list[str] = []
    for item, effective in pending_writes:
        assert item.component_key is not None
        data = _load_config_file(item.config_path)
        if not isinstance(data, dict) or not isinstance(
            data.get(item.component_key), dict
        ):
            continue
        _set_component_sd_service(
            data[item.component_key], item.component_key, effective
        )
        _write_config_file(item.config_path, data)
        _upsert_env_json_sd_service(
            env_path,
            item.kind,
            item.resource_id,
            item.component_key,
            effective,
            only_if_entry_exists=True,
        )
        updated_labels.append(f"{item.kind}/{item.resource_id}")

    return updated_labels
