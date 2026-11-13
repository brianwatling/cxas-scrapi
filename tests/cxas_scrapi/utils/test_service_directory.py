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

"""Unit tests for Service Directory mapping, pull, and push utilities."""

import json
from pathlib import Path

import pytest
import yaml

from cxas_scrapi.utils.service_directory import (
    collect_env_var_service_directory_targets,
    extract_fqdn,
    extract_schema_fqdn,
    is_direct_egress_fqdn,
    load_service_directory_map,
    parse_service_directory_map_text,
    preserve_service_directory_placeholders_on_pull,
    record_and_placeholderize_service_directories_on_pull,
    resolve_service_directories_in_dir,
    validate_sd_resource_name,
    write_service_directory_map,
)

SD_UAT_API = (
    "projects/my-agent-uat/locations/us-central1"
    "/namespaces/ces-egress/services/ces-svc-api-uat-3f9a1c"
)
SD_UAT_IDP = (
    "projects/my-agent-uat/locations/us-central1"
    "/namespaces/ces-egress/services/ces-svc-idp-uat-c207aa"
)
SD_DEV_API = (
    "projects/my-agent-dev/locations/us-central1"
    "/namespaces/ces-egress/services/ces-svc-api-dev-112233"
)


def test_validate_sd_resource_name() -> None:
    assert validate_sd_resource_name(SD_UAT_API) is None
    assert (
        validate_sd_resource_name(
            "projects/p/locations/northamerica-northeast1"
            "/namespaces/ns/services/svc"
        )
        is None
    )

    err_multi = validate_sd_resource_name(
        "projects/p/locations/us/namespaces/ns/services/svc"
    )
    assert err_multi is not None
    assert "concrete GCP region" in err_multi

    err_global = validate_sd_resource_name(
        "projects/p/locations/global/namespaces/ns/services/svc"
    )
    assert err_global is not None
    assert "concrete GCP region" in err_global

    assert validate_sd_resource_name("") is not None
    assert validate_sd_resource_name("ces-svc-only") is not None


def test_extract_fqdn_and_schema_fqdn() -> None:
    assert (
        extract_fqdn("https://API.Partner.Example.com:443/v1/orders/{id}")
        == "api.partner.example.com"
    )
    assert extract_fqdn("payments.partner.example.com:443") == (
        "payments.partner.example.com"
    )
    assert extract_fqdn("$env_var") == ""
    assert extract_fqdn("https://{env}.partner.example.com/v1") == ""

    assert is_direct_egress_fqdn("storage.googleapis.com")
    assert is_direct_egress_fqdn("bridge-abc.a.run.app")
    assert not is_direct_egress_fqdn("api.partner.example.com")

    openapi_yaml = """
openapi: 3.0.3
servers:
  - url: https://{stage}.partner.example.com/v1
    variables:
      stage:
        default: api-uat
paths: {}
"""
    assert extract_schema_fqdn(openapi_yaml) == "api-uat.partner.example.com"

    openapi_v2_json = json.dumps({"host": "legacy.partner.com", "paths": {}})
    assert extract_schema_fqdn(openapi_v2_json) == "legacy.partner.com"


def test_parse_structured_yaml_with_shorthand_expansion() -> None:
    content = """
project: my-agent-uat
location: us-central1
namespace: ces-egress
hosts:
  api-uat.partner.example.com: ces-svc-api-uat-3f9a1c
  idp-uat.partner.example.com: ces-svc-idp-uat-c207aa
toolsets:
  custom_ts:
    openApiToolset:
      serviceDirectoryConfig:
        service: ces-svc-custom-999999
"""
    parsed = parse_service_directory_map_text(content, suffix=".yaml")
    assert parsed.errors == []
    assert parsed.hosts["api-uat.partner.example.com"] == SD_UAT_API
    assert parsed.hosts["idp-uat.partner.example.com"] == SD_UAT_IDP
    assert parsed.toolsets["custom_ts"].endswith("/ces-svc-custom-999999")


def test_parse_setup_script_summary_output() -> None:
    summary_text = f"""
========================================================================
CX Agent Studio Static Egress Setup Complete
Project: my-agent-uat (123456789) | Region: us-central1
------------------------------------------------------------------------
Static External IPs to Allowlist (shared across all FQDNs, CSV): 198.51.100.20,198.51.100.21
  - 198.51.100.20
  - 198.51.100.21
------------------------------------------------------------------------
serviceDirectoryConfig.service per FQDN (paste into CES tools/toolsets):
  api-uat.partner.example.com (VIP 10.128.0.2:443) -> {SD_UAT_API}
  idp-uat.partner.example.com (VIP 10.128.0.3:443) -> {SD_UAT_IDP}
========================================================================
"""
    parsed = parse_service_directory_map_text(summary_text, suffix=".txt")
    assert parsed.errors == []
    assert parsed.hosts == {
        "api-uat.partner.example.com": SD_UAT_API,
        "idp-uat.partner.example.com": SD_UAT_IDP,
    }


def test_parse_map_detects_l4_invariant_and_conflicts() -> None:
    bad_l4 = {
        "hosts": {
            "api-1.partner.example.com": SD_UAT_API,
            "api-2.partner.example.com": SD_UAT_API,
        }
    }
    parsed = parse_service_directory_map_text(
        json.dumps(bad_l4), suffix=".json"
    )
    assert len(parsed.errors) == 1
    assert "L4 invariant violation" in parsed.errors[0]


def test_pull_record_and_push_resolve_roundtrip(tmp_path: Path) -> None:
    app_dir = tmp_path / "My_App"
    ts_dir = app_dir / "toolsets" / "customer_api"
    ts_dir.mkdir(parents=True)
    (ts_dir / "openapi.yaml").write_text(
        "openapi: 3.0.0\nservers:\n  - url: https://api-dev.partner.com/v1\n"
    )
    (ts_dir / "customer_api.json").write_text(
        json.dumps(
            {
                "displayName": "customer_api",
                "openApiToolset": {
                    "openApiSchema": "toolsets/customer_api/openapi.yaml",
                    "url": "$env_var",
                    "serviceDirectoryConfig": {"service": SD_DEV_API},
                },
            }
        )
    )

    mcp_dir = app_dir / "toolsets" / "partner_mcp"
    mcp_dir.mkdir(parents=True)
    (mcp_dir / "partner_mcp.json").write_text(
        json.dumps(
            {
                "displayName": "partner_mcp",
                "mcpToolset": {
                    "serverAddress": "https://idp-dev.partner.com/mcp",
                    "serviceDirectoryConfig": {
                        "service": (
                            "projects/my-agent-dev/locations/us-central1"
                            "/namespaces/ces-egress/services/ces-svc-idp-dev"
                        )
                    },
                },
            }
        )
    )

    # Cloud Run direct-egress toolset without SD
    cr_dir = app_dir / "toolsets" / "internal_bridge"
    cr_dir.mkdir(parents=True)
    (cr_dir / "internal_bridge.json").write_text(
        json.dumps(
            {
                "displayName": "internal_bridge",
                "openApiToolset": {
                    "url": "https://bridge-xyz.a.run.app",
                    "openApiSchema": "openapi: 3.0.0\npaths: {}\n",
                },
            }
        )
    )

    (app_dir / "environment.json").write_text(
        json.dumps(
            {
                "toolsets": {
                    "customer_api": {
                        "openApiToolset": {
                            "url": "https://api-dev.partner.com/v1"
                        }
                    }
                }
            }
        )
    )

    dev_map_path = tmp_path / "sd-dev.yaml"
    recorded = record_and_placeholderize_service_directories_on_pull(
        app_dir, dev_map_path
    )
    assert set(recorded) == {"toolsets/customer_api", "toolsets/partner_mcp"}

    # Local toolset configs now hold "$env_var"
    pulled_ts = json.loads((ts_dir / "customer_api.json").read_text())
    assert (
        pulled_ts["openApiToolset"]["serviceDirectoryConfig"]["service"]
        == "$env_var"
    )
    loaded_dev_map = load_service_directory_map(dev_map_path)
    assert loaded_dev_map.hosts["api-dev.partner.com"] == SD_DEV_API

    # Now stage a UAT push where environment.json switches URL to api-uat!
    (app_dir / "environment.json").write_text(
        json.dumps(
            {
                "toolsets": {
                    "customer_api": {
                        "openApiToolset": {
                            "url": "https://api-uat.partner.example.com/v1"
                        }
                    },
                    "partner_mcp": {
                        "mcpToolset": {
                            "serverAddress": (
                                "https://idp-uat.partner.example.com/mcp"
                            )
                        }
                    },
                }
            }
        )
    )
    # Also add a standalone OpenAPI tool without serviceDirectoryConfig locally
    tool_dir = app_dir / "tools" / "billing_lookup"
    tool_dir.mkdir(parents=True)
    (tool_dir / "billing_lookup.json").write_text(
        json.dumps(
            {
                "displayName": "billing_lookup",
                "openApiTool": {
                    "url": "https://api-uat.partner.example.com/v2/billing",
                    "openApiSchema": "openapi: 3.0.0\npaths: {}\n",
                },
            }
        )
    )

    uat_map_path = tmp_path / "sd-uat.yaml"
    uat_map_path.write_text(
        yaml.safe_dump(
            {
                "hosts": {
                    "api-uat.partner.example.com": SD_UAT_API,
                    "idp-uat.partner.example.com": SD_UAT_IDP,
                }
            }
        )
    )

    resolved = resolve_service_directories_in_dir(
        app_dir, map_path=uat_map_path
    )
    assert set(resolved) == {
        "toolsets/customer_api",
        "toolsets/partner_mcp",
        "tools/billing_lookup",
    }

    # Both customer_api and billing_lookup target api-uat.partner.example.com,
    # so sharing SD_UAT_API is valid!
    staged_ts = json.loads((ts_dir / "customer_api.json").read_text())
    assert (
        staged_ts["openApiToolset"]["serviceDirectoryConfig"]["service"]
        == SD_UAT_API
    )
    staged_tool = json.loads((tool_dir / "billing_lookup.json").read_text())
    assert (
        staged_tool["openApiTool"]["serviceDirectoryConfig"]["service"]
        == SD_UAT_API
    )
    # Cloud Run toolset remains untouched on direct egress
    staged_cr = json.loads((cr_dir / "internal_bridge.json").read_text())
    assert "serviceDirectoryConfig" not in staged_cr["openApiToolset"]


def test_preserve_placeholders_on_pull_without_map_file(tmp_path: Path) -> None:
    app_dir = tmp_path / "My_App"
    ts_dir = app_dir / "toolsets" / "customer_api"
    ts_dir.mkdir(parents=True)
    (ts_dir / "customer_api.json").write_text(
        json.dumps(
            {
                "displayName": "customer_api",
                "openApiToolset": {
                    "url": "https://api-dev.partner.com/v1",
                    "serviceDirectoryConfig": {"service": "$env_var"},
                },
            }
        )
    )
    prev_targets, prev_defaults = collect_env_var_service_directory_targets(
        app_dir
    )
    assert prev_targets == {("toolsets", "customer_api")}

    # Simulate ExportApp overwriting customer_api.json with concrete SD
    (ts_dir / "customer_api.json").write_text(
        json.dumps(
            {
                "displayName": "customer_api",
                "openApiToolset": {
                    "url": "https://api-dev.partner.com/v1",
                    "serviceDirectoryConfig": {"service": SD_DEV_API},
                },
            }
        )
    )

    preserved = preserve_service_directory_placeholders_on_pull(
        app_dir, prev_targets, previous_env_defaults=prev_defaults
    )
    assert preserved == ["toolsets/customer_api"]
    restored = json.loads((ts_dir / "customer_api.json").read_text())
    assert (
        restored["openApiToolset"]["serviceDirectoryConfig"]["service"]
        == "$env_var"
    )
    env_json = json.loads((app_dir / "environment.json").read_text())
    assert (
        env_json["toolsets"]["customer_api"]["openApiToolset"][
            "serviceDirectoryConfig"
        ]["service"]
        == SD_DEV_API
    )


def test_resolve_from_environment_json_without_map_and_fail_on_unresolved(
    tmp_path: Path,
) -> None:
    app_dir = tmp_path / "My_App"
    ts_dir = app_dir / "toolsets" / "customer_api"
    ts_dir.mkdir(parents=True)
    (ts_dir / "customer_api.json").write_text(
        json.dumps(
            {
                "displayName": "customer_api",
                "openApiToolset": {
                    "url": "https://api-uat.partner.example.com/v1",
                    "serviceDirectoryConfig": {"service": "$env_var"},
                },
            }
        )
    )

    # Fails fast when neither map nor environment.json resolves "$env_var"
    with pytest.raises(ValueError, match="no matching binding"):
        resolve_service_directories_in_dir(app_dir)

    # Resolves cleanly when environment.json provides concrete service
    (app_dir / "environment.json").write_text(
        json.dumps(
            {
                "toolsets": {
                    "customer_api": {
                        "openApiToolset": {
                            "serviceDirectoryConfig": {"service": SD_UAT_API}
                        }
                    }
                }
            }
        )
    )
    resolved = resolve_service_directories_in_dir(app_dir)
    assert resolved == ["toolsets/customer_api"]
    updated = json.loads((ts_dir / "customer_api.json").read_text())
    assert (
        updated["openApiToolset"]["serviceDirectoryConfig"]["service"]
        == SD_UAT_API
    )


def test_write_and_load_txt_map_roundtrip(tmp_path: Path) -> None:
    txt_map = tmp_path / "sd.txt"
    parsed = parse_service_directory_map_text(
        json.dumps(
            {
                "hosts": {"api-uat.partner.example.com": SD_UAT_API},
                "tools": {"custom_tool": SD_UAT_IDP},
            }
        ),
        suffix=".json",
    )
    write_service_directory_map(txt_map, parsed)
    reloaded = load_service_directory_map(txt_map)
    assert reloaded.errors == []
    assert reloaded.hosts == {"api-uat.partner.example.com": SD_UAT_API}
    assert reloaded.tools == {"custom_tool": SD_UAT_IDP}
