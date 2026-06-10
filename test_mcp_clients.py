from __future__ import annotations

import json
import sys
from pathlib import Path
import asyncio
from typing import Any

import pytest
from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parent
VULN_SERVER = ROOT / "mcp-tools" / "vuln-intel-mcp.py"
EXPLOIT_SERVER = ROOT / "mcp-tools" / "exploit-intel-mcp.py"
CVE = "CVE-2021-44228"


def _parse_tool_payload(result: types.CallToolResult) -> dict[str, Any]:
    if isinstance(result.structuredContent, dict):
        return result.structuredContent

    for block in result.content:
        if isinstance(block, types.TextContent):
            text = block.text.strip()
            try:
                parsed = json.loads(text)
                if isinstance(parsed, dict):
                    return parsed
            except json.JSONDecodeError:
                continue

    raise AssertionError(f"Unable to parse tool response as JSON: {result}")


async def _call_tool(script: Path, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    params = StdioServerParameters(command=sys.executable, args=[str(script)])
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(tool_name, arguments=arguments)
            return _parse_tool_payload(result)


def test_vuln_intel_lookup_cve_returns_real_data() -> None:
    payload = asyncio.run(_call_tool(VULN_SERVER, "lookup_cve", {"cve_id": CVE}))

    assert payload["ok"] is True
    assert payload["source"] == "nvd"
    assert payload["cve_id"] == CVE
    assert isinstance(payload.get("data"), dict)
    assert payload["data"].get("description")

    cvss = payload["data"].get("cvss_v31")
    assert cvss is not None
    assert cvss.get("vector_string")


def test_exploit_intel_find_public_exploits_returns_real_data() -> None:
    payload = asyncio.run(_call_tool(EXPLOIT_SERVER, "find_public_exploits", {"cve_id": CVE}))

    assert payload["ok"] is True
    assert payload["source"] == "github"
    assert payload["cve_id"] == CVE
    assert isinstance(payload.get("data"), dict)
    assert payload["data"].get("total_count", 0) > 0

    results = payload["data"].get("results", [])
    assert isinstance(results, list)
    assert len(results) > 0
    first = results[0]
    assert first.get("full_name")
    assert first.get("html_url")
