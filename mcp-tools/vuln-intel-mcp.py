#!/usr/bin/env python3
"""Vulnerability intelligence MCP server (stdio transport)."""

from __future__ import annotations

import asyncio
import os
import re
import sys
import time
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("vuln-intel-mcp", json_response=True)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

DEFAULT_TIMEOUT = httpx.Timeout(connect=10.0, read=25.0, write=10.0, pool=10.0)


def _validate_cve(cve_id: str) -> str:
    normalized = cve_id.strip().upper()
    if not CVE_RE.match(normalized):
        raise ValueError(f"Invalid CVE format: {cve_id}")
    return normalized


async def _request_json(
    client: httpx.AsyncClient,
    url: str,
    *,
    params: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    retries: int = 3,
) -> tuple[dict[str, Any], dict[str, str], int]:
    """GET JSON with graceful handling of HTTP 429 and transient 5xx."""
    backoff = 1.0
    last_error: Exception | None = None

    for attempt in range(1, retries + 1):
        try:
            response = await client.get(url, params=params, headers=headers)

            if response.status_code == 429:
                reset_ts = response.headers.get("x-ratelimit-reset")
                retry_after = response.headers.get("retry-after")
                if retry_after:
                    wait_s = min(float(retry_after), 30.0)
                elif reset_ts and reset_ts.isdigit():
                    wait_s = max(0.5, min(float(reset_ts) - time.time(), 30.0))
                else:
                    wait_s = min(backoff, 30.0)
                await asyncio.sleep(wait_s)
                backoff *= 2
                continue

            if response.status_code >= 500:
                await asyncio.sleep(min(backoff, 10.0))
                backoff *= 2
                continue

            response.raise_for_status()
            return response.json(), dict(response.headers), response.status_code
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            if attempt < retries:
                await asyncio.sleep(min(backoff, 10.0))
                backoff *= 2

    raise RuntimeError(f"Request failed for {url}: {last_error}") from last_error


@mcp.tool()
async def lookup_cve(cve_id: str) -> dict[str, Any]:
    """Fetch CVE details from NVD API 2.0 including CVSS v3.1 and CWE."""
    cve = _validate_cve(cve_id)

    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT, follow_redirects=True) as client:
        data, headers, _ = await _request_json(client, NVD_URL, params={"cveId": cve})

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return {
            "ok": False,
            "source": "nvd",
            "cve_id": cve,
            "error": {"type": "NOT_FOUND", "message": "CVE not found in NVD"},
            "rate_limit": {
                "remaining": headers.get("x-ratelimit-remaining"),
                "reset": headers.get("x-ratelimit-reset"),
            },
        }

    cve_obj = vulns[0].get("cve", {})
    descriptions = cve_obj.get("descriptions", [])
    english_desc = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "")

    metrics = cve_obj.get("metrics", {})
    cvss_v31 = metrics.get("cvssMetricV31", [])
    cvss_data = cvss_v31[0].get("cvssData", {}) if cvss_v31 else {}

    weaknesses = cve_obj.get("weaknesses", [])
    cwes: list[str] = []
    for weakness in weaknesses:
        for desc in weakness.get("description", []):
            value = (desc.get("value") or "").strip()
            if value:
                cwes.append(value)

    return {
        "ok": True,
        "source": "nvd",
        "cve_id": cve,
        "data": {
            "published": cve_obj.get("published"),
            "last_modified": cve_obj.get("lastModified"),
            "vuln_status": cve_obj.get("vulnStatus"),
            "description": english_desc,
            "cvss_v31": {
                "base_score": cvss_data.get("baseScore"),
                "base_severity": cvss_data.get("baseSeverity"),
                "vector_string": cvss_data.get("vectorString"),
                "attack_vector": cvss_data.get("attackVector"),
            }
            if cvss_data
            else None,
            "cwe": sorted(set(cwes)),
            "references": [r.get("url") for r in cve_obj.get("references", []) if r.get("url")],
        },
        "rate_limit": {
            "remaining": headers.get("x-ratelimit-remaining"),
            "reset": headers.get("x-ratelimit-reset"),
        },
    }


@mcp.tool()
async def get_epss_score(cve_id: str) -> dict[str, Any]:
    """Fetch EPSS exploit probability score for a CVE."""
    cve = _validate_cve(cve_id)

    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT, follow_redirects=True) as client:
        data, headers, _ = await _request_json(client, EPSS_URL, params={"cve": cve})

    rows = data.get("data", [])
    row = rows[0] if rows else None

    if not row:
        return {
            "ok": False,
            "source": "first_epss",
            "cve_id": cve,
            "error": {"type": "NOT_FOUND", "message": "EPSS data not available for CVE"},
            "rate_limit": {
                "remaining": headers.get("x-ratelimit-remaining"),
                "reset": headers.get("x-ratelimit-reset"),
            },
        }

    return {
        "ok": True,
        "source": "first_epss",
        "cve_id": cve,
        "data": {
            "epss": float(row.get("epss", 0.0)),
            "percentile": float(row.get("percentile", 0.0)),
            "date": row.get("date"),
        },
        "rate_limit": {
            "remaining": headers.get("x-ratelimit-remaining"),
            "reset": headers.get("x-ratelimit-reset"),
        },
    }


@mcp.tool()
async def check_kev(cve_id: str) -> dict[str, Any]:
    """Check whether CVE is present in CISA Known Exploited Vulnerabilities catalog."""
    cve = _validate_cve(cve_id)

    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT, follow_redirects=True) as client:
        kev_feed, headers, _ = await _request_json(client, CISA_KEV_URL)

    vulnerabilities = kev_feed.get("vulnerabilities", [])
    match = next((v for v in vulnerabilities if (v.get("cveID") or "").upper() == cve), None)

    return {
        "ok": True,
        "source": "cisa_kev",
        "cve_id": cve,
        "data": {
            "is_listed": bool(match),
            "catalog_version": kev_feed.get("catalogVersion"),
            "date_released": kev_feed.get("dateReleased"),
            "kev_entry": {
                "vulnerability_name": match.get("vulnerabilityName"),
                "vendor_project": match.get("vendorProject"),
                "product": match.get("product"),
                "date_added": match.get("dateAdded"),
                "required_action": match.get("requiredAction"),
                "known_ransomware_campaign_use": match.get("knownRansomwareCampaignUse"),
                "short_description": match.get("shortDescription"),
                "cwes": match.get("cwes"),
            }
            if match
            else None,
        },
        "rate_limit": {
            "remaining": headers.get("x-ratelimit-remaining"),
            "reset": headers.get("x-ratelimit-reset"),
        },
    }


if __name__ == "__main__":
    # Never print to stdout in stdio MCP servers.
    mcp.run()
