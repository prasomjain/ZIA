import hashlib
import json
import re
from typing import Any

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
# IPv4, domain-like hostnames, MD5/SHA1/SHA256, common URL prefix
IPV4_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"
)
DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b",
    re.IGNORECASE,
)
HASH_PATTERN = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


def _walk_values(obj: Any) -> list[str]:
    """Collect all string values from nested JSON for IOC/CVE scanning."""
    texts: list[str] = []
    if isinstance(obj, dict):
        for value in obj.values():
            texts.extend(_walk_values(value))
    elif isinstance(obj, list):
        for item in obj:
            texts.extend(_walk_values(item))
    elif isinstance(obj, str):
        texts.append(obj)
    elif obj is not None:
        texts.append(str(obj))
    return texts


def extract_cves(payload: dict[str, Any]) -> list[str]:
    found: set[str] = set()
    for text in _walk_values(payload):
        for match in CVE_PATTERN.findall(text):
            found.add(match.upper())
    return sorted(found)


def extract_iocs(payload: dict[str, Any]) -> list[str]:
    found: set[str] = set()
    for text in _walk_values(payload):
        for pattern in (IPV4_PATTERN, DOMAIN_PATTERN, HASH_PATTERN, URL_PATTERN):
            for match in pattern.findall(text):
                normalized = match.strip().lower()
                if normalized and not normalized.endswith(".local"):
                    found.add(normalized)
    return sorted(found)


def compute_fingerprint(cves: list[str], iocs: list[str]) -> str:
    material = f"{','.join(cves)}|{','.join(iocs)}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def normalize_payload(payload: dict[str, Any]) -> tuple[list[str], list[str], str]:
    cves = extract_cves(payload)
    iocs = extract_iocs(payload)
    fingerprint = compute_fingerprint(cves, iocs)
    return cves, iocs, fingerprint


def payload_to_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)
