"""Shared helpers for tools. Every tool returns a dict with a list of findings."""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass

import tldextract

# offline: use the bundled public-suffix snapshot, never download at runtime
_extract = tldextract.TLDExtract(suffix_list_urls=())

SEVERITY_POINTS = {"high": 30, "medium": 15, "low": 5, "info": 0, "safe": -10}


@dataclass
class Finding:
    signal: str          # short machine name, e.g. "lookalike_domain"
    severity: str        # high | medium | low | info | safe
    detail: str          # human-readable evidence

    def to_dict(self):
        return asdict(self)


def result(tool: str, findings: list[Finding], **extra) -> dict:
    return {
        "tool": tool,
        "findings": [f.to_dict() for f in findings],
        "risk_points": sum(SEVERITY_POINTS.get(f.severity, 0) for f in findings),
        **extra,
    }


def registered_domain(host_or_email: str) -> str:
    """'hr@careers.deloitte-jobs.net' -> 'deloitte-jobs.net'"""
    host = host_or_email.split("@")[-1].strip().strip(">").lower()
    ext = _extract(host)
    if not ext.suffix:
        return ext.domain or host
    return f"{ext.domain}.{ext.suffix}"


def domain_parts(host: str):
    return _extract(host.lower())


URL_RE = re.compile(
    r"""(?xi)
    \b(
      (?:https?://|www\.)[^\s<>"'()]+            # explicit URLs
      |
      (?:[a-z0-9-]+\.)+(?:com|net|org|io|co|xyz|top|click|link|info|live|online|site|icu|
         buzz|rest|work|support|shop|ly|gl|me|us|in|cfd|sbs|loan|zip|mov|gov|edu)
         (?:/[^\s<>"'()]*)?                       # bare domains like paypal-secure.xyz/login
    )""",
)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def find_urls(text: str) -> list[str]:
    urls = []
    for m in URL_RE.findall(text or ""):
        u = m.rstrip(".,;:!?)")
        # skip the domain part of e-mail addresses
        if re.search(r"@" + re.escape(u.split("/")[0]) + r"\b", text):
            continue
        if u not in urls:
            urls.append(u)
    return urls


def find_emails(text: str) -> list[str]:
    out = []
    for e in EMAIL_RE.findall(text or ""):
        if e.lower() not in out:
            out.append(e.lower())
    return out
