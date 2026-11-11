"""Tool: analyze links and domains for phishing indicators.

Checks: lookalike/typosquat domains, brand names hidden in subdomains,
URL shorteners, raw IP addresses, punycode, risky TLDs, http (no TLS),
domain age (python-whois, optional) and Google Safe Browsing (optional, free key).
"""
from __future__ import annotations

import datetime as dt
import re
from urllib.parse import urlparse

import requests
from rapidfuzz.distance import Levenshtein

from .. import config
from .common import Finding, domain_parts, find_urls, registered_domain, result

LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s", "@": "a"})
OFFICIAL_DOMAINS = {d for ds in config.KNOWN_BRANDS.values() for d in ds}


def _host(url: str) -> str:
    if not re.match(r"^https?://", url, re.I):
        url = "http://" + url
    return (urlparse(url).hostname or "").lower()


def _brand_check(host: str) -> list[Finding]:
    out = []
    reg = registered_domain(host)
    if reg in OFFICIAL_DOMAINS:
        return [Finding("official_domain", "safe", f"{reg} is a known official domain.")]
    parts = domain_parts(host)
    label = parts.domain
    norm = label.translate(LEET).replace("rn", "m").replace("vv", "w").replace("-", "")
    tokens = [t.translate(LEET).replace("rn", "m").replace("vv", "w") for t in re.split(r"[-_]", label)]
    for brand, domains in config.KNOWN_BRANDS.items():
        # 1) typosquat: paypa1, rnicrosoft, amaz0n (whole label or any hyphen-separated part)
        disguised = [t for t, raw in zip(tokens, re.split(r"[-_]", label)) if t == brand and raw != brand]
        if (norm != label.replace("-", "") and norm == brand) or disguised:
            out.append(Finding("lookalike_domain", "high",
                               f"{reg} imitates {brand} by swapping look-alike characters (real site: {domains[0]})."))
            continue
        near = [t for t in tokens if len(brand) >= 6 and 0 < Levenshtein.distance(t, brand) <= 2]
        if near:
            out.append(Finding("lookalike_domain", "high",
                               f"{reg} is one or two letters away from {brand} (real site: {domains[0]})."))
            continue
        # 2) brand inside a different domain: paypal-secure-login.xyz, deloitte-careers.net
        if brand in norm and norm != brand:
            out.append(Finding("brand_in_unofficial_domain", "high",
                               f"{reg} contains '{brand}' but is not an official {brand} domain ({', '.join(domains)})."))
            continue
        # 3) brand in subdomain: paypal.com.secure-check.io
        if brand in parts.subdomain.replace("-", "").split(".") or f"{brand}." in parts.subdomain:
            out.append(Finding("brand_in_subdomain", "high",
                               f"'{brand}' appears only in the subdomain of {host}; the real site is {reg}."))
    return out


def _domain_age_days(domain: str) -> int | None:
    if not config.ENABLE_WHOIS:
        return None
    try:
        import whois  # python-whois
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = min(c for c in created if c)
        if not created:
            return None
        if created.tzinfo:
            created = created.replace(tzinfo=None)
        return (dt.datetime.now() - created).days
    except Exception:
        return None


def _safe_browsing(urls: list[str]) -> list[str]:
    key = config.GOOGLE_SAFE_BROWSING_KEY
    if not key or not urls:
        return []
    body = {
        "client": {"clientId": "trustcheck", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u if u.startswith("http") else "http://" + u} for u in urls],
        },
    }
    try:
        r = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}", json=body, timeout=8)
        return [m["threat"]["url"] for m in r.json().get("matches", [])]
    except Exception:
        return []


def analyze_links(text: str, check_domain_age: bool = True) -> dict:
    urls = find_urls(text)
    findings: list[Finding] = []
    if not urls:
        return result("analyze_links", [Finding("no_links", "info", "No links found in the message.")], urls=[])

    seen_domains = set()
    for url in urls[:10]:
        host = _host(url)
        if not host:
            continue
        reg = registered_domain(host)
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
            findings.append(Finding("ip_address_url", "high", f"{url} points to a raw IP address, not a named website."))
            continue
        if host.startswith("xn--") or ".xn--" in host:
            findings.append(Finding("punycode_domain", "high",
                                    f"{host} uses punycode, which can disguise lookalike characters."))
        if reg in config.URL_SHORTENERS:
            findings.append(Finding("url_shortener", "medium", f"{url} uses a link shortener that hides the real destination."))
        tld = domain_parts(host).suffix.split(".")[-1]
        if tld in config.SUSPICIOUS_TLDS and reg not in OFFICIAL_DOMAINS:
            findings.append(Finding("risky_tld", "medium", f"{reg} uses the .{tld} ending, which is common in scam sites."))
        if url.lower().startswith("http://"):
            findings.append(Finding("no_https", "low", f"{url} is not encrypted (http, not https)."))
        if host.count(".") >= 4:
            findings.append(Finding("deep_subdomain", "low", f"{host} has many subdomains, a common way to hide the real domain."))
        findings.extend(_brand_check(host))
        if check_domain_age and reg not in seen_domains and reg not in OFFICIAL_DOMAINS:
            age = _domain_age_days(reg)
            if age is not None and age < 90:
                findings.append(Finding("new_domain", "high", f"{reg} was registered only {age} days ago."))
            elif age is not None:
                findings.append(Finding("domain_age", "info", f"{reg} is {age} days old."))
        seen_domains.add(reg)

    for bad in _safe_browsing(urls):
        findings.append(Finding("google_safe_browsing_match", "high", f"Google Safe Browsing flags {bad} as dangerous."))

    if not findings:
        findings.append(Finding("links_look_normal", "info", "Links didn't match any phishing patterns."))
    return result("analyze_links", findings, urls=urls)
