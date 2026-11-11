"""Tool: inspect raw email headers (.eml) for spoofing and sender mismatches.

Reads SPF / DKIM / DMARC results from the Authentication-Results header that
your mail provider already added, compares From / Reply-To / Return-Path,
and checks whether the display name claims a brand the address doesn't belong to.
"""
from __future__ import annotations

import email
import re
from email import policy
from email.utils import parseaddr

from .. import config
from .common import Finding, registered_domain, result


def parse_email(raw: str):
    msg = email.message_from_string(raw, policy=policy.default)
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body = part.get_content()
                break
        if not body:
            for part in msg.walk():
                if part.get_content_type() == "text/html":
                    body = re.sub(r"<[^>]+>", " ", part.get_content())
                    break
    else:
        try:
            body = msg.get_content()
        except Exception:
            body = msg.get_payload() or ""
        if msg.get_content_type() == "text/html":
            body = re.sub(r"<[^>]+>", " ", body)
    return msg, body


def looks_like_email(raw: str) -> bool:
    head = raw[:3000]
    return bool(re.search(r"^From:\s", head, re.M) and re.search(r"^(Subject|To|Date|Received):\s", head, re.M))


def analyze_email_headers(raw_email: str) -> dict:
    if not looks_like_email(raw_email):
        return result("analyze_email_headers",
                      [Finding("no_headers", "info", "No email headers provided; sender checks were skipped.")])
    msg, _ = parse_email(raw_email)
    findings: list[Finding] = []

    from_name, from_addr = parseaddr(msg.get("From", ""))
    _, reply_addr = parseaddr(msg.get("Reply-To", ""))
    _, return_addr = parseaddr(msg.get("Return-Path", ""))
    from_dom = registered_domain(from_addr) if from_addr else ""

    # Authentication results
    auth = " ".join(str(v) for v in (msg.get_all("Authentication-Results") or []))
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(rf"\b{mech}=(\w+)", auth, re.I)
        if not m:
            continue
        verdict = m.group(1).lower()
        if verdict in ("fail", "softfail", "permerror"):
            findings.append(Finding(f"{mech}_fail", "high",
                                    f"{mech.upper()} = {verdict}: the sending server isn't authorized for {from_dom}."))
        elif verdict == "pass":
            findings.append(Finding(f"{mech}_pass", "info", f"{mech.upper()} passed for the sending domain."))
        elif verdict in ("none", "neutral"):
            findings.append(Finding(f"{mech}_none", "low", f"{mech.upper()} = {verdict}: sender not verified."))
    if not auth:
        findings.append(Finding("no_auth_results", "low",
                                "No Authentication-Results header; SPF/DKIM/DMARC couldn't be checked."))

    # Reply-To / Return-Path mismatch
    if reply_addr and from_dom and registered_domain(reply_addr) != from_dom:
        findings.append(Finding("reply_to_mismatch", "high",
                                f"Replies go to {reply_addr}, not to the sender's domain {from_dom}."))
    if return_addr and from_dom and registered_domain(return_addr) != from_dom:
        findings.append(Finding("return_path_mismatch", "medium",
                                f"Return-Path ({registered_domain(return_addr)}) differs from From domain ({from_dom})."))

    # Display-name brand spoofing: "PayPal Support <alerts@secure-mail.xyz>"
    name_norm = re.sub(r"[^a-z]", "", from_name.lower())
    for brand, domains in config.KNOWN_BRANDS.items():
        if brand in name_norm and from_dom and from_dom not in domains:
            sev = "high"
            findings.append(Finding("display_name_spoof", sev,
                                    f'Sender name says "{from_name}" but the address is @{from_dom}, '
                                    f"not an official {brand} domain."))
            break

    # Company / HR claim from a free mailbox
    if from_dom in config.FREE_EMAIL_PROVIDERS and re.search(
            r"(hr|recruit|talent|hiring|support|security|billing|admin|team|department|inc|llc|corp)",
            from_name + " " + from_addr, re.I):
        findings.append(Finding("org_from_free_email", "medium",
                                f"Claims to be an organization ({from_name or from_addr}) but uses a free {from_dom} account."))

    return result("analyze_email_headers", findings,
                  sender=from_addr, sender_name=from_name, reply_to=reply_addr, subject=str(msg.get("Subject", "")))
