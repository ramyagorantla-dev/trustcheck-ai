"""Tool: scan message text for well-known social-engineering red flags.

Patterns are based on public guidance from the FTC (consumer.ftc.gov) and the
FBI Internet Crime Complaint Center (ic3.gov). Deterministic and explainable.
"""
from __future__ import annotations

import re

from .common import Finding, result

# (signal, severity, regex, explanation)
PATTERNS = [
    ("urgency_pressure", "medium",
     r"\b(urgent(ly)?|immediately|right away|within (24|48) hours|act now|final (notice|warning)|"
     r"expires? (today|soon)|last chance|account (will be )?(suspended|locked|closed|terminated))\b",
     "Creates time pressure so you act before thinking."),
    ("gift_card_request", "high",
     r"\b(gift ?cards?|itunes card|google play card|steam card|scratch (the|off) (code|back))\b",
     "Requests for gift cards are a classic scam; real organizations never pay or get paid this way."),
    ("crypto_or_wire", "high",
     r"\b(bitcoin|btc|usdt|crypto(currency)?|wallet address|wire transfer|western union|moneygram|zelle)\b",
     "Asks for hard-to-reverse payment methods often used by scammers."),
    ("upfront_payment", "high",
     r"\b(processing fee|registration fee|training fee|pay (for|a) (your )?(equipment|training|background check|visa)|"
     r"refundable (deposit|fee)|small fee|release fee|customs fee)\b",
     "Legitimate employers and agencies don't ask you to pay to receive a job, prize, or package."),
    ("check_deposit_scheme", "high",
     r"\b(deposit (the|this) check|mobile deposit|send (back|the remaining|the balance)|"
     r"purchase (equipment|supplies) from (our|the) (approved )?vendor)\b",
     "Fake-check scheme: you deposit a check, send money back, then the check bounces."),
    ("credential_request", "high",
     r"\b(verify your (account|identity|password)|confirm your (password|login|credentials)|"
     r"enter your (password|pin|ssn|social security)|one[- ]time (code|password)|otp|"
     r"(send|share) (me )?(the|your) (code|verification code))\b",
     "Asks for passwords, codes, or identity details that should never be shared."),
    ("sensitive_personal_info", "medium",
     r"\b(social security number|ssn|bank account (number|details)|routing number|"
     r"copy of (your )?(passport|driver'?s license|id)|date of birth)\b",
     "Requests sensitive personal or banking information."),
    ("prize_or_windfall", "medium",
     r"\b(you('ve| have)? (won|been selected)|congratulations[,!]? you|lottery|claim your (prize|reward|refund)|"
     r"unclaimed (funds|refund)|inheritance)\b",
     "Unexpected prize or money offers are a common hook."),
    ("off_platform_chat", "medium",
     r"\b(telegram|whatsapp|signal app|google hangouts|teams chat interview|text interview|"
     r"interview (will be )?(conducted )?(via|on|over) (chat|text|telegram|whatsapp|signal))\b",
     "Moving interviews or conversations to chat apps is a common fake-recruiter tactic."),
    ("secrecy_request", "medium",
     r"\b(keep (this|it) (confidential|between us|secret)|don'?t tell anyone|do not share this with)\b",
     "Asking for secrecy isolates you from people who might spot the scam."),
    ("authority_impersonation_claim", "low",
     r"\b(irs|internal revenue service|social security administration|police|fbi|customs|"
     r"it department|help ?desk|ceo|your manager|hr department)\b",
     "Claims to be an authority figure; verify through an official channel."),
    ("generic_greeting", "low",
     r"^\s*(dear (customer|user|valued (customer|member)|sir/madam|applicant|candidate)|hello (customer|user))",
     "Generic greeting instead of your name."),
    ("too_good_to_be_true_pay", "medium",
     r"(\$\s?\d{2,3}(\.\d+)?\s?(/|per)\s?h(ou)?r|\$\s?\d{1,2},?\d{3}\s?(/|per)\s?week|no experience (needed|required)|"
     r"work from home.{0,40}(\$|earn))",
     "Unusually high pay for little work or no experience."),
    ("package_delivery_lure", "medium",
     r"\b(package|parcel|shipment|delivery)\b.{0,60}\b(on hold|held|failed|unable to deliver|"
     r"update (your )?(address|details)|redeliver)\b",
     "Fake delivery-problem texts lead to phishing pages."),
]

COMPILED = [(s, sev, re.compile(rx, re.I | re.M), why) for s, sev, rx, why in PATTERNS]


def scan_text_signals(text: str) -> dict:
    findings = []
    for signal, sev, rx, why in COMPILED:
        m = rx.search(text or "")
        if m:
            snippet = m.group(0).strip()
            findings.append(Finding(signal, sev, f'"{snippet}" — {why}'))
    if not findings:
        findings.append(Finding("no_text_red_flags", "info",
                                "No common scam phrases found (this alone doesn't mean it's safe)."))
    return result("scan_text_signals", findings)
