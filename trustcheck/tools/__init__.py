"""Tool registry: Python functions + the JSON schemas the LLM sees.

Tools read the message from a shared context instead of having the LLM copy
the whole message into arguments (cheaper and avoids copying mistakes).
The LLM decides WHICH tools to call and supplies only small arguments.
"""
from __future__ import annotations

from .email_headers import analyze_email_headers
from .injection import detect_prompt_injection
from .knowledge import search_scam_knowledge
from .links import analyze_links
from .offer_letter import check_job_offer
from .text_signals import scan_text_signals

TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "analyze_links",
            "description": "Check every link/domain in the message for phishing signs: lookalike brand domains, "
                           "link shorteners, raw IP addresses, risky domain endings, newly registered domains. "
                           "Use when the message contains any URL or website name.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_email_headers",
            "description": "Inspect raw email headers: SPF/DKIM/DMARC results, From vs Reply-To mismatch, "
                           "display names that claim a brand the address doesn't belong to. "
                           "Only useful when the input is a full email with headers.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_job_offer",
            "description": "Run job-offer/recruiter scam checks: recruiter using free email, company name vs email "
                           "domain mismatch, no real interview, chat-app interviews, buying equipment, paying fees, "
                           "early requests for SSN/bank info. Use for any job offer, recruiter or hiring message.",
            "parameters": {
                "type": "object",
                "properties": {"company_name": {"type": "string",
                                                "description": "Company the message claims to be from, if known."}},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "scan_text_signals",
            "description": "Scan the wording for social-engineering red flags: urgency, gift cards, crypto/wire "
                           "payments, requests for passwords or codes, prize claims, secrecy, delivery-problem lures.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_scam_knowledge",
            "description": "Search a knowledge base of documented scam types (from FTC and FBI guidance) to find "
                           "which known scam this message resembles and how to verify it safely.",
            "parameters": {
                "type": "object",
                "properties": {"query": {"type": "string",
                                         "description": "Short description of the suspected scheme, e.g. "
                                                        "'fake recruiter asks to buy equipment with check'."}},
                "required": ["query"],
            },
        },
    },
]


def run_tool(name: str, args: dict, ctx: dict) -> dict:
    """Execute a tool by name. ctx holds 'text' (message body) and 'raw' (full input)."""
    args = args or {}
    if name == "analyze_links":
        return analyze_links(ctx["raw"])
    if name == "analyze_email_headers":
        return analyze_email_headers(ctx["raw"])
    if name == "check_job_offer":
        return check_job_offer(ctx["text"], company_name=str(args.get("company_name", "") or ""))
    if name == "scan_text_signals":
        return scan_text_signals(ctx["text"])
    if name == "search_scam_knowledge":
        return search_scam_knowledge(str(args.get("query") or ctx["text"][:300]))
    return {"tool": name, "error": f"Unknown tool '{name}'", "findings": [], "risk_points": 0}


ALL_TOOL_NAMES = [t["function"]["name"] for t in TOOL_SCHEMAS]

__all__ = [
    "TOOL_SCHEMAS", "run_tool", "ALL_TOOL_NAMES", "analyze_links", "analyze_email_headers",
    "check_job_offer", "scan_text_signals", "search_scam_knowledge", "detect_prompt_injection",
]
