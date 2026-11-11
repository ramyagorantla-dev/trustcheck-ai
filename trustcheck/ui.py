"""Visual layer for the Streamlit app: "the evidence desk".

The message is shown like an exhibit with suspicious phrases marked up, and the
verdict lands as a rubber stamp. The stamp is the one bold element; the rest is calm.
"""
from __future__ import annotations

import html
import re

INK = "#1B2A4A"        # navy ink: text, headings
PAPER = "#F5F8FC"      # security-paper blue-white: page
TEAL = "#0F766E"       # banknote teal: actions, links
RULE = "#D5DDEA"       # hairline borders
VERDICT = {"high": "#B42318", "medium": "#B54708", "low": "#067647"}
STAMP_TEXT = {"high": "LIKELY SCAM", "medium": "VERIFY FIRST", "low": "NO RED FLAGS"}
VERDICT_LINE = {
    "high": "Don't reply, click, or pay. The evidence below shows why.",
    "medium": "Some warning signs. Check it through an official channel before you act.",
    "low": "We didn't find strong warning signs. If money or passwords are involved, still verify it yourself.",
}

CSS = f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,500;12..96,700;12..96,800&family=Atkinson+Hyperlegible:ital,wght@0,400;0,700;1,400&display=swap');

html, body, .stApp, [class*="css"] {{
  font-family: 'Atkinson Hyperlegible', system-ui, sans-serif;
  color: {INK};
}}
.stApp {{ background: {PAPER}; }}
h1, h2, h3, h4 {{ font-family: 'Bricolage Grotesque', system-ui, sans-serif !important;
  color: {INK} !important; letter-spacing: -0.01em; }}
h3 {{ font-size: 1.35rem !important; }}
.block-container {{ padding-top: 2.2rem; max-width: 1180px; }}
a {{ color: {TEAL} !important; }}
a:focus-visible, button:focus-visible, textarea:focus-visible {{ outline: 3px solid {TEAL}; outline-offset: 2px; }}

/* sidebar: quiet, like the desk's edge */
[data-testid="stSidebar"] {{ background: #EAF0F8; border-right: 1px solid {RULE}; }}

/* primary action */
.stButton > button[kind="primary"] {{
  background: {TEAL}; border: 0; border-radius: 10px; padding: 0.7rem 1.6rem;
  font-weight: 700; font-size: 1.05rem;
}}
.stButton > button[kind="primary"]:hover {{ background: #0B5F59; }}

/* tabs */
.stTabs [data-baseweb="tab-list"] {{ gap: 0.4rem; border-bottom: 1px solid {RULE}; }}
.stTabs [data-baseweb="tab"] {{ font-weight: 700; padding: 0.5rem 0.9rem; }}
.stTabs [aria-selected="true"] {{ color: {TEAL} !important; }}

/* the message box looks like a sheet of paper */
.stTextArea textarea {{
  background: #FFFFFF; border: 1px solid {RULE}; border-radius: 6px;
  font-size: 1rem; line-height: 1.55;
  box-shadow: 0 1px 0 {RULE}, 0 6px 0 -3px #FFFFFF, 0 7px 0 -3px {RULE};
}}

/* ---------- hero ---------- */
.tc-hero {{ display: grid; grid-template-columns: 1fr auto; align-items: end; gap: 2rem;
  padding: 0.5rem 0 1.4rem; border-bottom: 2px solid {INK}; margin-bottom: 1.4rem; }}
.tc-hero h1 {{ font-size: clamp(2.1rem, 4.2vw, 3.3rem) !important; line-height: 1.02; margin: 0;
  font-weight: 800 !important; max-width: 15ch; }}
.tc-hero p {{ font-size: 1.12rem; max-width: 52ch; margin: 0.8rem 0 0; color: #33415C; }}

/* ---------- verdict ---------- */
.tc-verdict {{ position: relative; background: #FFFFFF; border: 1px solid {RULE}; border-radius: 8px;
  padding: 1.6rem 1.8rem 1.4rem; margin: 0.6rem 0 1.2rem; display: grid;
  grid-template-columns: auto 1fr; gap: 2rem; align-items: center; }}
.tc-stamp {{ font-family: 'Bricolage Grotesque', sans-serif; font-weight: 800;
  font-size: clamp(1.4rem, 3vw, 2.1rem); letter-spacing: 0.06em; line-height: 1;
  padding: 0.6rem 1rem; border: 4px double currentColor; border-radius: 6px;
  transform: rotate(-6deg); text-align: center;
  mask-image: radial-gradient(circle at 30% 40%, #000 60%, rgba(0,0,0,0.82) 61%);
  animation: tc-thunk 420ms cubic-bezier(.2,1.4,.4,1) both; }}
.tc-stamp small {{ display: block; font-size: 0.42em; letter-spacing: 0.04em; margin-top: 0.35rem;
  font-weight: 700; }}
@keyframes tc-thunk {{ 0% {{ transform: rotate(-14deg) scale(1.6); opacity: 0; }}
  100% {{ transform: rotate(-6deg) scale(1); opacity: 1; }} }}
@media (prefers-reduced-motion: reduce) {{ .tc-stamp {{ animation: none; }} }}
.tc-verdict h3 {{ margin: 0 0 0.35rem !important; font-size: 1.5rem !important; }}
.tc-verdict p {{ margin: 0; font-size: 1.05rem; max-width: 62ch; }}
.tc-meter {{ margin-top: 1rem; height: 10px; border-radius: 99px; position: relative;
  background: linear-gradient(90deg, {VERDICT['low']} 0 40%, {VERDICT['medium']} 40% 65%, {VERDICT['high']} 65% 100%);
  opacity: 0.9; max-width: 460px; }}
.tc-meter span {{ position: absolute; top: -6px; width: 4px; height: 22px; background: {INK};
  border-radius: 2px; box-shadow: 0 0 0 3px #FFFFFF; }}
.tc-meta {{ margin-top: 0.7rem; color: #52607A; font-size: 0.92rem; }}
@media (max-width: 720px) {{ .tc-verdict {{ grid-template-columns: 1fr; }} }}

/* ---------- exhibit: the message, marked up ---------- */
.tc-exhibit {{ background: #FFFFFF; border: 1px solid {RULE}; border-left: 6px solid {INK};
  border-radius: 4px; padding: 1.1rem 1.3rem; white-space: pre-wrap; line-height: 1.65;
  font-size: 1rem; max-height: 340px; overflow: auto; }}
.tc-exhibit mark {{ background: #FDE7E4; color: {INK}; border-bottom: 2px solid {VERDICT['high']};
  padding: 0 2px; border-radius: 2px; }}
.tc-exhibit-note {{ color: #52607A; font-size: 0.9rem; margin: 0.4rem 0 1.2rem; }}

/* ---------- evidence list ---------- */
.tc-evidence {{ list-style: none; padding: 0; margin: 0; }}
.tc-evidence li {{ padding: 0.6rem 0 0.6rem 1.6rem; border-bottom: 1px solid {RULE}; position: relative; }}
.tc-evidence li::before {{ content: ""; position: absolute; left: 0.2rem; top: 1.05rem; width: 9px; height: 9px;
  border-radius: 50%; background: var(--dot, {VERDICT['high']}); }}

/* ---------- hide the default Streamlit frame ---------- */
#MainMenu, footer[data-testid="stFooter"], [data-testid="stToolbar"], [data-testid="stDecoration"],
.stDeployButton, [data-testid="stAppDeployButton"] {{ display: none !important; }}
[data-testid="stHeader"] {{ background: transparent; }}

/* ---------- hero v2 ---------- */
.tc-hero {{ grid-template-columns: minmax(0, 1.1fr) minmax(0, 0.9fr); align-items: center; gap: 3rem;
  border-bottom: 0; padding-bottom: 0.6rem; margin-bottom: 0.6rem; }}
.tc-brand {{ display: inline-flex; align-items: center; gap: 0.4rem; font-family: 'Bricolage Grotesque', sans-serif;
  font-weight: 800; font-size: 1.15rem; color: {TEAL}; margin-bottom: 1.2rem; }}
.tc-hero h1 {{ font-size: clamp(2.4rem, 5vw, 4rem) !important; max-width: 12ch; }}
.tc-specimen {{ position: relative; margin: 0; background: #FFFFFF; border: 1px solid {RULE}; border-radius: 22px;
  padding: 1.1rem 1.2rem 1.4rem; box-shadow: 0 18px 40px -24px rgba(27,42,74,0.45); transform: rotate(1.5deg); }}
.tc-phone-top {{ font-size: 0.85rem; color: #52607A; padding-bottom: 0.7rem; border-bottom: 1px solid {RULE};
  margin-bottom: 0.9rem; }}
.tc-bubble {{ background: #E9EEF5; border-radius: 18px 18px 18px 4px; padding: 0.85rem 1rem; line-height: 1.55;
  font-size: 1rem; max-width: 92%; }}
.tc-bubble mark {{ background: #FDE7E4; color: {INK}; border-bottom: 2px solid {VERDICT['high']}; padding: 0 2px; }}
.tc-bubble-wrap {{ position: relative; padding-bottom: 1.6rem; }}
.tc-stamp-hero {{ position: absolute; right: 0.2rem; bottom: -0.2rem; color: {VERDICT['high']};
  font-size: 1.6rem; background: rgba(255,255,255,0.86); transform: rotate(-12deg); animation-delay: 300ms; }}
.tc-specimen figcaption {{ margin-top: 0.9rem; font-size: 0.9rem; color: #52607A; }}

/* how it works: a real three-step sequence */
.tc-steps {{ list-style: none; counter-reset: step; display: grid; grid-template-columns: repeat(3, 1fr);
  gap: 1.2rem; padding: 1.2rem 0 1.4rem; margin: 0 0 1.4rem; border-top: 2px solid {INK}; border-bottom: 1px solid {RULE}; }}
.tc-steps li {{ counter-increment: step; display: grid; grid-template-columns: auto 1fr; column-gap: 0.75rem; }}
.tc-steps li::before {{ content: counter(step); grid-row: span 2; width: 2rem; height: 2rem; border-radius: 50%;
  border: 2px solid {INK}; display: grid; place-items: center; font-family: 'Bricolage Grotesque', sans-serif;
  font-weight: 800; }}
.tc-steps b {{ font-family: 'Bricolage Grotesque', sans-serif; font-size: 1.05rem; }}
.tc-steps span {{ color: #52607A; font-size: 0.95rem; }}

/* the input reads like a letter handed in for inspection */
.stTextArea textarea {{ background-image: repeating-linear-gradient(#FFFFFF 0 1.55em, #EEF2F8 1.55em calc(1.55em + 1px));
  background-attachment: local; padding-top: 0.9rem; }}
[data-testid="stFileUploaderDropzone"] {{ border: 2px dashed {RULE}; background: #FFFFFF; border-radius: 10px; }}

.tc-footer {{ margin-top: 3rem; padding-top: 1.2rem; border-top: 1px solid {RULE}; color: #52607A; font-size: 0.9rem; }}
.tc-footer p {{ margin: 0 0 0.4rem; max-width: 80ch; }}

@media (max-width: 820px) {{
  .tc-hero {{ grid-template-columns: 1fr; gap: 1.6rem; }}
  .tc-specimen {{ transform: none; }}
  .tc-steps {{ grid-template-columns: 1fr; }}
}}
</style>
"""


def hero() -> str:
    """Headline on the left; on the right, a specimen showing the product doing its job."""
    return """
<div class="tc-hero">
  <div class="tc-hero-copy">
    <span class="tc-brand"><svg width="22" height="22" viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor"
      d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3Zm-1.2 14.2-3.5-3.5 1.4-1.4 2.1 2.1 4.9-4.9 1.4 1.4-6.3 6.3Z"/></svg>
      TrustCheck</span>
    <h1>Got a message that feels off?</h1>
    <p>Paste a text, email, or job offer. TrustCheck inspects it like evidence, shows you exactly
    what looks wrong, and tells you how to check it with the real organization.</p>
  </div>
  <figure class="tc-specimen" aria-label="Example: a fake delivery text with its warning signs highlighted">
    <div class="tc-phone-top">Text message &middot; +1 (555) 013-2277</div>
    <div class="tc-bubble-wrap">
      <div class="tc-bubble">USPS: Your package is <mark>on hold</mark> due to an incomplete address.
        Update <mark>within 24 hours</mark>: <mark>usps-redeliver.top</mark>/track</div>
      <div class="tc-stamp tc-stamp-hero">LIKELY SCAM</div>
    </div>
    <figcaption>Fake site, made-up deadline. The real USPS site is usps.com.</figcaption>
  </figure>
</div>
<ol class="tc-steps">
  <li><b>Paste or upload</b><span>A text, email, job offer, screenshot, or PDF.</span></li>
  <li><b>We inspect it</b><span>Links, sender, wording, and known scam patterns.</span></li>
  <li><b>You verify safely</b><span>Official contacts and steps, never the ones in the message.</span></li>
</ol>"""


def footer() -> str:
    return """
<footer class="tc-footer">
  <p><b>TrustCheck</b> helps you spot scams. It can't prove a message is genuine, so verify anything involving
  money, passwords, or documents through an official channel you look up yourself.</p>
  <p>Never paste passwords, full card numbers, or your SSN into any tool, including this one.</p>
</footer>"""


def verdict(level: str, score: int, scam_type: str, summary: str, meta: str) -> str:
    c = VERDICT[level]
    headline = {"high": "This looks like a scam", "medium": "Be careful with this one",
                "low": "No strong warning signs"}[level]
    kind = "" if not scam_type or scam_type.lower() in ("none detected", "unknown", "none") else \
        f"Looks like: {html.escape(scam_type)} &nbsp;|&nbsp; "
    body = html.escape(summary) if summary else VERDICT_LINE[level]
    return f"""
<div class="tc-verdict" role="status" aria-label="Verdict: {headline}, risk {score} out of 100">
  <div class="tc-stamp" style="color:{c}">{STAMP_TEXT[level]}</div>
  <div>
    <h3 style="color:{c} !important">{headline}</h3>
    <p>{body}</p>
    <div class="tc-meter"><span style="left:calc({score}% - 2px)"></span></div>
    <div class="tc-meta">{kind}Risk {score} of 100 &nbsp;|&nbsp; {" &nbsp;|&nbsp; ".join(html.escape(m.strip()) for m in meta.split("|"))}</div>
  </div>
</div>"""


_QUOTE = re.compile(r'["“]([^"”]{3,90})["”]')


def flagged_phrases(evidence: list[str], tool_results: list[dict], raw: str) -> list[str]:
    """Collect the exact phrases/domains that tools flagged, to highlight them in the message."""
    out: list[str] = []
    texts = list(evidence)
    for r in tool_results or []:
        for f in r.get("findings", []):
            if f.get("severity") in ("high", "medium", "low"):
                texts.append(f.get("detail", ""))
    for t in texts:
        out += _QUOTE.findall(t)
        out += re.findall(r"[\w.-]+@[\w-]+\.[\w.]+", t)
        out += re.findall(r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|xyz|top|click|online|site|info|io|ly)\b", t, re.I)
    seen, phrases = set(), []
    low = raw.lower()
    for p in sorted(out, key=len, reverse=True):
        k = p.strip().lower()
        if len(k) >= 3 and k not in seen and k in low:
            seen.add(k)
            phrases.append(p.strip())
    return phrases[:20]


def exhibit(raw: str, phrases: list[str]) -> str:
    """Highlight flagged phrases. Overlapping matches are merged so tags never nest or break."""
    text = raw[:4000]
    low = text.lower()
    spans = []
    for p in phrases:
        k = p.lower()
        i = low.find(k)
        while i != -1:
            spans.append((i, i + len(k)))
            i = low.find(k, i + len(k))
    spans.sort()
    merged: list[list[int]] = []
    for a, b in spans:
        if merged and a <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], b)
        else:
            merged.append([a, b])
    out, pos = [], 0
    for a, b in merged:
        out.append(html.escape(text[pos:a]))
        out.append(f"<mark>{html.escape(text[a:b])}</mark>")
        pos = b
    out.append(html.escape(text[pos:]))
    return f'<div class="tc-exhibit" aria-label="Your message with suspicious parts highlighted">{"".join(out)}</div>'


def evidence_list(items: list[str], level: str) -> str:
    dot = VERDICT[level] if items else VERDICT["low"]
    lis = "".join(f"<li>{html.escape(i)}</li>" for i in items) or "<li>No specific red flags found.</li>"
    return f'<ul class="tc-evidence" style="--dot:{dot}">{lis}</ul>'


# ================================================================== live investigation + case file
import hashlib
from datetime import datetime

TOOL_LABELS = {
    "detect_prompt_injection": ("Looking for hidden instructions aimed at AI tools", "Hidden AI instructions"),
    "detect_obfuscation": ("Looking for disguised words", "Disguised words"),
    "scan_text_signals": ("Reading the wording for pressure tactics", "Wording and pressure tactics"),
    "analyze_links": ("Scanning every link and website name", "Links and websites"),
    "analyze_email_headers": ("Checking the sender's email server", "Sender authenticity"),
    "check_job_offer": ("Checking recruiter red flags", "Job offer checks"),
    "search_scam_knowledge": ("Comparing with known scam patterns", "Known scam patterns"),
}


def _flags(result: dict) -> list[dict]:
    return [f for f in result.get("findings", []) if f.get("severity") in ("high", "medium", "low")]


def summarize(name: str, result: dict) -> tuple[str, str]:
    """(state, one-line summary) for a finished check. state: flagged | clear | info"""
    if name == "search_scam_knowledge":
        m = result.get("matches") or []
        return ("info", f"Closest known pattern: {m[0]['title']}") if m else ("info", "No close match in the scam library")
    flags = _flags(result)
    if not flags:
        if name == "analyze_links" and not result.get("urls"):
            return "info", "No links in the message"
        if name == "analyze_email_headers" and any(f["signal"] == "no_headers" for f in result.get("findings", [])):
            return "info", "No email headers to check"
        return "clear", "Nothing suspicious found"
    top = sorted(flags, key=lambda f: {"high": 0, "medium": 1, "low": 2}[f["severity"]])[0]
    detail = top["detail"].split(" — ")[-1] if " — " in top["detail"] else top["detail"]
    more = f" (+{len(flags) - 1} more)" if len(flags) > 1 else ""
    return "flagged", detail[:140] + more


def live_line(event: dict) -> str | None:
    """Markdown line shown inside the live status box while the agent works."""
    k, n = event["kind"], event["name"]
    if k == "thinking":
        return f"🧠 {event['text']}…"
    if k == "tool_done" and n in TOOL_LABELS:
        state, text = summarize(n, event["result"])
        icon = {"flagged": "🚩", "clear": "✅", "info": "🔎"}[state]
        return f"{icon} **{TOOL_LABELS[n][1]}**: {text}"
    return None


def case_id(raw: str) -> str:
    return "TC-" + hashlib.sha1(raw.encode("utf-8", "ignore")).hexdigest()[:6].upper()


def timeline_steps(events: list[dict]) -> list[tuple[str, str, str]]:
    steps, seen = [], set()
    for e in events:
        if e["kind"] == "tool_done" and e["name"] in TOOL_LABELS and e["name"] not in seen:
            seen.add(e["name"])
            state, text = summarize(e["name"], e["result"])
            steps.append((state, TOOL_LABELS[e["name"]][1], text))
    return steps


def case_file(events: list[dict], level: str, raw: str, when: datetime | None = None) -> str:
    when = when or datetime.now()
    steps = timeline_steps(events)
    n_flag = sum(1 for s in steps if s[0] == "flagged")
    lis = "".join(
        f'<li class="tc-step tc-{state}"><b>{html.escape(title)}</b><span>{html.escape(text)}</span></li>'
        for state, title, text in steps)
    lis += (f'<li class="tc-step tc-final" style="--v:{VERDICT[level]}"><b>Verdict</b>'
            f'<span>{STAMP_TEXT[level].capitalize()}, based on {n_flag} of {len(steps)} checks raising a flag</span></li>')
    return f"""
<section class="tc-case" aria-label="Investigation timeline">
  <header><span class="tc-case-id">Case {case_id(raw)}</span><span>{when.strftime('%b %d, %Y at %I:%M %p')}</span></header>
  <ol class="tc-timeline">{lis}</ol>
</section>"""


CASE_CSS = f"""
<style>
.tc-case {{ background:#FFFFFF; border:1px solid {RULE}; border-radius:8px; padding:1rem 1.2rem 0.6rem; }}
.tc-case header {{ display:flex; justify-content:space-between; gap:1rem; flex-wrap:wrap; color:#52607A;
  font-size:0.9rem; padding-bottom:0.6rem; border-bottom:1px dashed {RULE}; margin-bottom:0.6rem; }}
.tc-case-id {{ font-family:'Bricolage Grotesque', sans-serif; font-weight:800; color:{INK}; letter-spacing:0.02em; }}
.tc-timeline {{ list-style:none; margin:0; padding:0 0 0 1.4rem; position:relative; }}
.tc-timeline::before {{ content:""; position:absolute; left:0.42rem; top:0.5rem; bottom:0.9rem; width:2px; background:{RULE}; }}
.tc-step {{ position:relative; padding:0.35rem 0 0.75rem 0.6rem; display:flex; flex-direction:column; gap:0.1rem; }}
.tc-step::before {{ content:""; position:absolute; left:-1.32rem; top:0.55rem; width:12px; height:12px; border-radius:50%;
  background:#FFFFFF; border:3px solid #9AA6BC; }}
.tc-step b {{ font-family:'Bricolage Grotesque', sans-serif; font-size:1rem; }}
.tc-step span {{ color:#33415C; font-size:0.95rem; }}
.tc-flagged::before {{ border-color:{VERDICT['high']}; background:{VERDICT['high']}; }}
.tc-flagged b::after {{ content:" flagged"; font-family:'Atkinson Hyperlegible', sans-serif; font-weight:700;
  font-size:0.78rem; color:{VERDICT['high']}; margin-left:0.4rem; }}
.tc-clear::before {{ border-color:{VERDICT['low']}; }}
.tc-clear b::after {{ content:" clear"; font-family:'Atkinson Hyperlegible', sans-serif; font-weight:700;
  font-size:0.78rem; color:{VERDICT['low']}; margin-left:0.4rem; }}
.tc-final::before {{ border-color:var(--v); background:var(--v); width:16px; height:16px; left:-1.45rem; }}
.tc-final b {{ color:var(--v); }}
.tc-steps-verify {{ counter-reset:v; list-style:none; padding:0; margin:0; }}
.tc-steps-verify li {{ counter-increment:v; position:relative; padding:0.55rem 0 0.55rem 2.4rem; border-bottom:1px solid {RULE}; }}
.tc-steps-verify li::before {{ content:counter(v); position:absolute; left:0; top:0.5rem; width:1.7rem; height:1.7rem;
  border-radius:50%; background:{TEAL}; color:#FFFFFF; display:grid; place-items:center; font-weight:700; font-size:0.9rem; }}
</style>
"""


def verify_list(steps: list[str]) -> str:
    return '<ol class="tc-steps-verify">' + "".join(f"<li>{html.escape(s)}</li>" for s in steps) + "</ol>"


def report_html(report, raw: str, phrases: list[str], events: list[dict], when: datetime | None = None) -> str:
    """A standalone, printable case report users can save or forward when reporting a scam."""
    when = when or datetime.now()
    oc = report.official_contacts or {}
    orgs = "".join(
        f"<li><b>{html.escape(o['name'])}</b>: official site {html.escape(o['website'])}"
        + (f"; report scams to {html.escape(o['report'])}" if o.get("report") else "") + "</li>"
        for o in oc.get("organizations", []))
    general = "".join(f"<li>{html.escape(l)}" + (f": {html.escape(u)}" if u else "") + "</li>"
                      for l, u in oc.get("general", []))
    meta = f"{report.input_type.replace('_', ' ')} | {len(timeline_steps(events))} checks"
    body = f"""
<div class="block-container" style="max-width:860px;margin:0 auto;padding:2rem 1.5rem">
  <p class="tc-brand">TrustCheck case report</p>
  {verdict(report.risk_level, report.risk_score, report.scam_type, report.summary, meta)}
  <h3>The message, marked up</h3>{exhibit(raw, phrases)}
  <h3>What we found</h3>{evidence_list(report.evidence, report.risk_level)}
  <h3>Investigation</h3>{case_file(events, report.risk_level, raw, when)}
  <h3>How to check it yourself</h3>{verify_list(report.verification_steps)}
  {"<h3>Official contacts</h3><ul>" + orgs + "</ul>" if orgs else ""}
  {"<h3>Where to report scams (U.S.)</h3><ul>" + general + "</ul>" if general and report.risk_score >= 40 else ""}
  <p class="tc-exhibit-note" style="margin-top:2rem">Generated by TrustCheck on {when.strftime('%B %d, %Y at %I:%M %p')}.
  TrustCheck flags risk; it cannot prove a message is genuine. Verify through official channels you look up yourself.</p>
</div>"""
    return (f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>TrustCheck {case_id(raw)}</title>{CSS}{CASE_CSS}"
            "<style>body{margin:0} @media print{.tc-stamp{animation:none}}</style></head>"
            f"<body class='stApp'>{body}</body></html>")


# ================================================================== animated investigation board
BOARD_CSS = f"""
<style>
.tc-board {{ background:#FFFFFF; border:1px solid {RULE}; border-radius:12px; padding:1.1rem 1.3rem 1.2rem;
  margin:0.4rem 0 1.2rem; }}
.tc-board-head {{ display:flex; justify-content:space-between; align-items:baseline; gap:1rem; flex-wrap:wrap; }}
.tc-board-head b {{ font-family:'Bricolage Grotesque', sans-serif; font-size:1.15rem; }}
.tc-board-head span {{ color:#52607A; font-size:0.9rem; }}
.tc-progress {{ height:6px; background:#E9EEF5; border-radius:99px; margin:0.8rem 0 1rem; overflow:hidden; }}
.tc-progress i {{ display:block; height:100%; background:{TEAL}; border-radius:99px; transition:width 300ms ease; }}
.tc-cards {{ display:grid; grid-template-columns:repeat(auto-fill, minmax(230px, 1fr)); gap:0.7rem; }}
.tc-card {{ position:relative; border:1px solid {RULE}; border-radius:10px; padding:0.7rem 0.8rem 0.75rem 2.6rem;
  background:#FBFCFE; min-height:4.6rem; overflow:hidden; }}
.tc-card b {{ display:block; font-family:'Bricolage Grotesque', sans-serif; font-size:0.98rem; }}
.tc-card span {{ display:block; color:#52607A; font-size:0.86rem; line-height:1.35; margin-top:0.15rem; }}
.tc-card::before {{ content:""; position:absolute; left:0.8rem; top:0.85rem; width:1.15rem; height:1.15rem; border-radius:50%;
  border:2.5px solid #9AA6BC; box-sizing:border-box; display:grid; place-items:center; }}
/* running: pulsing ring + scanning shimmer */
.tc-card.run {{ border-color:{TEAL}; background:#F2FBFA; }}
.tc-card.run::before {{ border-color:{TEAL}; animation:tc-pulse 1s ease-out infinite; }}
.tc-card.run::after {{ content:""; position:absolute; inset:0; background:linear-gradient(100deg, transparent 30%,
  rgba(15,118,110,0.10) 50%, transparent 70%); animation:tc-scan 1.1s linear infinite; }}
@keyframes tc-pulse {{ 0% {{ box-shadow:0 0 0 0 rgba(15,118,110,0.45); }} 100% {{ box-shadow:0 0 0 10px rgba(15,118,110,0); }} }}
@keyframes tc-scan {{ from {{ transform:translateX(-100%); }} to {{ transform:translateX(100%); }} }}
/* finished states pop in */
.tc-card.flagged, .tc-card.clear, .tc-card.info {{ animation:tc-pop 260ms ease-out both; }}
@keyframes tc-pop {{ from {{ transform:scale(0.97); opacity:0.6; }} to {{ transform:scale(1); opacity:1; }} }}
.tc-card.flagged {{ border-color:#F3C6C1; background:#FFF6F5; }}
.tc-card.flagged::before {{ content:"!"; border-color:{VERDICT['high']}; background:{VERDICT['high']}; color:#FFFFFF;
  font-weight:800; font-size:0.75rem; }}
.tc-card.clear::before {{ content:"✓"; border-color:{VERDICT['low']}; background:{VERDICT['low']}; color:#FFFFFF;
  font-weight:800; font-size:0.72rem; }}
.tc-card.info::before {{ content:"i"; border-color:#52607A; color:#52607A; font-weight:800; font-size:0.72rem; }}
.tc-card.flagged b::after {{ content:"  flagged"; color:{VERDICT['high']}; font-family:'Atkinson Hyperlegible', sans-serif;
  font-size:0.75rem; font-weight:700; }}
.tc-card.clear b::after {{ content:"  clear"; color:{VERDICT['low']}; font-family:'Atkinson Hyperlegible', sans-serif;
  font-size:0.75rem; font-weight:700; }}
@media (prefers-reduced-motion: reduce) {{
  .tc-card.run::before, .tc-card.run::after, .tc-card.flagged, .tc-card.clear, .tc-card.info {{ animation:none; }}
}}
</style>
"""

THINK_LABELS = {"Reading the message": "Reading the message", "Weighing the evidence": "Weighing the evidence"}


class Board:
    """Keeps the state of the investigation and renders it as HTML after every event."""

    def __init__(self, case: str):
        self.case = case
        self.cards: list[dict] = []     # {key, title, state, text}
        self.closed = False
        self.verdict_level = None

    def _card(self, key):
        for c in self.cards:
            if c["key"] == key:
                return c
        return None

    def _finish_running(self):
        for c in self.cards:
            if c["state"] == "run" and c["key"].startswith("think:"):
                t = c["title"]
                c["state"] = "info"
                c["text"] = ("Understood the message and picked the checks to run" if t.startswith("Reading") else
                             "Combined every finding into one verdict" if t.startswith("Weighing") else
                             "Picked the next check" if t.startswith("Deciding") else "Complete")

    def update(self, event: dict) -> None:
        k, n = event["kind"], event["name"]
        if k == "thinking":
            self._finish_running()
            text = event["text"]
            self.cards.append({"key": f"think:{len(self.cards)}", "title": text, "state": "run",
                               "text": "The AI is deciding what to check" if "Deciding" in text or "Reading" in text
                               else "Combining all the findings"})
        elif k == "tool_start" and n in TOOL_LABELS:
            self._finish_running()
            if not self._card(n):
                self.cards.append({"key": n, "title": TOOL_LABELS[n][1], "state": "run", "text": TOOL_LABELS[n][0] + "…"})
        elif k == "tool_done" and n in TOOL_LABELS:
            c = self._card(n)
            state, text = summarize(n, event["result"])
            if c:
                c["state"], c["text"] = state, text
        elif k == "verdict":
            self._finish_running()

    def close(self, level: str) -> None:
        self._finish_running()
        self.closed, self.verdict_level = True, level

    def html(self) -> str:
        done = sum(1 for c in self.cards if c["state"] != "run")
        total = max(len(self.cards), 1)
        pct = 100 if self.closed else min(95, int(100 * done / (total + 1)))
        flags = sum(1 for c in self.cards if c["state"] == "flagged")
        if self.closed:
            head = f"Case closed: {flags} of {sum(1 for c in self.cards if not c['key'].startswith('think:'))} checks raised a flag"
        else:
            running = next((c["title"] for c in self.cards if c["state"] == "run"), "choosing the next check" if self.cards else "opening the case")
            head = f"Investigating… {running}"
        cards = "".join(
            f'<div class="tc-card {c["state"]}"><b>{html.escape(c["title"])}</b><span>{html.escape(c["text"])}</span></div>'
            for c in self.cards)
        return (f'<div class="tc-board" role="status" aria-live="polite"><div class="tc-board-head"><b>{html.escape(head)}</b>'
                f'<span>Case {self.case}</span></div><div class="tc-progress"><i style="width:{pct}%"></i></div>'
                f'<div class="tc-cards">{cards}</div></div>')
