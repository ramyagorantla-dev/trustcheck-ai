"""Tool: checks specific to job offers and recruiter messages.

Fake job offers often (FTC, FBI IC3 public advisories):
  * come from free email accounts or domains that don't match the company
  * skip a real interview, or hold it over text/Telegram/WhatsApp
  * ask you to buy equipment, pay for training, or deposit a check
  * ask for SSN / bank details before any formal onboarding
"""
from __future__ import annotations

import re

from .. import config
from .common import Finding, find_emails, registered_domain, result
from .normalize import normalize

COMPANY_RE = re.compile(
    r"(?:offer (?:of employment )?(?:from|with|at)|welcome to|join(?:ing)?|position (?:at|with)|"
    r"behalf of|employment (?:at|with))\s+([A-Z][A-Za-z0-9&.\- ]{1,40}?)"
    r"(?:\s+(?:Inc|LLC|Ltd|Corp|Corporation|Group|Technologies)\b\.?)?(?=[,.!\n]| as | for | in | is |$)",
)


def _company_tokens(name: str) -> set[str]:
    stop = {"inc", "llc", "ltd", "corp", "corporation", "group", "the", "company", "technologies", "co"}
    return {t for t in re.findall(r"[a-z0-9]+", name.lower()) if t not in stop and len(t) > 2}


def check_job_offer(text: str, company_name: str = "") -> dict:
    findings: list[Finding] = []
    raw = text or ""
    t = normalize(raw)

    if not company_name:
        m = COMPANY_RE.search(t)
        company_name = m.group(1).strip() if m else ""
    tokens = _company_tokens(company_name)

    emails = find_emails(raw)
    for e in emails:
        dom = registered_domain(e)
        if dom in config.FREE_EMAIL_PROVIDERS:
            findings.append(Finding("recruiter_free_email", "high",
                                    f"Contact address {e} is a free personal mailbox, not a company domain."))
        elif tokens and not any(tok in dom.replace("-", "") for tok in tokens):
            findings.append(Finding("company_domain_mismatch", "medium",
                                    f"Offer names '{company_name}' but contact domain is {dom}."))
        elif tokens and any(tok in dom for tok in tokens):
            official = [d for b, ds in config.KNOWN_BRANDS.items() if b in tokens for d in ds]
            if official and dom not in official:
                findings.append(Finding("company_domain_lookalike", "high",
                                        f"{dom} contains the company name but isn't its official domain ({', '.join(official)})."))

    checks = [
        ("no_real_interview", "high",
         r"\b(no interview (is )?(required|needed)|hired (you )?without (an )?interview|"
         r"based on your (resume|profile) (alone|only)|you have been (directly )?selected)\b",
         "Real employers interview candidates before making an offer."),
        ("chat_only_interview", "high",
         r"\b(interview|onboarding|hiring manager).{0,60}\b(telegram|whatsapp|signal|google chat|hangouts|text message)\b",
         "Interviews over chat apps are a hallmark of fake recruiters."),
        ("equipment_purchase", "high",
         r"\b(purchase|buy|order)\b.{0,40}\b(equipment|laptop|software|supplies|office kit)\b.{0,80}\b(vendor|reimburse|check)\b",
         "Being asked to buy equipment from a 'vendor' and get reimbursed is a fake-check scam."),
        ("pay_to_work", "high",
         r"(\b(fee|deposit|payment)\b.{0,40}\b(training|onboarding|background check|visa|registration|certification)\b"
         r"|\b(training|onboarding|background check|visa|registration|certification|processing)\s+(fee|deposit|payment)s?\b)",
         "You should never pay to get hired."),
        ("early_sensitive_info", "medium",
         r"\b(ssn|social security|bank (account|details)|routing number|direct deposit (form|details)|"
         r"copy of (your )?(passport|id|driver'?s license))\b",
         "Asks for sensitive data before you've verified the employer."),
        ("vague_role", "low",
         r"\b(data entry|virtual assistant|personal assistant|package (handler|forwarding)|reshipping|"
         r"payment processing (agent|associate)|mystery shopper)\b",
         "Role type frequently used in job scams."),
        ("unrealistic_pay", "medium",
         r"(\$\s?[4-9]\d(\.\d+)?\s?(/|per)\s?h(ou)?r.{0,40}(no experience|part[- ]time|entry)|"
         r"\$\s?\d{1,2},?\d{3}\s?(/|per)\s?week)",
         "Pay is unusually high for the described role."),
    ]
    for sig, sev, rx, why in checks:
        m = re.search(rx, t, re.I | re.S)
        if m:
            findings.append(Finding(sig, sev, f'"{m.group(0)[:90].strip()}" — {why}'))

    # Positive signals of a real process
    if re.search(r"\b(background check (will be )?(conducted|performed) by|i-9|e-verify|"
                 r"onboarding portal|workday|greenhouse|lever\.co|offer (letter )?expires)\b", t, re.I):
        findings.append(Finding("formal_process_markers", "info",
                                "Mentions formal onboarding steps (I-9, applicant portal); still verify the sender."))

    if not findings:
        findings.append(Finding("no_offer_red_flags", "info", "No job-offer-specific red flags found."))
    return result("check_job_offer", findings, company_detected=company_name or None)
