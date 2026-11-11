"""Official contact directory, so users don't have to search for it themselves.

Design rule: TrustCheck only shows contact details from this hand-checked list,
never contact details written by the LLM or found inside the suspicious message
(scammers put fake phone numbers and "support" emails in their messages).

We deliberately list official WEBSITES and official PHISHING-REPORT addresses,
not phone numbers: phone numbers change by country and product, and a wrong
number would send users somewhere unsafe. Users get the phone number from the
official site's Contact page (one click away) or the back of their bank card.

Checked November 2026. Companies change these; re-check before your demo.
"""
from __future__ import annotations

import re
from urllib.parse import quote_plus

from . import config
from .tools.common import find_emails, find_urls, registered_domain

# brand key (same keys as config.KNOWN_BRANDS) -> official info
OFFICIAL_CONTACTS = {
    "paypal": {"name": "PayPal", "website": "https://www.paypal.com",
               "report": "phishing@paypal.com",
               "tip": "Log in by typing paypal.com yourself and check the Activity page for alerts."},
    "apple": {"name": "Apple", "website": "https://www.apple.com",
              "report": "reportphishing@apple.com",
              "tip": "Check your Apple Account at account.apple.com, typed in yourself."},
    "netflix": {"name": "Netflix", "website": "https://www.netflix.com",
                "report": "phishing@netflix.com",
                "tip": "Open the Netflix app and look at Account → Membership for real billing issues."},
    "amazon": {"name": "Amazon", "website": "https://www.amazon.com",
               "report": "reportascam@amazon.com",
               "tip": "Check Your Orders and Message Center in the Amazon app; real Amazon notices appear there."},
    "chase": {"name": "Chase", "website": "https://www.chase.com",
              "report": "phishing@chase.com",
              "tip": "Call the number on the back of your Chase card."},
    "bankofamerica": {"name": "Bank of America", "website": "https://www.bankofamerica.com",
                      "report": "abuse@bankofamerica.com",
                      "tip": "Call the number on the back of your card or open the Bank of America app."},
    "wellsfargo": {"name": "Wells Fargo", "website": "https://www.wellsfargo.com",
                   "report": "reportphish@wellsfargo.com",
                   "tip": "Call the number on the back of your card or open the Wells Fargo app."},
    "irs": {"name": "IRS", "website": "https://www.irs.gov",
            "report": "phishing@irs.gov",
            "tip": "The IRS normally contacts people by postal mail first and never asks for gift cards or crypto."},
    "usps": {"name": "USPS", "website": "https://www.usps.com",
             "report": "spam@uspis.gov",
             "tip": "Track packages only at usps.com with a tracking number from the seller."},
    "fedex": {"name": "FedEx", "website": "https://www.fedex.com",
              "report": "abuse@fedex.com",
              "tip": "Track packages only at fedex.com with a tracking number from the seller."},
    "ups": {"name": "UPS", "website": "https://www.ups.com",
            "report": "fraud@ups.com",
            "tip": "Track packages only at ups.com with a tracking number from the seller."},
    "dhl": {"name": "DHL", "website": "https://www.dhl.com", "report": "",
            "tip": "Track packages only at dhl.com with a tracking number from the seller."},
    "microsoft": {"name": "Microsoft", "website": "https://www.microsoft.com", "report": "phish@office365.microsoft.com",
                  "tip": "Check sign-in activity at account.microsoft.com, typed in yourself. "
                         "In Outlook, use Report → Report phishing."},
    "google": {"name": "Google", "website": "https://www.google.com", "report": "",
               "tip": "Check myaccount.google.com → Security. In Gmail, use ⋮ → Report phishing. "
                      "Google jobs are only at careers.google.com."},
    "meta": {"name": "Meta / Facebook / Instagram", "website": "https://www.meta.com", "report": "",
             "tip": "Check alerts inside the official app (Settings → Security)."},
    "linkedin": {"name": "LinkedIn", "website": "https://www.linkedin.com", "report": "phishing@linkedin.com",
                 "tip": "Check the recruiter's profile and company page on LinkedIn itself."},
    "deloitte": {"name": "Deloitte", "website": "https://www.deloitte.com", "report": "",
                 "tip": "Apply only through the Careers section of deloitte.com. Deloitte doesn't ask candidates to pay."},
    "accenture": {"name": "Accenture", "website": "https://www.accenture.com", "report": "",
                  "tip": "Apply only through the Careers section of accenture.com."},
    "walmart": {"name": "Walmart", "website": "https://www.walmart.com", "report": "",
                "tip": "Walmart jobs are listed on careers.walmart.com."},
    "indeed": {"name": "Indeed", "website": "https://www.indeed.com", "report": "",
               "tip": "Report suspicious job posts using the Report job link on Indeed."},
    "coinbase": {"name": "Coinbase", "website": "https://www.coinbase.com", "report": "",
                 "tip": "Coinbase support will never ask for your password, 2-step codes, or to move funds."},
}

# Each company's OWN guidance pages (verified November 2026 by searching each company's site).
# Shown as "From <company>" links so users learn what that company says real messages look like.
COMPANY_PAGES = {
    "paypal": [("PayPal: How to identify fake messages",
                "https://www.paypal.com/us/security/learn-about-fake-messages")],
    "amazon": [("Amazon: Tips to spot and avoid scams impersonating Amazon",
                "https://www.aboutamazon.com/news/retail/how-to-avoid-amazon-scams"),
               ("Amazon: Report a scam (self-service tool)",
                "https://www.amazon.com/gp/help/customer/display.html?nodeId=GRGRY7AQ3LMPXVCV")],
    "apple": [("Apple: Recognize and avoid phishing messages and scams",
               "https://support.apple.com/en-us/HT204759")],
    "netflix": [("Netflix: How to tell if an email or text is really from Netflix",
                 "https://help.netflix.com/en/node/65674")],
    "microsoft": [("Microsoft: Protect yourself from phishing",
                   "https://support.microsoft.com/en-us/security/protect-yourself-from-phishing")],
    "google": [("Google: Job offer scams (real recruiters use @google.com)",
                "https://support.google.com/faqs/answer/10122524"),
               ("Google Careers: real Google jobs", "https://careers.google.com")],
    "chase": [("Chase: How to report fraud", 
               "https://www.chase.com/digital/resources/privacy-security/security/report-fraud.html")],
    "wellsfargo": [("Wells Fargo: Report phishing and see real examples",
                    "https://www.wellsfargo.com/privacy-security/fraud/report/phish/")],
    "irs": [("IRS: Report fake IRS emails, texts, and calls",
             "https://www.irs.gov/privacy-disclosure/report-phishing")],
    "usps": [("USPS: When USPS really sends text messages (Text Tracking FAQs)",
              "https://www.usps.com/text-tracking/welcome.htm"),
             ("U.S. Postal Inspection Service: Package-tracking text scams",
              "https://www.uspis.gov/news/scam-article/smishing-package-tracking-text-scams")],
    "fedex": [("FedEx: Recognize and report fraud", "https://www.fedex.com/fraud")],
    "linkedin": [("LinkedIn: Report fake jobs and recruiters", "https://www.linkedin.com/help/linkedin/answer/86030")],
    "deloitte": [("Deloitte: Recruitment scams targeting job seekers (UK notice, same rules apply)",
                  "https://www.deloitte.com/uk/en/careers/recruitment-scams-targeting-jobseekers.html"),
                 ("Deloitte US: real job listings", "https://apply.deloitte.com")],
    "accenture": [("Accenture: Recruitment fraud notice (no fees at any stage)",
                   "https://www.accenture.com/in-en/careers/support/important-notice")],
}

# Extra names people write that map to a brand key
ALIASES = {
    "bank of america": "bankofamerica", "bofa": "bankofamerica", "wells fargo": "wellsfargo",
    "internal revenue service": "irs", "postal service": "usps", "facebook": "meta",
    "instagram": "meta", "gmail": "google", "outlook": "microsoft", "office 365": "microsoft",
    "microsoft 365": "microsoft", "icloud": "apple", "itunes": "apple", "geek squad": None,
}

GENERAL_REPORTING = [
    ("U.S. Federal Trade Commission: report any scam", "https://reportfraud.ftc.gov"),
    ("FBI Internet Crime Complaint Center: if you lost money", "https://www.ic3.gov"),
    ("Scam text messages: forward the text to 7726 (SPAM) on your phone", ""),
    ("Phishing emails: forward to reportphishing@apwg.org (Anti-Phishing Working Group)", ""),
]
JOB_REPORTING = [
    ("Your university career center can check whether an employer is real", ""),
    ("Look up the company's official careers page and confirm the job is listed there", ""),
]

_WORD = re.compile(r"[a-z0-9]+")


def find_organizations(text: str, company_hint: str | None = None) -> list[str]:
    """Return brand keys mentioned in the message (by name, email domain, or link)."""
    # remove e-mail addresses and links first: "nexora.hr@outlook.com" must not count as Microsoft
    low = re.sub(r"\S+@\S+|https?://\S+|www\.\S+", " ", (text or "").lower())
    found: list[str] = []

    def add(k):
        if k and k in OFFICIAL_CONTACTS and k not in found:
            found.append(k)

    for alias, key in ALIASES.items():
        if alias in low:
            add(key)
    words = set(_WORD.findall(low))
    for key in OFFICIAL_CONTACTS:
        if key in words:
            add(key)
    # brands hidden inside domains: paypa1-secure.xyz, wellsfarg0-secure.com
    from .tools.links import LEET
    for item in find_urls(text) + find_emails(text):
        if registered_domain(item) in config.FREE_EMAIL_PROVIDERS:
            continue
        dom = registered_domain(item).split(".")[0].translate(LEET).replace("rn", "m").replace("-", "")
        for key in OFFICIAL_CONTACTS:
            if key in dom or (len(key) >= 6 and _close(key, dom)):
                add(key)
    if company_hint:
        for key in OFFICIAL_CONTACTS:
            if key in company_hint.lower().replace(" ", ""):
                add(key)
    return found[:3]


def _close(brand: str, token: str) -> bool:
    from rapidfuzz.distance import Levenshtein
    return any(Levenshtein.distance(brand, token[i:i + len(brand)]) <= 1
               for i in range(0, max(1, len(token) - len(brand) + 1)))


def build_contacts(text: str, input_type: str = "", company_hint: str | None = None) -> dict:
    orgs = []
    for key in find_organizations(text, company_hint):
        c = dict(OFFICIAL_CONTACTS[key])
        c["contact_page"] = c["website"]  # Contact/Help link is on the homepage of each site
        c["pages"] = COMPANY_PAGES.get(key, [])
        orgs.append(c)
    unknown = None
    if not orgs and company_hint:
        unknown = {"name": company_hint,
                   "search": f"https://www.google.com/search?q={quote_plus(company_hint + ' official website careers')}",
                   "linkedin": f"https://www.linkedin.com/search/results/companies/?keywords={quote_plus(company_hint)}"}
    is_job = input_type == "job_offer" or bool(re.search(r"\b(job|offer|recruit|hiring|intern|interview)\b", text or "", re.I))
    return {"organizations": orgs, "unknown_company": unknown,
            "general": GENERAL_REPORTING, "job": JOB_REPORTING if is_job else []}


# ------------------------------------------------------------------ "Learn more" official guidance
# Only official government pages, checked November 2026. Short ftc.gov links are the FTC's
# own redirects, so they keep working when articles move.
GUIDES = {
    "job": ("FTC: How to spot and avoid job scams", "https://www.ftc.gov/jobscams"),
    "phishing": ("FTC: How to recognize and avoid phishing scams",
                 "https://consumer.ftc.gov/articles/how-recognize-and-avoid-phishing-scams"),
    "text": ("FTC: How to recognize and report spam text messages",
             "https://consumer.ftc.gov/articles/how-recognize-and-report-spam-text-messages"),
    "gift_card": ("FTC: Gift card scams and how to get your money back", "https://www.ftc.gov/giftcards"),
    "imposter": ("FTC: Imposter scams (fake government, bank, boss, or company)", "https://www.ftc.gov/imposters"),
    "investment": ("FTC: Investment and crypto scams", "https://consumer.ftc.gov/articles/investment-scams"),
    "mail": ("U.S. Postal Inspection Service: Imposter and delivery scams", "https://www.uspis.gov/imposterscams"),
}
IF_YOU_RESPONDED = [
    ("Already shared personal info? Get a recovery plan at IdentityTheft.gov", "https://www.identitytheft.gov"),
    ("Already sent money? Report it to the FBI", "https://www.ic3.gov"),
    ("Report the scam to the FTC", "https://reportfraud.ftc.gov"),
]

_GUIDE_RULES = [
    ("job", r"job|offer|recruit|hiring|intern|employ|equipment|task"),
    ("gift_card", r"gift ?card"),
    ("investment", r"crypto|bitcoin|usdt|invest|trading|wallet"),
    ("mail", r"usps|package|parcel|delivery|fedex|ups\b|dhl"),
    ("imposter", r"irs|government|boss|ceo|manager|professor|impersonat|bank|chase|wells|paypal|"
                 r"amazon|apple|microsoft|netflix|tax|refund|police"),
    ("phishing", r"phish|password|verify|account|login|credential|link|suspend|locked"),
]


def learn_more(text: str, scam_type: str = "", input_type: str = "", evidence: list | None = None) -> dict:
    """Pick official guidance pages that match what the message looks like."""
    blob = " ".join([text or "", scam_type or "", " ".join(evidence or [])]).lower()
    keys = [k for k, rx in _GUIDE_RULES if re.search(rx, blob)]
    if input_type == "sms" or re.search(r"\b(text|sms|smish)", blob):
        keys.append("text")
    if not keys:
        keys = ["phishing"]
    seen, guides = set(), []
    for k in keys:
        if k not in seen:
            seen.add(k)
            guides.append(GUIDES[k])
    return {"guides": guides[:4], "if_you_responded": IF_YOU_RESPONDED}


# ------------------------------------------------------------------ Safety toolkit (always available)
# Useful for every visitor, not only when a scam is found. Government sites first; the few
# non-government tools (VirusTotal, Have I Been Pwned) are widely used, free, and well known.
SAFETY_TOOLKIT = {
    "🔍 Check before you click": [
        ("Google Safe Browsing: is this website dangerous?",
         "https://transparencyreport.google.com/safe-browsing/search"),
        ("VirusTotal: scan a link with 70+ security engines (free)", "https://www.virustotal.com"),
        ("ICANN Lookup: who owns a website, and when was it created?", "https://lookup.icann.org"),
    ],
    "🔐 Protect your accounts and identity": [
        ("Have I Been Pwned: was your email in a data breach?", "https://haveibeenpwned.com"),
        ("AnnualCreditReport.com: free credit reports (official U.S. site)", "https://www.annualcreditreport.com"),
        ("IdentityTheft.gov: step-by-step recovery plan if your info was stolen", "https://www.identitytheft.gov"),
    ],
    "🚩 Report a scam": [
        ("FTC: report any scam or fraud", "https://reportfraud.ftc.gov"),
        ("FBI Internet Crime Complaint Center: if you lost money", "https://www.ic3.gov"),
        ("National Do Not Call Registry: report unwanted calls", "https://www.donotcall.gov"),
        ("Scam texts: forward the message to 7726 (SPAM) from your phone", ""),
    ],
    "🎓 Students and job seekers": [
        ("FTC: How to spot and avoid job scams", "https://www.ftc.gov/jobscams"),
        ("USCIS: Avoid immigration scams (fake visa, OPT, and job offers)",
         "https://www.uscis.gov/scams-fraud-and-misconduct/avoid-scams"),
        ("USCIS: Common scams, including ones that target students",
         "https://www.uscis.gov/scams-fraud-and-misconduct/avoid-scams/common-scams"),
        ("Social Security: Protect yourself from SSA impostor scams", "https://www.ssa.gov/scam"),
    ],
    "📰 Stay updated": [
        ("FTC consumer alerts: the newest scams, explained", "https://consumer.ftc.gov/consumer-alerts"),
        ("FTC: Imposter scams (bank, government, boss, company)", "https://www.ftc.gov/imposters"),
    ],
}


def link_checkers(urls: list[str]) -> list[dict]:
    """For each suspicious domain: one-click checks that DON'T open the suspicious site itself."""
    from urllib.parse import quote
    out, seen = [], set()
    for u in urls[:5]:
        dom = registered_domain(re.sub(r"^https?://", "", u).split("/")[0])
        if not dom or dom in seen:
            continue
        seen.add(dom)
        out.append({
            "domain": dom,
            "checks": [
                ("Google Safe Browsing", f"https://transparencyreport.google.com/safe-browsing/search?url={quote(dom)}"),
                ("VirusTotal", f"https://www.virustotal.com/gui/domain/{quote(dom)}"),
                ("Who owns it / how old (ICANN)", f"https://lookup.icann.org/en/lookup?name={quote(dom)}"),
            ],
        })
    return out
