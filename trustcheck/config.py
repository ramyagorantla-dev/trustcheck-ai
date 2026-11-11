"""Central configuration. Override any value with an environment variable."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Load KEY=VALUE lines from a .env file in the project folder (keeps API keys out of code)
_env = ROOT / ".env"
if _env.exists():
    for _line in _env.read_text(encoding="utf-8").splitlines():
        if "=" in _line and not _line.strip().startswith("#"):
            _k, _v = _line.split("=", 1)
            os.environ.setdefault(_k.strip(), _v.strip().strip('"').strip("'"))
DATA_DIR = ROOT / "data"
KB_DIR = DATA_DIR / "kb"

# Which LLM backend: "ollama" (local, private) or "groq" (free cloud API, no download/RAM needed)
PROVIDER = os.getenv("TRUSTCHECK_PROVIDER", "ollama").lower()
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_URL = os.getenv("GROQ_URL", "https://api.groq.com/openai/v1")
GROQ_MODEL = os.getenv("GROQ_MODEL", "openai/gpt-oss-20b").split("=")[-1].strip() or "openai/gpt-oss-20b"

# Local LLM served by Ollama (free, runs on your machine)
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
AGENT_MODEL = os.getenv("TRUSTCHECK_MODEL", "qwen2.5:7b")       # must support tool calling
VISION_MODEL = os.getenv("TRUSTCHECK_VISION_MODEL", "qwen2.5vl:3b")  # optional, for screenshots
LLM_TIMEOUT = int(os.getenv("TRUSTCHECK_TIMEOUT", "180"))
TEMPERATURE = float(os.getenv("TRUSTCHECK_TEMPERATURE", "0.1"))

# Public mode: hide developer settings (backend/model/mode) from website visitors
PUBLIC_MODE = os.getenv("TRUSTCHECK_PUBLIC", "0") == "1"

MAX_AGENT_STEPS = int(os.getenv("TRUSTCHECK_MAX_STEPS", "6"))

# Optional free APIs (leave blank to skip)
GOOGLE_SAFE_BROWSING_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY", "")
ENABLE_WHOIS = os.getenv("TRUSTCHECK_WHOIS", "1") == "1"

# Brands commonly impersonated -> their real domains (extend as needed)
KNOWN_BRANDS = {
    "google": ["google.com", "gmail.com", "youtube.com"],
    "microsoft": ["microsoft.com", "outlook.com", "live.com", "office.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "amazon.jobs"],
    "paypal": ["paypal.com"],
    "netflix": ["netflix.com"],
    "fedex": ["fedex.com"],
    "ups": ["ups.com"],
    "usps": ["usps.com"],
    "dhl": ["dhl.com"],
    "chase": ["chase.com"],
    "bankofamerica": ["bankofamerica.com"],
    "wellsfargo": ["wellsfargo.com"],
    "irs": ["irs.gov"],
    "deloitte": ["deloitte.com"],
    "accenture": ["accenture.com"],
    "meta": ["meta.com", "facebook.com", "instagram.com"],
    "linkedin": ["linkedin.com"],
    "indeed": ["indeed.com"],
    "walmart": ["walmart.com"],
    "coinbase": ["coinbase.com"],
}

FREE_EMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com",
    "icloud.com", "proton.me", "protonmail.com", "gmx.com", "mail.com",
    "yandex.com", "zoho.com", "live.com",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "t.ly",
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "link", "info", "live", "online", "site", "icu",
    "buzz", "rest", "work", "support", "shop", "cfd", "sbs", "loan", "zip", "mov",
}
