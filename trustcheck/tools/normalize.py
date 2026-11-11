"""Defense against filter-evasion tricks scammers use to slip past keyword checks.

Tricks handled:
  * invisible characters inside words   (gi​ft card)
  * look-alike letters from other alphabets (Cyrillic "а" in "pаssword")
  * digits/symbols standing in for letters  (g1ft c4rd, v3rify, p@ssword)
  * full-width / stylized Unicode letters   (ｇｉｆｔ, 𝐠𝐢𝐟𝐭)

normalize() returns cleaned text for the keyword tools. detect_obfuscation()
turns the tricks themselves into evidence: genuine senders have no reason to
hide letters from spam filters.

The defense can be switched off with TRUSTCHECK_DEFENSE=0 so the red-team lab
can measure how much it helps (an ablation study).
"""
from __future__ import annotations

import os
import re
import unicodedata

from .common import Finding, result

ZERO_WIDTH = re.compile(r"[​-‏⁠-⁤﻿­͏᠎]")

# Cyrillic / Greek letters that look identical to Latin ones
HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j",
    "ѕ": "s", "ԁ": "d", "ɡ": "g", "һ": "h", "ӏ": "l", "ո": "n", "ս": "u", "ԝ": "w",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C",
    "Т": "T", "Х": "X", "Ү": "Y", "Ι": "I", "Ο": "O", "Ρ": "P", "Α": "A", "Β": "B", "Ε": "E",
    "Κ": "K", "Μ": "M", "Ν": "N", "Τ": "T", "Χ": "X", "ο": "o", "α": "a", "ν": "v",
})
LEET = {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"}
# a word made of letters with leet characters mixed in, e.g. g1ft, c4rd, v3r1fy, p@ssword
LEET_WORD = re.compile(r"(?<![\w@$])(?=[\w@$]*[a-zA-Z][\w@$]*[a-zA-Z])(?=[\w@$]*[013457@$])[a-zA-Z013457@$]{3,}(?![\w@$])")


# email addresses and links are left exactly as written (the link tools inspect them separately)
PROTECTED = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+|https?://\S+|www\.\S+")


def _outside_protected(text: str, fn) -> str:
    out, pos = [], 0
    for m in PROTECTED.finditer(text):
        out.append(fn(text[pos:m.start()]))
        out.append(m.group(0))
        pos = m.end()
    out.append(fn(text[pos:]))
    return "".join(out)


def defense_enabled() -> bool:
    return os.getenv("TRUSTCHECK_DEFENSE", "1") != "0"


def _deleet(word: str) -> str:
    # keep real numbers and amounts ("482913", "$45") untouched: only words that are mostly letters
    letters = sum(c.isalpha() for c in word)
    if letters < 2 or letters < len(word) / 2:
        return word
    return "".join(LEET.get(c, c) for c in word)


def normalize(text: str) -> str:
    if not text or not defense_enabled():
        return text or ""
    t = ZERO_WIDTH.sub("", text)
    t = unicodedata.normalize("NFKC", t)          # full-width and math-styled letters -> plain
    t = t.translate(HOMOGLYPHS)
    t = _outside_protected(t, lambda seg: LEET_WORD.sub(lambda m: _deleet(m.group(0)), seg))
    return t


def detect_obfuscation(text: str) -> dict:
    """Evidence when a message hides letters from filters."""
    findings = []
    if not text or not defense_enabled():
        return result("detect_obfuscation", findings, detected=False)
    zw = len(ZERO_WIDTH.findall(text))
    if zw:
        findings.append(Finding("invisible_characters", "high",
                                f"The message hides {zw} invisible character(s) inside words, a trick used to "
                                "sneak scam phrases past spam filters."))
    mixed = [w for w in re.findall(r"\w+", text)
             if any(c.isascii() and c.isalpha() for c in w) and any(ord(c) > 127 and c.translate(HOMOGLYPHS) != c for c in w)]
    if mixed:
        findings.append(Finding("lookalike_letters", "high",
                                f'Words mix in look-alike letters from other alphabets (e.g. "{mixed[0]}"), '
                                "so they look normal to you but not to filters."))
    stylized = unicodedata.normalize("NFKC", text) != text and re.search(r"[！-～\U0001d400-\U0001d7ff]", text)
    if stylized:
        findings.append(Finding("stylized_letters", "medium",
                                "Uses decorative Unicode letters that hide words from filters."))
    plain = PROTECTED.sub(" ", text)
    leet = [m.group(0) for m in LEET_WORD.finditer(plain) if _deleet(m.group(0)) != m.group(0)]
    leet = [w for w in leet if not re.fullmatch(r"[A-Za-z]+\d+|\d+[A-Za-z]+", w)]  # skip IDs like tc001, 2fa
    if leet:
        findings.append(Finding("number_letter_swaps", "medium",
                                f'Swaps letters for numbers or symbols (e.g. "{leet[0]}" for '
                                f'"{_deleet(leet[0])}"), a common way to dodge keyword filters.'))
    return result("detect_obfuscation", findings, detected=bool(findings))
