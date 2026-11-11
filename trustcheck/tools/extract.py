"""Turn uploads (screenshots, PDFs, .eml files) into text the agent can read.

* Images  -> Tesseract OCR (free). Optionally also a local vision model via Ollama,
             which can describe logos/layout that OCR misses.
* PDFs    -> embedded text via pypdf; falls back to OCR for scanned PDFs.
* .eml    -> kept raw so header checks can run.
"""
from __future__ import annotations

import io


def _find_tesseract():
    """On Windows, Tesseract is often installed but not on PATH. Find it automatically."""
    import os
    import shutil
    if shutil.which("tesseract"):
        return None
    for p in (r"C:\Program Files\Tesseract-OCR\tesseract.exe",
              r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
              os.path.expanduser(r"~\AppData\Local\Programs\Tesseract-OCR\tesseract.exe"),
              "/opt/homebrew/bin/tesseract", "/usr/local/bin/tesseract"):
        if os.path.exists(p):
            return p
    return None


def ocr_image(image_bytes: bytes) -> str:
    from PIL import Image
    import pytesseract
    path = _find_tesseract()
    if path:
        pytesseract.pytesseract.tesseract_cmd = path
    img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    # upscale small screenshots; improves OCR noticeably
    if img.width < 1000:
        img = img.resize((img.width * 2, img.height * 2))
    return pytesseract.image_to_string(img)


def pdf_text(pdf_bytes: bytes) -> str:
    from pypdf import PdfReader
    reader = PdfReader(io.BytesIO(pdf_bytes))
    text = "\n".join((p.extract_text() or "") for p in reader.pages[:10])
    if len(text.strip()) > 50:
        return text
    # scanned PDF -> rasterize + OCR
    try:
        import pypdfium2 as pdfium
        pdf = pdfium.PdfDocument(pdf_bytes)
        out = []
        for i in range(min(len(pdf), 5)):
            pil = pdf[i].render(scale=2).to_pil()
            buf = io.BytesIO()
            pil.save(buf, format="PNG")
            out.append(ocr_image(buf.getvalue()))
        return "\n".join(out)
    except Exception:
        return text


def describe_with_vision(image_bytes: bytes) -> str:
    """Optional: ask a local vision model what it sees (sender, logos, links)."""
    from ..llm import OllamaClient
    from .. import config
    client = OllamaClient(model=config.VISION_MODEL)
    return client.describe_image(
        image_bytes,
        "This is a screenshot of a message, email, or document. Transcribe all visible text exactly, "
        "including the sender name/number, any links, and any company names or logos you see. "
        "Do not judge whether it is a scam.",
    )


def extract_text(filename: str, data: bytes, use_vision: bool = False) -> tuple[str, str]:
    """Returns (text, input_type)."""
    name = filename.lower()
    if name.endswith(".eml"):
        return data.decode("utf-8", errors="replace"), "email"
    if name.endswith(".pdf"):
        return pdf_text(data), "document"
    if name.endswith((".png", ".jpg", ".jpeg", ".webp", ".bmp")):
        text = ocr_image(data)
        if use_vision:
            try:
                text = describe_with_vision(data) + "\n\n[OCR]\n" + text
            except Exception:
                pass
        return text, "screenshot"
    return data.decode("utf-8", errors="replace"), "text"
