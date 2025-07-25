# receipt_utils.py
from __future__ import annotations

"""
Utilities to
1.  convert images **or PDFs** (file paths *or* raw bytes) into base‑64 data‑URIs
2.  call an OpenAI Vision model and return a single deterministic JSON string
    always wrapped like {"receipts": [...]}

⭑  Compatible with Python 3.7 (uses typing.List / typing.Union if needed)
⭑  Keeps your original OpenAI key untouched
⭑  Handles PDFs given either as Path/filename or raw bytes
"""

import base64, mimetypes, io, json
from pathlib import Path
from typing import List, Union, Iterable

import fitz                          # PyMuPDF
from openai import OpenAI
import os

openai_token = os.environ['openai_token']

openai_client = OpenAI(api_key=openai_token)
VISION_MODEL = "gpt-4.1-2025-04-14"   # Vision‑capable model (leave as‑is)

# ---------------------------------------------------------------------------
FileLike = Union[str, Path, bytes]
# ---------------------------------------------------------------------------

def _pdf_bytes_to_images(pdf_bytes: bytes) -> Iterable[bytes]:
    """Rasterises every page of a PDF byte blob to JPEG bytes (300 dpi)."""
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    for page in doc:
        pix = page.get_pixmap(dpi=300)
        yield pix.tobytes("jpeg")


def to_image_bytes(src: FileLike) -> Iterable[bytes]:
    """Yield one or more JPEG byte strings from *src* (image or PDF)."""
    # ----- Already bytes ----------------------------------------------------
    if isinstance(src, (bytes, bytearray)):
        # Detect PDF by magic number %PDF
        if src[:4] == b"%PDF":
            yield from _pdf_bytes_to_images(src)  # all pages
        else:
            yield bytes(src)                      # assume image already
        return

    # ----- Path / filename --------------------------------------------------
    path = Path(src).expanduser()
    mime, _ = mimetypes.guess_type(path.name.lower())

    if mime == "application/pdf" or path.suffix.lower() == ".pdf":
        doc = fitz.open(path)
        for page in doc:
            yield page.get_pixmap(dpi=300).tobytes("jpeg")
    else:
        with path.open("rb") as f:
            yield f.read()


def to_data_uri(blob: bytes, mime: str = "image/jpeg") -> str:
    """Encode *blob* to a base‑64 data‑URI suitable for the Vision API."""
    b64 = base64.b64encode(blob).decode()
    return f"data:{mime};base64,{b64}"

from datetime import datetime
today = datetime.today()
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = (
    "These are my only personal receipts and conversations I am trying to register "
    "You are an assistant that extracts structured JSON data from Mexican "
    "purchase receipts. For every image you see, return ONE object with keys: "
    "amount_mxn (float), vendor (string), payment_method (string), "
    "factura (boolean), date (ISO-8601), category (string). "
    "The options for category are: Insumos Comida/Bebidas, Insumos Limpieza, Empaques, Renta, Gasto Extraordinario, Servicios Recurrentes, Inversion Capital, Nomina, Marketing, Impuestos, Reparaciones, Otro"
    "if one of the images is a BBVA transfer, use that as the transaction date and the payment method is bank transfer"
    "if it is not, try to guess the payment type from these options: ['Transferencia', 'Tarjeta', 'Efectivo']"
    "If the receipt is itemised, include an 'items' list with product, qty & price. "
    "Return JSON only—no comments."
    "If the date is illegible or there is no date, default to today: {}".format(today)
)

# ---------------------------------------------------------------------------

def extract_receipts(inputs: List[FileLike]) -> str:
    """High‑level helper → returns *wrapped* JSON string ready for `json.loads()`."""

    # Expand every input (PDF/image) into one or more JPEG blobs
    image_parts = [
        {
            "type": "image_url",
            "image_url": {"url": to_data_uri(img)}
        }
        for inp in inputs
        for img in to_image_bytes(inp)
    ]

    if not image_parts:
        raise ValueError("No valid images extracted from inputs")

    response = openai_client.chat.completions.create(
        model=VISION_MODEL,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": image_parts},
        ],
        response_format={"type": "json_object"},
        temperature=0,
        max_tokens=800,
    )

    content = response.choices[0].message.content
    if content is None:
        raise RuntimeError("Vision model returned no content. Raw response → {}".format(response))

    data = json.loads(content)

    # Ensure we always return {"receipts": [...]} for front‑end consistency
    if not isinstance(data, dict) or "receipts" not in data:
        data = {"receipts": [data] if isinstance(data, dict) else data}

    return json.dumps(data, ensure_ascii=False, separators=(",", ":"))
