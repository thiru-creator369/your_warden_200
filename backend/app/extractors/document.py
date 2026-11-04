"""Document extraction utilities: Base64 decoding, PDF text/metadata extraction."""

from __future__ import annotations

import base64
import io
import logging
import os
from dataclasses import dataclass, field
from typing import Dict, Optional

logger = logging.getLogger("warden.extractors")


@dataclass
class ExtractionResult:
    """Container for extracted document data."""
    text: str = ""
    metadata: Dict[str, str] = field(default_factory=dict)
    page_count: int = 0
    source_filename: Optional[str] = None
    mime_type: str = "text/plain"
    error: Optional[str] = None


def decode_base64(data: str) -> bytes:
    """Decode a Base64-encoded string to raw bytes."""
    # Strip optional data-URI prefix
    if "," in data and data.index(",") < 100:
        data = data.split(",", 1)[1]
    return base64.b64decode(data)


def extract_pdf_bytes(raw_bytes: bytes) -> ExtractionResult:
    """Extract text and metadata from raw PDF bytes using pypdf."""
    try:
        from pypdf import PdfReader

        reader = PdfReader(io.BytesIO(raw_bytes))
        pages_text = []
        for i, page in enumerate(reader.pages):
            page_text = page.extract_text() or ""
            pages_text.append(page_text)

        meta = reader.metadata or {}
        metadata = {}
        for key in ("/Title", "/Author", "/Subject", "/Creator", "/Producer", "/CreationDate"):
            val = meta.get(key)
            if val:
                metadata[key.lstrip("/")] = str(val)

        full_text = "\n\n".join(pages_text)
        return ExtractionResult(
            text=full_text,
            metadata=metadata,
            page_count=len(reader.pages),
            mime_type="application/pdf",
        )
    except Exception as exc:
        logger.error("PDF extraction failed: %s", exc, exc_info=True)
        return ExtractionResult(error=f"PDF extraction failed: {exc}")


def extract_from_file(file_path: str) -> ExtractionResult:
    """Read a file from disk and extract text based on extension."""
    resolved_path = os.path.abspath(file_path) if os.path.isabs(file_path) else file_path

    if not os.path.exists(resolved_path):
        filename = os.path.basename(file_path)
        search_dirs = [
            os.getcwd(),
            r"D:\wardenio",
            r"D:\wardenio\samples",
            r"D:\yourwardencopy",
            r"D:\yourwardencopy\samples",
            os.path.expanduser(r"~\Desktop"),
            os.path.expanduser(r"~\Downloads"),
            os.path.expanduser(r"~\Documents"),
        ]
        for d in search_dirs:
            candidate = os.path.join(d, filename)
            if os.path.exists(candidate):
                resolved_path = candidate
                break

    if not os.path.exists(resolved_path):
        return ExtractionResult(error=f"File not found: {file_path}")

    filename = os.path.basename(resolved_path)
    ext = os.path.splitext(filename)[1].lower()

    try:
        with open(resolved_path, "rb") as f:
            raw = f.read()
    except Exception as exc:
        return ExtractionResult(error=f"Failed to read file {resolved_path}: {exc}")

    if ext == ".pdf":
        result = extract_pdf_bytes(raw)
        result.source_filename = filename
        return result

    # For plain text / markdown / code files
    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception:
        text = raw.decode("latin-1", errors="replace")

    return ExtractionResult(
        text=text,
        source_filename=filename,
        mime_type="text/plain",
    )


def extract_from_base64(data: str, mime_type: str = "application/pdf") -> ExtractionResult:
    """Decode base64 data and extract text content."""
    try:
        raw_bytes = decode_base64(data)
    except Exception as exc:
        return ExtractionResult(error=f"Base64 decode failed: {exc}")

    if mime_type == "application/pdf" or data.startswith("JVBER"):
        result = extract_pdf_bytes(raw_bytes)
        result.mime_type = "application/pdf"
        return result

    # Treat as plain text
    try:
        text = raw_bytes.decode("utf-8", errors="replace")
    except Exception:
        text = raw_bytes.decode("latin-1", errors="replace")

    return ExtractionResult(text=text, mime_type=mime_type)
