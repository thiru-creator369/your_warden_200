"""Deterministic heuristic scanner for prompt injection indicators."""

from __future__ import annotations

import logging
import re
from typing import List

from app.schemas.models import HeuristicResult

logger = logging.getLogger("warden.heuristics")

# ── Zero-width / invisible codepoints ────────────────────────────────────────
INVISIBLE_CODEPOINTS = {
    "\u200B",  # Zero-width space
    "\u200C",  # Zero-width non-joiner
    "\u200D",  # Zero-width joiner
    "\uFEFF",  # Byte-order mark / zero-width no-break space
    "\u200E",  # Left-to-right mark
    "\u200F",  # Right-to-left mark
    "\u202A",  # Left-to-right embedding
    "\u202B",  # Right-to-left embedding
    "\u202C",  # Pop directional formatting
    "\u202D",  # Left-to-right override
    "\u202E",  # Right-to-left override
    "\u2060",  # Word joiner
    "\u2061",  # Function application
    "\u2062",  # Invisible times
    "\u2063",  # Invisible separator
    "\u2064",  # Invisible plus
    "\u2066",  # Left-to-right isolate
    "\u2067",  # Right-to-left isolate
    "\u2068",  # First strong isolate
    "\u2069",  # Pop directional isolate
}

# ── Override / injection trigger phrases (case-insensitive) ──────────────────
OVERRIDE_PATTERNS: List[re.Pattern] = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(r"ignore\s+(all\s+)?prior\s+instructions", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?previous", re.IGNORECASE),
    re.compile(r"forget\s+(all\s+)?(your\s+)?instructions", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(a|an)\s+", re.IGNORECASE),
    re.compile(r"new\s+persona\s*:", re.IGNORECASE),
    re.compile(r"system\s*prompt\s*:", re.IGNORECASE),
    re.compile(r"<\s*system\s*>", re.IGNORECASE),
    re.compile(r"\[INST\]", re.IGNORECASE),
    re.compile(r"###\s*Instruction", re.IGNORECASE),
    re.compile(r"<\|im_start\|>", re.IGNORECASE),
    re.compile(r"BEGIN\s+SYSTEM\s+MESSAGE", re.IGNORECASE),
    re.compile(r"OVERRIDE\s*:", re.IGNORECASE),
    re.compile(r"act\s+as\s+(if\s+)?(you\s+)?(are\s+)?a\s+", re.IGNORECASE),
    re.compile(r"do\s+not\s+follow\s+(your\s+)?safety", re.IGNORECASE),
    re.compile(r"reveal\s+(your\s+)?(system\s+)?prompt", re.IGNORECASE),
    re.compile(r"output\s+(your\s+)?(system\s+)?(instructions|prompt)", re.IGNORECASE),
    re.compile(r"repeat\s+(the\s+)?(text|words)\s+above", re.IGNORECASE),
]

# ── Markdown image exfiltration patterns ─────────────────────────────────────
EXFILTRATION_PATTERNS: List[re.Pattern] = [
    re.compile(r"!\[.*?\]\(https?://.*?\)", re.IGNORECASE),
    re.compile(r"<img\s+[^>]*src\s*=\s*[\"']https?://", re.IGNORECASE),
    re.compile(r"fetch\s*\(\s*[\"']https?://", re.IGNORECASE),
    re.compile(r"XMLHttpRequest", re.IGNORECASE),
    re.compile(r"navigator\.sendBeacon", re.IGNORECASE),
    re.compile(r"webhook\.site", re.IGNORECASE),
    re.compile(r"requestbin\.com", re.IGNORECASE),
    re.compile(r"burpcollaborator", re.IGNORECASE),
]


def scan_text(text: str) -> HeuristicResult:
    """Run all heuristic checks against the given text.

    Returns a HeuristicResult with details on every finding.
    """
    # ── Invisible character scan ─────────────────────────────────────────
    invisible_count = sum(1 for ch in text if ch in INVISIBLE_CODEPOINTS)
    has_invisible = invisible_count > 0

    # ── Override trigger scan ────────────────────────────────────────────
    override_matches: List[str] = []
    for pat in OVERRIDE_PATTERNS:
        for m in pat.finditer(text):
            override_matches.append(m.group())
    has_overrides = len(override_matches) > 0

    # ── Exfiltration pattern scan ────────────────────────────────────────
    exfil_matches: List[str] = []
    for pat in EXFILTRATION_PATTERNS:
        for m in pat.finditer(text):
            exfil_matches.append(m.group())
    has_exfil = len(exfil_matches) > 0

    # ── Composite heuristic risk ─────────────────────────────────────────
    risk = 0.0
    if has_invisible:
        risk += min(0.3, invisible_count * 0.05)
    if has_overrides:
        risk += 0.25 + len(override_matches) * 0.05
    if has_exfil:
        risk += 0.2 + len(exfil_matches) * 0.05
    risk = min(risk, 1.0)

    result = HeuristicResult(
        has_invisible_chars=has_invisible,
        invisible_char_count=invisible_count,
        has_override_triggers=has_overrides,
        override_triggers_found=override_matches,
        has_exfiltration_patterns=has_exfil,
        exfiltration_patterns_found=exfil_matches,
        heuristic_risk_score=round(risk, 4),
    )

    if risk > 0:
        logger.warning("Heuristic scan flagged content (risk=%.2f): %s", risk, result.model_dump())
    else:
        logger.debug("Heuristic scan clean")

    return result
