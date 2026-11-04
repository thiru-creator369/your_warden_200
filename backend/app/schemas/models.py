"""Pydantic models for incidents, verdicts, and evaluator responses."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


class ThreatType(str, Enum):
    NONE = "none"
    OVERRIDE = "override"
    EXFILTRATION = "exfiltration"
    JAILBREAK = "jailbreak"


class EvaluatorVerdict(BaseModel):
    """Structured response from the sandboxed evaluator AI."""
    is_injection: bool = False
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    threat_type: ThreatType = ThreatType.NONE
    flagged_excerpts: List[str] = Field(default_factory=list)


class HeuristicResult(BaseModel):
    """Result from the deterministic heuristic scanner."""
    has_invisible_chars: bool = False
    invisible_char_count: int = 0
    has_override_triggers: bool = False
    override_triggers_found: List[str] = Field(default_factory=list)
    has_exfiltration_patterns: bool = False
    exfiltration_patterns_found: List[str] = Field(default_factory=list)
    heuristic_risk_score: float = Field(default=0.0, ge=0.0, le=1.0)


class SeverityLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class IncidentStatus(str, Enum):
    QUARANTINED = "QUARANTINED"
    APPROVED_RAW = "APPROVED_RAW"
    APPROVED_SANITIZED = "APPROVED_SANITIZED"
    REJECTED = "REJECTED"
    PASSED = "PASSED"


class IncidentRecord(BaseModel):
    """Full incident record stored in Firebase RTDB."""
    incident_id: str
    status: IncidentStatus = IncidentStatus.QUARANTINED
    severity: SeverityLevel = SeverityLevel.LOW
    risk_score: float = 0.0
    threat_type: ThreatType = ThreatType.NONE
    flagged_excerpts: List[str] = Field(default_factory=list)
    source_filename: Optional[str] = None
    mime_type: str = "text/plain"
    extracted_text_preview: str = ""
    full_text: Optional[str] = None
    heuristic_details: Optional[HeuristicResult] = None
    created_at: Optional[str] = None
    resolved_at: Optional[str] = None
    resolved_by: Optional[str] = None
