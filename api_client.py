"""Client for the Fieldcraft Triage incident API.

Endpoint contract reverse-engineered from the console's JS
(https://fieldcraft-triage-*.azurefd.net/console):

  POST {api_base}/tenants/{tenant_id}/incidents
  Authorization: Bearer <token>
  Content-Type: application/json
  -> 202 Accepted with the created incident JSON + Location header

Payload schema (see createIncidentPayload in the console JS):
  {
    "service": "<identifier>",
    "symptom": "<1-2000 chars>",
    "severity": "info|low|medium|high|critical",
    "occurredAt": "<ISO-8601 timestamp>",
    "sourceSystem": "<identifier>",      # optional, must pair with sourceEventId
    "sourceEventId": "<identifier>",     # optional, used for idempotency
    "evidence": [                        # optional, max 20 items
      {
        "kind": "metric|log_summary|change|runbook|dependency",
        "summary": "<1-4000 chars>",
        "citation": "<1-512 chars>",
        "observedAt": "<ISO-8601 timestamp>",
        "source": "<identifier>",
        "playbookId": "<identifier>"     # optional
      }
    ]
  }
"""
from __future__ import annotations

import datetime as _dt
import logging
from dataclasses import dataclass, field
from typing import Any, Optional

import requests

logger = logging.getLogger("fieldcraft_sentinel.api")

SEVERITIES = ("info", "low", "medium", "high", "critical")
EVIDENCE_KINDS = ("metric", "log_summary", "change", "runbook", "dependency")
MAX_EVIDENCE_ITEMS = 20
API_VERSION = "2026-08-19-preview"


def now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass
class Evidence:
    kind: str
    summary: str
    citation: str
    source: str
    observed_at: str = field(default_factory=now_iso)
    playbook_id: Optional[str] = None

    def to_json(self) -> dict:
        if self.kind not in EVIDENCE_KINDS:
            raise ValueError(f"Unsupported evidence kind: {self.kind!r}")
        out = {
            "kind": self.kind,
            "summary": self.summary[:4000],
            "citation": self.citation[:512],
            "observedAt": self.observed_at,
            "source": self.source,
        }
        if self.playbook_id:
            out["playbookId"] = self.playbook_id
        return out


@dataclass
class Incident:
    service: str
    symptom: str
    severity: str
    source_system: str
    source_event_id: str
    evidence: list[Evidence] = field(default_factory=list)
    occurred_at: str = field(default_factory=now_iso)

    def to_json(self) -> dict:
        if self.severity not in SEVERITIES:
            raise ValueError(f"Unsupported severity: {self.severity!r}")
        if len(self.evidence) > MAX_EVIDENCE_ITEMS:
            raise ValueError(f"At most {MAX_EVIDENCE_ITEMS} evidence rows may be submitted.")
        payload: dict[str, Any] = {
            "service": self.service,
            "symptom": self.symptom[:2000],
            "severity": self.severity,
            "occurredAt": self.occurred_at,
            "sourceSystem": self.source_system,
            "sourceEventId": self.source_event_id,
        }
        if self.evidence:
            payload["evidence"] = [e.to_json() for e in self.evidence]
        return payload


class TriageApiError(RuntimeError):
    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


class TriageApiClient:
    def __init__(self, api_base: str, tenant_id: str, token: str, timeout: float = 10.0):
        self.api_base = api_base.rstrip("/")
        self.tenant_id = tenant_id
        self.token = token
        self.timeout = timeout
        self._session = requests.Session()

    def _incidents_url(self) -> str:
        return f"{self.api_base}/tenants/{self.tenant_id}/incidents?api-version={API_VERSION}"

    def submit_incident(self, incident: Incident) -> dict:
        url = self._incidents_url()
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.token}",
        }
        resp = self._session.post(
            url, json=incident.to_json(), headers=headers, timeout=self.timeout
        )
        if resp.status_code == 401:
            raise TriageApiError("401 Unauthorized: token missing/expired.", 401)
        if resp.status_code == 403:
            raise TriageApiError(
                "403 Forbidden: token lacks the matching tenant/role.", 403
            )
        if resp.status_code == 409:
            raise TriageApiError("409 Conflict: duplicate/conflicting incident.", 409)
        if resp.status_code == 429:
            raise TriageApiError("429 Too Many Requests: rate limited.", 429)
        if not resp.ok:
            raise TriageApiError(
                f"Incident submission failed: HTTP {resp.status_code}: {resp.text[:300]}",
                resp.status_code,
            )
        if resp.status_code != 202:
            raise TriageApiError(
                f"Expected 202 Accepted, got HTTP {resp.status_code}.", resp.status_code
            )
        return resp.json()
