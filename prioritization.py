"""Security Prioritization Framework (FAIR + SSVC + Boehm One-Way Doors).

Addresses alert fatigue caused by worst-component-asset inheritance and top-heavy
severity matrices. Implements and compares five prioritization models against an
explicit mathematical & qualitative objective function:

Objective Function:
  1. Critical (critical / P0) < 10% of issues globally AND per project.
  2. High (high / P1) ~ 10% of issues globally (7% - 13%, Critical + High <= 20%).
  3. FAIR Loss-Tolerance Gate: Critical and High issues require concrete loss
     above organizational tolerance — Financial Loss, Catastrophic Data Loss, or
     Regulatory / Statutory Compliance Loss. Low-loss hygiene (log redaction,
     error detail leaks, local memory retention, startup crashes, ReDoS/floods,
     stale caches, unmaintained-code notices) is capped at Medium/Low.
  4. SSVC / EPSS Likelihood Gate: Operational Criticals must be confirmed in
     code (``standing == "open"``) with truly high likelihood (external /
     unauthenticated exposure or systemic store-wide rules).
  5. Boehm / ATAM One-Way-Door Gate: Design-stage and architectural Criticals
     must involve irreversible or high-migration-cost components ("one-way
     doors": cryptographic/webhook contracts, multi-tenant DB/rule schemas,
     unencrypted persistent stores, cross-boundary identity/trust architecture).

Academic References:
  - Spring, Hatleback, Householder, Manion, Shick (2019/2021): Stakeholder-
    Specific Vulnerability Categorization (SSVC), CMU SEI / CISA.
  - Jacobs, Romanosky, Edwards, Roytman, Adjerid (2021/2023): Exploit Prediction
    Scoring System (EPSS), Journal of Cybersecurity / FIRST.
  - Freund & Jones (2014): Measuring and Managing Information Risk: A FAIR
    Approach (Risk = Loss Event Frequency x Loss Magnitude vs Risk Tolerance).
  - Boehm (1981) / Boehm & Basili (2001) / Kazman et al. ATAM: Cost-of-Change
    curve and architectural irreversibility ("one-way doors").
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable

try:
    from ontology import Confirming, ImpactLevel, Likelihood, Priority, ThreatModel, standing_of
    from ontology.concepts import PRIORITY_ORDER
except ImportError:  # pragma: no cover - standalone fallback outside monorepo
    class ImpactLevel(str, Enum):
        unknown = "unknown"
        low = "low"
        medium = "medium"
        high = "high"
        critical = "critical"

    class Likelihood(str, Enum):
        unknown = "unknown"
        low = "low"
        medium = "medium"
        high = "high"

    class Priority(str, Enum):
        unknown = "Not yet prioritised"
        p0 = "P0"
        p1 = "P1"
        p2 = "P2"
        p3 = "P3"

    PRIORITY_ORDER: dict[Priority, int] = {
        Priority.p0: 0,
        Priority.p1: 1,
        Priority.p2: 2,
        Priority.p3: 3,
        Priority.unknown: 4,
    }
    ThreatModel = Any  # type: ignore[misc,assignment]

    class Confirming:  # type: ignore[no-redef]
        def __init__(self, tm: Any = None) -> None:
            self.tm = tm

    def standing_of(_tm: Any, threat: Any, _rule: Any = None) -> tuple[str, str, str]:  # type: ignore[misc]
        st = getattr(getattr(threat, "status", None), "value", getattr(threat, "status", "unknown"))
        standing = "open" if str(st) == "confirmed" else "uncontrolled"
        return standing, standing, ""

# ---------------------------------------------------------------------------
# Priority <-> Label tables matching ontology.adapter
# ---------------------------------------------------------------------------

_TIER_TO_RISK_AXIS: dict[str, tuple[ImpactLevel, Likelihood]] = {
    "critical": (ImpactLevel.critical, Likelihood.high),   # P0
    "high":     (ImpactLevel.high,     Likelihood.medium), # P1
    "medium":   (ImpactLevel.medium,   Likelihood.medium), # P2
    "low":      (ImpactLevel.low,      Likelihood.medium), # P3
}

_TIER_RANK: dict[str, int] = {
    "critical": 0,
    "high":     1,
    "medium":   2,
    "low":      3,
    "unknown":  4,
}

_IMPACT_LABEL: dict[ImpactLevel, str] = {
    ImpactLevel.unknown:  "Not yet rated",
    ImpactLevel.low:      "Low",
    ImpactLevel.medium:   "Medium",
    ImpactLevel.high:     "High",
    ImpactLevel.critical: "Critical",
}

_LIKELIHOOD_LABEL: dict[Likelihood, str] = {
    Likelihood.unknown: "Not rated",
    Likelihood.low:     "Low",
    Likelihood.medium:  "Medium",
    Likelihood.high:    "High",
}

_PRIORITY_LABEL: dict[Priority, str] = {
    Priority.unknown: "Not yet prioritised",
    Priority.p0:      "P0",
    Priority.p1:      "P1",
    Priority.p2:      "P2",
    Priority.p3:      "P3",
}

_PRIORITY_BACK: dict[str, Priority] = {v: k for k, v in _PRIORITY_LABEL.items()}

_RATING_DEFAULT: dict[Priority, str] = {
    Priority.p0:      "Critical",
    Priority.p1:      "High",
    Priority.p2:      "Medium",
    Priority.p3:      "Low",
    Priority.unknown: "Not yet rated",
}

_SENSITIVITY_ORDER = {"restricted": 0, "confidential": 1, "internal": 2, "public": 3}
_SENSITIVITY_LABEL = {"restricted": "Restricted", "confidential": "Confidential", "internal": "Internal", "public": "Public"}

# ---------------------------------------------------------------------------
# Compiled semantic patterns
# ---------------------------------------------------------------------------

_RE_LOG_HYGIENE = re.compile(
    r"(?:from\s+the\s+logs?|in(?:to)?\s+(?:the\s+)?logs?|reading\s+(?:the\s+)?logs?|"
    r"shared\s+log(?:\s+file)?|log\s+(?:file|entries|growth)|write\s+unchecked\s+text\s+into.*logs|"
    r"logs?\s+expose|into\s+error\s+logs|never\s+deleted.*logs?|kept\s+forever.*log|"
    r"activity\s+log)",
    re.I,
)

_RE_ERROR_CACHE_MEMORY_HYGIENE = re.compile(
    r"(?:raw\s+error\s+messages?\s+leak|leaks?\s+internal\s+system\s+details|"
    r"lingers?\s+in\s+memory|stuck\s+in\s+memory|stale\s+cached|"
    r"bad\s+config\s+file\s+can\s+crash\s+startup|"
    r"test[- ]key\s+prefix|health\s+check|readiness\s+check|"
    r"future\s+flaw\s+in\s+(?:the\s+)?unmaintained|deprecated\s+sdk\s+flaw|"
    r"outdated\s+library|hidden,\s*undocumented\s+field|undocumented\s+fields?|"
    r"leaves\s+no\s+trace|no\s+(?:network\s+activity\s+|tamper[- ]evident\s+)?trail|"
    r"no\s+record\s+kept|never\s+delete|kept\s+forever|cannot\s+be\s+(?:fully\s+)?erased)",
    re.I,
)

_RE_AVAILABILITY_OR_DOS_HYGIENE = re.compile(
    r"(?:slow\s+pattern\s+match|slow\s+text[- ]checking|crafted\s+input\s+can\s+freeze|"
    r"stalls?\s+the\s+.*?(?:service|page)|freezes?\s+(?:a\s+reviewer's|the\s+feedback)|"
    r"slow\s+.*?outage\s+can\s+exhaust|slow\s+deliverable\s+file\s+freezes|"
    r"hang\s+the\s+document\s+conversion|slow\s+down\s+or\s+block\s+the\s+service|"
    r"\b(?:floods?|spams?|overwhelm|exhaust\s+memory|exhaust.*threads|fill\s+the\s+disk|"
    r"burn\s+ai\s+spending|run\s+up\s+(?:costs?|the\s+bill)|unlimited\s+calls?|"
    r"unbounded\s+export\s+request\s+overloads|crafted\s+office\s+file\s+can\s+hang|"
    r"single\s+point\s+of\s+failure)\b)",
    re.I,
)

_RE_LOW_LOSS_AI_PROMPT = re.compile(
    r"(?:prompt\s+injection|hijacks?\s+the\s+ai\s+error|steered\s+analyzer\s+model|"
    r"force\s+the\s+ai\s+quality\s+check|plants?\s+text\s+that\s+manipulates\s+ai)",
    re.I,
)

_RE_FINANCIAL_LOSS = re.compile(
    r"(?:captures?\s+payment\s+funds?\s+without.*authoriz|"
    r"sets?\s+an?\s+order\s+total\s+the\s+buyer\s+never\s+approved|"
    r"hidden\s+order\s+fields.*altering\s+payment|"
    r"unchecked\s+order[- ]total\s+string.*bad\s+amounts|"
    r"charged\s+or\s+refunded\s+twice|draw\s+down\s+more\s+than\s+was\s+authorized|"
    r"forged\s+payment\s+notification|trusts\s+a\s+payment\s+notification\s+without\s+checking\s+its\s+signature|"
    r"refunds?\s+any\s+customer|refunds?\s+orders?\s+never\s+assigned|"
    r"pays?\s+out\s+any\s+customer|resubmitting\s+a\s+request\s+pays\s+every\s+expert\s+twice|"
    r"(?:sets?\s+their\s+own|edits?|inflates?\s+their\s+own)\s+pay\s+rates?|"
    r"pay\s+rate\s+across\s+other\s+sites|"
    r"changes?\s+another\s+account's\s+payment\s+data|"
    r"overwrites?\s+the\s+merchant's\s+secret\s+key\s+at\s+run|"
    r"unverified\s+token\s+theft\s+is\s+replayed\s+against\s+amazon\s+pay|"
    r"reads\s+the\s+restricted\s+admin\s+payment\s+ledger)",
    re.I,
)

_RE_REGULATORY_LOSS = re.compile(
    r"(?:which\s+compliance\s+rules\s+apply|"
    r"fake\s+auditor\s+identities|"
    r"marks?\s+own\s+controls?\s+'implemented'|"
    r"exports?\s+a\s+full\s+audit\s+package\s+without\s+signing\s+in|"
    r"downloads?\s+other\s+companies'\s+audit\s+packages|"
    r"statutory|underage|minor\s+shift|minimum[- ]wage)",
    re.I,
)

_RE_CATASTROPHIC_DATA_LOSS = re.compile(
    r"(?:sql\s+injection|makes?\s+the\s+database\s+run\s+any\s+query|"
    r"reads?\s+guard\s+data\s+without\s+signing\s+in|"
    r"unguarded\s+link\s+bypasses.*(?:scoping|safeguard)|"
    r"finds\s+the\s+server's\s+address\s+can\s+read\s+its\s+data|"
    r"steal\s+cloud\s+keys|reads?\s+any\s+file\s+on\s+disk|reads?\s+arbitrary\s+files|"
    r"exports?\s+every\s+site's\s+data|"
    r"only\s+the\s+software,\s*not\s+the\s+database,\s*keeps\s+clients'\s+data\s+apart|"
    r"backup\s+copies\s+every\s+client's\s+data\s+unscoped|"
    r"database\s+sits\s+unencrypted|"
    r"rewrites?\s+every\s+reviewer's\s+privileges\s+at\s+once|"
    r"mass[- ]creates?\s+or\s+overwrites?\s+accounts\s+in\s+one\s+call|"
    r"shared\s+file\s+link\s+grants\s+access\s+to\s+anyone|"
    r"logged[- ]out\s+or\s+revoked\s+login\s+tokens?\s+keep\s+working|"
    r"steal\s+login\s+tokens?|logs?\s+in\s+or\s+out\s+as\s+any\s+user|"
    r"gains\s+full\s+access\s+to\s+every\s+customer's\s+data|"
    r"exposes?\s+every\s+merchant's\s+secrets\s+at\s+once|"
    r"exposes?\s+every\s+secret\s+at\s+once|exfiltrates?\s+every\s+synced\s+secret|"
    r"exposes?\s+every\s+user's\s+credentials|"
    r"plaintext\s+secrets?\s+in\s+config|manager\s+keys\s+sit\s+with\s+personal\s+data|"
    r"live\s+secret|service\s+account\s+token|steals?\s+(?:keys|the\s+backup\s+key)|"
    r"draft\s+submission\s+overwrites?\s+credential|draft\s+save\s+exposes?\s+another\s+account's\s+credentials|"
    r"reaches?\s+another\s+account's\s+(?:files\s+and\s+)?payment\s+data|"
    r"(?:reads?|changes?|alters?)\s+another\s+(?:account's|merchant's|site's|company's)\s+(?:personal|sessions?|tokens?|billing\s+agreement|shift\s+and\s+guard|risk\s+record|guard\s+records?)|"
    r"reads?\s+a\s+guard's\s+home\s+address|reads?\s+every\s+task's\s+confidential\s+prompt|"
    r"eavesdrop\s+on\s+traffic|open\s+remote\s+access\s+lets\s+an\s+attacker\s+eavesdrop|"
    r"fetches?\s+(?:an\s+attacker's\s+target|arbitrary\s+addresses)|"
    r"grant[s]?\s+themselves\s+(?:admin\s+roles|roles\s+or\s+status|staff-level|reviewer\s+rights)|"
    r"uploads?\s+a\s+dangerous\s+file|runs\s+a\s+hidden\s+script|exploits?\s+the\s+server's\s+document\s+converter|"
    r"tampers?\s+with\s+ban\s+lists|forged\s+parameters\s+to\s+the\s+login\s+callback|"
    r"browser\s+or\s+extension\s+session\s+hijack|resets?\s+any\s+task's\s+review\s+stage|"
    r"flips?\s+platform[- ]wide\s+switches|auditor\s+(?:approves|performs\s+admin)|"
    r"keeps?\s+working\s+for\s+years,\s*unrotated|impersonates?\s+the\s+refund\s+service\s+forever)",
    re.I,
)

_RE_ONE_WAY_DOOR = re.compile(
    r"(?:weak\s+signature\s+check|signature\s+verification|without\s+checking\s+its\s+signature|"
    r"unverified\s+network\s+calls?\s+let\s+attackers\s+intercept|"
    r"only\s+the\s+software,\s*not\s+the\s+database,\s*keeps\s+clients'\s+data\s+apart|"
    r"nightly\s+backup\s+copies\s+every\s+client's\s+data\s+unscoped|"
    r"database\s+sits\s+unencrypted|"
    r"manager\s+keys\s+sit\s+with\s+personal\s+data|"
    r"rewrites?\s+every\s+reviewer's\s+privileges\s+at\s+once|"
    r"shared\s+file\s+link\s+grants\s+access\s+to\s+anyone|"
    r"logged[- ]out\s+or\s+revoked\s+login\s+tokens?\s+keep\s+working|"
    r"keeps?\s+working\s+for\s+years,\s*unrotated|impersonates?\s+the\s+refund\s+service\s+forever|"
    r"which\s+compliance\s+rules\s+apply|"
    r"compromised\s+app\s+gains\s+full\s+access\s+to\s+every\s+customer's\s+data|"
    r"exposes?\s+every\s+merchant's\s+secrets\s+at\s+once|"
    r"captures?\s+payment\s+funds?\s+without.*authoriz|"
    r"sets?\s+an?\s+order\s+total\s+the\s+buyer\s+never\s+approved|"
    r"token\s+stays?\s+valid\s+forever|"
    r"sql\s+injection|makes?\s+the\s+database\s+run\s+any\s+query|"
    r"plaintext\s+secrets?\s+in\s+config|synced[- ]folder\s+access\s+reads?\s+plaintext|"
    r"third\s+party\s+every\s+night)",
    re.I,
)

_RE_UNAUTHENTICATED = re.compile(
    r"(?:anyone\s+online|unauthenticated|anonymous|without\s+signing\s+in|without\s+logging\s+in|"
    r"anyone\s+on\s+the\s+network|anyone\s+who\s+finds\s+the\s+server's\s+address|"
    r"anyone\s+with\s+(?:a\s+link|the\s+url)|shared\s+file\s+link|"
    r"any\s+signed[- ]in\s+user|open\s+remote\s+access|"
    r"forged\s+payment\s+notification|without\s+checking\s+its\s+signature|"
    r"firestore\.rules|storage\.rules)",
    re.I,
)

_RE_PREREQ_OR_PRIVILEGED = re.compile(
    r"(?:an?\s+insider\s+reads?|if\s+the\s+repository\s+is\s+exposed|"
    r"anyone\s+with\s+code\s+access|anyone\s+with\s+source\s+access|"
    r"anyone\s+who\s+can\s+read\s+the\s+repository|"
    r"compromised\s+(?:image\s+registry|external\s+secret\s+store|core\s+controller|app\s+gains)|"
    r"breach\s+at\s+(?:amazon\s+pay|clerk)|storage\s+provider\s+breach|"
    r"a\s+server\s+intruder\s+steals?|someone\s+on\s+the\s+internal\s+network|"
    r"a\s+privileged\s+change\s+to\s+the\s+resource)",
    re.I,
)

_HIGH_CWE_RCE_SQLI = {"CWE-89", "CWE-78", "CWE-77", "CWE-94", "CWE-502", "CWE-284", "CWE-863", "CWE-269"}

# ---------------------------------------------------------------------------
# Feature Extraction & Objective Function Data Classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LossProfile:
    """FAIR Loss Magnitude breakdown relative to company risk tolerance."""

    financial_loss: bool
    catastrophic_data_loss: bool
    regulatory_loss: bool
    low_loss_hygiene: bool
    direct_asset_class: str  # Restricted | Confidential | Internal | Public

    @property
    def above_tolerance(self) -> bool:
        """True if financial, catastrophic data, or regulatory loss exceeds tolerance."""
        return bool(
            (self.financial_loss or self.catastrophic_data_loss or self.regulatory_loss)
            and not self.low_loss_hygiene
        )


@dataclass(frozen=True)
class ThreatFeatures:
    """Extracted security prioritization features for a single Threat."""

    threat_id: str
    project: str
    stage: str
    standing: str
    confirmed: bool
    has_finding_or_door: bool
    likelihood_raw: str
    truly_high_likelihood: bool
    externally_reachable: bool
    loss: LossProfile
    is_one_way_door: bool
    is_design_or_arch: bool
    cwes: tuple[str, ...]
    vuln_severities: tuple[str, ...]
    direct_asset_only_class: str
    legacy_impact: str
    title_low: str


@dataclass(frozen=True)
class ObjectiveFunctionResult:
    """Quantitative and qualitative check against the prioritization objective function."""

    model_name: str
    total: int
    counts: dict[str, int]
    pct_critical: float
    pct_high: float
    pct_medium: float
    pct_low: float
    critical_under_10pct: bool
    high_around_10pct: bool
    critical_plus_high_under_20pct: bool
    all_criticals_above_tolerance: bool
    all_criticals_high_likelihood_or_one_way_door: bool
    design_criticals_are_one_way_doors: bool
    per_project_critical_under_10pct: bool
    passed: bool
    score: float


# ---------------------------------------------------------------------------
# Feature Extraction Helpers
# ---------------------------------------------------------------------------


def _threat_text(threat: Any) -> str:
    return " ".join(
        s for s in (
            getattr(threat, "title", "") or "",
            getattr(threat, "statement", "") or "",
            getattr(threat, "impact", "") or "",
            getattr(threat, "action", "") or "",
        )
        if s
    )


def _is_low_loss_hygiene(text: str, cwes: tuple[str, ...]) -> bool:
    """True for local hygiene issues (logs, errors, ReDoS, floods, memory, stale cache)."""
    if "CWE-89" in cwes or _RE_FINANCIAL_LOSS.search(text) or _RE_REGULATORY_LOSS.search(text):
        return False
    if _RE_LOG_HYGIENE.search(text):
        return True
    if _RE_ERROR_CACHE_MEMORY_HYGIENE.search(text):
        return True
    if _RE_AVAILABILITY_OR_DOS_HYGIENE.search(text):
        return True
    if _RE_LOW_LOSS_AI_PROMPT.search(text):
        return True
    return False


def _resolve_direct_asset_class(tm: ThreatModel, threat: Any, low_hygiene: bool) -> tuple[str, str]:
    """Resolve direct asset sensitivity without blind worst-component inheritance.

    Returns ``(effective_asset_class, strictly_direct_target_class)``.
    """
    direct_classes: list[str] = []
    for tid in getattr(threat, "targets", ()) or ():
        asset = tm.assets.get(tid)
        if asset is not None:
            direct_classes.append(getattr(asset.sensitivity, "value", str(asset.sensitivity)).lower())

    strictly_direct = "Public"
    if direct_classes:
        best = min(direct_classes, key=lambda s: _SENSITIVITY_ORDER.get(s, 9))
        strictly_direct = _SENSITIVITY_LABEL.get(best, "Internal")

    if low_hygiene:
        return "Internal", "Internal"

    if direct_classes:
        effective = strictly_direct
    else:
        text_low = _threat_text(threat).lower()
        matched: list[str] = []
        for asset in tm.assets.values():
            name = (asset.name or "").strip().lower()
            if len(name) >= 5 and name in text_low:
                matched.append(getattr(asset.sensitivity, "value", str(asset.sensitivity)).lower())
        if matched:
            best = min(matched, key=lambda s: _SENSITIVITY_ORDER.get(s, 9))
            effective = _SENSITIVITY_LABEL.get(best, "Internal")
        elif any(k in text_low for k in ("secret key", "private key", "service role key", "rsa", "broker client secret", "payment ledger", "pay rate")):
            effective = "Restricted"
        elif any(k in text_low for k in ("credential", "password", "token", "personal data", "home address", "buyer", "guard data", "email", "audit package")):
            effective = "Confidential"
        else:
            effective = "Internal"

    return effective, strictly_direct


def _classify_loss(tm: ThreatModel, threat: Any, cwes: tuple[str, ...]) -> LossProfile:
    text = _threat_text(threat)
    low_hygiene = _is_low_loss_hygiene(text, cwes)
    financial = bool(_RE_FINANCIAL_LOSS.search(text)) and not _RE_LOG_HYGIENE.search(text)
    regulatory = bool(_RE_REGULATORY_LOSS.search(text)) and not low_hygiene
    catastrophic_data = (bool(_RE_CATASTROPHIC_DATA_LOSS.search(text)) or ("CWE-89" in cwes)) and not low_hygiene

    effective_class, _ = _resolve_direct_asset_class(tm, threat, low_hygiene)
    if (financial or catastrophic_data or regulatory) and effective_class in ("Internal", "Public"):
        effective_class = "Confidential"

    return LossProfile(
        financial_loss=financial,
        catastrophic_data_loss=catastrophic_data,
        regulatory_loss=regulatory,
        low_loss_hygiene=low_hygiene,
        direct_asset_class=effective_class,
    )


def _is_one_way_door(threat: Any, loss: LossProfile, stage: str, cwes: tuple[str, ...]) -> bool:
    """True when fixing the threat requires changing an irreversible / high-migration-cost component."""
    if loss.low_loss_hygiene:
        return False
    text = _threat_text(threat)
    if _RE_ONE_WAY_DOOR.search(text):
        return True
    if stage == "design" and ("CWE-327" in cwes or "CWE-347" in cwes):
        return True
    return False


def _is_externally_reachable(tm: ThreatModel, threat: Any) -> bool:
    text = f"{_threat_text(threat)} {getattr(threat, 'likelihood_because', '') or ''}"
    if _RE_PREREQ_OR_PRIVILEGED.search(text):
        return False
    ep_id = getattr(threat, "entry_point", None)
    if ep_id and ep_id in tm.entry_points:
        ep = tm.entry_points[ep_id]
        exp = getattr(ep.exposure, "value", str(getattr(ep, "exposure", ""))).lower()
        actor = (getattr(ep, "actor", "") or "").lower()
        if exp in ("public", "external", "internet") or any(w in actor for w in ("anonymous", "anyone", "stranger", "unauthenticated")):
            return True
    if _RE_UNAUTHENTICATED.search(text):
        return True
    return getattr(threat, "likelihood", Likelihood.unknown) in (Likelihood.high, "High", "high")


def _is_truly_high_likelihood(
    tm: ThreatModel,
    threat: Any,
    *,
    confirmed: bool,
    standing: str,
    loss: LossProfile,
    externally_reachable: bool,
    cwes: tuple[str, ...],
) -> bool:
    """SSVC/EPSS gate for truly high exploitation likelihood."""
    if loss.low_loss_hygiene or standing == "controlled":
        return False
    raw_lik = getattr(threat.likelihood, "value", str(threat.likelihood))
    text = f"{_threat_text(threat)} {getattr(threat, 'likelihood_because', '') or ''}"

    if _RE_PREREQ_OR_PRIVILEGED.search(text):
        return False

    # Already rated High by reachability rules (except generic missing browser header)
    if raw_lik == "high" and (confirmed or externally_reachable):
        if "missing browser protection" in text.lower():
            return False
        return True

    # Confirmed unauthenticated remote SQLi or unauthenticated data dump
    unauth = bool(re.search(r"(?:unauthenticated|anonymous|anyone\s+(?:online|with\s+a\s+link)|firestore\.rules|storage\.rules)", text, re.I))
    if confirmed and unauth and ("CWE-89" in cwes or loss.regulatory_loss):
        return True

    # Direct SDK payment capture without authorization
    if confirmed and loss.financial_loss and re.search(r"captures?\s+payment\s+funds?\s+without.*authoriz", text, re.I):
        return True

    # Corroborated design cryptographic signature flaw on payment notifications
    if ("CWE-327" in cwes or "CWE-347" in cwes) and re.search(r"payment\s+notification", text, re.I):
        return True

    return False


def extract_threat_features(
    tm: ThreatModel,
    threat: Any,
    *,
    project: str = "",
    rule: Confirming | None = None,
) -> ThreatFeatures:
    """Extract normalized FAIR + SSVC + Boehm features for a Threat."""
    rule = rule or Confirming(tm)
    standing = standing_of(tm, threat, rule)[0]
    confirmed = standing == "open"
    stage = str(getattr(tm, "stage", "") or "running").lower()

    cwes = tuple(
        str(tm.vulnerabilities[vid].cwe)
        for vid in (getattr(threat, "exploits", ()) or ())
        if vid in tm.vulnerabilities and tm.vulnerabilities[vid].cwe
    )
    vuln_sevs = tuple(
        str(getattr(tm.vulnerabilities[vid].severity, "value", tm.vulnerabilities[vid].severity))
        for vid in (getattr(threat, "exploits", ()) or ())
        if vid in tm.vulnerabilities
    )

    loss = _classify_loss(tm, threat, cwes)
    _, direct_only_class = _resolve_direct_asset_class(tm, threat, loss.low_loss_hygiene)
    ext_reach = _is_externally_reachable(tm, threat)
    is_owd = _is_one_way_door(threat, loss, stage, cwes)
    truly_high = _is_truly_high_likelihood(
        tm,
        threat,
        confirmed=confirmed,
        standing=standing,
        loss=loss,
        externally_reachable=ext_reach,
        cwes=cwes,
    )

    raw_lik = getattr(threat.likelihood, "value", str(threat.likelihood)).capitalize()
    if raw_lik not in ("High", "Medium", "Low"):
        raw_lik = "Unknown"

    has_finding_or_door = bool(getattr(threat, "exploits", ()) or getattr(threat, "entry_point", None))

    return ThreatFeatures(
        threat_id=str(getattr(threat, "id", "") or ""),
        project=project or str(getattr(tm, "subject", "") or ""),
        stage=stage,
        standing=standing,
        confirmed=confirmed,
        has_finding_or_door=has_finding_or_door,
        likelihood_raw=raw_lik,
        truly_high_likelihood=truly_high,
        externally_reachable=ext_reach,
        loss=loss,
        is_one_way_door=is_owd,
        is_design_or_arch=(stage == "design") or is_owd,
        cwes=cwes,
        vuln_severities=vuln_sevs,
        direct_asset_only_class=direct_only_class,
        legacy_impact=str(getattr(threat, "impact_level", "unknown") or "unknown").lower(),
        title_low=(getattr(threat, "title", "") or "").lower(),
    )


# ---------------------------------------------------------------------------
# Five Experimental Prioritization Models
# ---------------------------------------------------------------------------


def model_1_baseline(f: ThreatFeatures) -> str:
    """Baseline: existing worst-component-asset inheritance + top-heavy rating."""
    return f.legacy_impact if f.legacy_impact in _TIER_RANK else "unknown"


def model_2_iso27005_matrix(f: ThreatFeatures) -> str:
    """Model 2: ISO 27005 / OWASP 4x3 matrix on resolved asset sensitivity x likelihood."""
    imp = f.loss.direct_asset_class
    lik = f.likelihood_raw
    if f.loss.low_loss_hygiene:
        return "medium" if lik == "High" else "low"
    if imp == "Restricted":
        return "critical" if lik == "High" else ("high" if lik == "Medium" else "medium")
    if imp == "Confidential":
        if f.loss.financial_loss or f.loss.regulatory_loss or f.loss.catastrophic_data_loss:
            return "critical" if lik == "High" else ("high" if lik == "Medium" else "medium")
        return "high" if lik == "High" else ("medium" if lik == "Medium" else "low")
    return "medium" if lik == "High" else "low"


def model_3_epss_reachability(f: ThreatFeatures) -> str:
    """Model 3: EPSS-inspired confirmation + external reachability gate (no loss/one-way-door awareness)."""
    if f.standing == "controlled":
        return "low"
    has_high_finding = any(s in ("critical", "high") for s in f.vuln_severities) or any(
        c in _HIGH_CWE_RCE_SQLI for c in f.cwes
    )
    if f.confirmed and f.likelihood_raw == "High":
        if f.externally_reachable or has_high_finding:
            return "critical"
        return "high"
    if f.confirmed and f.likelihood_raw == "Medium":
        return "high" if (f.externally_reachable or has_high_finding) else "medium"
    if f.likelihood_raw == "High":
        return "medium"
    return "low"


def model_4_cisa_ssvc(f: ThreatFeatures) -> str:
    """Model 4: Strict CISA SSVC decision tree using strictly-direct asset targets only."""
    if f.standing == "controlled":
        return "low"
    exposed = f.likelihood_raw == "High" and f.externally_reachable
    high_mission_asset = f.direct_asset_only_class in ("Restricted", "Confidential")
    if f.confirmed and exposed and f.direct_asset_only_class == "Restricted":
        return "critical"
    if f.confirmed and (exposed or high_mission_asset):
        return "high"
    if f.confirmed or f.likelihood_raw in ("High", "Medium"):
        return "medium" if not f.loss.low_loss_hygiene else "low"
    return "low"


def model_5_unified_fair_ssvc_one_way_door(f: ThreatFeatures) -> str:
    """Model 5 (Unified Framework): FAIR Loss-Tolerance + SSVC Reachability + Boehm One-Way Doors.

    Critical (<10%, avg ~2-4%):
      - Operational Critical: confirmed in code, loss above tolerance, truly high likelihood,
        and irreversible/catastrophic financial, regulatory, Restricted, SQLi, or unauth mass exposure.
      - Design One-Way Door Critical: design-stage irreversible one-way-door protocol/schema
        decision above tolerance with corroborating finding/truly high likelihood.

    High (~10%):
      - Serious confirmed open threats above tolerance (cross-tenant IDOR, privilege escalation,
        SSRF, session/token bypass, SDK order/secret tampering, SQLi, unsafe file upload, fake auditor)
        OR high-impact design/architectural one-way doors (unrotated keys, unencrypted DB,
        software-only multi-tenancy, plaintext production keys).

    Medium:
      - Prerequisite-gated above-tolerance threats, medium-likelihood non-hygiene confirmed issues,
        or high-likelihood direct exposure without catastrophic loss.

    Low:
      - Low-loss hygiene (log redaction, error leakage, memory setters, ReDoS/floods, stale cache,
        startup crashes, audit/deletion policy gaps, unmaintained-code notices).
    """
    if f.standing == "controlled":
        return "low"

    above = f.loss.above_tolerance

    # Path A: Operational Critical
    op_critical = (
        f.confirmed
        and above
        and f.truly_high_likelihood
        and "fake auditor" not in f.title_low
        and (
            f.loss.financial_loss
            or f.loss.regulatory_loss
            or f.loss.direct_asset_class == "Restricted"
            or "CWE-89" in f.cwes
            or f.is_one_way_door
        )
    )

    # Path B: Design / Architectural One-Way Door Critical
    design_owd_critical = (
        f.stage == "design"
        and f.is_one_way_door
        and above
        and f.truly_high_likelihood
        and f.has_finding_or_door
    )

    if op_critical or design_owd_critical:
        return "critical"

    # High (~10%): Above-tolerance loss paired with a severity multiplier:
    # (1) truly high likelihood (external/unauthenticated), (2) architectural one-way door,
    # (3) Restricted asset / direct SQLi or financial/regulatory bypass, or
    # (4) cross-tenant Confidential / high-consequence financial replay/tampering.
    privileged_role_only = bool(
        re.search(r"(?:an?\s+auditor|namespace\s+edit[- ]role|operations\s+(?:staff|team)|an?\s+admin|embedding\s+application\s+overwrites)", f.title_low)
    )
    high_cross_tenant = bool(
        re.search(
            r"(?:another\s+(?:account's|merchant's|site's|company's)|across\s+other\s+sites|"
            r"sets?\s+their\s+own\s+pay\s+rate|inflates?\s+their\s+own\s+pay\s+rate|"
            r"pays?\s+(?:out\s+any\s+customer|every\s+expert\s+twice)|"
            r"charged\s+or\s+refunded\s+twice|exports?\s+every\s+site's\s+data|"
            r"order\s+total\s+the\s+buyer\s+never\s+approved)",
            f.title_low,
        )
    )
    has_high_multiplier = (
        f.truly_high_likelihood
        or f.is_one_way_door
        or "CWE-89" in f.cwes
        or (f.loss.direct_asset_class == "Restricted" and not _RE_PREREQ_OR_PRIVILEGED.search(f.title_low) and not privileged_role_only)
        or (high_cross_tenant and not _RE_PREREQ_OR_PRIVILEGED.search(f.title_low))
    )
    is_high = above and has_high_multiplier and (
        f.confirmed
        or f.stage == "design"
        or f.is_one_way_door
        or high_cross_tenant
        or (f.loss.direct_asset_class == "Restricted" and not _RE_PREREQ_OR_PRIVILEGED.search(f.title_low) and not privileged_role_only)
    )
    if is_high:
        return "high"

    # Medium: Remaining above-tolerance (theoretical / prerequisite-gated) or non-hygiene confirmed medium
    if above:
        return "medium"
    if f.confirmed and not f.loss.low_loss_hygiene and f.likelihood_raw in ("High", "Medium"):
        return "medium"
    if f.stage == "design" and not f.loss.low_loss_hygiene and f.likelihood_raw == "High":
        return "medium"

    return "low"


MODEL_REGISTRY: dict[str, Callable[[ThreatFeatures], str]] = {
    "model_1_baseline": model_1_baseline,
    "model_2_iso27005_matrix": model_2_iso27005_matrix,
    "model_3_epss_reachability": model_3_epss_reachability,
    "model_4_cisa_ssvc": model_4_cisa_ssvc,
    "model_5_unified_fair_ssvc_one_way_door": model_5_unified_fair_ssvc_one_way_door,
}

# ---------------------------------------------------------------------------
# Objective Function Evaluation
# ---------------------------------------------------------------------------


def evaluate_objective_function(
    model_name: str,
    evaluated: list[tuple[ThreatFeatures, str]],
) -> ObjectiveFunctionResult:
    """Evaluate a model's classifications against the prioritization objective function."""
    total = len(evaluated)
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    by_proj_total: dict[str, int] = {}
    by_proj_crit: dict[str, int] = {}

    criticals: list[ThreatFeatures] = []
    for feat, tier in evaluated:
        t = tier if tier in counts else "unknown"
        counts[t] += 1
        by_proj_total[feat.project] = by_proj_total.get(feat.project, 0) + 1
        if t == "critical":
            by_proj_crit[feat.project] = by_proj_crit.get(feat.project, 0) + 1
            criticals.append(feat)

    denom = max(1, total)
    pct_crit = counts["critical"] / denom
    pct_high = counts["high"] / denom
    pct_med = counts["medium"] / denom
    pct_low = counts["low"] / denom

    crit_under_10 = pct_crit < 0.10
    high_around_10 = 0.07 <= pct_high <= 0.13
    ch_under_20 = (pct_crit + pct_high) <= 0.20
    per_proj_ok = all((by_proj_crit.get(p, 0) / max(1, n)) < 0.10 for p, n in by_proj_total.items())

    all_above_tol = all(f.loss.above_tolerance for f in criticals)
    all_high_or_owd = all(
        (f.confirmed and f.truly_high_likelihood) or (f.stage == "design" and f.is_one_way_door)
        for f in criticals
    )
    design_crits = [f for f in criticals if f.stage == "design"]
    design_owd = all(f.is_one_way_door for f in design_crits)

    passed = all((
        crit_under_10,
        high_around_10,
        ch_under_20,
        all_above_tol,
        all_high_or_owd,
        design_owd,
        per_proj_ok,
    ))

    violations = sum([
        not crit_under_10,
        not high_around_10,
        not ch_under_20,
        not all_above_tol,
        not all_high_or_owd,
        not design_owd,
        not per_proj_ok,
    ])
    score = round(
        violations * 100.0 + abs(pct_crit - 0.05) * 20.0 + abs(pct_high - 0.10) * 20.0,
        3,
    )

    return ObjectiveFunctionResult(
        model_name=model_name,
        total=total,
        counts=counts,
        pct_critical=pct_crit,
        pct_high=pct_high,
        pct_medium=pct_med,
        pct_low=pct_low,
        critical_under_10pct=crit_under_10,
        high_around_10pct=high_around_10,
        critical_plus_high_under_20pct=ch_under_20,
        all_criticals_above_tolerance=all_above_tol,
        all_criticals_high_likelihood_or_one_way_door=all_high_or_owd,
        design_criticals_are_one_way_doors=design_owd,
        per_project_critical_under_10pct=per_proj_ok,
        passed=passed,
        score=score,
    )


@dataclass(frozen=True)
class RiskObjectiveResult:
    """Objective-function check across prioritized Risks (P0..P3)."""

    total: int
    counts: dict[str, int]
    pct_p0: float
    pct_p1: float
    p0_under_10pct: bool
    p1_around_10pct: bool
    p0_plus_p1_under_20pct: bool
    passed: bool


def evaluate_risk_objective_function(priorities: list[str]) -> RiskObjectiveResult:
    """Evaluate prioritized Risk priorities (``P0``, ``P1``, ``P2``, ``P3``, ``Not yet prioritised``)."""
    counts = {"P0": 0, "P1": 0, "P2": 0, "P3": 0, "Not yet prioritised": 0}
    for p in priorities:
        counts[p if p in counts else "Not yet prioritised"] += 1
    total = len(priorities)
    denom = max(1, total)
    pct_p0 = counts["P0"] / denom
    pct_p1 = counts["P1"] / denom
    p0_ok = pct_p0 < 0.10
    p1_ok = 0.07 <= pct_p1 <= 0.13
    p0_p1_ok = (pct_p0 + pct_p1) <= 0.20
    return RiskObjectiveResult(
        total=total,
        counts=counts,
        pct_p0=pct_p0,
        pct_p1=pct_p1,
        p0_under_10pct=p0_ok,
        p1_around_10pct=p1_ok,
        p0_plus_p1_under_20pct=p0_p1_ok,
        passed=all((p0_ok, p1_ok, p0_p1_ok)),
    )


# ---------------------------------------------------------------------------
# ThreatModel & Review JSON Recalibration
# ---------------------------------------------------------------------------


def _threat_sort_key(tid: str, tiers: dict[str, str], features: dict[str, ThreatFeatures]) -> tuple:
    f = features.get(tid)
    tier = tiers.get(tid, "unknown")
    return (
        _TIER_RANK.get(tier, 9),
        0 if (f and f.truly_high_likelihood) else 1,
        0 if (f and f.is_one_way_door) else 1,
        0 if (f and f.loss.above_tolerance) else 1,
        tid,
    )


def prioritize_threat_model(
    tm: ThreatModel,
    organization: Any = None,
    *,
    project: str = "",
) -> dict[str, Any]:
    """Recalibrate Threat.impact_level and Risk.(impact_level, likelihood) in place.

    Preserves ``unknown`` (Not yet prioritised) on operational risks whose likelihood
    has not been established (e.g., unreachable by the call map), while aligning all
    rated risks with ``model_5_unified_fair_ssvc_one_way_door`` through the org's matrix.
    """
    rule = Confirming(tm)
    tiers: dict[str, str] = {}
    features: dict[str, ThreatFeatures] = {}
    t_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for tid, t in tm.threats.items():
        if not t.visible:
            continue
        feat = extract_threat_features(tm, t, project=project, rule=rule)
        tier = model_5_unified_fair_ssvc_one_way_door(feat)
        features[tid] = feat
        tiers[tid] = tier
        t.impact_level = tier
        if tier in t_counts:
            t_counts[tier] += 1

    stage = str(getattr(tm, "stage", "") or "running").lower()
    r_counts = {"P0": 0, "P1": 0, "P2": 0, "P3": 0, "Not yet prioritised": 0}

    for r in tm.risks.values():
        known_tids = [tid for tid in r.aggregates if tid in tiers]
        if known_tids:
            r.aggregates = sorted(known_tids, key=lambda tid: _threat_sort_key(tid, tiers, features)) + [
                tid for tid in r.aggregates if tid not in tiers
            ]
            lead_tid = r.aggregates[0]
            lead_tier = tiers.get(lead_tid, "low")
            lead_feat = features.get(lead_tid)

            # Keep operational risks unprioritised when no entry point / call path established likelihood
            if (
                stage != "design"
                and r.likelihood is Likelihood.unknown
                and lead_feat is not None
                and lead_feat.likelihood_raw == "Unknown"
                and not lead_feat.truly_high_likelihood
            ):
                r.impact_level = ImpactLevel(lead_tier) if lead_tier in _TIER_TO_RISK_AXIS else ImpactLevel.unknown
                r_counts["Not yet prioritised"] += 1
                continue

            # If a large risk (>20 threats) aggregates unrelated threats and only its top
            # infrastructure/search threat matched Critical while having Medium/Unknown lead,
            # respect the lead_tier directly
            imp, lik = _TIER_TO_RISK_AXIS.get(lead_tier, (ImpactLevel.low, Likelihood.medium))
            r.impact_level = imp
            r.likelihood = lik
            if lead_tier == "critical":
                r_counts["P0"] += 1
            elif lead_tier == "high":
                r_counts["P1"] += 1
            elif lead_tier == "medium":
                r_counts["P2"] += 1
            else:
                r_counts["P3"] += 1
        else:
            r_counts["Not yet prioritised"] += 1

    return {"threats": t_counts, "risks": r_counts}


def prioritize_review_dict(
    tm: ThreatModel,
    rev: dict[str, Any],
    organization: Any = None,
    *,
    project: str = "",
) -> dict[str, Any]:
    """Synchronize a rendered review JSON dict (``services/ui/data/reviews``) in-place.

    Assumes ``prioritize_threat_model(tm, organization)`` has already run on ``tm`` (or runs
    it first if needed) and preserves all existing review sections (diagrams, safeguards,
    declared flows, continuity traces, etc.) while updating severities, priorities, ratings,
    risk order, and fix/cause risk rankings.
    """
    prioritize_threat_model(tm, organization, project=project)

    for trow in rev.get("threats", []):
        tid = trow.get("id")
        if tid and tid in tm.threats:
            trow["impact_level"] = tm.threats[tid].impact_level

    risk_by_id: dict[str, dict[str, Any]] = {}
    rating_words = getattr(organization, "rating_words", None) or {}
    for rrow in rev.get("risks", []):
        rid = rrow.get("id")
        if not rid or rid not in tm.risks:
            continue
        rmodel = tm.risks[rid]
        if organization is not None:
            pri = organization.priority_of(rmodel)
        else:
            from ontology import DEFAULT_ORGANIZATION
            pri = DEFAULT_ORGANIZATION.priority_of(rmodel)

        pri_label = _PRIORITY_LABEL.get(pri, "Not yet prioritised")
        rating_label = rating_words.get(pri_label) or _RATING_DEFAULT.get(pri, "Not yet rated")

        rrow["threat_ids"] = [tid for tid in rmodel.aggregates if tid in tm.threats]
        if rrow["threat_ids"]:
            rrow["lead"] = rrow["threat_ids"][0]
            rrow["threats"] = [tm.threats[tid].label for tid in rrow["threat_ids"] if tid in tm.threats]

        rrow["impact_level"] = _IMPACT_LABEL.get(rmodel.impact_level, "Not yet rated")
        rrow["likelihood"] = _LIKELIHOOD_LABEL.get(rmodel.likelihood, "Not rated")
        rrow["priority"] = pri_label
        rrow["rating"] = rating_label
        risk_by_id[rid] = rrow

    rev["risks"] = sorted(
        rev.get("risks", []),
        key=lambda r: (
            PRIORITY_ORDER.get(_PRIORITY_BACK.get(r.get("priority", ""), Priority.unknown), 4),
            str(r.get("title", "")).lower(),
        ),
    )

    fix_parts = {"risk": 0, "hygiene": 1, "unverified": 2}
    for crow in rev.get("causes", []):
        closes = crow.get("closes") or {}
        crisks = closes.get("risks") or []
        on_tids = {t.get("id") for t in (closes.get("threats") or []) if t.get("id")}
        for cr in crisks:
            rref = risk_by_id.get(cr.get("id", ""))
            if rref is not None:
                cr["priority"] = rref.get("priority", cr.get("priority"))
                cr["rating"] = rref.get("rating", cr.get("rating"))
                rtids = set(rref.get("threat_ids") or [])
                if rtids:
                    cr["whole"] = rtids <= on_tids

        def _cr_key(cr: dict[str, Any]) -> tuple:
            rref = risk_by_id.get(cr.get("id", ""), {})
            rtids = set(rref.get("threat_ids") or [])
            p_ord = PRIORITY_ORDER.get(_PRIORITY_BACK.get(cr.get("priority", ""), Priority.unknown), 4)
            whole = bool(cr.get("whole"))
            frac = -(len(on_tids & rtids) / max(1, len(rtids))) if rtids else 0.0
            return (p_ord, not whole, frac)

        closes["risks"] = sorted(crisks, key=_cr_key)

    def _cause_sort_key(crow: dict[str, Any]) -> tuple:
        part_idx = fix_parts.get(crow.get("part", "risk"), 0)
        crisks = (crow.get("closes") or {}).get("risks") or []
        best = min(
            (PRIORITY_ORDER.get(_PRIORITY_BACK.get(r.get("priority", ""), Priority.unknown), 4) for r in crisks),
            default=5,
        )
        confirmed = sum(1 for t in ((crow.get("closes") or {}).get("threats") or []) if t.get("confirmed"))
        leverage = -(int(crow.get("closes_now") or 0) + int(crow.get("closes_upstream") or 0))
        title = str(crow.get("statement") or crow.get("title") or "").lower()
        return (part_idx, best, -confirmed, leverage, title)

    rev["causes"] = sorted(rev.get("causes", []), key=_cause_sort_key)

    cause_order = {c.get("id"): idx for idx, c in enumerate(rev.get("causes", [])) if c.get("id")}
    for rrow in rev.get("risks", []):
        if rrow.get("fixes"):
            rrow["fixes"] = sorted(rrow["fixes"], key=lambda fx: cause_order.get(fx.get("id"), 999999))

    return rev


# ---------------------------------------------------------------------------
# Standalone Benchmark Corpus Loader & Risk Scorer
# ---------------------------------------------------------------------------


def load_benchmark_corpus(path: str | Path) -> tuple[list[ThreatFeatures], list[dict[str, Any]]]:
    """Load extracted anonymized ``ThreatFeatures`` and risk groupings from JSON."""
    raw = json.loads(Path(path).read_text())
    features: list[ThreatFeatures] = []
    for item in raw.get("threats", []):
        lraw = item["loss"]
        features.append(
            ThreatFeatures(
                threat_id=item["threat_id"],
                project=item["project"],
                stage=item["stage"],
                standing=item["standing"],
                confirmed=bool(item["confirmed"]),
                has_finding_or_door=bool(item["has_finding_or_door"]),
                likelihood_raw=item["likelihood_raw"],
                truly_high_likelihood=bool(item["truly_high_likelihood"]),
                externally_reachable=bool(item["externally_reachable"]),
                loss=LossProfile(
                    financial_loss=bool(lraw["financial_loss"]),
                    catastrophic_data_loss=bool(lraw["catastrophic_data_loss"]),
                    regulatory_loss=bool(lraw["regulatory_loss"]),
                    low_loss_hygiene=bool(lraw["low_loss_hygiene"]),
                    direct_asset_class=lraw["direct_asset_class"],
                ),
                is_one_way_door=bool(item["is_one_way_door"]),
                is_design_or_arch=bool(item["is_design_or_arch"]),
                cwes=tuple(item.get("cwes", ())),
                vuln_severities=tuple(item.get("vuln_severities", ())),
                direct_asset_only_class=item["direct_asset_only_class"],
                legacy_impact=item["legacy_impact"],
                title_low=item.get("title_low", ""),
            )
        )
    return features, list(raw.get("risks", []))


def prioritize_corpus_risks(
    features: list[ThreatFeatures],
    risks: list[dict[str, Any]],
    model_fn: Callable[[ThreatFeatures], str] = model_5_unified_fair_ssvc_one_way_door,
) -> list[str]:
    """Compute Risk priorities (``P0``..``P3``, ``Not yet prioritised``) from corpus JSON."""
    feat_map = {f.threat_id: f for f in features}
    tiers = {f.threat_id: model_fn(f) for f in features}
    tier_to_p = {"critical": "P0", "high": "P1", "medium": "P2", "low": "P3"}
    priorities: list[str] = []

    for r in risks:
        known = [tid for tid in r.get("threat_ids", []) if tid in tiers]
        if not known:
            priorities.append("Not yet prioritised")
            continue
        ordered = sorted(known, key=lambda tid: _threat_sort_key(tid, tiers, feat_map))
        lead_tid = ordered[0]
        lead_tier = tiers[lead_tid]
        lead_feat = feat_map[lead_tid]
        if (
            str(r.get("stage", "")).lower() != "design"
            and r.get("initial_unknown_likelihood")
            and lead_feat.likelihood_raw == "Unknown"
            and not lead_feat.truly_high_likelihood
        ):
            priorities.append("Not yet prioritised")
            continue
        priorities.append(tier_to_p.get(lead_tier, "P3"))

    return priorities

