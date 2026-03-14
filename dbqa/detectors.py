"""
PII/sensitive data detectors.

Pure functions — no DB access, easy to unit-test.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


class Tag:
    EMAIL      = "EMAIL"
    PHONE      = "PHONE"
    NAME       = "NAME"
    ADDRESS    = "ADDRESS"
    DOB        = "DOB"
    GOV_ID     = "GOV_ID"
    PAYMENT    = "PAYMENT"
    AUTH       = "AUTH"
    UUID       = "UUID"
    JWT        = "JWT"
    HASH_LIKE  = "HASH_LIKE"
    IBAN       = "IBAN"


_NAME_PATTERNS: list[tuple[re.Pattern, str]] = [
    # EMAIL
    (re.compile(r"\b(e_?mail|mail)\b", re.I), Tag.EMAIL),
    # PHONE
    (re.compile(r"\b(phone|mobile|tel(ephone)?|gsm|cel)\b", re.I), Tag.PHONE),
    # NAME
    (re.compile(r"\b(first_?name|last_?name|full_?name|surname|ime|prezime)\b", re.I), Tag.NAME),
    # ADDRESS
    (re.compile(r"\b(address|street|city|zip|postal|adresa|grad|ulica)\b", re.I), Tag.ADDRESS),
    # DATE OF BIRTH
    (re.compile(r"\b(birth|dob|date_?of_?birth|datum_?rodjenja)\b", re.I), Tag.DOB),
    # GOV ID
    (re.compile(r"\b(jmbg|ssn|passport|national_?id|id_?number|oib|matični)\b", re.I), Tag.GOV_ID),
    # PAYMENT
    (re.compile(r"\b(iban|swift|bic|card|cc_?num|pan|credit_?card|debit_?card|account_?number)\b", re.I), Tag.PAYMENT),
    # AUTH / SECRETS
    (re.compile(r"\b(password|pass(wd)?|pwd|secret|token|api_?key|private_?key|access_?key|auth_?token|refresh_?token)\b", re.I), Tag.AUTH),
]


def detect_by_name(col_name: str) -> set[str]:
    """Return set of sensitivity tags based on column name heuristics."""
    tags: set[str] = set()
    for pattern, tag in _NAME_PATTERNS:
        if pattern.search(col_name):
            tags.add(tag)
    return tags


_RE_EMAIL = re.compile(
    r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
)
_RE_PHONE = re.compile(
    r"^\+?[\d\s\-().]{7,20}$"
)
_RE_DIGITS_ONLY = re.compile(r"^\d{7,20}$")
_RE_IBAN = re.compile(
    r"^[A-Z]{2}\d{2}[A-Z0-9]{4,30}$"
)
_RE_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.I,
)
_RE_JWT = re.compile(
    r"^[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}$"
)
_RE_HEX_HASH = re.compile(r"^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$", re.I)
_RE_BASE64_LONG = re.compile(r"^[A-Za-z0-9+/]{44,}={0,2}$")
_RE_CARD_RAW = re.compile(r"^[\d\s\-]{13,23}$")


@dataclass
class ValueDetectionResult:
    tag: str
    hit_count: int
    total: int
    examples_masked: list[str] = field(default_factory=list)

    @property
    def hit_rate(self) -> float:
        return self.hit_count / self.total if self.total else 0.0


def detect_values(values: list[str]) -> list[ValueDetectionResult]:
    """
    Run all value-based detectors on a sample of values.
    Returns one result per tag that had at least one hit.
    Raw values are NEVER included — only masked examples (max 3).
    """
    if not values:
        return []

    buckets: dict[str, list[str]] = {}

    for v in values:
        stripped = v.strip()

        if _RE_EMAIL.match(stripped):
            buckets.setdefault(Tag.EMAIL, []).append(mask_email(stripped))

        if _RE_PHONE.match(stripped) or _RE_DIGITS_ONLY.match(stripped):
            buckets.setdefault(Tag.PHONE, []).append(mask_phone(stripped))

        iban_candidate = stripped.replace(" ", "").upper()
        if _RE_IBAN.match(iban_candidate) and len(iban_candidate) >= 15:
            buckets.setdefault(Tag.IBAN, []).append(mask_generic(stripped, keep_last=4))

        if _RE_CARD_RAW.match(stripped):
            digits = re.sub(r"[\s\-]", "", stripped)
            if len(digits) in range(13, 20) and luhn_check(digits):
                buckets.setdefault(Tag.PAYMENT, []).append(mask_generic(digits, keep_last=4))

        if _RE_UUID.match(stripped):
            buckets.setdefault(Tag.UUID, []).append(mask_generic(stripped, keep_last=4))

        if _RE_JWT.match(stripped):
            buckets.setdefault(Tag.JWT, []).append(stripped[:8] + "…[redacted]")

        if _RE_HEX_HASH.match(stripped) or (
            _RE_BASE64_LONG.match(stripped) and len(stripped) >= 44
        ):
            buckets.setdefault(Tag.HASH_LIKE, []).append(
                stripped[:6] + "…[" + str(len(stripped)) + "chars]"
            )

    results = []
    total = len(values)
    for tag, examples in buckets.items():
        results.append(
            ValueDetectionResult(
                tag=tag,
                hit_count=len(examples),
                total=total,
                examples_masked=examples[:3],
            )
        )
    return results


def mask_email(email: str) -> str:
    """a***@d***.com"""
    try:
        local, domain = email.rsplit("@", 1)
        masked_local = local[0] + "***" if len(local) > 1 else "***"
        parts = domain.rsplit(".", 1)
        if len(parts) == 2:
            masked_domain = parts[0][0] + "***." + parts[1] if parts[0] else "***." + parts[1]
        else:
            masked_domain = "***"
        return f"{masked_local}@{masked_domain}"
    except Exception:
        return "***@***"


def mask_phone(phone: str) -> str:
    """Keep country code prefix, mask middle."""
    digits = re.sub(r"[^\d+]", "", phone)
    if len(digits) >= 8:
        return digits[:3] + "****" + digits[-2:]
    return "****"


def mask_generic(value: str, keep_last: int = 4) -> str:
    """****1234"""
    if len(value) <= keep_last:
        return "****"
    return "****" + value[-keep_last:]


def luhn_check(number: str) -> bool:
    """Return True if the digit string passes the Luhn check."""
    try:
        digits = [int(c) for c in number if c.isdigit()]
        if len(digits) < 13:
            return False
        total = 0
        for i, d in enumerate(reversed(digits)):
            if i % 2 == 1:
                d *= 2
                if d > 9:
                    d -= 9
            total += d
        return total % 10 == 0
    except Exception:
        return False
