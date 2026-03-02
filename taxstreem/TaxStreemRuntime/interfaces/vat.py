"""
VAT filing interfaces — mirrors src/interfaces/vat.ts from the Node SDK.

Field names follow Python's snake_case convention. The as_dict() method
on each model handles the translation to camelCase for the wire format.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class VatFilingItem:
    """A single line item within a VAT filing."""

    vat_status: int
    amount: float
    item: str
    narration: str
    tax_id: str
    beneficiary: str

    def __post_init__(self) -> None:
        if self.amount < 0:
            raise ValueError("amount must be non-negative")
        if not self.item:
            raise ValueError("item is required")
        if not self.tax_id:
            raise ValueError("tax_id is required")
        if not self.beneficiary:
            raise ValueError("beneficiary is required")

    def as_dict(self) -> Dict[str, Any]:
        """Serialise to the camelCase wire format expected by the API."""
        return {
            "vatStatus": self.vat_status,
            "amount": self.amount,
            "item": self.item,
            "narration": self.narration,
            "taxId": self.tax_id,
            "beneficiary": self.beneficiary,
        }


@dataclass
class VatFilingPayload:
    """Payload for a single VAT return submission."""

    encrypted_payload: str
    month: int
    year: int
    data: List[VatFilingItem]

    def __post_init__(self) -> None:
        if not (1 <= self.month <= 12):
            raise ValueError(f"month must be 1–12, got {self.month}")
        if self.year < 2000:
            raise ValueError(f"year must be >= 2000, got {self.year}")
        if not self.encrypted_payload:
            raise ValueError("encrypted_payload is required")

    def as_dict(self) -> Dict[str, Any]:
        return {
            "encryptedPayload": self.encrypted_payload,
            "month": self.month,
            "year": self.year,
            "data": [item.as_dict() for item in self.data],
        }


@dataclass
class VatFilingBatchPayload:
    """Payload for a batch of VAT return submissions."""

    batch_id: str
    payload: List[VatFilingPayload]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "batchId": self.batch_id,
            "payload": [p.as_dict() for p in self.payload],
        }


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


@dataclass
class FilingResponse:
    """API response for a single filing submission."""

    status: str
    reference_id: str
    message: str
    data: Optional[Any] = None

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> FilingResponse:
        return cls(
            status=raw["status"],
            reference_id=raw["reference_id"],
            message=raw["message"],
            data=raw.get("data"),
        )


@dataclass
class BatchFilingResponse:
    """API response for a batch filing submission."""

    status: str
    batch_id: str
    message: str
    data: Optional[Any] = None

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> BatchFilingResponse:
        return cls(
            status=raw["status"],
            # API returns "batchId" (camelCase) — normalise to snake_case here.
            batch_id=raw.get("batchId") or raw.get("batch_id", ""),
            message=raw["message"],
            data=raw.get("data"),
        )