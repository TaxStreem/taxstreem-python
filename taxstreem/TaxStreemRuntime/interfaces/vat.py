"""
VAT filing interfaces — mirrors src/interfaces/vat.ts from the Node SDK.
Uses Python dataclasses for zero-dependency typed models with camelCase
API serialisation to match the Node SDK wire format exactly.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


@dataclass
class VatFilingItem:
    """A single line item within a VAT filing."""
    vatStatus: int
    amount: float
    item: str
    narration: str
    taxId: str
    beneficiary: str

    def __post_init__(self):
        if not isinstance(self.vatStatus, int):
            raise ValueError("vatStatus must be an int")
        if not isinstance(self.amount, (int, float)):
            raise ValueError("amount must be a number")
        for fname in ("item", "narration", "taxId", "beneficiary"):
            if not getattr(self, fname):
                raise ValueError(f"{fname} is required")

    def _api_dict(self) -> Dict:
        return {
            "vatStatus": self.vatStatus,
            "amount": self.amount,
            "item": self.item,
            "narration": self.narration,
            "taxId": self.taxId,
            "beneficiary": self.beneficiary,
        }


@dataclass
class VatFilingPayload:
    """Payload for a single VAT return submission."""
    encryptedPayload: str
    month: int
    year: int
    data: List[VatFilingItem]

    def __post_init__(self):
        if not (1 <= self.month <= 12):
            raise ValueError("month must be between 1 and 12")
        if self.year < 2000:
            raise ValueError("year must be >= 2000")
        if not self.encryptedPayload:
            raise ValueError("encryptedPayload is required")

    def _api_dict(self) -> Dict:
        return {
            "encryptedPayload": self.encryptedPayload,
            "month": self.month,
            "year": self.year,
            "data": [item._api_dict() for item in self.data],
        }


@dataclass
class VatFilingBatchPayload:
    """Payload for a batch of VAT return submissions."""
    batchId: str
    payload: List[VatFilingPayload]

    def _api_dict(self) -> Dict:
        return {
            "batchId": self.batchId,
            "payload": [p._api_dict() for p in self.payload],
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
    def from_dict(cls, d: Dict) -> "FilingResponse":
        return cls(
            status=d["status"],
            reference_id=d["reference_id"],
            message=d["message"],
            data=d.get("data"),
        )


@dataclass
class BatchFilingResponse:
    """API response for a batch filing submission."""
    status: str
    batch_id: str
    message: str
    data: Optional[Any] = None

    @classmethod
    def from_dict(cls, d: Dict) -> "BatchFilingResponse":
        return cls(
            status=d["status"],
            batch_id=d.get("batchId", d.get("batch_id", "")),
            message=d["message"],
            data=d.get("data"),
        )
