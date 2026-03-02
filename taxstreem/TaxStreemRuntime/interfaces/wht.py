"""
WHT filing interfaces — mirrors src/interfaces/wht.ts from the Node SDK.
Uses Python dataclasses for zero-dependency typed models with camelCase
API serialisation to match the Node SDK wire format exactly.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


@dataclass
class WhtFilingItem:
    """A single line item within a WHT filing."""
    beneficiaryName: str
    beneficiaryTin: str
    transactionDate: str
    transactionDesc: str
    transactionAmount: float
    rate: float
    taxAmount: float
    scheduleReference: str

    def _api_dict(self) -> Dict:
        return {
            "beneficiaryName": self.beneficiaryName,
            "beneficiaryTin": self.beneficiaryTin,
            "transactionDate": self.transactionDate,
            "transactionDesc": self.transactionDesc,
            "transactionAmount": self.transactionAmount,
            "rate": self.rate,
            "taxAmount": self.taxAmount,
            "scheduleReference": self.scheduleReference,
        }


@dataclass
class WhtFilingPayload:
    """Payload for a single WHT return submission."""
    encryptedPayload: str
    month: int
    year: int
    data: List[WhtFilingItem]

    def __post_init__(self):
        if not (1 <= self.month <= 12):
            raise ValueError("month must be between 1 and 12")
        if self.year < 2000:
            raise ValueError("year must be >= 2000")

    def _api_dict(self) -> Dict:
        return {
            "encryptedPayload": self.encryptedPayload,
            "month": self.month,
            "year": self.year,
            "data": [item._api_dict() for item in self.data],
        }


@dataclass
class WhtFilingBatchPayload:
    """Payload for a batch of WHT return submissions."""
    batchId: str
    payload: List[WhtFilingPayload]

    def _api_dict(self) -> Dict:
        return {
            "batchId": self.batchId,
            "payload": [p._api_dict() for p in self.payload],
        }
