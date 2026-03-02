"""
WHT filing interfaces — mirrors src/interfaces/wht.ts from the Node SDK.

Field names follow Python's snake_case convention. The as_dict() method
handles translation to the camelCase wire format.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List


@dataclass
class WhtFilingItem:
    """A single line item within a WHT filing."""

    beneficiary_name: str
    beneficiary_tin: str
    transaction_date: str
    transaction_desc: str
    transaction_amount: float
    rate: float
    tax_amount: float
    schedule_reference: str

    def __post_init__(self) -> None:
        if self.transaction_amount < 0:
            raise ValueError("transaction_amount must be non-negative")
        if not (0 <= self.rate <= 100):
            raise ValueError(f"rate must be 0–100, got {self.rate}")
        if self.tax_amount < 0:
            raise ValueError("tax_amount must be non-negative")

    def as_dict(self) -> Dict[str, Any]:
        """Serialise to the camelCase wire format expected by the API."""
        return {
            "beneficiaryName": self.beneficiary_name,
            "beneficiaryTin": self.beneficiary_tin,
            "transactionDate": self.transaction_date,
            "transactionDesc": self.transaction_desc,
            "transactionAmount": self.transaction_amount,
            "rate": self.rate,
            "taxAmount": self.tax_amount,
            "scheduleReference": self.schedule_reference,
        }


@dataclass
class WhtFilingPayload:
    """Payload for a single WHT return submission."""

    encrypted_payload: str
    month: int
    year: int
    data: List[WhtFilingItem]

    def __post_init__(self) -> None:
        if not (1 <= self.month <= 12):
            raise ValueError(f"month must be 1–12, got {self.month}")
        if self.year < 2000:
            raise ValueError(f"year must be >= 2000, got {self.year}")

    def as_dict(self) -> Dict[str, Any]:
        return {
            "encryptedPayload": self.encrypted_payload,
            "month": self.month,
            "year": self.year,
            "data": [item.as_dict() for item in self.data],
        }


@dataclass
class WhtFilingBatchPayload:
    """Payload for a batch of WHT return submissions."""

    batch_id: str
    payload: List[WhtFilingPayload]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "batchId": self.batch_id,
            "payload": [p.as_dict() for p in self.payload],
        }