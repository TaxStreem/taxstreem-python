"""
TaxStreem Python SDK — top-level client.

Mirrors ``src/index.ts`` from the Node SDK.

Usage::

    from taxstreem import TaxStreem

    sdk = TaxStreem(
        api_key="your-api-key",
        shared_secret="your-shared-secret",
        debug=True,
    )

    # Encrypt credentials
    encrypted = sdk.encryption.encrypt_tax_pro_max_credential(
        {"email": "user@example.com", "password": "s3cr3t"}
    )

    # Submit a VAT filing
    from taxstreem import VatFilingPayload, VatFilingItem

    result = sdk.flux.file_vat_single(
        VatFilingPayload(
            encryptedPayload=encrypted,
            month=1,
            year=2024,
            data=[
                VatFilingItem(
                    vatStatus=1,
                    amount=5000,
                    item="Baby diapers",
                    narration="Bought kisskid diaper",
                    taxId="2345544-0001",
                    beneficiary="Retail Customer",
                )
            ],
        )
    )
    print(result.reference_id)
"""
from __future__ import annotations

from typing import Optional

from taxstreem.runtime import TaxStreemConfig, TaxStreemRuntime
from taxstreem.services.encryption import EncryptionService
from taxstreem.services.flux import FluxResource

# Re-export public interfaces for convenience
from taxstreem.interfaces.vat import (
    VatFilingItem,
    VatFilingPayload,
    VatFilingBatchPayload,
    FilingResponse,
    BatchFilingResponse,
)
from taxstreem.interfaces.wht import (
    WhtFilingItem,
    WhtFilingPayload,
    WhtFilingBatchPayload,
)

__all__ = [
    "TaxStreem",
    "TaxStreemConfig",
    # VAT
    "VatFilingItem",
    "VatFilingPayload",
    "VatFilingBatchPayload",
    "FilingResponse",
    "BatchFilingResponse",
    # WHT
    "WhtFilingItem",
    "WhtFilingPayload",
    "WhtFilingBatchPayload",
]


class TaxStreem:
    """
    Main entry point for the TaxStreem Python SDK.

    Args:
        api_key:       Your TaxStreem API key (sent as ``x-api-key`` header).
        shared_secret: Your TaxStreem shared secret — used for AES-256-GCM
                       payload encryption.
        debug:         When ``True``, HTTP requests/responses are logged at
                       ``DEBUG`` level.  Defaults to ``False``.
        base_url:      Override the API base URL.  Defaults to
                       ``"https://api.taxstreem.com/v1"``.
        max_retries:   Maximum number of retry attempts on transient errors.
                       Defaults to ``3``.
    """

    flux: FluxResource
    encryption: EncryptionService

    def __init__(
        self,
        api_key: str,
        shared_secret: str,
        *,
        debug: bool = False,
        base_url: str = "https://api.taxstreem.com/v1",
        max_retries: int = 3,
    ) -> None:
        config = TaxStreemConfig(
            api_key=api_key,
            shared_secret=shared_secret,
            debug=debug,
            base_url=base_url,
            max_retries=max_retries,
        )
        runtime = TaxStreemRuntime(config)

        self.flux = FluxResource(runtime)
        self.encryption = EncryptionService(shared_secret)
