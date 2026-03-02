"""
TaxStreem Python SDK.

Usage::

    from taxstreem import TaxStreem, VatFilingPayload, VatFilingItem

    sdk = TaxStreem(
        api_key="your-api-key",
        shared_secret="your-shared-secret",
    )

    encrypted = sdk.encryption.encrypt_tax_pro_max_credential(
        {"email": "user@example.com", "password": "s3cr3t"}
    )

    result = sdk.flux.file_vat_single(
        VatFilingPayload(
            encrypted_payload=encrypted,
            month=1,
            year=2024,
            data=[
                VatFilingItem(
                    vat_status=1,
                    amount=5000,
                    item="Baby diapers",
                    narration="Bought kisskid diaper",
                    tax_id="2345544-0001",
                    beneficiary="Retail Customer",
                )
            ],
        )
    )
    print(result.reference_id)
"""
from __future__ import annotations

from taxstreem.runtime import TaxStreemConfig, TaxStreemRuntime, TaxStreemError
from taxstreem.services.encryption import EncryptionService
from taxstreem.services.flux import FluxResource
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
    "TaxStreemError",
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
        api_key:        Your TaxStreem API key (sent as ``x-api-key`` header).
        shared_secret:  Your TaxStreem shared secret — used for AES-256-GCM
                        payload encryption and request signing.
        debug:          When ``True``, HTTP requests/responses are logged at
                        ``DEBUG`` level via the ``taxstreem`` logger.
        base_url:       Override the API base URL.
        max_retries:    Max retry attempts on transient (5xx / network) errors.
                        Non-retryable 4xx errors always raise immediately.
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