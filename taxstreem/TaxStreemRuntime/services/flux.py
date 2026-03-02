"""
FluxResource — mirrors src/services/flux.ts from the Node SDK.
"""
from __future__ import annotations

import logging

from taxstreem.interfaces.vat import (
    BatchFilingResponse,
    FilingResponse,
    VatFilingBatchPayload,
    VatFilingPayload,
)
from taxstreem.interfaces.wht import WhtFilingBatchPayload, WhtFilingPayload
from taxstreem.runtime import TaxStreemRuntime

logger = logging.getLogger(__name__)


class FluxResource:
    """Exposes all Flux API endpoints for VAT and WHT filing."""

    def __init__(self, runtime: TaxStreemRuntime) -> None:
        self._runtime = runtime

    # ------------------------------------------------------------------
    # VAT
    # ------------------------------------------------------------------

    def file_vat_single(self, payload: VatFilingPayload) -> FilingResponse:
        """Submit a single VAT filing."""
        if self._runtime.debug:
            logger.debug('{"event": "Sending out request, plan: FLUX", "type": "VAT-Single"}')
        raw = self._runtime.request("POST", "/flux/vat-filing/single", payload.as_dict())
        return FilingResponse.from_dict(raw)

    def file_vat_batch(self, payload: VatFilingBatchPayload) -> BatchFilingResponse:
        """Submit a batch of VAT filings."""
        if self._runtime.debug:
            logger.debug('{"event": "Sending out request, plan: FLUX", "type": "VAT-Batch"}')
        raw = self._runtime.request("POST", "/flux/vat-filing/batch", payload.as_dict())
        return BatchFilingResponse.from_dict(raw)

    # ------------------------------------------------------------------
    # WHT
    # ------------------------------------------------------------------

    def file_wht_single(self, payload: WhtFilingPayload) -> FilingResponse:
        """Submit a single WHT filing."""
        if self._runtime.debug:
            logger.debug('{"event": "Sending out request, plan: FLUX", "type": "WHT-Single"}')
        raw = self._runtime.request("POST", "/flux/wht-filing/single", payload.as_dict())
        return FilingResponse.from_dict(raw)

    def file_wht_batch(self, payload: WhtFilingBatchPayload) -> BatchFilingResponse:
        """Submit a batch of WHT filings."""
        if self._runtime.debug:
            logger.debug('{"event": "Sending out request, plan: FLUX", "type": "WHT-Batch"}')
        raw = self._runtime.request("POST", "/flux/wht-filing/batch", payload.as_dict())
        return BatchFilingResponse.from_dict(raw)