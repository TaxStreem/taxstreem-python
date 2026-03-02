"""
Test suite for the TaxStreem Python SDK.
"""
from __future__ import annotations

import base64
import json
import math
import sys
import time
import unittest
from unittest.mock import MagicMock, call, patch

from taxstreem import (
    TaxStreem,
    TaxStreemError,
    VatFilingItem,
    VatFilingPayload,
    VatFilingBatchPayload,
    WhtFilingItem,
    WhtFilingPayload,
    WhtFilingBatchPayload,
    FilingResponse,
    BatchFilingResponse,
)
from taxstreem.runtime import TaxStreemConfig, TaxStreemRuntime, _full_jitter_sleep
from taxstreem.services.encryption import EncryptionService
from taxstreem.services.flux import FluxResource


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_sdk(debug=False) -> TaxStreem:
    return TaxStreem(api_key="test-api-key", shared_secret="test-shared-secret", debug=debug)


def _vat_item() -> VatFilingItem:
    return VatFilingItem(
        vat_status=1,
        amount=5000.0,
        item="Test item",
        narration="Test narration",
        tax_id="1234567-0001",
        beneficiary="Test Customer",
    )


def _wht_item() -> WhtFilingItem:
    return WhtFilingItem(
        beneficiary_name="Acme Ltd",
        beneficiary_tin="1234567890",
        transaction_date="2024-01-15",
        transaction_desc="Consulting fees",
        transaction_amount=100_000.0,
        rate=10.0,
        tax_amount=10_000.0,
        schedule_reference="SCH-001",
    )


def _mock_response(status_code: int, json_data: dict) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data
    resp.reason = "OK" if status_code < 400 else "Error"
    return resp


# ---------------------------------------------------------------------------
# 1. Client structure
# ---------------------------------------------------------------------------

class TestClientStructure(unittest.TestCase):
    def setUp(self):
        self.sdk = _make_sdk()

    def test_has_flux_resource(self):
        self.assertIsInstance(self.sdk.flux, FluxResource)

    def test_has_encryption_service(self):
        self.assertIsInstance(self.sdk.encryption, EncryptionService)

    def test_flux_exposes_all_four_methods(self):
        for method in ("file_vat_single", "file_vat_batch", "file_wht_single", "file_wht_batch"):
            self.assertTrue(callable(getattr(self.sdk.flux, method)), f"Missing method: {method}")


# ---------------------------------------------------------------------------
# 2. Retry and back-off — full jitter
# ---------------------------------------------------------------------------

class TestFullJitterSleep(unittest.TestCase):
    """Verify _full_jitter_sleep produces values in the expected range."""

    def _sample(self, attempt: int, base: float, cap: float, n: int = 500) -> list[float]:
        sleeps = []
        with patch("time.sleep") as mock_sleep:
            for _ in range(n):
                _full_jitter_sleep(attempt, base, cap)
                sleeps.append(mock_sleep.call_args[0][0])
        return sleeps

    def test_sleep_within_bounds_attempt_0(self):
        # cap = min(10, 1 * 2^0) = 1 s  →  sleep ∈ [0, 1]
        sleeps = self._sample(attempt=0, base=1.0, cap=10.0)
        self.assertTrue(all(0.0 <= s <= 1.0 for s in sleeps), "Sleep exceeded [0, 1]")

    def test_sleep_within_bounds_attempt_2(self):
        # cap = min(10, 1 * 2^2) = 4 s  →  sleep ∈ [0, 4]
        sleeps = self._sample(attempt=2, base=1.0, cap=10.0)
        self.assertTrue(all(0.0 <= s <= 4.0 for s in sleeps), "Sleep exceeded [0, 4]")

    def test_max_delay_cap_enforced(self):
        # cap = min(5, 1 * 2^10) = 5 s  →  sleep ∈ [0, 5]
        sleeps = self._sample(attempt=10, base=1.0, cap=5.0)
        self.assertTrue(all(s <= 5.0 for s in sleeps), "Sleep exceeded max_delay cap")

    def test_distribution_is_not_constant(self):
        # With 100 samples the chance of all being identical is astronomically small.
        sleeps = self._sample(attempt=2, base=1.0, cap=10.0, n=100)
        self.assertGreater(len(set(round(s, 6) for s in sleeps)), 1)

    def test_average_is_roughly_half_cap(self):
        # Full jitter converges to cap/2 as n → ∞
        sleeps = self._sample(attempt=2, base=1.0, cap=10.0, n=1000)
        avg = sum(sleeps) / len(sleeps)
        # cap = min(10, 4) = 4  →  expected mean ≈ 2.0
        self.assertAlmostEqual(avg, 2.0, delta=0.4)


# ---------------------------------------------------------------------------
# 3. Runtime HTTP behaviour
# ---------------------------------------------------------------------------

class TestRuntime(unittest.TestCase):
    def _make_runtime(self, **kwargs) -> TaxStreemRuntime:
        config = TaxStreemConfig(api_key="key", shared_secret="secret", **kwargs)
        return TaxStreemRuntime(config)

    # Success

    def test_returns_json_on_200(self):
        rt = self._make_runtime()
        with patch.object(rt._session, "request") as mock_req:
            mock_req.return_value = _mock_response(200, {"status": "ok"})
            self.assertEqual(rt.request("POST", "/x"), {"status": "ok"})

    def test_returns_json_on_202(self):
        rt = self._make_runtime()
        with patch.object(rt._session, "request") as mock_req:
            mock_req.return_value = _mock_response(202, {"status": "accepted"})
            self.assertEqual(rt.request("POST", "/x")["status"], "accepted")

    # Non-retryable 4xx — no sleep, single call

    def _assert_no_retry(self, status_code: int) -> None:
        rt = self._make_runtime(max_retries=3)
        with patch.object(rt._session, "request") as mock_req, \
             patch("taxstreem.runtime.time.sleep") as mock_sleep:
            mock_req.return_value = _mock_response(status_code, {"message": f"Error {status_code}"})
            with self.assertRaises(TaxStreemError) as ctx:
                rt.request("POST", "/x")
        self.assertEqual(ctx.exception.status_code, status_code)
        mock_req.assert_called_once()          # no retries
        mock_sleep.assert_not_called()         # no sleep

    def test_400_no_retry(self):
        self._assert_no_retry(400)

    def test_401_no_retry(self):
        self._assert_no_retry(401)

    def test_403_no_retry(self):
        self._assert_no_retry(403)

    def test_404_no_retry(self):
        self._assert_no_retry(404)

    def test_422_no_retry(self):
        self._assert_no_retry(422)

    # Retryable 5xx

    def test_500_retries_and_eventually_succeeds(self):
        rt = self._make_runtime(max_retries=2, base_delay_s=0.0)
        with patch.object(rt._session, "request") as mock_req, \
             patch("taxstreem.runtime.time.sleep"):
            mock_req.side_effect = [
                _mock_response(500, {"message": "Server Error"}),
                _mock_response(500, {"message": "Server Error"}),
                _mock_response(200, {"status": "ok"}),
            ]
            result = rt.request("POST", "/x")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(mock_req.call_count, 3)

    def test_exhausted_retries_raises_taxstreem_error(self):
        rt = self._make_runtime(max_retries=2, base_delay_s=0.0)
        with patch.object(rt._session, "request") as mock_req, \
             patch("taxstreem.runtime.time.sleep"):
            mock_req.return_value = _mock_response(503, {"message": "Unavailable"})
            with self.assertRaises(TaxStreemError):
                rt.request("POST", "/x")
        self.assertEqual(mock_req.call_count, 3)  # 1 initial + 2 retries

    def test_sleep_called_between_retries(self):
        rt = self._make_runtime(max_retries=2, base_delay_s=1.0)
        with patch.object(rt._session, "request") as mock_req, \
             patch("taxstreem.runtime.time.sleep") as mock_sleep:
            mock_req.side_effect = [
                _mock_response(500, {}),
                _mock_response(500, {}),
                _mock_response(200, {"status": "ok"}),
            ]
            rt.request("POST", "/x")
        # Two failures → two sleeps (one after attempt 0, one after attempt 1)
        self.assertEqual(mock_sleep.call_count, 2)

    def test_sleep_duration_respects_jitter_bounds(self):
        """Each sleep value must be in [0, cap] for its attempt."""
        rt = self._make_runtime(max_retries=3, base_delay_s=1.0, max_delay_s=10.0)
        sleep_calls: list[float] = []
        with patch.object(rt._session, "request") as mock_req, \
             patch("taxstreem.runtime.time.sleep", side_effect=lambda d: sleep_calls.append(d)):
            mock_req.side_effect = [
                _mock_response(500, {}),
                _mock_response(500, {}),
                _mock_response(500, {}),
                _mock_response(200, {"status": "ok"}),
            ]
            rt.request("POST", "/x")

        expected_caps = [
            min(10.0, 1.0 * math.pow(2, attempt)) for attempt in range(3)
        ]
        for i, (sleep_val, cap) in enumerate(zip(sleep_calls, expected_caps)):
            self.assertGreaterEqual(sleep_val, 0.0, f"Sleep {i} is negative")
            self.assertLessEqual(sleep_val, cap, f"Sleep {i} exceeded cap {cap}")

    def test_network_error_retries(self):
        from requests import ConnectionError as RConnectionError
        rt = self._make_runtime(max_retries=1, base_delay_s=0.0)
        with patch.object(rt._session, "request") as mock_req, \
             patch("taxstreem.runtime.time.sleep"):
            mock_req.side_effect = [
                RConnectionError("refused"),
                _mock_response(200, {"status": "ok"}),
            ]
            result = rt.request("POST", "/x")
        self.assertEqual(result["status"], "ok")

    def test_network_error_exhausted_raises(self):
        from requests import ConnectionError as RConnectionError
        rt = self._make_runtime(max_retries=1, base_delay_s=0.0)
        with patch.object(rt._session, "request") as mock_req, \
             patch("taxstreem.runtime.time.sleep"):
            mock_req.side_effect = RConnectionError("refused")
            with self.assertRaises(TaxStreemError):
                rt.request("POST", "/x")

    # Headers

    def test_api_key_header_injected(self):
        rt = self._make_runtime()
        self.assertEqual(rt._session.headers["x-api-key"], "key")

    def test_content_type_header_injected(self):
        rt = self._make_runtime()
        self.assertEqual(rt._session.headers["Content-Type"], "application/json")

    def test_user_agent_header(self):
        rt = self._make_runtime()
        self.assertIn("TaxStreem-Python-SDK", rt._session.headers["User-Agent"])


# ---------------------------------------------------------------------------
# 4. Encryption
# ---------------------------------------------------------------------------

class TestEncryptionService(unittest.TestCase):
    def setUp(self):
        self.svc = EncryptionService("test-shared-secret")
        self.cred = {"email": "user@example.com", "password": "s3cr3t"}

    def test_returns_valid_base64(self):
        result = self.svc.encrypt_tax_pro_max_credential(self.cred)
        decoded = base64.b64decode(result)  # raises if invalid
        self.assertIsInstance(decoded, bytes)

    def test_output_has_minimum_length(self):
        # IV(12) + at least 1 byte plaintext + tag(16) = 29 bytes minimum
        raw = base64.b64decode(self.svc.encrypt_tax_pro_max_credential(self.cred))
        self.assertGreaterEqual(len(raw), 29)

    def test_random_iv_means_different_outputs(self):
        r1 = self.svc.encrypt_tax_pro_max_credential(self.cred)
        r2 = self.svc.encrypt_tax_pro_max_credential(self.cred)
        self.assertNotEqual(r1, r2)

    def test_round_trip_decryption(self):
        """Encrypt then decrypt and verify plaintext is identical."""
        import hashlib
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        secret = "round-trip-secret"
        cred = {"email": "a@b.com", "password": "pw123"}
        encrypted_b64 = EncryptionService(secret).encrypt_tax_pro_max_credential(cred)

        raw = base64.b64decode(encrypted_b64)
        iv, ciphertext_with_tag = raw[:12], raw[12:]
        key = hashlib.sha256(secret.encode()).digest()
        aad = secret.encode("utf-8")

        plaintext = AESGCM(key).decrypt(iv, ciphertext_with_tag, aad)
        self.assertEqual(json.loads(plaintext), cred)

    def test_wrong_key_cannot_decrypt(self):
        import hashlib
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        raw = base64.b64decode(
            EncryptionService("correct-secret").encrypt_tax_pro_max_credential({"x": 1})
        )
        wrong_key = hashlib.sha256(b"wrong-secret").digest()
        with self.assertRaises(Exception):
            AESGCM(wrong_key).decrypt(raw[:12], raw[12:], b"wrong-secret")


# ---------------------------------------------------------------------------
# 5. FluxResource — VAT
# ---------------------------------------------------------------------------

class TestFluxVat(unittest.TestCase):
    def setUp(self):
        self.sdk = _make_sdk()
        self.sdk.flux._runtime.request = MagicMock()

    def _stub(self, data: dict) -> None:
        self.sdk.flux._runtime.request.return_value = data

    def _single_payload(self) -> VatFilingPayload:
        return VatFilingPayload(
            encrypted_payload="enc", month=1, year=2024, data=[_vat_item()]
        )

    def test_file_vat_single_posts_to_correct_endpoint(self):
        self._stub({"status": "success", "reference_id": "REF-001", "message": "Filed"})
        self.sdk.flux.file_vat_single(self._single_payload())
        method, path, _ = self.sdk.flux._runtime.request.call_args[0]
        self.assertEqual(method, "POST")
        self.assertEqual(path, "/flux/vat-filing/single")

    def test_file_vat_single_returns_filing_response(self):
        self._stub({"status": "success", "reference_id": "REF-001", "message": "Filed"})
        result = self.sdk.flux.file_vat_single(self._single_payload())
        self.assertIsInstance(result, FilingResponse)
        self.assertEqual(result.reference_id, "REF-001")
        self.assertEqual(result.status, "success")

    def test_file_vat_batch_posts_to_correct_endpoint(self):
        self._stub({"status": "success", "batchId": "BATCH-001", "message": "Queued"})
        batch = VatFilingBatchPayload(batch_id="BATCH-001", payload=[self._single_payload()])
        self.sdk.flux.file_vat_batch(batch)
        _, path, _ = self.sdk.flux._runtime.request.call_args[0]
        self.assertEqual(path, "/flux/vat-filing/batch")

    def test_file_vat_batch_returns_batch_response(self):
        self._stub({"status": "success", "batchId": "BATCH-001", "message": "Queued"})
        batch = VatFilingBatchPayload(batch_id="BATCH-001", payload=[self._single_payload()])
        result = self.sdk.flux.file_vat_batch(batch)
        self.assertIsInstance(result, BatchFilingResponse)
        self.assertEqual(result.batch_id, "BATCH-001")

    def test_serialisation_uses_camel_case_on_the_wire(self):
        """Python snake_case fields must be camelCase in the sent body."""
        self._stub({"status": "success", "reference_id": "REF-001", "message": "Filed"})
        self.sdk.flux.file_vat_single(self._single_payload())
        _, _, body = self.sdk.flux._runtime.request.call_args[0]
        # Top-level
        self.assertIn("encryptedPayload", body)
        self.assertNotIn("encrypted_payload", body)
        # Item level
        item = body["data"][0]
        self.assertIn("vatStatus", item)
        self.assertIn("taxId", item)
        self.assertNotIn("vat_status", item)
        self.assertNotIn("tax_id", item)


# ---------------------------------------------------------------------------
# 6. FluxResource — WHT
# ---------------------------------------------------------------------------

class TestFluxWht(unittest.TestCase):
    def setUp(self):
        self.sdk = _make_sdk()
        self.sdk.flux._runtime.request = MagicMock()

    def _stub(self, data: dict) -> None:
        self.sdk.flux._runtime.request.return_value = data

    def _single_payload(self) -> WhtFilingPayload:
        return WhtFilingPayload(
            encrypted_payload="enc", month=2, year=2024, data=[_wht_item()]
        )

    def test_file_wht_single_posts_to_correct_endpoint(self):
        self._stub({"status": "success", "reference_id": "REF-002", "message": "Filed"})
        self.sdk.flux.file_wht_single(self._single_payload())
        _, path, _ = self.sdk.flux._runtime.request.call_args[0]
        self.assertEqual(path, "/flux/wht-filing/single")

    def test_file_wht_batch_posts_to_correct_endpoint(self):
        self._stub({"status": "success", "batchId": "BATCH-002", "message": "Queued"})
        batch = WhtFilingBatchPayload(batch_id="BATCH-002", payload=[self._single_payload()])
        self.sdk.flux.file_wht_batch(batch)
        _, path, _ = self.sdk.flux._runtime.request.call_args[0]
        self.assertEqual(path, "/flux/wht-filing/batch")

    def test_wht_serialisation_uses_camel_case(self):
        self._stub({"status": "success", "reference_id": "REF-002", "message": "Filed"})
        self.sdk.flux.file_wht_single(self._single_payload())
        _, _, body = self.sdk.flux._runtime.request.call_args[0]
        item = body["data"][0]
        self.assertIn("beneficiaryName", item)
        self.assertIn("beneficiaryTin", item)
        self.assertIn("transactionDate", item)
        self.assertIn("transactionAmount", item)
        self.assertIn("taxAmount", item)
        self.assertIn("scheduleReference", item)
        self.assertNotIn("beneficiary_name", item)
        self.assertNotIn("tax_amount", item)


# ---------------------------------------------------------------------------
# 7. Model validation
# ---------------------------------------------------------------------------

class TestModelValidation(unittest.TestCase):

    def test_vat_payload_month_zero_invalid(self):
        with self.assertRaises(ValueError):
            VatFilingPayload(encrypted_payload="x", month=0, year=2024, data=[])

    def test_vat_payload_month_thirteen_invalid(self):
        with self.assertRaises(ValueError):
            VatFilingPayload(encrypted_payload="x", month=13, year=2024, data=[])

    def test_vat_payload_year_before_2000_invalid(self):
        with self.assertRaises(ValueError):
            VatFilingPayload(encrypted_payload="x", month=1, year=1999, data=[])

    def test_vat_item_negative_amount_invalid(self):
        with self.assertRaises(ValueError):
            VatFilingItem(vat_status=1, amount=-1, item="x", narration="x", tax_id="x", beneficiary="x")

    def test_wht_item_rate_over_100_invalid(self):
        with self.assertRaises(ValueError):
            WhtFilingItem(
                beneficiary_name="X", beneficiary_tin="X",
                transaction_date="2024-01-01", transaction_desc="X",
                transaction_amount=1000, rate=101, tax_amount=100,
                schedule_reference="SCH-001",
            )

    def test_wht_payload_month_bounds(self):
        with self.assertRaises(ValueError):
            WhtFilingPayload(encrypted_payload="x", month=0, year=2024, data=[])


# ---------------------------------------------------------------------------
# 8. End-to-end workflow (encrypt → file)
# ---------------------------------------------------------------------------

class TestEndToEndWorkflow(unittest.TestCase):

    def test_vat_single_full_workflow(self):
        sdk = _make_sdk()
        sdk.flux._runtime.request = MagicMock(return_value={
            "status": "success", "reference_id": "REF-E2E-001", "message": "Processing",
        })
        encrypted = sdk.encryption.encrypt_tax_pro_max_credential(
            {"email": "ops@company.com", "password": "s3cr3t"}
        )
        self.assertIsInstance(encrypted, str)
        result = sdk.flux.file_vat_single(
            VatFilingPayload(encrypted_payload=encrypted, month=6, year=2024, data=[_vat_item()])
        )
        self.assertEqual(result.reference_id, "REF-E2E-001")

    def test_wht_single_full_workflow(self):
        sdk = _make_sdk()
        sdk.flux._runtime.request = MagicMock(return_value={
            "status": "success", "reference_id": "REF-WHT-E2E", "message": "Processing",
        })
        encrypted = sdk.encryption.encrypt_tax_pro_max_credential(
            {"email": "ops@company.com", "password": "s3cr3t"}
        )
        result = sdk.flux.file_wht_single(
            WhtFilingPayload(encrypted_payload=encrypted, month=3, year=2024, data=[_wht_item()])
        )
        self.assertEqual(result.reference_id, "REF-WHT-E2E")


if __name__ == "__main__":
    unittest.main()