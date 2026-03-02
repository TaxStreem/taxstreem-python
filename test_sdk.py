"""
Test suite for the TaxStreem Python SDK.
"""
from __future__ import annotations

import base64
import json
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, "/home/claude/taxstreem-python")

from taxstreem import (
    TaxStreem,
    VatFilingItem,
    VatFilingPayload,
    VatFilingBatchPayload,
    WhtFilingItem,
    WhtFilingPayload,
    WhtFilingBatchPayload,
    FilingResponse,
    BatchFilingResponse,
)
from taxstreem.runtime import TaxStreemConfig, TaxStreemRuntime, TaxStreemError
from taxstreem.services.encryption import EncryptionService
from taxstreem.services.flux import FluxResource


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_sdk(debug=False):
    return TaxStreem(api_key="test-api-key", shared_secret="test-shared-secret", debug=debug)


def _vat_item():
    return VatFilingItem(
        vatStatus=1, amount=5000.0, item="Test item",
        narration="Test narration", taxId="1234567-0001", beneficiary="Test Customer",
    )


def _wht_item():
    return WhtFilingItem(
        beneficiaryName="Acme Ltd", beneficiaryTin="1234567890",
        transactionDate="2024-01-15", transactionDesc="Consulting fees",
        transactionAmount=100_000.0, rate=10.0, taxAmount=10_000.0,
        scheduleReference="SCH-001",
    )


# ---------------------------------------------------------------------------
# Structure tests
# ---------------------------------------------------------------------------

class TestClientStructure(unittest.TestCase):
    def setUp(self):
        self.sdk = _make_sdk()

    def test_has_flux(self):
        self.assertIsInstance(self.sdk.flux, FluxResource)

    def test_has_encryption(self):
        self.assertIsInstance(self.sdk.encryption, EncryptionService)

    def test_flux_has_vat_methods(self):
        self.assertTrue(callable(self.sdk.flux.file_vat_single))
        self.assertTrue(callable(self.sdk.flux.file_vat_batch))

    def test_flux_has_wht_methods(self):
        self.assertTrue(callable(self.sdk.flux.file_wht_single))
        self.assertTrue(callable(self.sdk.flux.file_wht_batch))


# ---------------------------------------------------------------------------
# Runtime / HTTP layer tests
# ---------------------------------------------------------------------------

class TestRuntime(unittest.TestCase):
    def _make_runtime(self, **kwargs):
        config = TaxStreemConfig(api_key="key", shared_secret="secret", **kwargs)
        return TaxStreemRuntime(config)

    def _mock_response(self, status_code, json_data):
        resp = MagicMock()
        resp.status_code = status_code
        resp.json.return_value = json_data
        resp.reason = "OK" if status_code < 400 else "Error"
        return resp

    def test_successful_200(self):
        runtime = self._make_runtime()
        with patch.object(runtime._session, "request") as mock_req:
            mock_req.return_value = self._mock_response(200, {"status": "ok"})
            result = runtime.request("POST", "/test", {"foo": "bar"})
        self.assertEqual(result, {"status": "ok"})

    def test_successful_202(self):
        runtime = self._make_runtime()
        with patch.object(runtime._session, "request") as mock_req:
            mock_req.return_value = self._mock_response(202, {"status": "accepted"})
            result = runtime.request("POST", "/test", {})
        self.assertEqual(result["status"], "accepted")

    def test_400_raises_immediately(self):
        runtime = self._make_runtime(max_retries=3)
        with patch.object(runtime._session, "request") as mock_req:
            mock_req.return_value = self._mock_response(400, {"message": "Bad Request"})
            with self.assertRaises(TaxStreemError) as ctx:
                runtime.request("POST", "/test")
        self.assertEqual(ctx.exception.status_code, 400)
        mock_req.assert_called_once()  # no retries

    def test_401_raises_immediately(self):
        runtime = self._make_runtime(max_retries=3)
        with patch.object(runtime._session, "request") as mock_req:
            mock_req.return_value = self._mock_response(401, {"message": "Unauthorized"})
            with self.assertRaises(TaxStreemError):
                runtime.request("POST", "/test")
        mock_req.assert_called_once()

    def test_404_raises_immediately(self):
        runtime = self._make_runtime(max_retries=3)
        with patch.object(runtime._session, "request") as mock_req:
            mock_req.return_value = self._mock_response(404, {"message": "Not Found"})
            with self.assertRaises(TaxStreemError):
                runtime.request("POST", "/test")
        mock_req.assert_called_once()

    def test_422_raises_immediately(self):
        runtime = self._make_runtime(max_retries=3)
        with patch.object(runtime._session, "request") as mock_req:
            mock_req.return_value = self._mock_response(422, {"message": "Unprocessable"})
            with self.assertRaises(TaxStreemError):
                runtime.request("POST", "/test")
        mock_req.assert_called_once()

    def test_500_retries_and_succeeds(self):
        runtime = self._make_runtime(max_retries=2, base_delay=0.0)
        with patch.object(runtime._session, "request") as mock_req, patch("time.sleep"):
            mock_req.side_effect = [
                self._mock_response(500, {"message": "Server Error"}),
                self._mock_response(500, {"message": "Server Error"}),
                self._mock_response(200, {"status": "ok", "reference_id": "REF-001"}),
            ]
            result = runtime.request("POST", "/test")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(mock_req.call_count, 3)

    def test_exhausted_retries_raises(self):
        runtime = self._make_runtime(max_retries=2, base_delay=0.0)
        with patch.object(runtime._session, "request") as mock_req, patch("time.sleep"):
            mock_req.return_value = self._mock_response(503, {"message": "Unavailable"})
            with self.assertRaises(TaxStreemError):
                runtime.request("POST", "/test")
        self.assertEqual(mock_req.call_count, 3)  # initial + 2 retries

    def test_network_error_retries(self):
        runtime = self._make_runtime(max_retries=1, base_delay=0.0)
        with patch.object(runtime._session, "request") as mock_req, patch("time.sleep"):
            mock_req.side_effect = [
                ConnectionError("Network failure"),
                self._mock_response(200, {"status": "ok"}),
            ]
            result = runtime.request("POST", "/test")
        self.assertEqual(result["status"], "ok")

    def test_api_key_header_sent(self):
        runtime = self._make_runtime()
        self.assertEqual(runtime._session.headers["x-api-key"], "key")

    def test_user_agent_header(self):
        runtime = self._make_runtime()
        self.assertIn("TaxStreem-Python-SDK", runtime._session.headers["User-Agent"])


# ---------------------------------------------------------------------------
# Encryption tests
# ---------------------------------------------------------------------------

class TestEncryptionService(unittest.TestCase):
    def setUp(self):
        self.svc = EncryptionService("test-shared-secret")
        self.cred = {"email": "user@example.com", "password": "s3cr3t"}

    def test_returns_base64_string(self):
        result = self.svc.encrypt_tax_pro_max_credential(self.cred)
        decoded = base64.b64decode(result)
        self.assertIsInstance(decoded, bytes)

    def test_minimum_length(self):
        result = self.svc.encrypt_tax_pro_max_credential(self.cred)
        decoded = base64.b64decode(result)
        # IV(12) + min ciphertext + tag(16) >= 29 bytes
        self.assertGreaterEqual(len(decoded), 29)

    def test_different_calls_produce_different_ciphertext(self):
        r1 = self.svc.encrypt_tax_pro_max_credential(self.cred)
        r2 = self.svc.encrypt_tax_pro_max_credential(self.cred)
        self.assertNotEqual(r1, r2)

    def test_decryptable_with_correct_key(self):
        import hashlib
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        secret = "test-shared-secret"
        svc = EncryptionService(secret)
        cred = {"email": "a@b.com", "password": "pw"}
        encrypted_b64 = svc.encrypt_tax_pro_max_credential(cred)
        raw = base64.b64decode(encrypted_b64)

        iv = raw[:12]
        ciphertext_with_tag = raw[12:]
        key = hashlib.sha256(secret.encode()).digest()
        aad = secret.encode("utf-8")

        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(iv, ciphertext_with_tag, aad)
        self.assertEqual(json.loads(plaintext), cred)

    def test_wrong_secret_cannot_decrypt(self):
        import hashlib
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        svc = EncryptionService("correct-secret")
        encrypted_b64 = svc.encrypt_tax_pro_max_credential({"foo": "bar"})
        raw = base64.b64decode(encrypted_b64)

        wrong_key = hashlib.sha256(b"wrong-secret").digest()
        aesgcm = AESGCM(wrong_key)
        with self.assertRaises(Exception):
            aesgcm.decrypt(raw[:12], raw[12:], b"wrong-secret")


# ---------------------------------------------------------------------------
# FluxResource - VAT tests
# ---------------------------------------------------------------------------

class TestFluxVat(unittest.TestCase):
    def setUp(self):
        self.sdk = _make_sdk()
        self.sdk.flux._runtime.request = MagicMock()

    def _set_response(self, data):
        self.sdk.flux._runtime.request.return_value = data

    def test_file_vat_single_calls_correct_endpoint(self):
        self._set_response({"status": "success", "reference_id": "REF-001", "message": "Filed"})
        payload = VatFilingPayload(encryptedPayload="enc", month=1, year=2024, data=[_vat_item()])
        self.sdk.flux.file_vat_single(payload)
        args = self.sdk.flux._runtime.request.call_args[0]
        self.assertEqual(args[0], "POST")
        self.assertEqual(args[1], "/flux/vat-filing/single")

    def test_file_vat_single_returns_filing_response(self):
        self._set_response({"status": "success", "reference_id": "REF-001", "message": "Filed"})
        payload = VatFilingPayload(encryptedPayload="enc", month=3, year=2024, data=[_vat_item()])
        result = self.sdk.flux.file_vat_single(payload)
        self.assertIsInstance(result, FilingResponse)
        self.assertEqual(result.reference_id, "REF-001")
        self.assertEqual(result.status, "success")

    def test_file_vat_batch_calls_correct_endpoint(self):
        self._set_response({"status": "success", "batchId": "BATCH-001", "message": "Queued"})
        single = VatFilingPayload(encryptedPayload="enc", month=1, year=2024, data=[_vat_item()])
        batch = VatFilingBatchPayload(batchId="BATCH-001", payload=[single])
        self.sdk.flux.file_vat_batch(batch)
        args = self.sdk.flux._runtime.request.call_args[0]
        self.assertEqual(args[1], "/flux/vat-filing/batch")

    def test_file_vat_batch_returns_batch_response(self):
        self._set_response({"status": "success", "batchId": "BATCH-001", "message": "Queued"})
        single = VatFilingPayload(encryptedPayload="enc", month=1, year=2024, data=[_vat_item()])
        batch = VatFilingBatchPayload(batchId="BATCH-001", payload=[single])
        result = self.sdk.flux.file_vat_batch(batch)
        self.assertIsInstance(result, BatchFilingResponse)
        self.assertEqual(result.batch_id, "BATCH-001")

    def test_vat_payload_serialised_with_camel_case(self):
        self._set_response({"status": "success", "reference_id": "REF-001", "message": "Filed"})
        payload = VatFilingPayload(encryptedPayload="enc", month=1, year=2024, data=[_vat_item()])
        self.sdk.flux.file_vat_single(payload)
        _, _, sent_body = self.sdk.flux._runtime.request.call_args[0]
        self.assertIn("encryptedPayload", sent_body)
        self.assertIn("vatStatus", sent_body["data"][0])
        self.assertIn("taxId", sent_body["data"][0])


# ---------------------------------------------------------------------------
# FluxResource - WHT tests
# ---------------------------------------------------------------------------

class TestFluxWht(unittest.TestCase):
    def setUp(self):
        self.sdk = _make_sdk()
        self.sdk.flux._runtime.request = MagicMock()

    def _set_response(self, data):
        self.sdk.flux._runtime.request.return_value = data

    def test_file_wht_single_calls_correct_endpoint(self):
        self._set_response({"status": "success", "reference_id": "REF-002", "message": "Filed"})
        payload = WhtFilingPayload(encryptedPayload="enc", month=2, year=2024, data=[_wht_item()])
        self.sdk.flux.file_wht_single(payload)
        args = self.sdk.flux._runtime.request.call_args[0]
        self.assertEqual(args[1], "/flux/wht-filing/single")

    def test_file_wht_batch_calls_correct_endpoint(self):
        self._set_response({"status": "success", "batchId": "BATCH-002", "message": "Queued"})
        single = WhtFilingPayload(encryptedPayload="enc", month=2, year=2024, data=[_wht_item()])
        batch = WhtFilingBatchPayload(batchId="BATCH-002", payload=[single])
        self.sdk.flux.file_wht_batch(batch)
        args = self.sdk.flux._runtime.request.call_args[0]
        self.assertEqual(args[1], "/flux/wht-filing/batch")

    def test_wht_payload_serialised_with_camel_case(self):
        self._set_response({"status": "success", "reference_id": "REF-002", "message": "Filed"})
        payload = WhtFilingPayload(encryptedPayload="enc", month=2, year=2024, data=[_wht_item()])
        self.sdk.flux.file_wht_single(payload)
        _, _, sent_body = self.sdk.flux._runtime.request.call_args[0]
        self.assertIn("encryptedPayload", sent_body)
        item = sent_body["data"][0]
        self.assertIn("beneficiaryName", item)
        self.assertIn("beneficiaryTin", item)
        self.assertIn("transactionDate", item)
        self.assertIn("scheduleReference", item)


# ---------------------------------------------------------------------------
# Model validation tests
# ---------------------------------------------------------------------------

class TestModelValidation(unittest.TestCase):

    def test_vat_payload_month_too_low(self):
        with self.assertRaises(ValueError):
            VatFilingPayload(encryptedPayload="x", month=0, year=2024, data=[])

    def test_vat_payload_month_too_high(self):
        with self.assertRaises(ValueError):
            VatFilingPayload(encryptedPayload="x", month=13, year=2024, data=[])

    def test_vat_payload_year_too_old(self):
        with self.assertRaises(ValueError):
            VatFilingPayload(encryptedPayload="x", month=1, year=1999, data=[])

    def test_wht_payload_month_bounds(self):
        with self.assertRaises(ValueError):
            WhtFilingPayload(encryptedPayload="x", month=0, year=2024, data=[])


# ---------------------------------------------------------------------------
# Integration-style: encrypt then file
# ---------------------------------------------------------------------------

class TestEncryptAndFile(unittest.TestCase):
    def test_full_vat_single_workflow(self):
        sdk = _make_sdk()
        sdk.flux._runtime.request = MagicMock(return_value={
            "status": "success",
            "reference_id": "REF-XYZ",
            "message": "Processing",
        })

        encrypted = sdk.encryption.encrypt_tax_pro_max_credential(
            {"email": "test@example.com", "password": "secure123"}
        )
        self.assertIsInstance(encrypted, str)

        payload = VatFilingPayload(
            encryptedPayload=encrypted, month=6, year=2024, data=[_vat_item()]
        )
        result = sdk.flux.file_vat_single(payload)
        self.assertEqual(result.reference_id, "REF-XYZ")

    def test_full_wht_single_workflow(self):
        sdk = _make_sdk()
        sdk.flux._runtime.request = MagicMock(return_value={
            "status": "success",
            "reference_id": "REF-WHT-001",
            "message": "Processing",
        })

        encrypted = sdk.encryption.encrypt_tax_pro_max_credential(
            {"email": "test@example.com", "password": "secure123"}
        )
        payload = WhtFilingPayload(
            encryptedPayload=encrypted, month=3, year=2024, data=[_wht_item()]
        )
        result = sdk.flux.file_wht_single(payload)
        self.assertEqual(result.reference_id, "REF-WHT-001")


if __name__ == "__main__":
    unittest.main()
