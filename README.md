# TaxStreem Python SDK

A lightweight Python client library for the TaxStreem API. Built for clarity and correctness, with zero unnecessary dependencies.

## Features

- **Minimal Dependencies**: Only `requests`, `pydantic`, and `cryptography` — no bloat.
- **Pydantic v2 Models**: Full request/response validation with typed interfaces for VAT and WHT.
- **In-Flight Encryption**: AES-256-GCM encryption for sensitive credentials — matches the Node SDK byte-for-byte.
- **Automatic Retries**: Exponential back-off with jitter on transient errors; non-retryable 4xx errors raised immediately.
- **Debug Mode**: Structured `logging` output for request/response inspection.
- **Python 3.10+**: Uses modern Python features and type hints throughout.

## Requirements

- Python 3.10 or higher
- Node SDK parity: encryption output is interoperable with the Node SDK

## Installation

```bash
pip install taxstreem-python
```

## Quick Start

```python
from taxstreem import TaxStreem

sdk = TaxStreem(
    api_key="your-api-key",
    shared_secret="your-shared-secret",
    debug=True,  # Enables request/response logging
)
```

## Usage

### 1. Encrypt Credentials

TaxStreem uses **In-Flight Encryption** (AES-256-GCM) to protect sensitive credentials (e.g. TaxProMax login details) before they reach the API.

```python
encrypted_payload = sdk.encryption.encrypt_tax_pro_max_credential({
    "email": "user@example.com",
    "password": "secure-password",
})
```

### 2. Submit a VAT Filing (Single)

```python
from taxstreem import VatFilingPayload, VatFilingItem

payload = VatFilingPayload(
    encryptedPayload=encrypted_payload,
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

try:
    result = sdk.flux.file_vat_single(payload)
    print("Filed successfully:", result.reference_id)
except Exception as e:
    print("Filing failed:", e)
```

### 3. Submit a VAT Filing (Batch)

```python
from taxstreem import VatFilingBatchPayload

batch = VatFilingBatchPayload(
    batchId="BATCH-001",
    payload=[payload],  # list of VatFilingPayload
)

result = sdk.flux.file_vat_batch(batch)
print("Batch queued:", result.batch_id)
```

### 4. Submit a WHT Filing

```python
from taxstreem import WhtFilingPayload, WhtFilingItem

wht_payload = WhtFilingPayload(
    encryptedPayload=encrypted_payload,
    month=1,
    year=2024,
    data=[
        WhtFilingItem(
            beneficiaryName="Acme Suppliers Ltd",
            beneficiaryTin="9876543210",
            transactionDate="2024-01-15",
            transactionDesc="Consultancy fees",
            transactionAmount=100_000,
            rate=10.0,
            taxAmount=10_000,
            scheduleReference="SCH-001",
        )
    ],
)

result = sdk.flux.file_wht_single(wht_payload)
print("WHT filed:", result.reference_id)
```

## API Reference

### `TaxStreem(api_key, shared_secret, *, debug, base_url, max_retries)`

| Parameter       | Type    | Default                          | Description                         |
|-----------------|---------|----------------------------------|-------------------------------------|
| `api_key`       | `str`   | —                                | Your TaxStreem API key              |
| `shared_secret` | `str`   | —                                | Your TaxStreem shared secret        |
| `debug`         | `bool`  | `False`                          | Enable request/response logging     |
| `base_url`      | `str`   | `https://api.taxstreem.com/v1`   | Override API base URL               |
| `max_retries`   | `int`   | `3`                              | Max retry attempts on 5xx errors    |

### `sdk.flux`

| Method                        | Payload type            | Returns               |
|-------------------------------|-------------------------|-----------------------|
| `file_vat_single(payload)`    | `VatFilingPayload`      | `FilingResponse`      |
| `file_vat_batch(payload)`     | `VatFilingBatchPayload` | `BatchFilingResponse` |
| `file_wht_single(payload)`    | `WhtFilingPayload`      | `FilingResponse`      |
| `file_wht_batch(payload)`     | `WhtFilingBatchPayload` | `BatchFilingResponse` |

### `sdk.encryption`

| Method                                    | Returns  |
|-------------------------------------------|----------|
| `encrypt_tax_pro_max_credential(tpm_cred)`| `str`    |

## Security Design

Two layers of security, identical to the Node SDK:

1. **API Key Authentication**: Every request includes your `api_key` as the `x-api-key` header.
2. **Payload Encryption (AES-256-GCM)**: Sensitive credential data is encrypted client-side using your `shared_secret`.  
   - Key derivation: `SHA-256(shared_secret)` → 32-byte AES key  
   - 12-byte random IV per call  
   - AAD: `shared_secret` as UTF-8 bytes  
   - Wire format: `Base64(IV[12] || Ciphertext || Tag[16])`

## Retry Behaviour

| HTTP Status    | Behaviour                        |
|----------------|----------------------------------|
| 200, 202       | Success, return parsed JSON      |
| 400, 401, 403, 404, 422 | Raise immediately (no retry) |
| 5xx / network  | Retry with exponential back-off + jitter |

Back-off formula: `min(10s, 1s × 2^attempt) + uniform(0, 0.2s)`

## Running Tests

```bash
pip install taxstreem-python[dev]
pytest tests/ -v
```

## Issues

Please [open an issue](https://github.com/TaxStreem/taxstreem-python/issues) if you find a bug.

## License

MIT License. See [LICENSE](LICENSE) for more information.