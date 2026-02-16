# TaxStreem Python SDK

A Python SDK for interacting with the TaxStreem API.

## Installation

```bash
pip install taxstreem-python
```

## Usage

```python
from taxstreem import TaxStreem

# Initialize the client
client = TaxStreem(secret_key="your_secret_key")

# Use the API
result = client.flux.vat_filing.batch({
    "data": [
        {
            "invoice_number": "INV-001",
            "amount": 100.0,
            "vat_amount": 10.0,
            "date": "2023-01-01"
        }
    ]
})

print(result)
```
def submit_vat_single(
    items: List[Dict]
) -> Dict:
    """
    Encrypt each item and submit the batch to TaxStreem Flux VAT API.
    """
    aes_key = derive_key(API_SECRET_KEY)

    encrypted_payloads = []

    # Encrypt each item
    enc = encrypt_payload({"email":"","password":""}, aes_key)

    # Build request body
    body = {
        "data": items,
        "encryptedPayload": enc,
    }

    headers = {
        "Content-Type": "application/json",
        "x-api-key": API_KEY,  # or appropriate signature header
    }

    response = requests.post(API_BASE_URL, json=body, headers=headers)
    print(response.json())
    response.raise_for_status()

    return response.json()
