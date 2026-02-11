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