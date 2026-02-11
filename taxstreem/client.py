import requests

class Flux:
    def __init__(self, client):
        self.vat_filing = VatFiling(client)

class VatFiling:
    def __init__(self, client):
        self.client = client

    def batch(self, data):
        return self.client.request("POST", "/v1/flux/vat-filing/batch", data)

class TaxStreem:
    def __init__(self, secret_key, base_url="http://localhost:4000"):
        self.secret_key = secret_key
        self.base_url = base_url
        self.flux = Flux(self)

    def request(self, method, path, json_data):
        url = f"{self.base_url}{path}"
        headers = {
            "Authorization": f"Bearer {self.secret_key}",
            "Content-Type": "application/json"
        }
        response = requests.request(method, url, json=json_data, headers=headers)
        response.raise_for_status()
        return response.json()