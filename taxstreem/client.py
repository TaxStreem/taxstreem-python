import requests
import time
import random
import functools
from typing import Union, List, Dict, Any, Optional
from taxstreem.models.schemas import EmailPasswordModel, RequestBody

# ---------------------
# Retry Decorator
# ---------------------

def retry_with_jitter(max_retries: int = 3, base_delay: float = 1.0, max_delay: float = 10.0):
    """
    Decorator that implements retry logic with exponential backoff and jitter.
    
    Args:
        max_retries (int): Maximum number of retries.
        base_delay (float): Initial delay in seconds.
        max_delay (float): Maximum delay in seconds.
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            retries = 0
            while True:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if retries >= max_retries:
                        raise e
                    
                    # Exponential backoff
                    delay = min(base_delay * (2 ** retries), max_delay)
                    # Add jitter (randomness between 0 and delay)
                    jitter = random.uniform(0, delay)
                    sleep_time = delay + jitter
                    
                    time.sleep(sleep_time)
                    retries += 1
        return wrapper
    return decorator

# ---------------------
# Filing Classes
# ---------------------

class BaseFiling:
    """
    Base class for filing operations.
    """
    def __init__(self, client, endpoint_base: str):
        self.client = client
        self.endpoint_base = endpoint_base

class SingleFiling(BaseFiling):
    """
    Class for handling single filing requests.
    """
    @retry_with_jitter()
    def submit(self, data: Union[Dict[str, Any], RequestBody]) -> Any:
        """
        Submit a single filing.
        
        Args:
            data: The data to submit. Can be a dict or RequestBody model.
        """
        payload = data.dict() if isinstance(data, RequestBody) else data
        # Ensure it's a single object if passed as list? The API might expect dict.
        # But RequestBody union allows list. 
        # For 'Single' endpoint, presumably it expects one object.
        return self.client.request("POST", f"{self.endpoint_base}/single", payload)

class BatchFiling(BaseFiling):
    """
    Class for handling batch filing requests.
    """
    @retry_with_jitter()
    def submit(self, data: Union[List[Dict[str, Any]], RequestBody]) -> Any:
        """
        Submit a batch filing.
        
        Args:
            data: The data to submit. Can be a list of dicts or RequestBody model.
        """
        payload = data.dict() if isinstance(data, RequestBody) else data
        return self.client.request("POST", f"{self.endpoint_base}/batch", payload)

class VatFiling:
    """
    Handler for VAT filings.
    """
    def __init__(self, client):
        self.single = SingleFiling(client, "/v1/flux/vat-filing")
        self.batch = BatchFiling(client, "/v1/flux/vat-filing")

class WhtFiling:
    """
    Handler for WHT filings.
    """
    def __init__(self, client):
        self.single = SingleFiling(client, "/v1/flux/wht-filing")
        self.batch = BatchFiling(client, "/v1/flux/wht-filing")

class Flux:
    """
    Flux API wrapper.
    """
    def __init__(self, client):
        self.vat = VatFiling(client)
        self.wht = WhtFiling(client)

class TaxStreem:
    """
    Main TaxStreem Client.
    """
    def __init__(self, secret_key: str, base_url: str = "http://localhost:4000"):
        self.secret_key = secret_key
        self.base_url = base_url
        self.flux = Flux(self)

    @retry_with_jitter()
    def request(self, method: str, path: str, json_data: Any) -> Any:
        """
        Make an HTTP request to the API.
        
        Args:
            method (str): HTTP method (GET, POST, etc.)
            path (str): Endpoint path.
            json_data (Any): JSON payload.
            
        Returns:
            Any: JSON response.
        """
        url = f"{self.base_url}{path}"
        headers = {
            "Authorization": f"Bearer {self.secret_key}",
            "Content-Type": "application/json"
        }
        # If the user wants to pass encrypted data, they might pass it as json_data directly
        # or we might need to look at if 'data' is already encrypted string?
        # For now, we assume json_data is the payload to send.
        
        response = requests.request(method, url, json=json_data, headers=headers)
        response.raise_for_status()
        return response.json()