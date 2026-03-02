"""
TaxStreem Runtime — core HTTP layer with retry logic.
Mirrors the TaxStreemRuntime class from the Node.js SDK.
"""
from __future__ import annotations

import json
import logging
import random
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import requests
from requests import Response

logger = logging.getLogger(__name__)

NON_RETRYABLE_STATUSES = {400, 401, 403, 404, 422}


@dataclass
class TaxStreemConfig:
    api_key: str
    shared_secret: str
    debug: bool = False
    base_url: str = "https://api.taxstreem.com/v1"
    max_retries: int = 3
    base_delay: float = 1.0      # seconds
    max_delay: float = 10.0      # seconds


class TaxStreemError(Exception):
    """Raised when the TaxStreem API returns an error response."""

    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


class TaxStreemRuntime:
    """
    Low-level HTTP client for the TaxStreem API.

    Handles:
    - Authentication header injection (x-api-key)
    - JSON serialisation / deserialisation
    - Exponential back-off with jitter (non-retryable 4xx errors are raised
      immediately, matching the Node SDK behaviour)
    - Debug logging
    """

    def __init__(self, config: TaxStreemConfig) -> None:
        self._config = config
        self._session = requests.Session()
        self._session.headers.update(
            {
                "x-api-key": config.api_key,
                "Content-Type": "application/json",
                "User-Agent": "TaxStreem-Python-SDK/1.0.0",
            }
        )

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    @property
    def debug(self) -> bool:
        return self._config.debug

    # ------------------------------------------------------------------
    # Core request method
    # ------------------------------------------------------------------

    def request(self, method: str, path: str, body: Any = None) -> Any:
        """
        Perform an HTTP request against the TaxStreem API.

        Args:
            method: HTTP verb (``"POST"``, ``"GET"``, …).
            path:   URL path relative to ``base_url`` (e.g. ``"/flux/vat-filing/single"``).
            body:   Optional JSON-serialisable payload.

        Returns:
            Parsed JSON response (``dict`` or ``list``).

        Raises:
            TaxStreemError: On non-retryable API errors or exhausted retries.
        """
        url = f"{self._config.base_url}{path}"
        payload: Optional[str] = json.dumps(body) if body is not None else None
        last_error: Optional[Exception] = None

        for attempt in range(self._config.max_retries + 1):
            if self.debug:
                logger.debug(
                    "HTTP Request (Attempt %d/%d): %s %s",
                    attempt + 1,
                    self._config.max_retries + 1,
                    method,
                    url,
                )
                if body is not None and attempt == 0:
                    logger.debug("[TaxStreem] Body: %s", json.dumps(body, indent=2))

            try:
                response: Response = self._session.request(
                    method,
                    url,
                    data=payload,
                )

                if response.status_code in (200, 202):
                    data = response.json()
                    if self.debug:
                        logger.debug(
                            "[TaxStreem] Response: %s", json.dumps(data, indent=2)
                        )
                    return data

                # --- Error path ---
                try:
                    error_data = response.json()
                    error_message = error_data.get(
                        "message",
                        f"TaxStreem Error: {response.reason}",
                    )
                except Exception:
                    error_message = f"TaxStreem Error: {response.reason}"

                if self.debug:
                    logger.error(
                        "[TaxStreem] ERROR (Attempt %d) — %d: %s",
                        attempt + 1,
                        response.status_code,
                        error_message,
                    )

                if (
                    response.status_code in NON_RETRYABLE_STATUSES
                    or attempt == self._config.max_retries
                ):
                    raise TaxStreemError(error_message, status_code=response.status_code)

                last_error = TaxStreemError(error_message, status_code=response.status_code)

            except TaxStreemError:
                raise
            except Exception as exc:  # network-level errors
                last_error = exc
                if attempt == self._config.max_retries:
                    break

            # Exponential back-off with jitter
            delay = min(
                self._config.max_delay,
                self._config.base_delay * (2 ** attempt),
            )
            jitter = random.uniform(0, 0.2)  # up to 200 ms jitter
            sleep_for = delay + jitter

            if self.debug:
                logger.debug("[TaxStreem] Retrying in %.3fs…", sleep_for)

            time.sleep(sleep_for)

        raise last_error or TaxStreemError("Request failed after retries")
