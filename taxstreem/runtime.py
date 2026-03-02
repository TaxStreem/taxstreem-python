"""
TaxStreem Runtime — core HTTP client with exponential back-off + full jitter.
"""
from __future__ import annotations

import json
import logging
import math
import random
import time
from dataclasses import dataclass
from typing import Any, Optional

import requests
from requests import Response, RequestException

logger = logging.getLogger(__name__)

NON_RETRYABLE_STATUSES: frozenset[int] = frozenset({400, 401, 403, 404, 422})


@dataclass
class TaxStreemConfig:
    """Immutable configuration for the TaxStreem HTTP client."""

    api_key: str
    shared_secret: str
    debug: bool = False
    base_url: str = "https://api.taxstreem.com/v1"
    max_retries: int = 3
    base_delay_s: float = 1.0   # initial back-off window, seconds
    max_delay_s: float = 10.0   # upper cap on any single sleep, seconds


class TaxStreemError(Exception):
    """
    Raised whenever the TaxStreem API returns an error response or all
    retry attempts are exhausted.
    """

    def __init__(self, message: str, status_code: Optional[int] = None) -> None:
        super().__init__(message)
        self.status_code = status_code

    def __repr__(self) -> str:
        return f"TaxStreemError(status_code={self.status_code!r}, message={str(self)!r})"


def _full_jitter_sleep(attempt: int, base_delay_s: float, max_delay_s: float) -> None:
    """
    Sleep for a random duration drawn uniformly from [0, cap] where
    cap = min(max_delay_s, base_delay_s * 2^attempt).

    This is "Full Jitter" as described in the AWS Architecture Blog post
    "Exponential Backoff And Jitter". It:
      - Prevents thundering-herd by spreading retries evenly across the window.
      - Still honours the exponential growth in the *maximum* possible delay.
      - Is on average cheaper than additive jitter (old impl added 200 ms on
        top of the full delay, giving ~10.1 s at cap; this averages cap/2).
    """
    cap = min(max_delay_s, base_delay_s * math.pow(2, attempt))
    sleep_for = random.uniform(0, cap)
    logger.debug(
        "[TaxStreem] Retry attempt %d — sleeping %.3fs (cap=%.1fs)",
        attempt + 1, sleep_for, cap,
    )
    time.sleep(sleep_for)


class TaxStreemRuntime:
    """
    Low-level HTTP client for the TaxStreem API.

    Responsibilities:
    - Injects x-api-key and standard headers on every request.
    - Deserialises JSON responses.
    - Retries transient errors (5xx, network faults) with full-jitter
      exponential back-off.
    - Raises TaxStreemError immediately on non-retryable 4xx responses.
    """

    def __init__(self, config: TaxStreemConfig) -> None:
        self._config = config
        self._session = requests.Session()
        self._session.headers.update({
            "x-api-key": config.api_key,
            "Content-Type": "application/json",
            "User-Agent": "TaxStreem-Python-SDK/1.0.0",
        })

    @property
    def debug(self) -> bool:
        return self._config.debug

    def request(self, method: str, path: str, body: Any = None) -> Any:
        """
        Execute an HTTP request with automatic retry on transient failures.

        Args:
            method: HTTP verb (e.g. "POST").
            path:   Path relative to base_url (e.g. "/flux/vat-filing/single").
            body:   JSON-serialisable request payload, or None.

        Returns:
            Parsed JSON response body.

        Raises:
            TaxStreemError: On non-retryable API errors or exhausted retries.
        """
        url = f"{self._config.base_url}{path}"
        serialised_body: Optional[str] = json.dumps(body) if body is not None else None
        last_exc: Optional[TaxStreemError] = None

        for attempt in range(self._config.max_retries + 1):
            self._log_request(attempt, method, url, body)

            try:
                response = self._session.request(method, url, data=serialised_body)
                return self._handle_response(response, attempt)

            except TaxStreemError as exc:
                # Non-retryable 4xx or final attempt — let it propagate.
                if exc.status_code in NON_RETRYABLE_STATUSES or attempt == self._config.max_retries:
                    raise
                last_exc = exc

            except RequestException as exc:
                # Network-level failure (timeout, connection reset, DNS, etc.)
                if attempt == self._config.max_retries:
                    raise TaxStreemError(f"Network error: {exc}") from exc
                last_exc = TaxStreemError(f"Network error: {exc}")
                logger.debug("[TaxStreem] Network error on attempt %d: %s", attempt + 1, exc)

            _full_jitter_sleep(attempt, self._config.base_delay_s, self._config.max_delay_s)

        raise last_exc or TaxStreemError("Request failed after all retries")

    def _handle_response(self, response: Response, attempt: int) -> Any:
        """Return parsed JSON on 200/202; raise TaxStreemError otherwise."""
        if response.status_code in (200, 202):
            data = response.json()
            if self.debug:
                logger.debug("[TaxStreem] Response: %s", json.dumps(data, indent=2))
            return data

        try:
            error_body = response.json()
            message = error_body.get("message") or f"TaxStreem Error: {response.reason}"
        except ValueError:
            message = f"TaxStreem Error: {response.reason}"

        if self.debug:
            logger.error(
                "[TaxStreem] Error (attempt %d) — HTTP %d: %s",
                attempt + 1, response.status_code, message,
            )

        raise TaxStreemError(message, status_code=response.status_code)

    def _log_request(self, attempt: int, method: str, url: str, body: Any) -> None:
        if not self.debug:
            return
        logger.debug(
            "HTTP Request (attempt %d/%d): %s %s",
            attempt + 1, self._config.max_retries + 1, method, url,
        )
        if body is not None and attempt == 0:
            logger.debug("[TaxStreem] Body: %s", json.dumps(body, indent=2))