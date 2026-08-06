"""ModelClient interface and implementations (agent-spec.md section 6).

The agent loop talks to a pluggable ``ModelClient`` protocol. The default
backend is a local Ollama instance (``/api/generate`` with the pinned
generation options); when no model is reachable the ``PlaybookClient``
placeholder is selected so the caller runs the deterministic playbook
instead. Selection logic is uniform: ``select_client`` always returns a
``ModelClient``, and ``PlaybookClient.complete`` raising ``ModelUnavailable``
is what signals degraded mode.
"""

from __future__ import annotations

import os
from typing import Protocol, runtime_checkable

import httpx

DEFAULT_OLLAMA_URL = "http://localhost:11434"
DEFAULT_MODEL = "llama3.1:8b"
DEFAULT_TIMEOUT_SECONDS = 120.0
PROBE_TIMEOUT_SECONDS = 3.0

# Generation options pinned by agent-spec.md section 6: deterministic seed,
# low temperature — agent output must be reproducible and grounded.
GENERATE_OPTIONS: dict[str, int | float] = {
    "seed": 42,
    "temperature": 0.1,
    "top_p": 0.9,
    "top_k": 40,
    "num_ctx": 8192,
    "num_predict": 1024,
}

# Environment override forcing the deterministic playbook mode.
MODEL_ENV_VAR = "SENTINEL_AGENT_MODEL"


class ModelUnavailable(RuntimeError):
    """Raised when the model backend cannot produce a completion."""


@runtime_checkable
class ModelClient(Protocol):
    """One text completion backend for the agent loop."""

    name: str

    async def complete(self, system: str, user: str) -> str:
        """Return one completion for the given system/user prompt pair."""
        ...


class OllamaClient:
    """Async client for a local Ollama generate endpoint."""

    def __init__(
        self,
        ollama_url: str = DEFAULT_OLLAMA_URL,
        model: str = DEFAULT_MODEL,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        """Create a client for ``{ollama_url}/api/generate``."""
        self.ollama_url = ollama_url.rstrip("/")
        self.model = model
        self.timeout = timeout

    @property
    def name(self) -> str:
        """Backend identifier, e.g. ``ollama/llama3.1:8b``."""
        return f"ollama/{self.model}"

    async def complete(self, system: str, user: str) -> str:
        """POST one generate request and return the ``response`` text.

        Raises ``ModelUnavailable`` on any transport error, timeout, or
        malformed payload so the caller can degrade gracefully.
        """
        payload = {
            "model": self.model,
            "prompt": f"{system}\n\n{user}",
            "stream": False,
            "options": GENERATE_OPTIONS,
        }
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.ollama_url}/api/generate", json=payload
                )
                response.raise_for_status()
                data = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise ModelUnavailable(
                f"ollama /api/generate request failed: {exc}"
            ) from exc
        text = data.get("response")
        if not isinstance(text, str):
            raise ModelUnavailable("ollama returned a non-string 'response' field")
        return text


class PlaybookClient:
    """Placeholder client selecting the deterministic playbook mode.

    Exists so client selection is uniform: the caller always receives a
    ``ModelClient``; ``complete`` raising ``ModelUnavailable`` tells the
    loop it must fall back to ``playbook.investigate_target_playbook``.
    """

    name = "playbook"

    async def complete(self, system: str, user: str) -> str:
        """Always raise — there is no model in playbook mode."""
        raise ModelUnavailable("playbook mode")


async def select_client(
    ollama_url: str = DEFAULT_OLLAMA_URL,
    timeout: float = PROBE_TIMEOUT_SECONDS,
) -> ModelClient:
    """Pick the model backend for this run.

    ``SENTINEL_AGENT_MODEL=playbook`` forces the deterministic playbook.
    Otherwise probe ``{ollama_url}/api/tags`` (3s default): reachable ->
    ``OllamaClient``; any failure -> ``PlaybookClient``.
    """
    if os.environ.get(MODEL_ENV_VAR) == "playbook":
        return PlaybookClient()
    url = ollama_url.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(f"{url}/api/tags")
    except httpx.HTTPError:
        return PlaybookClient()
    if response.status_code == 200:
        return OllamaClient(ollama_url=url)
    return PlaybookClient()
