"""Tests for the model client layer (agent-spec.md section 6)."""

from __future__ import annotations

import json

import httpx
import pytest
import respx
from src.model_client import (
    GENERATE_OPTIONS,
    MODEL_ENV_VAR,
    ModelUnavailable,
    OllamaClient,
    PlaybookClient,
    select_client,
)

BASE_URL = "http://localhost:11434"


@pytest.mark.asyncio
async def test_select_client_returns_ollama_when_tags_up() -> None:
    """A reachable /api/tags probe selects the Ollama backend."""
    with respx.mock(base_url=BASE_URL) as router:
        router.get("/api/tags").mock(
            return_value=httpx.Response(200, json={"models": []})
        )
        client = await select_client(ollama_url=BASE_URL)
    assert isinstance(client, OllamaClient)
    assert client.name == "ollama/llama3.1:8b"


@pytest.mark.asyncio
async def test_select_client_falls_back_to_playbook_when_down() -> None:
    """A transport failure on /api/tags selects the playbook fallback."""
    with respx.mock(base_url=BASE_URL) as router:
        router.get("/api/tags").mock(side_effect=httpx.ConnectError("refused"))
        client = await select_client(ollama_url=BASE_URL)
    assert isinstance(client, PlaybookClient)
    assert client.name == "playbook"


@pytest.mark.asyncio
async def test_select_client_env_override_forces_playbook(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SENTINEL_AGENT_MODEL=playbook wins even when Ollama is reachable."""
    monkeypatch.setenv(MODEL_ENV_VAR, "playbook")
    with respx.mock(base_url=BASE_URL, assert_all_called=False) as router:
        route = router.get("/api/tags").mock(
            return_value=httpx.Response(200, json={"models": []})
        )
        client = await select_client(ollama_url=BASE_URL)
    assert isinstance(client, PlaybookClient)
    assert not route.called  # no probe at all under the override


@pytest.mark.asyncio
async def test_ollama_complete_posts_pinned_options() -> None:
    """complete() POSTs the spec-pinned generation options and prompt."""
    with respx.mock(base_url=BASE_URL) as router:
        route = router.post("/api/generate").mock(
            return_value=httpx.Response(200, json={"response": "the-answer"})
        )
        client = OllamaClient(ollama_url=BASE_URL)
        text = await client.complete("SYS", "USER")
    assert text == "the-answer"
    request = route.calls.last.request
    body = json.loads(request.content)
    assert body["model"] == "llama3.1:8b"
    assert body["prompt"] == "SYS\n\nUSER"
    assert body["stream"] is False
    assert body["options"] == GENERATE_OPTIONS
    assert body["options"]["seed"] == 42
    assert body["options"]["temperature"] == 0.1
    assert body["options"]["top_p"] == 0.9
    assert body["options"]["top_k"] == 40
    assert body["options"]["num_ctx"] == 8192
    assert body["options"]["num_predict"] == 1024


@pytest.mark.asyncio
async def test_ollama_complete_raises_model_unavailable_on_http_error() -> None:
    """Transport/HTTP errors surface as ModelUnavailable."""
    with respx.mock(base_url=BASE_URL) as router:
        router.post("/api/generate").mock(
            return_value=httpx.Response(500, json={"error": "boom"})
        )
        client = OllamaClient(ollama_url=BASE_URL)
        with pytest.raises(ModelUnavailable):
            await client.complete("SYS", "USER")


@pytest.mark.asyncio
async def test_playbook_client_complete_raises() -> None:
    """PlaybookClient.complete always signals playbook mode."""
    with pytest.raises(ModelUnavailable, match="playbook mode"):
        await PlaybookClient().complete("SYS", "USER")
