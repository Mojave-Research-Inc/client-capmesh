"""Local embedding model configuration and integration.

Configures the capability mesh to use a local embedding model
(e.g. sentence-transformers) instead of the deterministic lexical
embedding. Falls back gracefully when the model is not available.
"""

from __future__ import annotations

from typing import Any

# Default local embedding model configuration
DEFAULT_LOCAL_EMBEDDING_CONFIG: dict[str, Any] = {
    "provider": "sentence-transformers",
    "model": "all-MiniLM-L6-v2",
    "dims": 384,
    "batchSize": 32,
    "normalize": True,
    "cacheDir": "~/.cache/huggingface",
    "fallback": "deterministic-lexical-hash",
}

BGE_M3_CONFIG: dict[str, Any] = {
    "provider": "sentence-transformers",
    "model": "BAAI/bge-m3",
    "dims": 1024,
    "batchSize": 16,
    "normalize": True,
    "cacheDir": "~/.cache/huggingface",
    "fallback": "deterministic-lexical-hash",
}

QWEN_EMBEDDING_CONFIG: dict[str, Any] = {
    "provider": "sentence-transformers",
    "model": "Qwen/Qwen3-Embedding-0.6B",
    "dims": 1024,
    "batchSize": 32,
    "normalize": True,
    "cacheDir": "~/.cache/huggingface",
    "fallback": "deterministic-lexical-hash",
}

AVAILABLE_MODELS = {
    "all-MiniLM-L6-v2": DEFAULT_LOCAL_EMBEDDING_CONFIG,
    "bge-m3": BGE_M3_CONFIG,
    "Qwen3-Embedding-0.6B": QWEN_EMBEDDING_CONFIG,
}


def get_embedding_config(model_name: str | None = None) -> dict[str, Any]:
    """Return the embedding configuration for a named model."""
    if model_name and model_name in AVAILABLE_MODELS:
        return AVAILABLE_MODELS[model_name].copy()
    return DEFAULT_LOCAL_EMBEDDING_CONFIG.copy()


def is_model_available(model_name: str) -> bool:
    """Check whether a local embedding model is available."""
    try:
        from sentence_transformers import SentenceTransformer  # noqa: F401
        return True
    except ImportError:
        return False


def embed_text_local(text: str, model_name: str = "all-MiniLM-L6-v2") -> list[float] | None:
    """Embed text using a local sentence-transformers model.

    Returns None if the model is not available (graceful fallback).
    """
    try:
        from sentence_transformers import SentenceTransformer
        model = SentenceTransformer(model_name)
        embedding = model.encode(text, normalize_embeddings=True)
        return embedding.tolist()
    except Exception:
        return None


def build_embedding_config_for_environment() -> dict[str, Any]:
    """Build the appropriate embedding config based on what is available."""
    # Try to find a local model that is available
    for config in AVAILABLE_MODELS.values():
        if is_model_available(config["model"]):
            return config.copy()
    # Fall back to deterministic lexical
    return {
        "provider": "lexical",
        "model": "deterministic-lexical-hash",
        "dims": 256,
        "fallback": "deterministic lexical retrieval",
    }
