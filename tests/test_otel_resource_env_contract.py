"""Contract tests pinning the OTel Resource env-override precedence.

These tests lock the resolution order implemented in
``capmesh.otel_resource.create_resource``:

    defaults
      < explicit ``service_name`` / ``service_version`` / ``service_namespace``
      < ``extra`` dict
      < env-parsed ``OTEL_RESOURCE_ATTRIBUTES``
      < env ``OTEL_SERVICE_NAME`` (for ``service.name`` only)

They also pin the env parser's whitespace handling, the sorted OTLP
rendering, the ``EMPTY_RESOURCE`` constant, ``Resource.merge`` semantics
(other wins on conflict) and the frozen-dataclass behaviour. Isolation is
achieved with ``mock.patch.dict(os.environ, ...)`` so real ``OTEL_*`` vars
never leak into a test.

The module under test imports only the standard library; these tests mirror
that boundary and do not import any other ``capmesh`` module.
"""

from __future__ import annotations

import os
from unittest import mock

import pytest

from capmesh.otel_resource import (
    DEFAULT_SERVICE_NAME,
    DEFAULT_SERVICE_NAMESPACE,
    DEFAULT_SERVICE_VERSION,
    EMPTY_RESOURCE,
    Resource,
    create_resource,
)

# The two OTel env vars that influence ``create_resource``. Centralising them
# makes the per-test clearing intent obvious.
_OTEL_ENV_KEYS = ("OTEL_SERVICE_NAME", "OTEL_RESOURCE_ATTRIBUTES")


def _clean_otel_env() -> dict[str, str]:
    """Blank out both OTEL_* keys when used with ``patch.dict``.

    ``os.environ`` rejects non-str values, so ``None`` (which ``patch.dict``
    would otherwise treat as a delete) cannot be used here. Empty strings
    work instead because the source checks env values with truthiness
    (``if raw_attrs:`` / ``if env_service_name:``), so ``""`` is
    observationally indistinguishable from an absent key.
    """
    return {key: "" for key in _OTEL_ENV_KEYS}


def test_defaults_no_env_no_args() -> None:
    with mock.patch.dict(os.environ, _clean_otel_env(), clear=False):
        resource = create_resource()
    assert resource.attributes["service.name"] == DEFAULT_SERVICE_NAME == "capmesh"
    assert resource.attributes["service.version"] == DEFAULT_SERVICE_VERSION == "unknown"
    assert resource.attributes["service.namespace"] == DEFAULT_SERVICE_NAMESPACE == "asg"


def test_explicit_arg_overrides_default() -> None:
    with mock.patch.dict(os.environ, _clean_otel_env(), clear=False):
        resource = create_resource(service_name="explicit-svc")
    assert resource.attributes["service.name"] == "explicit-svc"
    # Untouched defaults still come through.
    assert resource.attributes["service.version"] == "unknown"
    assert resource.attributes["service.namespace"] == "asg"


def test_extra_attributes_overrides_explicit_arg() -> None:
    with mock.patch.dict(os.environ, _clean_otel_env(), clear=False):
        resource = create_resource(
            service_name="arg-svc",
            extra={"service.name": "extra-svc"},
        )
    assert resource.attributes["service.name"] == "extra-svc"


def test_otel_resource_attributes_env_overrides_extra() -> None:
    env = {**_clean_otel_env(), "OTEL_RESOURCE_ATTRIBUTES": "service.name=env-svc,host.id=h1"}
    with mock.patch.dict(os.environ, env, clear=False):
        resource = create_resource(
            service_name="arg-svc",
            extra={"service.name": "extra-svc"},
        )
    assert resource.attributes["service.name"] == "env-svc"
    # Env-parsed attributes also contribute brand-new keys.
    assert resource.attributes["host.id"] == "h1"


def test_otel_service_name_env_highest() -> None:
    env = {
        **_clean_otel_env(),
        "OTEL_SERVICE_NAME": "top-svc",
        "OTEL_RESOURCE_ATTRIBUTES": "service.name=env-svc",
    }
    with mock.patch.dict(os.environ, env, clear=False):
        resource = create_resource(service_name="arg-svc")
    assert resource.attributes["service.name"] == "top-svc"


def test_otel_resource_attributes_parsing() -> None:
    # Whitespace around keys and values is trimmed; trailing spaces survive
    # neither side of the ``=``.
    env = {
        **_clean_otel_env(),
        "OTEL_RESOURCE_ATTRIBUTES": " service.name = spaced , host.id=bar ",
    }
    with mock.patch.dict(os.environ, env, clear=False):
        resource = create_resource()
    assert resource.attributes["service.name"] == "spaced"
    assert resource.attributes["host.id"] == "bar"


def test_to_otlp_attributes_sorted() -> None:
    resource = Resource(attributes={"b.key": "2", "a.key": "1", "c.key": "3"})
    assert resource.to_otlp_attributes() == [
        {"key": "a.key", "value": {"stringValue": "1"}},
        {"key": "b.key", "value": {"stringValue": "2"}},
        {"key": "c.key", "value": {"stringValue": "3"}},
    ]


def test_empty_resource_to_otlp_attributes() -> None:
    assert EMPTY_RESOURCE.to_otlp_attributes() == []


def test_resource_merge() -> None:
    r1 = Resource(attributes={"a": "1", "b": "2"})
    r2 = Resource(attributes={"b": "3", "c": "4"})
    merged = r1.merge(r2)
    # ``other`` (r2) wins on conflict; operands are left unchanged.
    assert merged.attributes == {"a": "1", "b": "3", "c": "4"}
    assert r1.attributes == {"a": "1", "b": "2"}
    assert r2.attributes == {"b": "3", "c": "4"}


def test_resource_is_frozen() -> None:
    resource = Resource(attributes={"a": "1"})
    with pytest.raises((Exception,)):  # FrozenInstanceError is a dataclass detail.
        resource.attributes = {"a": "2"}  # type: ignore[misc]
