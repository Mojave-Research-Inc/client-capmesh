"""Bounded, self-contained OpenTelemetry Resource helper.

Third slice of plan item CM-13-full (OTel trace export). An OTel Resource
describes the entity producing telemetry -- service name, version, deployment
environment and so on -- and is attached to exported spans and batches. This
module builds a Resource from defaults, explicit arguments and the standard
``OTEL_SERVICE_NAME`` / ``OTEL_RESOURCE_ATTRIBUTES`` environment variables so a
later wave can wire it into the OTLP exporter's ``resourceSpans`` envelope.

The module is a standalone helper: it imports ONLY the Python standard library
(``os`` for the environment, ``dataclasses`` for the value object) and has no
runtime dependency on any other ``capmesh`` module -- in particular it never
imports ``governance``, ``server``, ``lifecycle`` or the sibling ``tracing`` /
``otlp_exporter`` lanes -- so it can be used without risking import cycles. It
makes no clock calls.

Provided surface:
    * ``DEFAULT_SERVICE_NAME`` / ``DEFAULT_SERVICE_VERSION`` /
      ``DEFAULT_SERVICE_NAMESPACE`` -- fallback values when neither an explicit
      argument nor the environment supplies one.
    * ``Resource`` -- immutable-in-spirit value object holding a
      ``dict[str, str]`` of attributes, with ``merge`` (returns a new Resource,
      other wins on conflict) and ``to_otlp_attributes`` (sorted list of
      ``{"key": k, "value": {"stringValue": v}}`` entries for stable export).
    * ``_parse_resource_attributes`` -- parse the ``OTEL_RESOURCE_ATTRIBUTES``
      comma-separated ``key=value`` format into a dict (whitespace-trimmed,
      malformed entries skipped, no URL-decoding).
    * ``create_resource`` -- assemble a ``Resource`` from defaults, explicit
      args, an ``extra`` dict and the environment, honouring the OTel
      resolution order: defaults < explicit args < extra < env-parsed
      ``OTEL_RESOURCE_ATTRIBUTES`` < env ``OTEL_SERVICE_NAME`` (for
      ``service.name``).
    * ``EMPTY_RESOURCE`` -- a module-level ``Resource`` with no attributes.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

DEFAULT_SERVICE_NAME = "capmesh"
DEFAULT_SERVICE_VERSION = "unknown"
DEFAULT_SERVICE_NAMESPACE = "asg"


@dataclass(frozen=True)
class Resource:
    """An OpenTelemetry Resource: a bag of string attributes.

    Immutable in spirit: ``merge`` returns a NEW ``Resource`` rather than
    mutating either operand. ``attributes`` defaults to an empty dict.
    """

    attributes: dict[str, str] = field(default_factory=dict)

    def merge(self, other: Resource) -> Resource:
        """Return a new Resource merging ``self`` and ``other``.

        The result's attributes are ``{**self.attributes, **other.attributes}``
        so ``other`` wins on any key conflict. Both operands are left
        unchanged.
        """
        return Resource(attributes={**self.attributes, **other.attributes})

    def to_otlp_attributes(self) -> list[dict[str, object]]:
        """Render attributes as the OTLP ``AttributeValue`` list shape.

        Returns ``[{"key": k, "value": {"stringValue": v}}, ...]`` with entries
        sorted by key for deterministic export output.
        """
        return [
            {"key": key, "value": {"stringValue": value}}
            for key, value in sorted(self.attributes.items())
        ]


def _parse_resource_attributes(env_value: str) -> dict[str, str]:
    """Parse the ``OTEL_RESOURCE_ATTRIBUTES`` env format into a dict.

    The format is comma-separated ``key=value`` pairs, e.g.
    ``"service.version=1.2.3,host.name=box1"``. Keys and values are
    whitespace-trimmed. Entries with no ``=`` are malformed and skipped. An
    empty (or whitespace-only) input yields ``{}``. No URL-decoding is
    performed -- the OTel spec leaves that to the consumer.
    """
    if not env_value:
        return {}
    result: dict[str, str] = {}
    for entry in env_value.split(","):
        if "=" not in entry:
            continue
        key, _, value = entry.partition("=")
        key = key.strip()
        value = value.strip()
        if not key:
            # An entry that trims to an empty key (e.g. " = x") is malformed.
            continue
        result[key] = value
    return result


def create_resource(
    *,
    service_name: str | None = None,
    service_version: str | None = None,
    service_namespace: str | None = None,
    extra: dict[str, str] | None = None,
    env: dict[str, str] | None = None,
) -> Resource:
    """Build a ``Resource`` from defaults, explicit args and the environment.

    The ``env`` mapping (default ``os.environ``) supplies two OTel-standard
    keys: ``OTEL_SERVICE_NAME`` overrides ``service.name`` and
    ``OTEL_RESOURCE_ATTRIBUTES`` (parsed via ``_parse_resource_attributes``)
    contributes arbitrary attributes. Resolution order, later wins:

        defaults
          < explicit ``service_name`` / ``service_version`` / ``service_namespace``
          < ``extra``
          < env-parsed ``OTEL_RESOURCE_ATTRIBUTES``
          < env ``OTEL_SERVICE_NAME`` (for ``service.name`` only)

    ``service.name`` falls back to ``DEFAULT_SERVICE_NAME`` when neither the
    explicit argument nor ``OTEL_SERVICE_NAME`` supplies a value.
    ``service.version`` falls back to ``DEFAULT_SERVICE_VERSION`` when neither
    the explicit argument nor an env-parsed attribute supplies one.
    ``service.namespace`` falls back to ``DEFAULT_SERVICE_NAMESPACE`` when no
    explicit argument supplies one.
    """
    if env is None:
        env = os.environ

    attributes: dict[str, str] = {
        "service.name": DEFAULT_SERVICE_NAME,
        "service.version": DEFAULT_SERVICE_VERSION,
        "service.namespace": DEFAULT_SERVICE_NAMESPACE,
    }

    if service_name is not None:
        attributes["service.name"] = service_name
    if service_version is not None:
        attributes["service.version"] = service_version
    if service_namespace is not None:
        attributes["service.namespace"] = service_namespace

    if extra:
        attributes.update(extra)

    raw_attrs = env.get("OTEL_RESOURCE_ATTRIBUTES")
    if raw_attrs:
        attributes.update(_parse_resource_attributes(raw_attrs))

    env_service_name = env.get("OTEL_SERVICE_NAME")
    if env_service_name:
        attributes["service.name"] = env_service_name

    return Resource(attributes=attributes)


EMPTY_RESOURCE = Resource(attributes={})
