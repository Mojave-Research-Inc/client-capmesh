"""Tests for ``capmesh.otel_resource`` (CM-13-full third slice).

These pin the self-contained OTel Resource value object: attribute-merge
semantics (other wins, operands unmutated), sorted OTLP attribute rendering,
the ``OTEL_RESOURCE_ATTRIBUTES`` env parser, and ``create_resource``'s
resolution order across defaults, explicit arguments, ``extra`` and the
environment. The module under test imports only the standard library; these
tests mirror that boundary.
"""

from __future__ import annotations

from capmesh.otel_resource import (
    EMPTY_RESOURCE,
    Resource,
    _parse_resource_attributes,
    create_resource,
)


def test_resource_merge() -> None:
    left = Resource({"a": "1"})
    right = Resource({"a": "2", "b": "3"})
    merged = left.merge(right)
    assert merged.attributes == {"a": "2", "b": "3"}
    # Operands must be left unchanged.
    assert left.attributes == {"a": "1"}
    assert right.attributes == {"a": "2", "b": "3"}


def test_to_otlp_attributes_sorted() -> None:
    resource = Resource({"b": "2", "a": "1"})
    assert resource.to_otlp_attributes() == [
        {"key": "a", "value": {"stringValue": "1"}},
        {"key": "b", "value": {"stringValue": "2"}},
    ]


def test_parse_resource_attributes() -> None:
    assert _parse_resource_attributes("service.version=1.2.3, host.name=box1 ") == {
        "service.version": "1.2.3",
        "host.name": "box1",
    }
    assert _parse_resource_attributes("") == {}
    assert _parse_resource_attributes("malformed,noequals") == {}


def test_create_resource_defaults() -> None:
    resource = create_resource()
    assert resource.attributes["service.name"] == "capmesh"
    assert resource.attributes["service.version"] == "unknown"
    assert resource.attributes["service.namespace"] == "asg"


def test_create_resource_explicit_args() -> None:
    resource = create_resource(
        service_name="myapp",
        service_version="9.9",
        service_namespace="ns1",
    )
    assert resource.attributes["service.name"] == "myapp"
    assert resource.attributes["service.version"] == "9.9"
    assert resource.attributes["service.namespace"] == "ns1"


def test_create_resource_env_service_name() -> None:
    resource = create_resource(env={"OTEL_SERVICE_NAME": "env-svc"})
    assert resource.attributes["service.name"] == "env-svc"


def test_create_resource_env_resource_attributes() -> None:
    resource = create_resource(
        env={"OTEL_RESOURCE_ATTRIBUTES": "service.version=2.0.0,deployment.environment=prod"}
    )
    assert resource.attributes["service.version"] == "2.0.0"
    assert resource.attributes["deployment.environment"] == "prod"


def test_create_resource_precedence() -> None:
    # env OTEL_SERVICE_NAME wins over the explicit service_name argument.
    env_wins = create_resource(service_name="arg", env={"OTEL_SERVICE_NAME": "env"})
    assert env_wins.attributes["service.name"] == "env"
    # env-parsed OTEL_RESOURCE_ATTRIBUTES win over the explicit argument.
    ra_wins = create_resource(
        service_name="arg", env={"OTEL_RESOURCE_ATTRIBUTES": "service.name=ra"}
    )
    assert ra_wins.attributes["service.name"] == "ra"


def test_empty_resource_constant() -> None:
    assert isinstance(EMPTY_RESOURCE, Resource)
    assert EMPTY_RESOURCE.attributes == {}
