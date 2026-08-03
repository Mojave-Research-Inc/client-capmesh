from __future__ import annotations

from unittest.mock import patch

import test_capmesh_soak as soak


def _case(name: str, status: soak.Status) -> soak._TestCase:
    return soak._TestCase(
        name=name,
        uri=f"cap://test/{name}",
        cap_type="skill",
        plugin="fixture",
        description="fixture",
        status=status,
    )


def test_run_all_executes_every_discovered_capability() -> None:
    rows = [{"name": "one"}, {"name": "two"}, {"name": "three"}]
    returned = [_case("one", soak.Status.PASS), _case("two", soak.Status.FAIL), _case("three", soak.Status.SKIP)]
    with (
        patch.object(soak, "_test_agent_brief", return_value=_case("agent-brief", soak.Status.PASS)),
        patch.object(soak, "_test_search_load", return_value=_case("search-load", soak.Status.PASS)),
        patch.object(soak, "discover_all_capabilities", return_value=rows),
        patch.object(soak, "_test_load_capability", side_effect=returned) as load,
        patch.object(soak, "MAX_WORKERS", 2),
    ):
        report = soak.run_all()

    assert load.call_count == len(rows)
    assert report.total == 5
    assert report.pass_count == 3
    assert report.fail_count == 1
    assert report.skip_count == 1


def test_worker_limit_is_bounded(monkeypatch) -> None:
    monkeypatch.setenv("CAPMESH_SOAK_WORKERS", "999")
    assert soak._worker_limit() == 30
    monkeypatch.setenv("CAPMESH_SOAK_WORKERS", "not-an-int")
    assert soak._worker_limit() == 10
