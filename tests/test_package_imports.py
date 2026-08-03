"""Every capmesh module must import, and the CLI must actually run.

WHY THIS EXISTS
---------------
On 2026-07-26 the capmesh package was completely un-importable for an unknown
length of time. A single missing `import os` in models.py meant `from
capmesh.cli import main` raised NameError, so the `capmesh` CLI could not start
at all.

Nothing caught it, for two compounding reasons:

1. No test ever imported the package. The existing suite exercises specific
   subsystems, each importing only what it needs, so a module that nothing
   imported directly could sit broken indefinitely.
2. The caller swallowed the crash. capmesh-select's search helper returned []
   on non-zero exit, which is the same value as a genuine no-match -- so a dead
   mesh and an empty mesh were byte-identical to every consumer. Callers logged
   "capmesh search returned no hits" and bound zero capabilities, silently.

The eventual breakage was five distinct faults at once (four missing stdlib
imports, a stray '.' inside an f-string, an undefined SUPERADMIN_ACTORS, fifteen
mangled f-string literals, and two malformed SQL statements), all introduced by
an automated tenant-sanitization pass. Any one of them would have been caught in
seconds by the first test below.

These tests are deliberately cheap and dependency-free so there is no excuse to
skip them.
"""
from __future__ import annotations

import ast
import importlib
import pathlib
import pkgutil
import subprocess
import sys

import pytest

PACKAGE_ROOT = pathlib.Path(__file__).resolve().parents[1]
CAPMESH_DIR = PACKAGE_ROOT / "capmesh"


def _module_names() -> list[str]:
    if not CAPMESH_DIR.is_dir():  # pragma: no cover - layout guard
        pytest.skip(f"capmesh package not found at {CAPMESH_DIR}")
    return sorted(
        f"capmesh.{m.name}"
        for m in pkgutil.iter_modules([str(CAPMESH_DIR)])
        if not m.ispkg
    )


@pytest.fixture(scope="module", autouse=True)
def _ensure_importable():
    if str(PACKAGE_ROOT) not in sys.path:
        sys.path.insert(0, str(PACKAGE_ROOT))


@pytest.mark.parametrize("module_name", _module_names())
def test_every_module_imports(module_name: str) -> None:
    """A module that cannot be imported cannot be exercised by any other test."""
    importlib.import_module(module_name)


def test_cli_entrypoint_imports() -> None:
    """The exact import the `capmesh` console script performs on startup.

    This is the one that actually failed: `capmesh` does
    `from capmesh.cli import main`, which transitively pulled in models.py,
    governance.py, help.py and install_policy.py -- every one of which was
    broken.
    """
    from capmesh.cli import main  # noqa: F401


def test_no_module_scope_syntax_errors() -> None:
    """Parse every file, including any not exposed by pkgutil.

    Catches a SyntaxError in a module that nothing currently imports, before it
    becomes a runtime failure the moment something does.
    """
    broken: list[str] = []
    for path in sorted(CAPMESH_DIR.rglob("*.py")):
        try:
            ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError as exc:
            broken.append(f"{path.relative_to(PACKAGE_ROOT)}:{exc.lineno}: {exc.msg}")
    assert not broken, "syntax errors in capmesh package:\n  " + "\n  ".join(broken)


def test_no_fstring_fragments_in_plain_strings() -> None:
    """Guard the specific corruption an automated rewrite produced.

    A sanitizer replaced literals like `cap://system/asg/help@0.1.0` with the
    text `"f'cap://system/{tenant_id}'/help@0.1.0"` -- an f-string fragment
    embedded inside an ordinary string. It never interpolates, so the value is
    silently wrong rather than loudly broken, and two such fragments landed
    inside SQL statements and produced `near "cap": syntax error` at runtime.
    """
    offenders: list[str] = []
    for path in sorted(CAPMESH_DIR.rglob("*.py")):
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if '"f\'' in line or "'f\"" in line:
                offenders.append(f"{path.relative_to(PACKAGE_ROOT)}:{lineno}")
    assert not offenders, (
        "f-string fragment embedded in a plain string literal:\n  "
        + "\n  ".join(offenders)
    )


def test_cli_runs_and_emits_json() -> None:
    """End-to-end: the installed CLI starts and returns parseable output.

    Import success alone is not enough -- the package imported fine while
    governance.py still raised sqlite3.OperationalError during init_db. Skips
    rather than fails when the CLI is not installed, so a source-only checkout
    stays green.
    """
    import json
    import shutil

    exe = shutil.which("capmesh")
    if not exe:
        pytest.skip("capmesh CLI not installed on PATH")
    proc = subprocess.run(
        [exe, "search", "test", "--k", "1"],
        capture_output=True, text=True, timeout=60, check=False,
    )
    assert proc.returncode == 0, (
        f"capmesh CLI exited {proc.returncode}:\n{proc.stderr[:2000]}"
    )
    json.loads(proc.stdout)  # raises if the CLI emitted non-JSON
