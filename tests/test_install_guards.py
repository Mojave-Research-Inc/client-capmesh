"""Admission guard tests -- the regression suite for the 2026-07-31 measurement.

Each case below corresponds to a defect that was measured directly on the
authority catalog, not to a hypothetical:

  case 1  a servable capability is still admitted (the guards must not be a
          blanket refusal)
  case 2  439 of 732 registered package roots did not exist on the authority;
          those rows returned HTTP 400 from cap.delegate and stalled the
          non-voting replica sync
  case 3  kubernetes-audit existed at both @0.1.0 (from ~/.agents/skill-registry)
          and @1.1.0 (from asg-os/plugins) -- 141 such duplicates in total
  case 4  a version bump within one root is NOT that defect and must stay legal
  case 5  containment: an entrypoint may never climb out of its package

All filesystem work is confined to pytest ``tmp_path``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from capmesh.install_guards import (
    Candidate,
    DuplicateCapabilityError,
    EntrypointEscapesRootError,
    UnknownRootError,
    UnservableEntrypointError,
    admit,
    check_duplicate,
    check_servable,
)

# --------------------------------------------------------------------------
# fixtures / helpers
# --------------------------------------------------------------------------


def _write_package(
    root: Path,
    plugin: str,
    entrypoint: str = "SKILL.md",
    body: str = "---\nname: demo\n---\n# demo\n",
) -> Path:
    """Materialize a package with a real entrypoint body under ``root``."""
    path = root / plugin / entrypoint
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


def _candidate(
    root: Path,
    *,
    plugin: str = "kubernetes-audit",
    name: str = "audit-cluster",
    version: str = "1.1.0",
    entrypoint: str = "SKILL.md",
) -> Candidate:
    return Candidate(
        plugin=plugin,
        name=name,
        version=version,
        root=str(root),
        package_path=plugin,
        entrypoint=entrypoint,
    )


@pytest.fixture()
def canonical_root(tmp_path: Path) -> Path:
    """Stands in for capability-roots/asg-os-plugins -- what deploy materializes."""
    root = tmp_path / "canonical" / "capability-roots" / "asg-os-plugins"
    root.mkdir(parents=True)
    return root


@pytest.fixture()
def ambient_root(tmp_path: Path) -> Path:
    """Stands in for ~/.agents/skill-registry -- a workstation root deploy never ships."""
    root = tmp_path / "ambient" / "skill-registry"
    root.mkdir(parents=True)
    return root


# --------------------------------------------------------------------------
# case 1 -- present entrypoint is ACCEPTED
# --------------------------------------------------------------------------


def test_capability_with_existing_entrypoint_is_accepted(canonical_root: Path) -> None:
    written = _write_package(canonical_root, "kubernetes-audit")
    candidate = _candidate(canonical_root)

    resolved = check_servable(candidate)

    assert resolved == written.resolve()
    assert resolved.is_file()
    assert admit([candidate], roots=[str(canonical_root)]) == [(candidate, "insert")]


# --------------------------------------------------------------------------
# case 2 -- missing entrypoint is REFUSED, naming root and file
# --------------------------------------------------------------------------


def test_missing_entrypoint_is_refused_and_names_root_and_file(
    canonical_root: Path,
) -> None:
    """The exact shape of the 439 unservable rows: the package directory is
    registered, but the entrypoint body was never committed."""
    (canonical_root / "proton-pass-cli" / "commands").mkdir(parents=True)
    candidate = Candidate(
        plugin="proton-pass-cli",
        name="vault-ops",
        version="0.1.0",
        root=str(canonical_root),
        package_path="proton-pass-cli",
        entrypoint="commands/vault-ops.md",
    )

    with pytest.raises(UnservableEntrypointError) as excinfo:
        check_servable(candidate)

    message = str(excinfo.value)
    assert excinfo.value.code == "UNSERVABLE_ENTRYPOINT"
    # The refusal must be self-explanatory: which root, which file.
    assert str(canonical_root.resolve()) in message, message
    assert "commands/vault-ops.md" in message, message
    assert "proton-pass-cli" in message, message


def test_missing_entrypoint_aborts_the_whole_batch(canonical_root: Path) -> None:
    """Partial admission is how the unservable rows accumulated; a batch with a
    bad member must admit none of it."""
    _write_package(canonical_root, "good-plugin")
    good = _candidate(canonical_root, plugin="good-plugin", name="ok")
    bad = _candidate(canonical_root, plugin="never-committed", name="ghost")

    with pytest.raises(UnservableEntrypointError):
        admit([good, bad], roots=[str(canonical_root)])


def test_root_the_authority_never_materializes_is_refused(
    canonical_root: Path, ambient_root: Path
) -> None:
    """Closing the back door: a real file under an ambient workstation root is
    still not admissible, because deploy will not ship that root."""
    _write_package(ambient_root, "kubernetes-audit")
    candidate = _candidate(ambient_root)

    with pytest.raises(UnknownRootError) as excinfo:
        admit([candidate], roots=[str(canonical_root)])

    assert str(ambient_root.resolve()) in str(excinfo.value)


# --------------------------------------------------------------------------
# case 3 -- duplicate (plugin, name) from a DIFFERENT root is REFUSED
# --------------------------------------------------------------------------


def test_duplicate_plugin_name_from_different_root_is_refused_naming_both_uris(
    canonical_root: Path, ambient_root: Path
) -> None:
    """The measured kubernetes-audit case: @1.1.0 canonical, @0.1.0 ambient."""
    _write_package(canonical_root, "kubernetes-audit")
    _write_package(ambient_root, "kubernetes-audit")

    incumbent = _candidate(canonical_root, version="1.1.0")
    intruder = _candidate(ambient_root, version="0.1.0")
    registry = {incumbent.key: incumbent}

    with pytest.raises(DuplicateCapabilityError) as excinfo:
        check_duplicate(intruder, registry)

    error = excinfo.value
    message = str(error)
    assert error.code == "DUPLICATE_CAPABILITY"
    # Both competing URIs must appear, so the operator can see winner and loser.
    assert error.existing_uri == "cap://org/asg/kubernetes-audit/audit-cluster@1.1.0"
    assert error.incoming_uri == "cap://org/asg/kubernetes-audit/audit-cluster@0.1.0"
    assert error.existing_uri in message, message
    assert error.incoming_uri in message, message
    # ...and both source roots, since same-name/different-source is the defect.
    assert str(canonical_root.resolve()) in message, message
    assert str(ambient_root.resolve()) in message, message


def test_duplicate_within_one_request_is_refused(
    canonical_root: Path, ambient_root: Path
) -> None:
    """A request cannot supersede itself into coherence."""
    _write_package(canonical_root, "kubernetes-audit")
    _write_package(ambient_root, "kubernetes-audit")

    with pytest.raises(DuplicateCapabilityError):
        admit(
            [_candidate(canonical_root, version="1.1.0"), _candidate(ambient_root, version="0.1.0")],
            roots=[str(canonical_root), str(ambient_root)],
        )


def test_explicit_supersede_of_the_incumbent_uri_is_allowed(
    canonical_root: Path, ambient_root: Path
) -> None:
    """Refusal must be escapable deliberately -- but only by naming the URI."""
    _write_package(canonical_root, "kubernetes-audit")
    _write_package(ambient_root, "kubernetes-audit")

    incumbent = _candidate(canonical_root, version="1.1.0")
    replacement = _candidate(ambient_root, version="2.0.0")

    action = check_duplicate(
        replacement,
        {incumbent.key: incumbent},
        supersedes=[incumbent.uri],
    )

    assert action == "supersede"


# --------------------------------------------------------------------------
# case 4 -- same (plugin, name) from the SAME root is a version bump, allowed
# --------------------------------------------------------------------------


def test_same_plugin_name_from_same_root_is_a_revision_not_a_duplicate(
    canonical_root: Path,
) -> None:
    _write_package(canonical_root, "kubernetes-audit")

    previous = _candidate(canonical_root, version="1.1.0")
    bumped = _candidate(canonical_root, version="1.2.0")

    assert check_duplicate(bumped, {previous.key: previous}) == "revision"
    assert admit(
        [bumped],
        {previous.key: previous},
        roots=[str(canonical_root)],
    ) == [(bumped, "revision")]


def test_revision_is_recognised_regardless_of_root_spelling(
    canonical_root: Path,
) -> None:
    """A root written with a redundant path segment is the same root; the guard
    must not manufacture a duplicate out of a cosmetic difference."""
    _write_package(canonical_root, "kubernetes-audit")

    previous = _candidate(canonical_root, version="1.1.0")
    noisy_root = canonical_root / "sub" / ".."
    bumped = _candidate(noisy_root, version="1.2.0")

    assert check_duplicate(bumped, {previous.key: previous}) == "revision"


# --------------------------------------------------------------------------
# case 5 -- containment regression guard
# --------------------------------------------------------------------------


def test_path_traversal_entrypoint_is_refused(tmp_path: Path, canonical_root: Path) -> None:
    """Regression guard. This MUST fail loudly if containment is ever weakened.

    The traversal target is deliberately created as a REAL file, so an
    implementation that checks existence before containment -- or that drops
    containment altogether -- would resolve it happily and accept. Only a guard
    that rejects on the path itself passes this test.
    """
    (canonical_root / "kubernetes-audit").mkdir(parents=True)
    secret = tmp_path / "etc" / "passwd"
    secret.parent.mkdir(parents=True, exist_ok=True)
    secret.write_text("root:x:0:0:root:/root:/bin/sh\n", encoding="utf-8")
    assert secret.is_file(), "traversal target must exist for this guard to be meaningful"

    candidate = _candidate(canonical_root, entrypoint="../../etc/passwd")

    with pytest.raises(EntrypointEscapesRootError) as excinfo:
        check_servable(candidate)

    message = str(excinfo.value)
    assert excinfo.value.code == "ENTRYPOINT_ESCAPES_ROOT"
    assert "../../etc/passwd" in message, message
    # A containment breach must never be reported as a merely-missing file,
    # whose documented remedy is "commit the file" -- wrong and dangerous here.
    assert "UNSERVABLE_ENTRYPOINT" not in message, message
    assert not isinstance(excinfo.value, UnservableEntrypointError)


def test_traversal_that_stays_inside_the_package_is_allowed(canonical_root: Path) -> None:
    """Containment is about the boundary, not about the literal '..' token."""
    _write_package(canonical_root, "kubernetes-audit", entrypoint="skills/SKILL.md")
    candidate = _candidate(canonical_root, entrypoint="skills/../skills/SKILL.md")

    assert check_servable(candidate).is_file()


def test_absolute_entrypoint_escaping_the_root_is_refused(
    tmp_path: Path, canonical_root: Path
) -> None:
    """An absolute path silently discards the package prefix on join; the guard
    must catch that rather than trust the resulting path."""
    (canonical_root / "kubernetes-audit").mkdir(parents=True)
    outside = tmp_path / "outside.md"
    outside.write_text("# outside\n", encoding="utf-8")

    candidate = _candidate(canonical_root, entrypoint=str(outside))

    with pytest.raises(EntrypointEscapesRootError):
        check_servable(candidate)


def test_traversal_is_refused_before_existence_is_consulted(canonical_root: Path) -> None:
    """Ordering proof: the escaping path does NOT exist, and the refusal is
    still a containment error rather than an unservable-entrypoint error."""
    (canonical_root / "kubernetes-audit").mkdir(parents=True)
    candidate = _candidate(canonical_root, entrypoint="../../nowhere/at/all.md")

    with pytest.raises(EntrypointEscapesRootError):
        check_servable(candidate)


# ---------------------------------------------------------------------------
# Release-invariant duplicate detection (2026-07-31)
#
# Each deploy materializes the canonical root into a fresh release-stamped
# directory. Promotion records the package_path of the release a capability was
# ingested under, so comparing absolute paths made every deploy after the first
# promotion fail: release 20260731T213306Z was refused against rows pointing at
# 20260731T191059Z for byte-identical content, and no new release could be cut.
# ---------------------------------------------------------------------------

_REL_A = (
    "/data/secure/asg-capmesh-archive/releases/20260731T191059Z-99dd4d8caa18"
    "/capability-roots/asg-os-plugins/agentic-flow-specialists-2026"
)
_REL_B = (
    "/data/secure/asg-capmesh-archive/releases/20260731T213306Z-809e0ab09711"
    "/capability-roots/asg-os-plugins/agentic-flow-specialists-2026"
)


def _row(package_path: str, uri: str = "cap://all/asg/everyone/agent/x@0.1.0"):
    return {
        "plugin": "agentic-flow-specialists-2026",
        "name": "accessibility-qa-lead",
        "package_path": package_path,
        "uri": uri,
    }


def test_redeploy_of_same_root_under_a_new_release_is_a_refresh():
    """The exact failure that blocked the 20260731T213306Z deploy."""
    from capmesh.install_policy import assert_not_duplicate

    assert_not_duplicate(
        "agentic-flow-specialists-2026",
        "accessibility-qa-lead",
        [_row(_REL_A)],
        package_path=_REL_B,
        uri="cap://asg.local/agent/agentic-flow-specialists-2026.accessibility-qa-lead@0.1.0",
    )


def test_two_different_canonical_roots_still_refused():
    """Release-invariance must not collapse genuinely distinct roots."""
    import pytest

    from capmesh.install_policy import InstallPolicyError, assert_not_duplicate

    other_root = _REL_B.replace("asg-os-plugins", "some-other-root")
    with pytest.raises(InstallPolicyError):
        assert_not_duplicate(
            "agentic-flow-specialists-2026",
            "accessibility-qa-lead",
            [_row(_REL_A)],
            package_path=other_root,
        )


def test_mirror_root_may_not_shadow_an_existing_canonical_row():
    """The original defect, in the direction that is still a defect.

    A skill-registry copy arriving alongside an already-canonical asg-os-plugins
    row is a second, LOWER-authority root and is refused. (The opposite
    direction -- canonical arriving over a mirror-rooted row -- is a canonical
    takeover and is allowed; see
    test_canonical_root_may_take_over_a_mirror_rooted_row.)
    """
    import pytest

    from capmesh.install_policy import (
        SupersededCapability,
        assert_not_duplicate,
    )

    workstation = "/home/jason/.agents/skill-registry/agentic-flow-specialists-2026"
    with pytest.raises(SupersededCapability):
        assert_not_duplicate(
            "agentic-flow-specialists-2026",
            "accessibility-qa-lead",
            [_row(_REL_B)],
            package_path=workstation,
        )


def test_release_invariant_ignores_paths_without_the_segment():
    from capmesh.install_policy import _normalized, _release_invariant

    plain = "/home/jason/.agents/skill-registry/some-plugin"
    assert _release_invariant(plain) == _normalized(plain)


# ---------------------------------------------------------------------------
# assert_body_resolvable gates on the RESOLVED BODY, not on package_path
# ---------------------------------------------------------------------------


def test_package_path_above_the_root_is_allowed_when_the_body_is_inside(tmp_path):
    """Discovery anchors some capabilities at the parent of a configured root.

    Measured 2026-07-31: package_path=~/.codex with
    entrypoint=skills/plugin-forge/agents/plugin-installer.md, where
    ~/.codex/skills is the configured root. Gating on package_path refused these
    as "outside every configured capability root" though their bodies read fine,
    and that blocked the entire deploy.
    """
    from capmesh.install_policy import assert_body_resolvable

    home = tmp_path / "dot-codex"
    root = home / "skills"
    body = root / "plugin-forge" / "agents" / "plugin-installer.md"
    body.parent.mkdir(parents=True)
    body.write_text("# installer\n", encoding="utf-8")

    returned = assert_body_resolvable(
        home, "skills/plugin-forge/agents/plugin-installer.md", [root]
    )
    assert returned == root.resolve()


def test_body_outside_every_root_still_refused(tmp_path):
    import pytest

    from capmesh.install_policy import InstallPolicyError, assert_body_resolvable

    root = tmp_path / "root"
    root.mkdir()
    stray = tmp_path / "elsewhere" / "SKILL.md"
    stray.parent.mkdir(parents=True)
    stray.write_text("# stray\n", encoding="utf-8")

    with pytest.raises(InstallPolicyError, match="outside every configured"):
        assert_body_resolvable(stray.parent, "SKILL.md", [root])


def test_upward_traversing_entrypoint_refused(tmp_path):
    """`..` is rejected before resolution, which would otherwise collapse it."""
    import pytest

    from capmesh.install_policy import InstallPolicyError, assert_body_resolvable

    root = tmp_path / "root"
    pkg = root / "pkg"
    pkg.mkdir(parents=True)
    secret = tmp_path / "secret.md"
    secret.write_text("nope\n", encoding="utf-8")

    with pytest.raises(InstallPolicyError, match="traverses upward"):
        assert_body_resolvable(pkg, "../../secret.md", [root])


def test_missing_body_still_refused(tmp_path):
    import pytest

    from capmesh.install_policy import InstallPolicyError, assert_body_resolvable

    root = tmp_path / "root"
    pkg = root / "pkg"
    pkg.mkdir(parents=True)

    with pytest.raises(InstallPolicyError, match="body is missing"):
        assert_body_resolvable(pkg, "SKILL.md", [root])


# ---------------------------------------------------------------------------
# Authority-managed anchors are not competing source roots
# ---------------------------------------------------------------------------


def test_promoted_row_in_the_content_store_is_not_a_rival_root():
    """The bolde-command 1.0.0 -> 1.0.1 case that blocked deploy 20260731T214327Z."""
    from capmesh.install_policy import assert_not_duplicate

    existing = {
        "plugin": "bolde-command",
        "name": "bolde-command",
        "package_path": "/secure/asg-capmesh/content/sha256",
        "uri": "cap://org/asg/bolde/command/plugin/bolde-command.bolde-command@1.0.0",
    }
    assert_not_duplicate(
        "bolde-command",
        "bolde-command",
        [existing],
        package_path=(
            "/data/secure/asg-capmesh-archive/releases/20260731T214327Z-bcc3a777f36d"
            "/capability-roots/asg-os-plugins/bolde-command"
        ),
        uri="cap://asg.local/plugin/bolde-command.bolde-command@1.0.1",
    )


def test_system_capability_anchored_in_the_service_package_is_not_a_rival_root():
    from capmesh.install_policy import assert_not_duplicate

    existing = {
        "plugin": None,
        "name": "approve",
        "package_path": (
            "/data/secure/asg-capmesh-archive/releases/20260731T191059Z-99dd4d8caa18/capmesh"
        ),
        "uri": "cap://system/asg/approve@0.1.0",
    }
    assert_not_duplicate(
        None,
        "approve",
        [existing],
        package_path="/home/jason/.agents/skill-registry/some-plugin",
    )


def test_authority_managed_anchor_predicate():
    from capmesh.install_policy import _is_authority_managed_anchor as A

    assert A("/secure/asg-capmesh/content/sha256") is True
    assert A("/data/secure/asg-capmesh-archive/releases/20260731T191059Z-x/capmesh") is True
    assert A("/home/jason/.agents/skill-registry/kubernetes-audit") is False
    assert A("/data/.../capability-roots/asg-os-plugins/bolde-command") is False
    # A plain directory literally named "capmesh" outside a release is a source path.
    assert A("/home/jason/GitHub/asg-os/services/asg-capmesh/capmesh") is False


# ---------------------------------------------------------------------------
# Canonical takeover: a strictly higher-authority root may claim an existing row
# ---------------------------------------------------------------------------

_CANONICAL = "/rel/20260731T215022Z-abc/capability-roots/asg-os-plugins/humanizer"
_MIRROR = "/home/jason/.agents/skill-registry/humanizer"
_CACHE = "/home/jason/.codex/plugins/cache/openai-bundled/humanizer"


def test_canonical_root_may_take_over_a_mirror_rooted_row():
    """asg-os/plugins (500) outranks ~/.agents/skill-registry (400).

    20 packages exist in both roots, so refusing this killed every deploy on the
    first one. Many are already promoted to org, so dropping the mirror-rooted
    row instead would have cut team access until each was re-promoted.
    """
    from capmesh.install_policy import assert_not_duplicate

    existing = {
        "plugin": "humanizer",
        "name": "humanizer",
        "package_path": _MIRROR,
        "uri": "cap://org/asg/agentic-secure-group-inc/shared/skill/humanizer.humanizer@0.1.0",
    }
    assert_not_duplicate(
        "humanizer",
        "humanizer",
        [existing],
        package_path=_CANONICAL,
        uri="cap://asg.local/plugin/humanizer.humanizer@2.2.0",
    )


def test_equal_authority_from_two_roots_still_fails_closed():
    """source_authority_rank's own contract: equal-rank conflicts are ambiguous."""
    import pytest

    from capmesh.install_policy import InstallPolicyError, assert_not_duplicate

    other_mirror = "/mnt/backup/.agents/skill-registry/humanizer"
    existing = {"plugin": "humanizer", "name": "humanizer", "package_path": _MIRROR, "uri": "u"}
    with pytest.raises(InstallPolicyError):
        assert_not_duplicate("humanizer", "humanizer", [existing], package_path=other_mirror)


def test_lower_authority_second_root_is_superseded_not_ambiguous():
    """A cache copy must not shadow the canonical row -- but it is not ambiguous.

    It raises SupersededCapability (a subclass), which ingest drops from the
    batch rather than aborting on: the outcome the guard wants, one row from the
    canonical root, is already true. Measured: asg-small-business.call-list
    existed canonically at 0.2.0 (promoted to org) while the ~/.agents mirror
    carried 0.1.0, and treating it as fatal blocked the release.
    """
    import pytest

    from capmesh.install_policy import (
        InstallPolicyError,
        SupersededCapability,
        assert_not_duplicate,
    )

    existing = {"plugin": "humanizer", "name": "humanizer", "package_path": _CANONICAL, "uri": "u"}
    with pytest.raises(SupersededCapability):
        assert_not_duplicate("humanizer", "humanizer", [existing], package_path=_CACHE)
    assert issubclass(SupersededCapability, InstallPolicyError)


def test_equal_authority_is_NOT_superseded_it_is_fatal():
    """Ambiguity must keep aborting: it needs an operator to choose a root."""
    import pytest

    from capmesh.install_policy import (
        InstallPolicyError,
        SupersededCapability,
        assert_not_duplicate,
    )

    existing = {"plugin": "humanizer", "name": "humanizer", "package_path": _MIRROR, "uri": "u"}
    with pytest.raises(InstallPolicyError) as excinfo:
        assert_not_duplicate(
            "humanizer",
            "humanizer",
            [existing],
            # Same authority tier, different tree -- source_system_for matches
            # the "/.agents/skill-registry/" marker in both, so both rank 400.
            package_path="/mnt/backup/.agents/skill-registry/humanizer",
        )
    assert not isinstance(excinfo.value, SupersededCapability)


def test_authority_rank_matches_manifest():
    from capmesh.install_policy import _authority_rank

    assert _authority_rank(_CANONICAL) == 500
    assert _authority_rank(_MIRROR) == 400
    assert _authority_rank(_CACHE) == 250
