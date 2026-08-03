"""Fail-closed production policy for superadmin capability installations."""

from __future__ import annotations

import os
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

SUPERADMIN_AUTO_APPROVE_ENV = "CAPMESH_SUPERADMIN_INSTALL_AUTO_APPROVE"
SUPERADMIN_ACTOR_ENV = "CAPMESH_SUPERADMIN_ACTOR"
SUPERADMIN_ACTOR_DEFAULT = os.environ.get("CAPMESH_SUPERADMIN_ACTOR", "admin@example.com")
SUPERADMIN_ACTORS_ENV = "CAPMESH_SUPERADMIN_ACTORS"


def _parse_superadmin_actors() -> tuple[str, ...]:
    """Operator-approved tenant superadmins, from CAPMESH_SUPERADMIN_ACTORS.

    governance.py imports this as SUPERADMIN_ACTORS and grants the
    platform-superadmin role to every subject in it, so the default is
    FAIL-CLOSED: an unset or empty variable grants nobody. That is safe to do
    here because the enforcement loop only ADDS grants -- an empty set revokes
    nothing that already exists.

    Deliberately NOT defaulting to SUPERADMIN_ACTOR_DEFAULT: that falls back to
    the placeholder "admin@example.com", and handing platform-superadmin to a
    placeholder address on an unconfigured host is exactly the kind of silent
    privilege grant this should never do.

    Parsing matches the comma/strip/lower normalization already used by
    require_superadmin_actor() below, so both sides agree on identity.
    """
    raw = os.environ.get(SUPERADMIN_ACTORS_ENV, "")
    return tuple(a.strip().lower() for a in raw.split(",") if a.strip())


SUPERADMIN_ACTORS = _parse_superadmin_actors()


def superadmin_actor() -> str:
    """The configured superadmin actor, read at CALL time.

    production_config.py imported a module-level `SUPERADMIN_ACTOR` that no
    longer existed. Restoring it as a constant would have imported cleanly and
    still been wrong: SUPERADMIN_ACTOR_DEFAULT is evaluated once at import, so
    it freezes whatever CAPMESH_SUPERADMIN_ACTOR happened to be when the module
    was first loaded. configure_canonical_root() renders this value into an env
    file at call time, and its tests patch the variable per case, so a frozen
    constant would silently render a stale actor into real configuration.
    """
    return os.environ.get(SUPERADMIN_ACTOR_ENV, SUPERADMIN_ACTOR_DEFAULT)


_TRUE = frozenset({"1", "true", "yes", "on"})
_FALSE = frozenset({"", "0", "false", "no", "off"})


def configured_superadmin_auto_approval(actor: str | None = None) -> str | None:
    """Return the audited actor when immediate post-ingest approval is enabled.

    The actor is deliberately pinned rather than accepting an arbitrary identity
    from the environment.  An invalid flag or actor is a configuration error,
    never a reason to silently fall back to a pending catalog.
    """

    raw = os.environ.get(SUPERADMIN_AUTO_APPROVE_ENV, "").strip().lower()
    if raw in _FALSE:
        return None
    if raw not in _TRUE:
        raise ValueError(f"{SUPERADMIN_AUTO_APPROVE_ENV} must be a boolean value.")
    configured_actor = os.environ.get(SUPERADMIN_ACTOR_ENV, "").strip().lower()
    # The multi-actor allowlist is OPTIONAL. The sanitizer pass that introduced
    # CAPMESH_SUPERADMIN_ACTORS made it mandatory without supplying a default or
    # updating callers, so with it unset the list is empty and NO actor could
    # ever validate -- every auto-approve raised "must be one of the configured
    # superadmins: " with an empty list. That is a config trap, not a security
    # control: it fails closed on a variable nobody knew to set.
    # Unset  -> the single CAPMESH_SUPERADMIN_ACTOR governs (original behaviour).
    # Set    -> it is the allowlist, and the single actor must be a member.
    allowed = [a.strip().lower() for a in
               os.environ.get(SUPERADMIN_ACTORS_ENV, "").split(",") if a.strip()]
    if not allowed:
        allowed = [configured_actor] if configured_actor else []
    configured_allowed = allowed
    if configured_actor not in configured_allowed:
        raise ValueError(
            f"{SUPERADMIN_ACTOR_ENV} must be one of the configured superadmins: "
            f"{', '.join(configured_allowed)}"
        )
    if actor is None:
        return configured_actor
    requested_actor = actor.strip().lower()
    if requested_actor not in configured_allowed:
        return None
    return requested_actor


class InstallPolicyError(ValueError):
    """A capability was refused admission to the catalog.

    Deliberately a hard error, not a skip. The measured 2026-07-31 failure was
    exactly the silent variety: 439 of 732 package roots in the live authority
    catalog pointed at paths that do not exist there, because ingest accepted
    whatever root it was pointed at and never checked that the body would still
    be resolvable on the machine that has to serve it. Nothing raised, so the
    breakage only surfaced downstream as cap.delegate HTTP 400 and as the
    non-voting replica sync aborting on a missing authoritative body.
    """


class SupersededCapability(InstallPolicyError):
    """A lower-authority copy of a capability the canonical root already owns.

    Distinct from a plain ``InstallPolicyError`` because the remedy is
    different. An equal-authority pair is genuinely ambiguous and must stop the
    ingest so an operator picks a canonical root. A LOWER-authority copy is not
    ambiguous at all -- ``manifest.source_authority_rank`` already says which
    root wins -- so the correct action is to leave the mirror copy out of the
    catalog and carry on, not to abort the deploy.

    Measured 2026-07-31: asg-small-business.call-list existed as the canonical
    plugins row at 0.2.0 (already promoted to org) while the ~/.agents mirror
    still carried 0.1.0. Treating that as fatal blocked the release even though
    the outcome the guard wants -- one row, from the canonical root -- was
    already true.
    """


def _normalized(path: str | Path) -> Path:
    """Absolute, symlink-free form used for every containment comparison.

    ``expanduser`` matters because configured roots are written with ``~``
    (see manifest.DEFAULT_ROOTS) while discovered ``package_path`` values are
    already resolved; comparing the two raw forms never matches.
    """

    return Path(os.path.expandvars(str(path))).expanduser().resolve()


# Directory segment under which the deploy materializes canonical roots, i.e.
# ``<release>/capability-roots/<root-name>/<package>``. See
# ops/deploy-capmesh.sh:135.
_CAPABILITY_ROOTS_SEGMENT = "capability-roots"


def _release_invariant(path: str | Path) -> Path:
    """Identity of a package root that does NOT change between releases.

    Every deploy materializes the canonical root into a fresh, release-stamped
    directory:

        /data/secure/asg-capmesh-archive/releases/<RELEASE_ID>/
            capability-roots/asg-os-plugins/<package>

    ``_normalized`` resolves that to an absolute path *including* ``<RELEASE_ID>``,
    so the same canonical package compares unequal across two releases. Once any
    capability has been promoted -- promotion records the ``package_path`` of the
    release it was ingested under -- the duplicate guard then fires on EVERY
    subsequent deploy, and no new release can ever be cut. Measured 2026-07-31:
    release 20260731T213306Z was refused against rows still pointing at
    20260731T191059Z, for a package whose content was byte-identical.

    So anchor the identity at the ``capability-roots`` segment when one is
    present. Paths without that segment -- workstation roots such as
    ``~/.agents/skill-registry/...`` -- are returned fully resolved, unchanged.
    That preserves the defect this guard exists for: a skill-registry copy and an
    asg-os-plugins copy still compare unequal, because one has no
    ``capability-roots`` segment at all and the other's root name differs.
    """

    resolved = _normalized(path)
    parts = resolved.parts
    for index in range(len(parts) - 1, -1, -1):
        if parts[index] == _CAPABILITY_ROOTS_SEGMENT:
            return Path(*parts[index:])
    return resolved


def _is_authority_managed_anchor(path: str | Path) -> bool:
    """True when ``path`` is authority-internal storage rather than a source root.

    ``assert_not_duplicate`` exists to catch two competing SOURCE roots for one
    capability -- the measured pair was ``kubernetes-audit`` present in both
    ``~/.agents/skill-registry`` and ``asg-os-plugins``. Some rows are instead
    anchored at storage the authority manages itself, and those are not a rival
    source of anything:

      * the content-addressed store, ``<state>/content/sha256`` with a digest as
        the entrypoint -- where the authority materializes a body it has already
        admitted (6 rows, the promoted ``bolde-*`` plugin capabilities);
      * the service's own ``capmesh`` package inside a release -- the built-in
        ``cap://system/asg/*`` capabilities (help, onboard, auth, approve, ...)
        are implemented by ``governance.py`` and anchored there (15 rows).

    Comparing an incoming source copy against either produced a spurious
    duplicate. Measured 2026-07-31: the ``bolde-command`` plugin at 1.0.1 from
    ``capability-roots/asg-os-plugins`` was refused against the already-promoted
    1.0.0 whose package root is ``/secure/asg-capmesh/content/sha256`` -- a
    routine version bump of one capability from its canonical root, reported as
    two roots.
    """

    resolved = _normalized(path)
    if resolved.name == "sha256" and resolved.parent.name == "content":
        return True
    return resolved.name == "capmesh" and "releases" in resolved.parts


def _containing_root(package_path: str | Path, roots: Iterable[str | Path]) -> Path | None:
    """The first configured root that contains *package_path*, else ``None``.

    ``Path.is_relative_to`` is used rather than string prefixing so that a root
    ``/srv/caps`` does not spuriously "contain" ``/srv/caps-scratch``.
    """

    target = _normalized(package_path)
    for root in roots:
        candidate = _normalized(root)
        if target == candidate or target.is_relative_to(candidate):
            return candidate
    return None


def assert_body_resolvable(
    package_path: str | Path,
    entrypoint: str,
    roots: Iterable[str | Path],
) -> Path:
    """Refuse a capability whose body is not servable from a configured root.

    Two independent conditions, both fatal:

    1. The RESOLVED BODY (``package_path/entrypoint``) lies outside every
       configured root. This is the case that admitted the home-directory
       installs: the deploy pipeline materializes exactly one root
       (``capability-roots/asg-os-plugins``, built from ``git archive <sha>
       plugins``), so a row whose body lives in ``~/.agents/skill-registry`` is
       advertised by the authority and can never be served by it.
    2. ``package_path/entrypoint`` does not exist as a readable file. A row
       whose body is absent is worse than an absent row: it ranks, it is
       returned by ``cap.search``, and it fails only at load time.

    Containment is judged on the resolved body, NOT on ``package_path``. The
    two differ legitimately: discovery anchors some capabilities at the parent
    of a configured root and carries the rest of the path in the entrypoint --
    e.g. ``package_path=~/.codex`` with
    ``entrypoint=skills/plugin-forge/agents/plugin-installer.md``, where
    ``~/.codex/skills`` is the configured root. Measured 2026-07-31: gating on
    ``package_path`` refused those rows as "outside every configured capability
    root" even though their bodies sit squarely inside one and read fine, which
    blocked the whole deploy. What actually determines servability is where the
    body is, so that is what is checked.

    Returns the containing root on success so callers may record provenance.
    """

    roots = tuple(roots)
    if not roots:
        raise InstallPolicyError(
            "no capability roots are configured; refusing to admit "
            f"{_normalized(package_path)} because no root could ever serve it"
        )

    # Reject a traversing entrypoint before touching the filesystem. Resolving
    # the body would collapse ``..`` first, so an entrypoint that climbs out of
    # its package and back into some other root would otherwise look containable.
    if any(part == ".." for part in Path(entrypoint).parts):
        raise InstallPolicyError(
            f"capability entrypoint {entrypoint!r} traverses upward out of its "
            f"package ({_normalized(package_path)}); refusing to admit it"
        )

    body = _normalized(Path(package_path) / entrypoint)
    root = _containing_root(body, roots)
    if root is None:
        configured = ", ".join(str(_normalized(item)) for item in roots)
        raise InstallPolicyError(
            f"capability body {body} is outside every configured capability "
            f"root; configured roots are: {configured}. Only content under a "
            "materialized root can be served by the authority, so admitting "
            "this row would register an unservable capability."
        )

    if not body.is_file():
        raise InstallPolicyError(
            f"capability body is missing: {body} does not exist under capability "
            f"root {root} (package path {_normalized(package_path)}, entrypoint "
            f"{entrypoint!r}); refusing to register a capability the authority "
            "cannot serve"
        )

    return root


def _row_field(row: Any, key: str, position: int | None = None) -> Any:
    """Read *key* from a mapping, an sqlite3.Row, or a plain tuple.

    Callers hand us rows from several places (``sqlite3`` with and without a
    row factory, plus in-memory dicts in tests), and a duplicate guard that
    silently returns ``None`` for an unrecognized row shape would fail open.
    """

    if isinstance(row, Mapping):
        return row.get(key)
    if hasattr(row, "keys"):
        try:
            return row[key]
        except (IndexError, KeyError):
            return None
    if (
        position is not None
        and isinstance(row, Sequence)
        and not isinstance(row, (str, bytes))
        and position < len(row)
    ):
        return row[position]
    return None


def _authority_rank(path: str | Path) -> int:
    """Authority tier of the root a ``package_path`` sits in.

    Reuses ``manifest.source_authority_rank`` so the duplicate guard and ingest's
    merge step agree on which root outranks which. Imported inside the function:
    ``manifest`` does not import this module today, and a module-level import
    would create a cycle the moment it did.
    """

    from .manifest import source_authority_rank, source_system_for

    resolved = _normalized(path)
    return source_authority_rank(source_system_for(resolved), str(resolved))


def assert_not_duplicate(
    plugin: str | None,
    name: str,
    existing_rows: Iterable[Any],
    *,
    package_path: str | Path | None = None,
    uri: str | None = None,
) -> None:
    """Refuse a second registration of ``(plugin, name)`` from a different root.

    Keyed on ``(plugin, name)`` and deliberately NOT on version: the measured
    duplicate pair was ``kubernetes-audit@0.1.0`` from ``~/.agents/skill-registry``
    alongside ``kubernetes-audit@1.1.0`` from ``asg-os-plugins``. Keying on
    version would have let exactly that pair through, which is the whole defect.

    Re-ingesting the SAME package root is the normal refresh path and is always
    allowed; only a second, differently-rooted copy is refused. "Same root" is
    judged release-invariantly (see :func:`_release_invariant`), because each
    deploy materializes the canonical root under a fresh release-stamped
    directory and a literal path comparison would refuse every deploy made after
    the first promotion. The error names
    both URIs and both roots so the operator can decide which is canonical
    rather than being told merely that "a duplicate exists".
    """

    incoming_key = (plugin or "", name)
    # Compare release-invariant identities so re-deploying the same canonical
    # root is a refresh, not a duplicate. See _release_invariant.
    incoming_root = _release_invariant(package_path) if package_path is not None else None

    for row in existing_rows:
        existing_plugin = _row_field(row, "plugin", 0)
        existing_name = _row_field(row, "name", 1)
        if (existing_plugin or "", existing_name) != incoming_key:
            continue
        existing_path_raw = _row_field(row, "package_path", 2)
        if existing_path_raw is None:
            continue
        if _is_authority_managed_anchor(existing_path_raw):
            # Not a source root; see _is_authority_managed_anchor.
            continue
        existing_root = _release_invariant(existing_path_raw)
        if incoming_root is not None and existing_root == incoming_root:
            # Same package, same location: this is a refresh, not a duplicate.
            continue
        if package_path is not None and _authority_rank(package_path) > _authority_rank(
            existing_path_raw
        ):
            # CANONICAL TAKEOVER, not a conflict. manifest.source_authority_rank
            # already establishes that asg-os/plugins (500) outranks
            # ~/.agents/skill-registry (400), the codex caches, and the rest --
            # and CLAUDE.md says the same thing in words: plugins/ is the only
            # authoring source and the home-directory trees are runtime mirrors.
            # Ingest's merge step honours that ranking; refusing here vetoed it.
            #
            # That veto was not hypothetical: 20 packages exist in both roots
            # (humanizer, redteam-*, codeforensics-*, dfir-network-cloud,
            # executive-gtm-operators-2026, ...), so every deploy died on the
            # first one. Refusing them would also have been the wrong remedy --
            # many are already promoted to org, so dropping the mirror-rooted row
            # to make way would have cut the team's access until each was
            # re-promoted. Letting the canonical root take the row over updates
            # it in place and keeps placement via the promoted_from_uri carryover.
            #
            # Only a strictly HIGHER rank passes. Equal rank from two different
            # roots is the genuine ambiguity this guard exists for and still
            # fails closed, exactly as source_authority_rank's own docstring
            # requires; a lower-ranked second root is the original defect and is
            # still refused.
            continue
        existing_uri = _row_field(row, "uri", 3)
        if package_path is not None and _authority_rank(package_path) < _authority_rank(
            existing_path_raw
        ):
            raise SupersededCapability(
                f"capability {plugin or '<none>'}/{name} from "
                f"{_normalized(package_path)} is superseded by the higher-authority "
                f"copy already registered as {existing_uri or '<unknown uri>'} from "
                f"{existing_root}; skipping the lower-authority copy"
            )
        raise InstallPolicyError(
            "duplicate capability registration refused: "
            f"plugin={plugin or '<none>'} name={name} is already registered as "
            f"{existing_uri or '<unknown uri>'} from package root {existing_root}, "
            f"and the incoming copy {uri or '<unknown uri>'} comes from "
            f"{incoming_root if incoming_root is not None else '<unknown path>'}. "
            "Two roots for one capability produce split versions and unservable "
            "rows; choose which root is canonical and remove the other."
        )
