"""Admission guards for capability registration.

These implement the two preconditions from
``docs/design/11-install-ingest-contract.md`` sections 4 and 5. They exist
because of a measured failure on the authority catalog (2026-07-31):

  * 732 distinct package roots were registered, 439 of them pointing at paths
    that do not exist on the authority host. Those rows are advertised but
    unservable, which is what returned HTTP 400 from ``cap.delegate`` and what
    stalled ``ops/sync-nonvoting-member.sh`` on
    ``/home/jason/.agents/skill-registry/plugins/proton-pass-cli/commands/vault-ops.md``.
  * 141 of 477 workstation packages duplicated packages already canonical in
    ``asg-os/plugins``, which is how ``kubernetes-audit`` came to exist in the
    catalog at both ``@0.1.0`` and ``@1.1.0`` with ranking free to return
    either.

Every refusal is fail-closed and names the offending root, file, and — for
duplicates — both competing URIs, so an operator never has to query the catalog
to understand why admission stopped.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

UNSERVABLE_ENTRYPOINT = "UNSERVABLE_ENTRYPOINT"
DUPLICATE_CAPABILITY = "DUPLICATE_CAPABILITY"
ENTRYPOINT_ESCAPES_ROOT = "ENTRYPOINT_ESCAPES_ROOT"
UNKNOWN_ROOT = "UNKNOWN_ROOT"


class InstallGuardError(Exception):
    """Base class for admission refusals. Carries a stable machine code."""

    code = "INSTALL_GUARD"

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class UnservableEntrypointError(InstallGuardError):
    code = UNSERVABLE_ENTRYPOINT


class DuplicateCapabilityError(InstallGuardError):
    code = DUPLICATE_CAPABILITY

    def __init__(self, message: str, *, incoming_uri: str, existing_uri: str) -> None:
        super().__init__(message)
        self.incoming_uri = incoming_uri
        self.existing_uri = existing_uri


class EntrypointEscapesRootError(InstallGuardError):
    """Containment breach: the entrypoint resolves outside its package.

    Kept distinct from UnservableEntrypointError on purpose. A missing file is
    an operator mistake; an escaping path is an attempt to register bytes the
    reviewed release will never contain, and must never be downgraded into the
    ordinary "just commit the file" remedy.
    """

    code = ENTRYPOINT_ESCAPES_ROOT


class UnknownRootError(InstallGuardError):
    code = UNKNOWN_ROOT


@dataclass(frozen=True)
class Candidate:
    """A capability being offered for registration.

    ``root`` is the configured capability root; ``package_path`` is relative to
    it; ``entrypoint`` is relative to the package.
    """

    plugin: str
    name: str
    version: str
    root: str
    package_path: str
    entrypoint: str

    @property
    def key(self) -> tuple[str, str]:
        """Identity for duplicate detection.

        Deliberately excludes version and root. Keying on either would have
        admitted the measured kubernetes-audit @0.1.0 / @1.1.0 pair, since they
        differ in both.
        """
        return (self.plugin, self.name)

    @property
    def uri(self) -> str:
        return f"cap://org/asg/{self.plugin}/{self.name}@{self.version}"


def _normalized_root(root: str) -> Path:
    return Path(os.path.expanduser(str(root))).resolve()


def resolve_entrypoint(candidate: Candidate) -> Path:
    """Resolve the entrypoint, refusing anything outside its package.

    Resolution happens BEFORE any existence check. A traversal such as
    ``../../etc/passwd`` frequently resolves to a file that really does exist,
    so ordering the checks the other way round would let containment be decided
    by whether the attacker guessed a live path.
    """

    root = _normalized_root(candidate.root)
    package = (root / candidate.package_path).resolve()
    target = (package / candidate.entrypoint).resolve()

    for boundary, label in ((package, "package"), (root, "root")):
        if boundary != target and boundary not in target.parents:
            raise EntrypointEscapesRootError(
                f"REFUSED: {ENTRYPOINT_ESCAPES_ROOT}\n\n"
                f"  capability  {candidate.plugin} / {candidate.name}\n"
                f"  entrypoint  {candidate.entrypoint}\n"
                f"  resolved to {target}\n"
                f"  escapes {label}  {boundary}\n\n"
                "  An entrypoint may only name bytes inside its own package. A path that\n"
                "  climbs out would register content the reviewed release never carries.\n\n"
                "  Remedy: reference a file committed inside the package."
            )
    return target


def check_servable(candidate: Candidate) -> Path:
    """Refuse a capability whose entrypoint body is not present under a root.

    This single check would have prevented all 439 unservable rows.
    """

    target = resolve_entrypoint(candidate)
    root = _normalized_root(candidate.root)
    if not target.is_file():
        raise UnservableEntrypointError(
            f"REFUSED: {UNSERVABLE_ENTRYPOINT}\n\n"
            f"  capability  {candidate.plugin} / {candidate.name}\n"
            f"  entrypoint  {candidate.entrypoint}\n"
            f"  root        {root}\n"
            f"  resolved to {target}\n"
            "  not present under that root\n\n"
            "  The authority materializes only reviewed content, so registering this would\n"
            "  advertise a capability the authority cannot serve -- the condition that\n"
            "  returned HTTP 400 from cap.delegate and stalled the non-voting replica.\n\n"
            f"  Remedy: commit {candidate.entrypoint} under {candidate.package_path},\n"
            "  then republish."
        )
    return target


def check_duplicate(
    candidate: Candidate,
    registry: Mapping[tuple[str, str], Candidate],
    *,
    supersedes: Sequence[str] = (),
) -> str:
    """Classify a candidate against already-registered capabilities.

    Returns ``"insert"``, ``"supersede"``, or ``"revision"``.

    A re-registration of the same ``(plugin, name)`` from the SAME root is a
    revision -- a version bump of one package is not a duplicate, and refusing
    it would make the canonical root unable to move forward. The same pair
    arriving from a DIFFERENT root is the measured defect and is refused unless
    the operator explicitly supersedes the incumbent.
    """

    existing = registry.get(candidate.key)
    if existing is None:
        return "insert"
    if _normalized_root(existing.root) == _normalized_root(candidate.root):
        return "revision"
    if existing.uri in tuple(supersedes):
        return "supersede"

    raise DuplicateCapabilityError(
        f"REFUSED: {DUPLICATE_CAPABILITY}\n\n"
        f"  capability           {candidate.plugin} / {candidate.name}\n"
        f"  you are publishing   {candidate.uri}\n"
        f"                       from root {_normalized_root(candidate.root)}\n"
        f"  already registered   {existing.uri}\n"
        f"                       from root {_normalized_root(existing.root)}\n\n"
        "  A capability with this (plugin, name) already exists from another source.\n"
        "  Publishing a second row would leave ranking free to return either one -- this\n"
        "  is the defect that put kubernetes-audit into the catalog at both @0.1.0 and\n"
        "  @1.1.0.\n\n"
        "  Choose one:\n"
        f"    (a) Supersede it:  supersedes: [\"{existing.uri}\"]\n"
        "    (b) Publish under a distinct name if this is genuinely different.\n"
        "    (c) Cancel, if the existing capability already does this.",
        incoming_uri=candidate.uri,
        existing_uri=existing.uri,
    )


def admit(
    candidates: Iterable[Candidate],
    registry: Mapping[tuple[str, str], Candidate] | None = None,
    *,
    roots: Sequence[str] | None = None,
    supersedes: Sequence[str] = (),
) -> list[tuple[Candidate, str]]:
    """Admit a batch atomically: every candidate passes, or none are admitted.

    Partial admission is exactly how the 439 unservable rows accumulated, so
    the first refusal aborts the whole request and nothing is written.
    """

    known = {**(registry or {})}
    allowed = {_normalized_root(r) for r in roots} if roots is not None else None
    decisions: list[tuple[Candidate, str]] = []

    for candidate in candidates:
        if allowed is not None and _normalized_root(candidate.root) not in allowed:
            raise UnknownRootError(
                f"REFUSED: {UNKNOWN_ROOT}\n\n"
                f"  capability  {candidate.plugin} / {candidate.name}\n"
                f"  root        {_normalized_root(candidate.root)}\n\n"
                "  That root is not one the authority materializes, so nothing published\n"
                "  from it could be served. Ambient workstation roots are the ingest\n"
                "  surface that produced every unservable row."
            )
        check_servable(candidate)
        action = check_duplicate(candidate, known, supersedes=supersedes)
        known[candidate.key] = candidate
        decisions.append((candidate, action))

    return decisions
