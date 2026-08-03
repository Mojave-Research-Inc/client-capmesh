# 11 — The Install / Ingest Contract

**Status:** Design (not yet implemented)
**Date:** 2026-07-31
**Scope:** `services/asg-capmesh` — publish path, ingest admission, root policy
**Non-goals:** No production mutation. This document specifies a contract; a separate
operator-driven process owns rollout.

---

## 1. Problem statement

The operator's framing: *"build a fully easy install and ingest part of the MCP so local
installs stop happening."*

Local installs are not a style preference — they are the direct cause of four measured
production defects. The mechanism is a single mismatch between what **ingest** accepts and
what **deploy** materializes.

### 1.1 The mismatch, in code

Ingest accepts capabilities from workstation home directories. `capmesh/manifest.py`:

```python
DEFAULT_ROOTS = (
    "~/GitHub/asg-os/plugins",
    "~/.agents/skill-registry",
    "~/.codex/skills",
    "~/.codex/plugins/cache",
    "~/.claude/plugins/cache/personal",
)
```

Four of those five roots are ambient workstation state. Ingest records the discovered path
verbatim into `capabilities.package_path` (`capmesh/index.py:350`, `:553`).

Deploy materializes exactly **one** capability root, and only from reviewed git content.
`ops/deploy-capmesh.sh:141`:

```sh
mkdir -p "$PAYLOAD/capability-roots/asg-os-plugins"
git -C "$REPO_ROOT" archive --format=tar "$GIT_SHA" plugins \
  | tar -xf - -C "$PAYLOAD/capability-roots/asg-os-plugins" --strip-components=1
```

with the stated invariant (`ops/deploy-capmesh.sh:137-140`):

> Package the exact reviewed commit, not the ambient working directory. This excludes ignored
> build/cache output by construction and prevents local filesystem metadata from entering an
> otherwise immutable release.

and a hard guard that the runtime root list must *begin* with that canonical root
(`ops/deploy-capmesh.sh:311-315`):

```sh
      *) echo 'CAPMESH_ROOTS does not begin with the immutable canonical plugin root' >&2; exit 1 ;;
```

**So: ingest admits five roots; deploy guarantees one.** Every capability ingested from the
other four is advertised by the catalog and unresolvable on the authority.

### 1.2 Measured consequences (2026-07-31, on the authority host)

| Measurement | Value |
|---|---|
| Distinct `package_path` roots in the live authority catalog | 732 |
| Of those, roots that **do not exist** on the authority | 439 |
| Packages in operator `~/.agents/skill-registry` | 477 |
| — exact duplicates of packages already canonical in `asg-os/plugins` | 141 |
| — genuinely distinct, git-untracked | 336 |

Two user-visible failures, one root cause:

- **`cap.delegate` → HTTP 400** whenever ranking pulled an unservable capability into the
  bundle. This blocked *every* mutating `asgcode-workflow` run.
- **Non-voting replica sync dead since 2026-07-14.** `ops/sync-nonvoting-member.sh` aborts:
  `missing authoritative capability body: /home/jason/.agents/skill-registry/plugins/proton-pass-cli/commands/vault-ops.md`
  The Mac failover mirror had been stale for 17 days.

Duplication compounds it: `kubernetes-audit` existed twice — `@0.1.0` from `skill-registry`
and `@1.1.0` from `asg-os-plugins` — with no relationship recorded between them, so ranking
could return the stale one.

### 1.3 Target architecture

Capabilities live in CapMesh and **lazy-load**. Only foundational plugins required to drive
the system (`asgcode`, `workflow`, `capmesh`, and baseline function plugins) are materialized
on disk. cpubox CapMesh is the **lead**; the Mac is a **pull-only failover mirror**.
Mac → cpubox writes happen only for deliberate repo work, never as routine sync.

There is currently **no first-class publish path** into that architecture. Local install is
the only affordance an operator has, so operators use it. This document specifies the
affordance that makes local install unnecessary — and then makes it impossible.

---

## 2. The tool: `cap.publish`

`cap.publish` is already a reserved scope in `capmesh/help.py:33` (`CAPMESH_SCOPES`) but has
no tool behind it. This design fills that slot, so scope and tool names align with no new
vocabulary.

It joins the existing mutating tool set (`cap.call`, `cap.delegate`, `cap.approve`,
`cap.report`) and therefore dispatches **under `state_lock`**, matching the serialization rule
already documented at `capmesh/server.py:968` — read-only tools run unlocked, mutating tools
serialize so the WAL stays coherent.

### 2.1 Input schema

```jsonc
{
  "name": "cap.publish",
  "description":
    "Publish one or more capabilities into the authority catalog from a reviewed git commit. \
Refuses ambient workstation paths, duplicate (plugin, name) pairs, and any capability whose \
body will not be resolvable on the authority after deploy.",
  "inputSchema": {
    "type": "object",
    "additionalProperties": false,
    "required": ["source", "namespace", "lifecycle"],
    "properties": {

      "source": {
        "description": "Where the content comes from. Exactly one variant.",
        "oneOf": [
          {
            "type": "object",
            "additionalProperties": false,
            "required": ["kind", "repo", "ref", "path"],
            "properties": {
              "kind":   { "const": "git" },
              "repo":   {
                "type": "string",
                "description":
                  "Canonical remote URL. Must match an entry in the publish allowlist \
(see §3.2). Local filesystem paths are rejected."
              },
              "ref":    {
                "type": "string",
                "description":
                  "Branch, tag, or full SHA. Resolved to an immutable 40-char SHA at admission \
and recorded; the resolved SHA — never the ref — is what binds the publish."
              },
              "path":   {
                "type": "string",
                "description":
                  "Repo-relative directory containing the capability package, e.g. \
'plugins/kubernetes-audit'. Must be inside a materializable prefix (§3.3)."
              },
              "expect_sha": {
                "type": "string",
                "pattern": "^[0-9a-f]{40}$",
                "description":
                  "Optional. If present, admission fails unless 'ref' resolves to exactly this \
SHA. Closes the resolve-then-move race for automated publishers."
              }
            }
          },
          {
            "type": "object",
            "additionalProperties": false,
            "required": ["kind", "bundle_sha256", "bundle_bytes", "provenance"],
            "properties": {
              "kind":          { "const": "bundle" },
              "bundle_bytes":  {
                "type": "string",
                "contentEncoding": "base64",
                "description": "A tar archive produced by 'git archive'. Not a working-tree tar."
              },
              "bundle_sha256": {
                "type": "string",
                "pattern": "^[0-9a-f]{64}$",
                "description": "Digest of bundle_bytes. Verified before the archive is opened."
              },
              "provenance": {
                "type": "object",
                "additionalProperties": false,
                "required": ["repo", "commit_sha", "path"],
                "description":
                  "The commit the bundle was archived from. Admission re-derives the tree \
digest from the archive and requires it to equal the tree digest of <commit_sha>:<path> in \
<repo>. A bundle whose contents do not match a reachable commit is rejected — the bundle \
variant is a transport convenience, never an immutability escape hatch (§3.4).",
                "properties": {
                  "repo":       { "type": "string" },
                  "commit_sha": { "type": "string", "pattern": "^[0-9a-f]{40}$" },
                  "path":       { "type": "string" }
                }
              }
            }
          }
        ]
      },

      "namespace": {
        "type": "string",
        "description":
          "Target namespace, e.g. 'org/asg' or 'user/jason'. Must already exist \
(capmesh namespaces) and the caller must hold publish rights on it.",
        "pattern": "^(org|user|team)/[a-z0-9][a-z0-9-]{0,62}$"
      },

      "visibility": {
        "enum": ["private", "org", "shared"],
        "default": "private",
        "description":
          "Catalog visibility. 'org' and 'shared' on an org namespace additionally require the \
promotion path (cap.submit / cap.approve) and cannot be granted by cap.publish alone."
      },

      "lifecycle": {
        "enum": ["draft", "published"],
        "description":
          "'draft' registers the capability as advisory-only: it is searchable but cannot \
expand tools or permissions and cannot be bound by cap.delegate. 'published' makes it \
dispatchable and requires every precondition in §3-§5 to pass."
      },

      "supersedes": {
        "type": "array",
        "items": { "type": "string", "format": "uri" },
        "description":
          "Explicit capability URIs this publish replaces. Required to resolve a DUPLICATE_ \
CAPABILITY refusal (§4). Superseded rows are marked superseded_by, not deleted."
      },

      "dry_run": {
        "type": "boolean",
        "default": false,
        "description":
          "Run every admission check and return the full decision report without writing. \
The operator story (§7) always dry-runs first."
      },

      "reason": {
        "type": "string",
        "maxLength": 500,
        "description": "Free-text change rationale, recorded in the governance audit event."
      }
    }
  }
}
```

### 2.2 Output

```jsonc
{
  "decision": "accepted" | "refused",
  "dry_run": false,
  "resolved": {
    "repo": "…",
    "commit_sha": "<40-hex>",       // immutable binding, §3
    "path": "plugins/kubernetes-audit",
    "tree_sha": "<40-hex>",
    "release_root": "capability-roots/asg-os-plugins"
  },
  "capabilities": [
    { "uri": "…", "plugin": "…", "name": "…", "version": "…",
      "entrypoint": "…", "servable": true, "action": "insert" | "supersede" }
  ],
  "refusals": [
    { "code": "DUPLICATE_CAPABILITY" | "UNSERVABLE_ENTRYPOINT" |
              "AMBIENT_SOURCE_PATH"  | "UNREVIEWED_REF" |
              "NON_MATERIALIZABLE_PREFIX" | "NAMESPACE_DENIED",
      "message": "…", "remedy": "…" }
  ],
  "audit_event_id": "…"
}
```

**Refusal is atomic and all-or-nothing.** A publish covering N capabilities either registers
all N or registers none. Partial admission is exactly how the 439 unservable rows accumulated:
a batch that half-succeeded left the catalog describing content the authority did not have.

---

## 3. The immutability rule

**Invariant:** *catalog content is only ever derived from a reviewed git commit that the deploy
pipeline can reproduce. Ambient workstation paths are never a content source.*

This is not a new rule. It is `deploy-capmesh.sh`'s existing invariant, lifted from the deploy
boundary — where it is enforced today — up to the ingest boundary, where the violation actually
originates.

### 3.1 Binding a publish to a SHA

1. Caller supplies `repo` + `ref` (+ optional `expect_sha`).
2. Admission resolves `ref` → a full 40-char SHA against the **remote**, using
   `git ls-remote <repo> <ref>` for named refs. The local working tree is never consulted.
3. If `expect_sha` is present and differs, refuse `UNREVIEWED_REF`.
4. The resolved SHA is written to `capabilities.source_commit` (new column) and to the audit
   event. **Every later servability check and every replica sync validates against that SHA,
   not against a mutable ref.**
5. If `ref` resolves to a commit **not reachable from a protected branch** (`main`, or a tag
   matching the release pattern), refuse `UNREVIEWED_REF`. This is what makes the commit
   *reviewed* rather than merely *immutable*: an arbitrary SHA pushed to a scratch branch is
   immutable and still unreviewed.

### 3.2 The repo allowlist

`repo` must appear in a configured allowlist (env `CAPMESH_PUBLISH_REPOS`, comma-separated
canonical remote URLs). Fail-closed on unset — matching the deliberate fail-closed default
already used for `SUPERADMIN_ACTORS` in `capmesh/install_policy.py`, whose comment states the
principle: an unset variable *grants nobody*.

Any `source.repo` that resolves to a local filesystem path (`/…`, `~…`, `file://`, or a bare
relative path) is refused `AMBIENT_SOURCE_PATH` regardless of allowlist contents.

### 3.3 Materializable prefixes

`source.path` must be inside a prefix that the deploy pipeline actually copies into a release.
Today that set is exactly one entry, derived from `deploy-capmesh.sh:141-143`:

| Repo | Repo prefix | Materialized release root |
|---|---|---|
| `asg-os` | `plugins/` | `capability-roots/asg-os-plugins` |

A publish whose `path` is outside every mapped prefix is refused `NON_MATERIALIZABLE_PREFIX`
with the remedy: *move the package under `plugins/` in `asg-os`, or extend the prefix map and
`deploy-capmesh.sh` together in one reviewed change.*

**The prefix map is a single source of truth consumed by both `cap.publish` and
`deploy-capmesh.sh`.** They must not be able to drift — drift between "what ingest accepts" and
"what deploy ships" is the entire defect class this document exists to close. Concretely: the
map lives in one checked-in file, `deploy-capmesh.sh` iterates it to build its
`git archive` invocations, and admission reads the same file. Adding a root is one edit that
both sides observe.

### 3.4 Why bundles are still SHA-bound

The `bundle` variant exists so a publisher without direct remote access can still ship. It is
**not** an immutability bypass: admission re-derives the tree digest from the archive and
requires equality with `<commit_sha>:<path>` in the allowlisted repo. A bundle that does not
correspond to a reachable reviewed commit is refused exactly like a bad ref. The bundle changes
*transport*, never *provenance*.

---

## 4. Duplicate prevention

**Measured:** 141 of 477 `skill-registry` packages duplicated packages already canonical in
`asg-os/plugins`, at divergent versions, with no recorded relationship.

### 4.1 The check

Identity key: **`(plugin, name)`** — deliberately *not* including version or root. Two rows with
the same `(plugin, name)` from different roots are the failure being prevented; keying on
version or root would let precisely that pair through.

At admission, for each capability the source yields:

```
existing = SELECT uri, version, package_path, source_commit, lifecycle
           FROM capabilities
           WHERE plugin = ? AND name = ? AND superseded_by IS NULL
```

- **No row** → accept as `insert`.
- **Row exists, and its `uri` is listed in the request's `supersedes`** → accept as
  `supersede`. Write the new row; set `superseded_by = <new uri>` on the old row. The old row
  is **retained, not deleted** — history stays auditable and any live delegate holding the old
  URI gets a resolvable, explicitly-superseded answer rather than a dangling reference.
- **Row exists and is not listed in `supersedes`** → **refuse** `DUPLICATE_CAPABILITY`.

Same-`(plugin, name)` collisions *within a single publish request* are refused the same way —
a request cannot supersede itself into coherence.

### 4.2 Operator-facing error

```
REFUSED: DUPLICATE_CAPABILITY

  capability   kubernetes-audit / audit-cluster
  you are publishing   @1.2.0  from asg-os@a1b2c3d  plugins/kubernetes-audit
  already registered   @1.1.0  from asg-os@9f8e7d6  capability-roots/asg-os-plugins/kubernetes-audit
                       uri: cap://org/asg/kubernetes-audit/audit-cluster@1.1.0

  A capability with this (plugin, name) already exists from another source. Publishing a
  second row would leave ranking free to return either one — this is the defect that put
  kubernetes-audit into the catalog at both @0.1.0 and @1.1.0.

  Choose one:
    (a) Supersede the existing capability — the normal path for a new version:
          supersedes: ["cap://org/asg/kubernetes-audit/audit-cluster@1.1.0"]
    (b) Publish under a distinct name if this is genuinely a different capability.
    (c) Cancel, if the existing capability already does this.
```

The error names the winner, the loser, both commits, and the exact remedy. An operator should
never have to query the catalog to understand a refusal.

---

## 5. Servability precondition

**This single check would have prevented all 439 unservable rows.**

**Rule:** *refuse to register any capability whose entrypoint body cannot be resolved from a
root the authority will actually have after deploy.*

### 5.1 The check

For each capability, admission computes the **post-deploy authority path** — not the path the
content happens to occupy on any workstation:

```
release_root  = prefix_map[repo][matched_prefix]        # e.g. capability-roots/asg-os-plugins
package_rel   = source.path  with matched_prefix stripped
authority_rel = release_root / package_rel / entrypoint
```

Then it verifies the blob exists **in the bound commit's tree**:

```
git cat-file -e <commit_sha>:<source.path>/<entrypoint>
```

Verifying against the git tree rather than against a filesystem is the load-bearing detail.
A filesystem check would pass on the publisher's machine — that is exactly how the ambient
paths got in. The git tree is the same content `deploy-capmesh.sh` will `git archive` at deploy
time, so a pass here is a genuine prediction that the authority will have the bytes.

Additionally required for `lifecycle: "published"`:

- `authority_rel` must be a path under the canonical root that survives the
  `CAPMESH_ROOTS` guard at `deploy-capmesh.sh:311-315`.
- The entrypoint must be non-empty and parse under the same manifest reader that
  `capmesh/manifest.py` uses for its `from_skill` / `from_agent` / `from_command` /
  `from_plugin_manifest` / `from_mcp_manifest` constructors. A file that ingest cannot parse
  is not servable even though the blob exists.

`lifecycle: "draft"` relaxes only the last two: a draft may be registered with an unparseable
or not-yet-materialized entrypoint, because drafts are advisory and can never be bound by
`cap.delegate`. Drafts therefore cannot reproduce the HTTP 400.

### 5.2 Refusal

```
REFUSED: UNSERVABLE_ENTRYPOINT

  capability  proton-pass-cli / vault-ops
  entrypoint  commands/vault-ops.md
  resolved to capability-roots/asg-os-plugins/proton-pass-cli/commands/vault-ops.md
  not present in asg-os@a1b2c3d

  The authority materializes only reviewed git content (deploy-capmesh.sh:141). Registering
  this would advertise a capability the authority cannot serve — the condition that returned
  HTTP 400 from cap.delegate and stalled the non-voting replica on exactly this file.

  Remedy: commit commands/vault-ops.md under plugins/proton-pass-cli in asg-os, then republish
  against the merge commit.
```

### 5.3 Closing the back door

The precondition is worthless while `capmesh ingest` still walks home directories. Two changes
land with it:

1. **`DEFAULT_ROOTS` drops the four ambient entries.** It becomes
   `("~/GitHub/asg-os/plugins",)` — repo content only. The four home-dir roots are the ingest
   surface that produced every unservable row.
2. **`capmesh ingest` refuses any root not present in the deploy prefix map** unless invoked
   with an explicit development flag that additionally forces `lifecycle: "draft"` and marks
   every resulting row `source_kind: "local-dev"`. Local-dev rows are never replicated to the
   authority and are excluded from `cap.delegate` binding.

After this, an operator physically cannot put an unservable row into the authority catalog
through the supported path.

---

## 6. Migration path for the 336 distinct capabilities

The 141 duplicates need no migration — they are already canonical in `asg-os/plugins`; the
skill-registry copies are deleted. The 336 genuinely-distinct capabilities do need a path.

The goal state for each: **git-tracked under `plugins/` in `asg-os`, reviewed on `main`,
materializable by `deploy-capmesh.sh`, registered via `cap.publish`.**

### Phase M0 — Freeze (prerequisite)

Land §5.3. New ambient rows stop being creatable before existing ones are migrated, otherwise
migration races new drift.

### Phase M1 — Classify

Produce a manifest over all 477 skill-registry packages, one row each:

| field | meaning |
|---|---|
| `package` | directory name |
| `class` | `duplicate-identical` \| `duplicate-divergent` \| `distinct` |
| `canonical_uri` | for duplicates: the `asg-os/plugins` capability it shadows |
| `entrypoints` | files ingest would parse |
| `unservable_rows` | live catalog rows currently pointing into this package |

`duplicate-identical` (content-equal to canonical) → delete, no review.
`duplicate-divergent` (same `(plugin, name)`, different content) → **must not be silently
deleted**; it may carry a local fix that never made it upstream. Diff against canonical and
either fold the delta into the canonical package or reclassify as `distinct` under a new name.

### Phase M2 — Land content in batches

Per batch (10–20 packages, grouped by owner):

1. `git mv` / copy the package tree into `asg-os/plugins/<package>/`.
2. Normalize to the manifest shapes `capmesh/manifest.py` already reads. A package that needs
   no normalization is a strong signal it was always repo-shaped and only ever lived in a home
   dir by accident.
3. Open a PR. **The review gate is the migration's only quality control** — this content has
   never been reviewed by anyone. Review checks: no secrets, no absolute home paths inside the
   content, entrypoints resolve relative to the package, no `(plugin, name)` collision with
   existing canonical packages.
4. Merge to `main`.

### Phase M3 — Publish and cut over

Per merged batch:

```
cap.publish  source={git, asg-os, main, plugins/<package>}  lifecycle=draft   dry_run=true
cap.publish  source={git, asg-os, main, plugins/<package>}  lifecycle=draft
# verify search + load against the draft
cap.publish  … lifecycle=published  supersedes=[<old ambient uri>, …]
```

Publishing with `supersedes` pointed at the old ambient rows is what retires them: the ambient
row becomes `superseded_by` the new git-backed row, so any holder of the old URI resolves to a
servable answer instead of a 400.

### Phase M4 — Sweep the residue

After every batch is superseded, any catalog row still satisfying
`package_path NOT LIKE 'capability-roots/%'` is orphaned by definition. Report them, then
retire them. **Success criterion, directly against the two measurements that opened this
document:** distinct roots in the authority catalog drops from 732 toward the small mapped set,
and roots-that-do-not-exist-on-the-authority reaches **0**.

The replica-sync abort in `ops/sync-nonvoting-member.sh` is the natural regression test — it
already fails loudly on exactly this condition. A clean sync of the Mac mirror is proof the
sweep is complete, and re-establishes the failover mirror that has been dead since 2026-07-14.

---

## 7. The operator story

Publishing a new skill, start to finish. **No home-directory install appears anywhere.**

### 7.1 Author

```sh
cd ~/GitHub/asg-os
mkdir -p plugins/my-new-skill/skills/my-new-skill
$EDITOR plugins/my-new-skill/skills/my-new-skill/SKILL.md
```

The package is authored *in the repo*. There is no `~/.agents/skill-registry` step, no
`~/.claude/plugins/cache` step, and no "install it locally to try it" step — §7.2 replaces
that.

### 7.2 Try it, without installing it

```sh
capmesh publish --local-dev \
  --path plugins/my-new-skill \
  --namespace user/jason \
  --dry-run
```

`--local-dev` registers a **draft, non-replicated, non-delegatable** row from the working tree
so the author can `capmesh search` / `capmesh load` against it. It cannot reach the authority
and cannot be bound by `cap.delegate`. This is the affordance that makes home-dir install
unnecessary — the reason operators reached for it was iteration speed, and this returns that
without the drift.

### 7.3 Review

```sh
git add plugins/my-new-skill
git commit -m "feat(capmesh): add my-new-skill"
git push -u origin feat/my-new-skill
gh pr create --fill
```

Merge to `main`. The merge commit is the reviewed, immutable, materializable artifact that §3
binds to.

### 7.4 Dry-run the real publish

```sh
capmesh publish \
  --repo   git@github.com:MRIHub/asg-os.git \
  --ref    main \
  --path   plugins/my-new-skill \
  --namespace org/asg \
  --lifecycle draft \
  --dry-run --json
```

Returns the full decision report: resolved SHA, per-capability servability, and any refusal
with its remedy. Nothing is written.

### 7.5 Publish

```sh
capmesh publish --repo … --ref main --path plugins/my-new-skill \
  --namespace org/asg --lifecycle draft
# search/load the draft, confirm ranking finds it for the intended queries

capmesh publish --repo … --ref main --path plugins/my-new-skill \
  --namespace org/asg --lifecycle published \
  --reason "reviewed in PR #1234"
```

### 7.6 Ship a new version

Identical, plus the supersede that §4 requires:

```sh
capmesh publish --repo … --ref main --path plugins/my-new-skill \
  --namespace org/asg --lifecycle published \
  --supersedes cap://org/asg/my-new-skill/my-new-skill@1.0.0 \
  --reason "1.1.0 — reviewed in PR #1301"
```

Omitting `--supersedes` refuses with `DUPLICATE_CAPABILITY` (§4.2) rather than silently
creating the second row. **Duplication becomes a loud refusal instead of a quiet defect.**

### 7.7 Deploy

Unchanged and operator-driven. `ops/deploy-capmesh.sh` `git archive`s the same reviewed commit
`cap.publish` bound to, so the catalog and the release are derived from one SHA by construction.

---

## 8. Invariants this contract establishes

1. Every catalog row is traceable to a reviewed commit reachable from a protected branch.
2. Every `published` row's entrypoint is present in that commit's tree, under a prefix the
   deploy pipeline materializes.
3. No two live rows share a `(plugin, name)`; version succession is explicit via `supersedes`.
4. Ingest's accepted root set and deploy's materialized root set are one shared map — they
   cannot drift.
5. The supported author→publish path never writes to a home directory, so local install stops
   being the path of least resistance and then stops being possible.

## 9. Open questions for the operator

- **Protected-branch definition (§3.1 step 5).** `main` only, or `main` plus release tags?
- **Prefix map extension (§3.3).** Should additional roots beyond `plugins/` be allowed at all,
  or is a single canonical root the desired end state?
- **`duplicate-divergent` adjudication (§M1).** Who decides whether a divergent local copy
  carries a real fix versus stale drift?
- **`--local-dev` scope (§7.2).** Working-tree draft rows are a deliberate ergonomic
  concession. Confirm they are acceptable, given they are non-replicated and non-delegatable.
