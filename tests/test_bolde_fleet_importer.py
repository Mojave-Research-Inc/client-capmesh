from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


def _resolve_importer_script() -> Path:
    """Walk up from this test file to find scripts/import-bolde-capability-fleet.py.

    Robust to repository layout depth so the suite does not assume a particular
    monorepo nesting (the asg-os source lived under services/asg-capmesh/tests).
    """
    here = Path(__file__).resolve()
    for parent in (here.parent, *here.parents):
        candidate = parent / "scripts" / "import-bolde-capability-fleet.py"
        if candidate.is_file():
            return candidate
    raise FileNotFoundError("scripts/import-bolde-capability-fleet.py not found above " + str(here))


SCRIPT = _resolve_importer_script()
SPEC = importlib.util.spec_from_file_location("import_bolde_capability_fleet", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
IMPORTER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(IMPORTER)


def make_managed_plugin(
    root: Path, name: str, marker: str, *, conversion: str | None = None
) -> Path:
    plugin = root / name
    manifest = plugin / ".claude-plugin" / "plugin.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(
        json.dumps(
            {
                "name": name,
                "sourceProvenance": {
                    "fleet": IMPORTER.FLEET_NAME,
                    "conversion": conversion or IMPORTER.CONVERSION_ID,
                },
            }
        ),
        encoding="utf-8",
    )
    (plugin / "marker.txt").write_text(marker, encoding="utf-8")
    return plugin


def _build_source_fleet(bundle: Path) -> None:
    """Build a complete JW SeeSuite fleet bundle in *bundle*.

    The bundle satisfies validate_source() and yields exactly the 6/25/23/39
    capability counts validate_generated() enforces, so generate() can run end
    to end against synthetic input instead of a committed external corpus.
    Capability frontmatter names use the jw-seesuite prefix to exercise the
    importer's seesuite->bolde transformation; every agent points at skill-00 so
    agent skill references resolve after transformation.
    """
    plugin_root = bundle / "adapters" / "claude" / "plugins"
    plugin_root.mkdir(parents=True)
    (bundle / "FLEET_MANIFEST.json").write_text(
        json.dumps(
            {
                "name": IMPORTER.FLEET_NAME,
                "version": IMPORTER.SOURCE_FLEET_VERSION,
                "plugins": [{"name": name} for name in IMPORTER.PLUGIN_MAP],
            }
        ),
        encoding="utf-8",
    )
    source_names = list(IMPORTER.PLUGIN_MAP)

    for source_name in source_names:
        plugin = plugin_root / source_name
        (plugin / ".claude-plugin").mkdir(parents=True)
        (plugin / ".claude-plugin" / "plugin.json").write_text(
            json.dumps(
                {"name": source_name, "version": "1.0.0", "description": "JW SEESUITE plugin"}
            ),
            encoding="utf-8",
        )
        (plugin / "README.md").write_text(
            f"# {source_name} plugin\n\nSeeSuite capability plugin.\n",
            encoding="utf-8",
        )

    def skill_name(i: int) -> str:
        return f"jw-seesuite-skill-{i:02d}"

    def agent_name(i: int) -> str:
        return f"jw-seesuite-agent-{i:02d}"

    def command_name(i: int) -> str:
        return f"jw-seesuite-command-{i:02d}"

    for i in range(25):
        plugin = plugin_root / source_names[i % 6]
        skill_dir = plugin / "skills" / skill_name(i)
        skill_dir.mkdir(parents=True, exist_ok=True)
        (skill_dir / "SKILL.md").write_text(
            "---\n"
            f"name: {skill_name(i)}\n"
            f'description: "JW SEESUITE skill {i:02d}"\n'
            "---\n\n"
            f"# Skill {i:02d}\n\nSeeSuite body.\n",
            encoding="utf-8",
        )

    for i in range(23):
        plugin = plugin_root / source_names[i % 6]
        (plugin / "agents").mkdir(parents=True, exist_ok=True)
        (plugin / "agents" / f"{agent_name(i)}.md").write_text(
            "---\n"
            f"name: {agent_name(i)}\n"
            f'description: "JW SEESUITE agent {i:02d}"\n'
            "---\n\n"
            f"# Agent {i:02d}\n\n- :{skill_name(0)}\n",
            encoding="utf-8",
        )

    for i in range(39):
        plugin = plugin_root / source_names[i % 6]
        (plugin / "commands").mkdir(parents=True, exist_ok=True)
        (plugin / "commands" / f"{command_name(i)}.md").write_text(
            "---\n"
            f"name: {command_name(i)}\n"
            f'description: "JW SEESUITE command {i:02d}"\n'
            "---\n\n"
            f"# Command {i:02d}\n\nRun a seesuite action.\n",
            encoding="utf-8",
        )


class BoldeFleetImporterTests(unittest.TestCase):
    def test_install_replaces_managed_plugins(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            plugins = root / "plugins"
            generated = root / "generated"
            plugins.mkdir()
            generated.mkdir()
            make_managed_plugin(
                plugins, "bolde-command", "old", conversion="bolde-native-semantic-v1"
            )
            candidate = make_managed_plugin(generated, "bolde-command", "new")

            IMPORTER.install_generated([candidate], plugins)

            self.assertEqual((plugins / "bolde-command" / "marker.txt").read_text(), "new")
            self.assertEqual(list(root.glob(".bolde-capability-import-*")), [])

    def test_install_refuses_unmanaged_destination(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            plugins = root / "plugins"
            generated = root / "generated"
            plugins.mkdir()
            generated.mkdir()
            unmanaged = plugins / "bolde-command"
            unmanaged.mkdir()
            (unmanaged / "keep.txt").write_text("owner data", encoding="utf-8")
            candidate = make_managed_plugin(generated, "bolde-command", "new")

            with self.assertRaisesRegex(IMPORTER.ImportFailure, "unmanaged plugin"):
                IMPORTER.install_generated([candidate], plugins)

            self.assertEqual((unmanaged / "keep.txt").read_text(), "owner data")

    def test_failed_multi_plugin_swap_rolls_back_every_destination(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            plugins = root / "plugins"
            generated = root / "generated"
            plugins.mkdir()
            generated.mkdir()
            candidates = []
            for name in ("bolde-command", "bolde-foundation"):
                make_managed_plugin(plugins, name, f"old-{name}")
                candidates.append(make_managed_plugin(generated, name, f"new-{name}"))

            real_replace = IMPORTER.os.replace
            calls = 0

            def fail_during_second_install(source: Path, destination: Path) -> None:
                nonlocal calls
                calls += 1
                if calls == 4:
                    raise OSError("simulated swap failure")
                real_replace(source, destination)

            with mock.patch.object(IMPORTER.os, "replace", side_effect=fail_during_second_install):
                with self.assertRaisesRegex(OSError, "simulated swap failure"):
                    IMPORTER.install_generated(candidates, plugins)

            for name in ("bolde-command", "bolde-foundation"):
                marker = (plugins / name / "marker.txt").read_text()
                self.assertEqual(marker, f"old-{name}")

    def test_source_tree_rejects_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            target = root / "target.txt"
            target.write_text("data", encoding="utf-8")
            (root / "link.txt").symlink_to(target)
            with self.assertRaisesRegex(IMPORTER.ImportFailure, "symlink"):
                IMPORTER.tree_digest(root)

    def test_incomplete_rollback_preserves_recoverable_backup(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            plugins = root / "plugins"
            generated = root / "generated"
            plugins.mkdir()
            generated.mkdir()
            candidate = make_managed_plugin(generated, "bolde-command", "new")
            make_managed_plugin(plugins, "bolde-command", "old")

            real_replace = IMPORTER.os.replace
            calls = 0

            def fail_install_and_restore(source: Path, destination: Path) -> None:
                nonlocal calls
                calls += 1
                if calls in {2, 3}:
                    raise OSError("simulated install/restore failure")
                real_replace(source, destination)

            with mock.patch.object(IMPORTER.os, "replace", side_effect=fail_install_and_restore):
                with self.assertRaisesRegex(
                    IMPORTER.ImportFailure, "recoverable backups preserved"
                ):
                    IMPORTER.install_generated([candidate], plugins)

            transactions = list(root.glob(".bolde-capability-import-*"))
            self.assertEqual(len(transactions), 1)
            backup = transactions[0] / "backup" / "bolde-command" / "marker.txt"
            self.assertEqual(backup.read_text(), "old")

    def test_every_indexed_capability_declares_seesuite_bolde_identity(self) -> None:
        # Self-contained replacement for the asg-os corpus index: build a
        # complete synthetic source fleet, run the real generate() pipeline, and
        # assert every generated capability carries both identity markers.
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            bundle = root / "source-bundle"
            bundle.mkdir()
            _build_source_fleet(bundle)

            generated_root = root / "generated"
            generated_root.mkdir()
            generated = IMPORTER.generate(bundle, generated_root)

            plugin_names = set(IMPORTER.PLUGIN_MAP.values())
            self.assertEqual({plugin.name for plugin in generated}, plugin_names)

            sources: list[Path] = []
            for name in plugin_names:
                plugin = generated_root / name
                sources.append(plugin / ".claude-plugin" / "plugin.json")
                sources.extend(sorted(plugin.glob("skills/*/SKILL.md")))
                sources.extend(sorted(plugin.glob("agents/*.md")))
                sources.extend(sorted(plugin.glob("commands/*.md")))

            self.assertEqual(len(sources), 93)
            for source in sources:
                content = source.read_text(encoding="utf-8")
                self.assertIn(IMPORTER.IDENTITY_RULE, content, source)
                self.assertIn(IMPORTER.IDENTITY_DISCOVERY_SUFFIX, content, source)

            for name in plugin_names:
                readme = generated_root / name / "README.md"
                self.assertIn(IMPORTER.IDENTITY_RULE, readme.read_text(encoding="utf-8"))

    def test_transformed_text_canonicalizes_identity_and_versions(self) -> None:
        source = (
            "JW SEESUITE and SeeSuite and jw-seesuite and seesuite names\n"
            "effort: xhigh\n"
            "OpenLineage Python 1.51.0; OpenLineage Python releases, including 1.51.0\n"
            "see `.bolde-fleet/knowledge/` and https://github.com/example/bolde\n"
            "and `example/bolde` too. trailing-space line   \n"
        )
        out = IMPORTER.transformed_text(source)

        # All four identity tokens on the names line collapse to Bolde. The
        # repository-URL rewrites below intentionally reintroduce "jw-seesuite"
        # as the canonical source repo name (the fleet name is kept), so the
        # negations are scoped to the names line rather than the whole output.
        names_line = out.splitlines()[0]
        self.assertEqual(names_line, "BOLDE and Bolde and bolde and bolde names")
        self.assertNotIn("JW SEESUITE", names_line)
        self.assertNotIn("SeeSuite", names_line)
        self.assertIn("BOLDE", out)
        self.assertIn("Bolde", out)
        self.assertIn("bolde", out)

        # Version/effort baselines are pinned to the audited versions.
        self.assertNotIn("xhigh", out)
        self.assertIn("effort: low", out)
        self.assertNotIn("1.51.0", out)
        self.assertIn("1.47.0", out)
        self.assertIn("OpenLineage Python releases; 1.47.0 was verified on 2026-07-20", out)

        # Knowledge path and repository-URL rewrites use the sanitized literals.
        self.assertIn("`knowledge/`", out)
        self.assertNotIn("`.bolde-fleet/knowledge/`", out)
        self.assertIn(IMPORTER.SOURCE_REPOSITORY, out)
        self.assertNotIn("https://github.com/example/bolde", out)
        self.assertIn("`example/jw-seesuite`", out)
        self.assertNotIn("`example/bolde`", out)

        # Canonicalized text: no trailing whitespace, exactly one trailing newline.
        self.assertNotIn("line   \n", out)
        self.assertTrue(out.endswith("trailing-space line\n"))
        self.assertFalse(out.endswith("\n\n"))

    def test_validate_source_rejects_incomplete_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            # No manifest, no plugin root.
            with self.assertRaisesRegex(IMPORTER.ImportFailure, "not a complete"):
                IMPORTER.validate_source(root)

            # Present structure but wrong fleet identity.
            bundle = root / "wrong"
            plugin_root = bundle / "adapters" / "claude" / "plugins"
            plugin_root.mkdir(parents=True)
            (bundle / "FLEET_MANIFEST.json").write_text(
                json.dumps({"name": "other-fleet", "version": "9.9.9", "plugins": []}),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(IMPORTER.ImportFailure, "unsupported source fleet"):
                IMPORTER.validate_source(bundle)


if __name__ == "__main__":
    unittest.main()
