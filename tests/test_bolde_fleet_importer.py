from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).parents[3] / "scripts" / "import-bolde-capability-fleet.py"
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
        repo = SCRIPT.parent.parent
        plugin_names = set(IMPORTER.PLUGIN_MAP.values())
        sources: list[Path] = []
        for name in plugin_names:
            plugin = repo / "plugins" / name
            sources.append(plugin / ".claude-plugin" / "plugin.json")
            sources.extend(plugin.glob("skills/*/SKILL.md"))
            sources.extend(plugin.glob("agents/*.md"))
            sources.extend(plugin.glob("commands/*.md"))

        self.assertEqual(len(sources), 93)
        for source in sources:
            content = source.read_text(encoding="utf-8")
            self.assertIn(IMPORTER.IDENTITY_RULE, content, source)
            self.assertIn(IMPORTER.IDENTITY_DISCOVERY_SUFFIX, content, source)

        for name in plugin_names:
            readme = repo / "plugins" / name / "README.md"
            self.assertIn(IMPORTER.IDENTITY_RULE, readme.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
