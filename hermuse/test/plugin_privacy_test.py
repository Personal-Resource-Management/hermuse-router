"""Privacy tagging tests for the local Hermes Muse router plugin."""

import importlib.util
import os
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch


PLUGIN_PATH = Path(os.environ.get(
    "PLUGIN_SOURCE",
    Path(__file__).resolve().parents[1] / "plugin" / "__init__.py",
))
SPEC = importlib.util.spec_from_file_location("hermuse_router_plugin_under_test", PLUGIN_PATH)
plugin = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(plugin)


class FakeSessionDB:
    CANONICAL_BOT_CHAT_TITLE = "Bot Chat"
    rows = {}
    per_home = None

    def __init__(self, db_path, read_only):
        self.db_path = db_path
        self.read_only = read_only

    def get_session(self, session_id):
        return (self.rows if self.per_home is None else self.per_home.get(self.db_path.parent, {})).get(session_id)

    def close(self):
        pass


class PluginPrivacyTest(unittest.TestCase):
    def setUp(self):
        self.home = Path("/synthetic/hermes-home")
        FakeSessionDB.rows = {}
        FakeSessionDB.per_home = None
        state = types.ModuleType("hermes_state")
        state.SessionDB = FakeSessionDB
        constants = types.ModuleType("hermes_constants")
        constants.get_hermes_home = lambda: self.home
        self.modules = patch.dict(sys.modules, {"hermes_state": state, "hermes_constants": constants})
        self.modules.start()
        self.homes_patch = patch.object(plugin, 'candidate_homes', return_value=[self.home])
        self.file_patch = patch.object(Path, 'is_file', return_value=True)
        self.homes_patch.start(); self.file_patch.start()

    def tearDown(self):
        self.modules.stop()
        self.homes_patch.stop(); self.file_patch.stop()

    def tag(self, session_id, headers=None, base_url="http://127.0.0.1:20129/v1"):
        request = {"model": "synthetic-local-model", "extra_headers": headers or {}}
        result = plugin.tag_request(request=request, session_id=session_id, base_url=base_url)
        return result["request"]["extra_headers"] if result else None

    def test_cron_session_is_private(self):
        FakeSessionDB.rows["cron-1"] = {"source": "cron", "title": "Scheduled task", "parent_session_id": None}
        headers = self.tag("cron-1")
        self.assertEqual(headers["X-Hermuse-Privacy"], "required")
        self.assertEqual(plugin.session_lineage("cron-1", self.home), ([("cron-1", self.home)], True))

    def test_bot_chat_and_compacted_descendant_are_private(self):
        FakeSessionDB.rows.update({
            "bot": {"source": "bot-chat", "title": "Bot Chat", "parent_session_id": None},
            "compacted": {"source": "cli", "title": "Compacted chat", "parent_session_id": "bot"},
        })
        self.assertEqual(plugin.session_lineage("compacted", self.home), ([("compacted", self.home), ("bot", self.home)], True))
        self.assertEqual(self.tag("compacted")["X-Hermuse-Privacy"], "required")

    def test_ordinary_cli_session_does_not_force_private(self):
        FakeSessionDB.rows["cli-1"] = {"source": "cli", "title": "Chat", "parent_session_id": None}
        headers = self.tag("cli-1")
        self.assertNotIn("X-Hermuse-Privacy", headers)
        self.assertIn("X-Hermuse-Lineage", headers)

    def test_unresolved_ancestry_fails_closed(self):
        FakeSessionDB.rows["child"] = {"source": "cli", "title": "Chat", "parent_session_id": "missing"}
        headers = self.tag("child")
        self.assertEqual(headers["X-Hermuse-Privacy"], "required")
        self.assertNotIn("X-Hermuse-Lineage", headers)

    def test_cyclic_ancestry_fails_closed(self):
        FakeSessionDB.rows.update({
            "a": {"source": "cli", "title": "A", "parent_session_id": "b"},
            "b": {"source": "cli", "title": "B", "parent_session_id": "a"},
        })
        headers = self.tag("a")
        self.assertEqual(headers["X-Hermuse-Privacy"], "required")

    def test_unrelated_provider_is_not_tagged(self):
        self.assertIsNone(self.tag("cli-1", base_url="https://api.example.invalid/v1"))

    def test_missing_session_id_is_private(self):
        headers = self.tag(None)
        self.assertEqual(headers["X-Hermuse-Privacy"], "required")
        self.assertTrue(headers["X-Hermuse-Session"].endswith(":auxiliary"))

    def test_existing_required_privacy_header_is_preserved(self):
        FakeSessionDB.rows["cli-1"] = {"source": "cli", "title": "Chat", "parent_session_id": None}
        headers = self.tag("cli-1", {"X-Hermuse-Privacy": "required"})
        self.assertEqual(headers["X-Hermuse-Privacy"], "required")

    def test_cross_profile_child_uses_its_parent_database_identity(self):
        voice = self.home / 'profiles' / 'voice'
        home = self.home / 'profiles' / 'home'
        self.homes_patch.stop()
        self.homes_patch = patch.object(plugin, 'candidate_homes', return_value=[self.home, voice, home]); self.homes_patch.start()
        FakeSessionDB.per_home = {voice: {
            'child': {'source':'subagent','parent_session_id':'parent'},
            'parent': {'source':'cli','parent_session_id':None},
        }}
        with patch.dict(sys.modules, {'hermes_constants': types.SimpleNamespace(get_hermes_home=lambda: home)}):
            headers = self.tag('child')
        lineage = __import__('json').loads(headers['X-Hermuse-Lineage'])
        prefix = __import__('hashlib').sha256(str(voice).encode()).hexdigest()[:16]
        active = __import__('hashlib').sha256(str(home).encode()).hexdigest()[:16]
        self.assertEqual(lineage, [active + ':child', prefix + ':child', active + ':parent', prefix + ':parent'])
        self.assertEqual(headers['X-Hermuse-Session'], active + ':child')
        self.assertNotIn('X-Hermuse-Privacy', headers)

    def test_cross_profile_private_or_ambiguous_ancestry_fails_closed(self):
        private = self.home / 'profiles' / 'private'
        voice = self.home / 'profiles' / 'voice'
        self.homes_patch.stop()
        self.homes_patch = patch.object(plugin, 'candidate_homes', return_value=[self.home, private, voice]); self.homes_patch.start()
        FakeSessionDB.per_home = {voice: {'child': {'source':'subagent','parent_session_id':'parent'}},
                                  private: {'parent': {'source':'cli','parent_session_id':None}}}
        self.assertEqual(self.tag('child')['X-Hermuse-Privacy'], 'required')
        FakeSessionDB.per_home[self.home] = {'parent': {'source':'cli','parent_session_id':None}}
        self.assertEqual(self.tag('child')['X-Hermuse-Privacy'], 'required')

    def test_database_read_error_cannot_fall_back_to_subscription(self):
        with patch.object(FakeSessionDB, 'get_session', side_effect=OSError('synthetic read failure')):
            headers = self.tag('child')
        self.assertEqual(headers['X-Hermuse-Privacy'], 'required')
        self.assertNotIn('X-Hermuse-Lineage', headers)


if __name__ == "__main__":
    unittest.main()
