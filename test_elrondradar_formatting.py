import ast
import os
import re
import time
import unittest
import urllib.parse
from pathlib import Path
from typing import Any, Optional, Tuple
from unittest.mock import patch


METHODS = {
    "_normalize_username",
    "_strip_code_fences",
    "_table_lines_from_output",
    "_compact_k8s_workload_name",
    "_code_block",
    "_code_blocks",
    "_tenant_node_from_pods",
    "_compact_pods_table",
    "_compact_pod_usage_table",
    "_split_discord",
    "_truncate_inline",
    "_md_value",
    "_store_links",
    "_admin_post_link",
    "_format_subscriptions",
    "_format_orders",
    "_support_jsonrpc_text",
    "_discord_linked_user_id",
    "_build_support_context",
    "_palantir_usage_block",
}


def load_subject_class():
    source_path = Path(__file__).resolve().parent / "elrondradar" / "elrondradar.py"
    tree = ast.parse(source_path.read_text())
    module_body = []
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            names = []
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        names.append(target.id)
            elif isinstance(node.target, ast.Name):
                names.append(node.target.id)
            if any(name in {"USERNAME_RE", "USERNAME_STOPWORDS"} for name in names):
                module_body.append(node)
        if isinstance(node, ast.ClassDef) and node.name == "ElrondRadar":
            methods = [item for item in node.body if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name in METHODS]
            module_body.append(ast.ClassDef(name="Subject", bases=[], keywords=[], body=methods, decorator_list=[]))
            break
    test_module = ast.Module(body=module_body, type_ignores=[])
    ast.fix_missing_locations(test_module)
    ns = {"os": os, "re": re, "time": time, "urllib": urllib, "Any": Any, "Optional": Optional, "Tuple": Tuple}
    exec(compile(test_module, str(source_path), "exec"), ns)
    return ns["Subject"]


class ElrondRadarFormattingTests(unittest.TestCase):
    def setUp(self):
        self.subject = load_subject_class()()

    def test_compacts_usage_from_decorated_or_fenced_output(self):
        raw = """📊 **Pod Usage**
_Tenant-supplied diagnostic data._
```text
POD                                      CONTAINER  CPU(cores)   MEMORY(bytes)
demo-radarr-7g8h9j0klm-ab12c            radarr       12m          512Mi
demo-radarr-exporter-7g8h9j0klm-cd34e   exporter      1m           32Mi
```"""
        formatted = self.subject._compact_pod_usage_table(raw, "demo")

        self.assertIn("APP", formatted)
        self.assertIn("CONTAINER", formatted)
        self.assertIn("radarr", formatted)
        self.assertIn("radarr-exporter", formatted)
        self.assertNotIn("7g8h9j0klm", formatted)
        self.assertNotIn("demo-", formatted)

    def test_preserves_legitimate_long_workload_suffixes(self):
        self.assertEqual(
            self.subject._compact_k8s_workload_name("media-configurator-abcdefgh-abcde", ""),
            "media-configurator-abcdefgh-abcde",
        )

    def test_compacts_pod_table_and_still_extracts_node_with_intro_text(self):
        raw = """📋 **Pods**
```text
APP     POD                                READY  STATUS   RESTARTS  AGE  NODE       IMAGE
radarr  radarr-7g8h9j0klm-ab12c            1/1    Running  0         2h   node-one   v5.27.5
plex    plex-very-long-name-8k9l0m1n2p-zz99q  1/1    Running  2         3d   node-two   v1
```"""
        formatted = self.subject._compact_pods_table(raw)
        node = self.subject._tenant_node_from_pods(raw)

        self.assertIn("APP", formatted)
        self.assertIn("POD", formatted)
        self.assertIn("radarr", formatted)
        self.assertIn("plex-very-long-name", formatted)
        self.assertNotIn("7g8h9j0klm", formatted)
        self.assertEqual(node, "node-one, node-two")

    def test_code_sections_fit_splitter_without_breaking_fences_or_dropping_rows(self):
        usage_rows = "\n".join(f"app-{index}  container  {index}m  {index}Mi" for index in range(80))
        pods_rows = "\n".join(f"app-{index}  pod-{index}  1/1  Running  0  1h" for index in range(80))
        usage_section = "\n".join(["📊 **Pod Usage**", *self.subject._code_blocks(usage_rows, 1050)])
        pods_section = "\n".join(["📋 **Pods**", *self.subject._code_blocks(pods_rows, 1050)])
        chunks = self.subject._split_discord("intro\n\n" + usage_section + "\n\n" + pods_section)
        joined = "\n".join(chunks)

        self.assertGreaterEqual(len(chunks), 2)
        self.assertIn("app-0  container", joined)
        self.assertIn("app-79  container", joined)
        self.assertIn("app-0  pod-0", joined)
        self.assertIn("app-79  pod-79", joined)
        for chunk in chunks:
            self.assertLessEqual(len(chunk), 1800)
            self.assertEqual(chunk.count("```") % 2, 0, chunk)


class ElrondRadarIdentityResolutionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.subject = load_subject_class()()

    async def test_discord_linked_profile_overrides_wrong_supplied_username(self):
        async def fake_discord_linked_user_id(discord_id):
            self.assertEqual(discord_id, "1472032059756122203")
            return 4242

        calls = []

        async def fake_support_http_json(base_url, path, secret, params=None, timeout=15):
            calls.append((path, dict(params or {})))
            if path == "/customer/profile":
                self.assertEqual(params, {"customer_id": "4242"})
                return {"id": 4242, "username": "spence23"}
            if path == "/tenant/lookup":
                self.assertEqual(params, {"username": "spence23"})
                return {"cluster": "elfhosted.cafe", "apps": ["comet"], "userId": 4242}
            raise AssertionError(path)

        self.subject._discord_linked_user_id = fake_discord_linked_user_id
        self.subject._support_http_json = fake_support_http_json
        with patch.dict(os.environ, {"WOO_SECRET": "woo", "GITOPS_SECRET": "gitops", "DISCORDBOT_SECRET": "discord"}, clear=True):
            context = await self.subject._build_support_context(
                username="spence",
                discord_id="1472032059756122203",
                include_kubernetes=False,
            )

        self.assertIn("ElfHosted username: `spence23`", context)
        self.assertIn(
            "Discord-linked billing profile username `spence23` differs from supplied ticket username `spence`; using verified Discord-linked billing username",
            context,
        )
        self.assertIn("`comet`", context)
        self.assertIn(("/customer/profile", {"customer_id": "4242"}), calls)
        self.assertIn(("/tenant/lookup", {"username": "spence23"}), calls)

    async def test_discord_id_parser_rejects_unlinked_message_containing_discord_digits(self):
        async def fake_jsonrpc(base_url, secret, tool_name, args, timeout=10):
            return "No user linked to Discord ID 1472032059756122203"

        self.subject._support_jsonrpc_text = fake_jsonrpc
        with patch.dict(os.environ, {"DISCORDBOT_SECRET": "discord"}, clear=True):
            self.assertIsNone(await self.subject._discord_linked_user_id("1472032059756122203"))

    async def test_discord_id_parser_requires_bare_positive_integer(self):
        async def fake_jsonrpc(base_url, secret, tool_name, args, timeout=10):
            return "WordPress User ID: 4242"

        self.subject._support_jsonrpc_text = fake_jsonrpc
        with patch.dict(os.environ, {"DISCORDBOT_SECRET": "discord"}, clear=True):
            self.assertIsNone(await self.subject._discord_linked_user_id("1472032059756122203"))

    async def test_invalid_discord_profile_does_not_skip_supplied_username_search(self):
        async def fake_discord_linked_user_id(discord_id):
            return 4242

        calls = []

        async def fake_support_http_json(base_url, path, secret, params=None, timeout=15):
            calls.append((path, dict(params or {})))
            if path == "/customer/profile":
                return {"id": 4242}
            if path == "/customer/search":
                self.assertEqual(params, {"query": "spence"})
                return {"customers": [{"id": 99, "username": "spence"}]}
            if path == "/tenant/lookup":
                self.assertEqual(params, {"username": "spence"})
                return {"cluster": "elfhosted.cafe", "apps": ["comet"], "userId": 99}
            raise AssertionError(path)

        self.subject._discord_linked_user_id = fake_discord_linked_user_id
        self.subject._support_http_json = fake_support_http_json
        with patch.dict(os.environ, {"WOO_SECRET": "woo", "GITOPS_SECRET": "gitops", "DISCORDBOT_SECRET": "discord"}, clear=True):
            context = await self.subject._build_support_context(
                username="spence",
                discord_id="1472032059756122203",
                include_kubernetes=False,
            )

        self.assertIn("ElfHosted username: `spence`", context)
        self.assertIn(("/customer/search", {"query": "spence"}), calls)
        self.assertIn(("/tenant/lookup", {"username": "spence"}), calls)


class PalantirUsageBlockTests(unittest.IsolatedAsyncioTestCase):
    """The intake block is shown only when a tenant is anomalous, and states
    what was measured rather than what it means."""

    def setUp(self):
        self.subject = load_subject_class()()

    def _stub(self, payload=None, error=None):
        async def fake(base_url, path, secret, params=None, timeout=15):
            if error:
                raise RuntimeError(error)
            return payload
        self.subject._support_http_json = fake

    async def test_unflagged_tenant_produces_no_block(self):
        # Most tickets have nothing to do with sharing. A usage block on all of
        # them would prime an agent to suspect a customer who has done nothing.
        self._stub({"flagged": False, "apps": [{"app": "plex", "clients": 4}]})
        with patch.dict(os.environ, {"ELROND_PALANTIR_URL": "http://p:8080", "ELROND_PALANTIR_SECRET": "t"}):
            block, warning = await self.subject._palantir_usage_block("jrcorwin")
        self.assertEqual(block, "")
        self.assertEqual(warning, "")

    async def test_flagged_tenant_shows_measurements(self):
        self._stub({"flagged": True, "apps": [
            {"app": "aiostreams", "clients": 84, "peak_concurrent": 2, "countries": 3,
             "requests": 130440, "flagged": True},
            {"app": "comet", "clients": 6, "peak_concurrent": 1, "countries": 1, "requests": 900},
        ]})
        with patch.dict(os.environ, {"ELROND_PALANTIR_URL": "http://p:8080", "ELROND_PALANTIR_SECRET": "t"}):
            block, warning = await self.subject._palantir_usage_block("gformica")
        self.assertEqual(warning, "")
        self.assertIn("84 clients", block)
        self.assertIn("2 at once", block)
        self.assertIn("130,440 requests", block)
        self.assertIn("Ask Elrond", block)

    async def test_block_states_facts_not_a_verdict(self):
        # The assessment lives in elrond, where someone deliberately asked for
        # it. Every strong signal here has had a confident-and-wrong case.
        self._stub({"flagged": True, "verdict": "resale",
                    "apps": [{"app": "aiostreams", "clients": 84, "flagged": True}]})
        with patch.dict(os.environ, {"ELROND_PALANTIR_URL": "http://p:8080", "ELROND_PALANTIR_SECRET": "t"}):
            block, _ = await self.subject._palantir_usage_block("gformica")
        for word in ("resale", "abuse", "suspend"):
            self.assertNotIn(word, block.lower(), f"{word!r} leaked into the intake block")

    async def test_lookup_failure_warns_but_does_not_break_intake(self):
        self._stub(error="connection refused")
        with patch.dict(os.environ, {"ELROND_PALANTIR_URL": "http://p:8080", "ELROND_PALANTIR_SECRET": "t"}):
            block, warning = await self.subject._palantir_usage_block("coins")
        self.assertEqual(block, "")
        self.assertIn("connection refused", warning)

    async def test_unconfigured_is_silent(self):
        self._stub({"flagged": True, "apps": [{"app": "x", "clients": 9}]})
        with patch.dict(os.environ, {"ELROND_PALANTIR_URL": "", "ELROND_PALANTIR_SECRET": ""}):
            block, warning = await self.subject._palantir_usage_block("coins")
        self.assertEqual(block, "")
        self.assertEqual(warning, "")


if __name__ == "__main__":
    unittest.main()
