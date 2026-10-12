"""Exercise the cog's real detection methods without loading a running Red bot."""

from __future__ import annotations

import ast
import io
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock
import uuid


class Response:
    def __init__(self, status, payload):
        self.status, self.payload = status, payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False

    async def json(self, **_):
        return self.payload


class BackendDetectionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        source = Path(__file__).with_name("logscan.py")
        if not source.exists():
            source = Path(__file__).with_name("discord_logscan.py")
        tree = ast.parse(source.read_text(encoding="utf-8"))
        original = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "LogScan")
        methods = {"log_attachments", "validate_attachment", "usable_log_attachments", "valid_log_count", "scan_prompt_content"}
        # Compile unchanged production methods; future annotations keep Discord optional.
        body = [node for node in original.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in methods]
        module = ast.Module(
            body=[
                ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0),
                ast.ClassDef(name="Detection", bases=[], keywords=[], body=body, decorator_list=[]),
            ],
            type_ignores=[],
        )
        ast.fix_missing_locations(module)
        self.requests = []
        self.fields = []
        self.response = Response(200, {"files": [{"content_size": 100}]})
        self.job_response = Response(200, {"phase": "complete", "result": {"files": [{"content_size": 100}, {"content_size": 200}]}})
        test = self

        class Form:
            def add_field(self, name, value, **kwargs):
                test.fields.append((name, value.getvalue(), kwargs))

        class Session(Response):
            def __init__(self, **_):
                pass

            def post(self, url, **kwargs):
                test.requests.append((url, kwargs))
                return test.response

            def get(self, *_args, **_kwargs):
                return test.job_response

        self.namespace = {
            "io": io,
            "uuid": uuid,
            "asyncio": SimpleNamespace(sleep=AsyncMock()),
            "MAX_BYTES": 1024**3,
            "MAX_BATCH_BYTES": 1024**3,
            "ALLOWED_SUFFIXES": (".log", ".zip", ".gz"),
            "SCAN_PROMPT_TIMEOUT_SECONDS": 10,
            "aiohttp": SimpleNamespace(FormData=Form, ClientSession=Session, ClientTimeout=lambda **_: None, ClientError=ConnectionError),
        }
        exec(compile(module, str(source), "exec"), self.namespace)
        self.cog = self.namespace["Detection"]()
        self.cog.config = SimpleNamespace(url=AsyncMock(return_value="https://example.test/"), api_key=AsyncMock(return_value="test-key"))
        self.cog.validated_log_counts = {}

    def attachment(self, filename="meta.log", content=b"[imagemaid.py:1] [INFO] ImageMaid"):
        return SimpleNamespace(id=1, filename=filename, content_type="text/plain", size=len(content), read=AsyncMock(return_value=content))

    async def test_imagemaid_named_meta_log_is_sent_to_backend_validator(self):
        attachment = self.attachment()
        self.assertEqual(await self.cog.validate_attachment(attachment), (100, 1))
        self.assertEqual(self.requests[0][0], "https://example.test/api/bot/validate")
        self.assertEqual(self.requests[0][1]["headers"]["Authorization"], "Bearer test-key")
        self.assertEqual(self.fields[0][1], await attachment.read())
        self.assertEqual(self.fields[0][2]["filename"], "meta.log")

    async def test_backend_rejection_is_not_overridden_by_filename(self):
        self.response = Response(400, {"error": "Not a supported log"})
        self.assertIsNone(await self.cog.validate_attachment(self.attachment("imagemaid.log", b"not a log")))

    async def test_queued_mixed_archive_uses_backend_file_count(self):
        self.response = Response(202, {"job_id": "queued"})
        attachment = self.attachment("mixed.zip", b"archive")
        usable = await self.cog.usable_log_attachments(SimpleNamespace(attachments=[attachment]))
        self.assertEqual(usable, [attachment])
        self.assertEqual(self.cog.valid_log_count(attachment), 2)
        self.assertIn("2 Kometa or ImageMaid log(s)", self.cog.scan_prompt_content(usable))

    async def test_missing_api_key_does_not_submit_attachment(self):
        self.cog.config.api_key = AsyncMock(return_value="")
        self.assertIsNone(await self.cog.validate_attachment(self.attachment()))
        self.assertEqual(self.requests, [])


if __name__ == "__main__":
    unittest.main()
