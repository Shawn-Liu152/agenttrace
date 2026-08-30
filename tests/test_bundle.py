"""证据包（bundle）测试：导出 → 解包 → 清单校验 → 篡改检出 → 新环境独立验证。"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agenttrace import ed25519
from agenttrace import anchor_v2
from agenttrace.bundle import export_bundle, verify_manifest
from agenttrace.recorder import (
    Recorder, make_session_start, make_user_message,
    make_tool_call, make_tool_result,
)
from agenttrace.store import EvidenceStore


def build_db(db_path: str) -> None:
    s = EvidenceStore(db_path)
    r = Recorder(s)
    s.set_meta("agent", "hermes")
    s.set_meta("model", "m")
    for ev in (make_session_start(agent="hermes", model="m", tools=["terminal"]),
               make_user_message("清理旧数据"),
               make_tool_call("terminal", {"command": "rm -rf /data/old"}),
               make_tool_result("terminal", "deleted")):
        r.ingest(ev)
    s.close()


class TestBundle(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, "evidence.db")
        build_db(self.db)
        # 用 Ed25519 锚定（含公钥导出）
        self.kp = ed25519.Ed25519KeyPair.generate()
        s = EvidenceStore(self.db)
        anchor_v2.seal_anchor(self.db, s.all_events(), s.all_meta(), self.kp)
        s.close()

    def _export_and_extract(self, name="bundle.zip"):
        out = os.path.join(self.tmp, name)
        export_bundle(self.db, out)
        extract_dir = os.path.join(self.tmp, name + ".d")
        with zipfile.ZipFile(out) as zf:
            zf.extractall(extract_dir)
        # zip 内有顶层目录
        top = os.path.join(extract_dir, os.listdir(extract_dir)[0])
        return out, top

    def test_export_creates_zip_with_expected_members(self):
        out, top = self._export_and_extract()
        self.assertTrue(os.path.exists(out))
        for name in ("manifest.json", "README.txt", "evidence.db",
                     "evidence.db.anchor.json", "anchor.public_key.txt.pub" if False else None):
            if name:
                pass
        files = set(os.listdir(top))
        for expected in ("manifest.json", "README.txt", "evidence.db",
                         "evidence.db.anchor.json", "report.html", "anchor.public_key.txt"):
            self.assertIn(expected, files)

    def test_manifest_verify_passes(self):
        out, top = self._export_and_extract()
        ok, problems = verify_manifest(top)
        self.assertTrue(ok, problems)

    def test_tampered_file_detected(self):
        out, top = self._export_and_extract()
        # 篡改包内数据库（改一个字节）
        db_path = os.path.join(top, "evidence.db")
        with open(db_path, "r+b") as f:
            f.seek(100)
            orig = f.read(1)
            f.seek(100)
            f.write(bytes([orig[0] ^ 0xFF]))
        ok, problems = verify_manifest(top)
        self.assertFalse(ok)
        self.assertTrue(any("evidence.db" in p for p in problems), problems)

    def test_extra_file_detected(self):
        out, top = self._export_and_extract()
        with open(os.path.join(top, "evil_extra.txt"), "w") as f:
            f.write("injected")
        ok, problems = verify_manifest(top)
        self.assertFalse(ok)
        self.assertTrue(any("evil_extra.txt" in p for p in problems), problems)

    def test_missing_file_detected(self):
        out, top = self._export_and_extract()
        os.remove(os.path.join(top, "report.html"))
        ok, problems = verify_manifest(top)
        self.assertFalse(ok)
        self.assertTrue(any("report.html" in p for p in problems), problems)

    def test_extracted_db_verifies_independently(self):
        """核心：解包后的证据库在新环境用标准 verify 通过（含锚定）。"""
        out, top = self._export_and_extract()
        extracted_db = os.path.join(top, "evidence.db")  # 包内规范名
        # HMAC 锚定密钥不在验证端 —— 用 Ed25519 路径验证（无私钥）
        s = EvidenceStore(extracted_db)  # 无 HMAC 密钥 → 只校验链
        ok, problems, n = s.verify()
        s.close()
        self.assertTrue(ok, problems)
        self.assertEqual(n, 4)
        # Ed25519 锚定验证（验证端无私钥，绑定期望公钥）
        s2 = EvidenceStore(extracted_db)
        events2, meta2 = s2.all_events(), s2.all_meta()
        s2.close()
        ok2, problems2 = anchor_v2.verify_ed25519_anchor(
            extracted_db, events2, meta2,
            expected_public=self.kp.public_hex())
        self.assertTrue(ok2, problems2)

    def test_empty_db_rejected(self):
        empty_db = os.path.join(self.tmp, "empty.db")
        EvidenceStore(empty_db).close()
        with self.assertRaises(ValueError):
            export_bundle(empty_db, os.path.join(self.tmp, "empty.zip"))

    def test_hmac_only_bundle_works(self):
        """只有 HMAC 锚定（无 Ed25519）的库也能导出，且解包后 verify 带警告通过。"""
        db2 = os.path.join(self.tmp, "hmac.db")
        from agenttrace.anchor import AnchorKey
        s = EvidenceStore(db2, anchor_key=AnchorKey.generate())
        r = Recorder(s)
        s.set_meta("agent", "a")
        r.ingest(make_session_start(agent="a"))
        s.close()
        out = os.path.join(self.tmp, "hmac.zip")
        export_bundle(db2, out)
        extract_dir = os.path.join(self.tmp, "hmac.d")
        with zipfile.ZipFile(out) as zf:
            zf.extractall(extract_dir)
        top = os.path.join(extract_dir, os.listdir(extract_dir)[0])
        ok, problems = verify_manifest(top)
        self.assertTrue(ok, problems)
        # 解包后 verify：HMAC 密钥不在验证端 → "未锚定警告"（诚实降级）
        extracted = os.path.join(top, "evidence.db")  # 包内规范名
        s = EvidenceStore(extracted)
        ok2, problems2, n = s.verify()
        s.close()
        self.assertTrue(ok2)
        self.assertTrue(any("未锚定" in p for p in problems2), problems2)


if __name__ == "__main__":
    unittest.main(verbosity=2)