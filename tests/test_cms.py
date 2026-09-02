"""CMS 签名验证（v1.1 零依赖实现）测试：真实密码学 fixture + 对抗检出。

fixture 由 tests/make_fixture.py 用 cryptography 库生成（仅测试脚本，
产品代码零依赖不变）：CA → TSA 两级真实 RSA-SHA256 签名链。
"""
from __future__ import annotations

import hashlib
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agenttrace import cms

FIXDIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def setUpModule():
    """fixture 缺失时自动生成（封闭在 tests/fixtures/ 目录内）。"""
    if not os.path.exists(os.path.join(FIXDIR, "fixture_tsr.der")):
        from make_fixture import build_fixture
        build_fixture(FIXDIR)


def load():
    with open(os.path.join(FIXDIR, "fixture_tsr.der"), "rb") as f:
        tsr = f.read()
    with open(os.path.join(FIXDIR, "fixture_ca.der"), "rb") as f:
        ca = f.read()
    with open(os.path.join(FIXDIR, "fixture_tsa.der"), "rb") as f:
        tsa = f.read()
    return tsr, ca, tsa


class TestVerifyCms(unittest.TestCase):
    def test_valid_cms_trusted(self):
        """真实签名 + 正确 CA → verified, ca-trusted。"""
        tsr, ca, tsa = load()
        res = cms.verify_cms(tsr, ca_certs=[ca])
        self.assertTrue(res["verified"], res["problems"])
        self.assertEqual(res["level"], "ca-trusted")
        self.assertTrue(res["signature_math_ok"])
        self.assertTrue(res["message_digest_ok"])
        self.assertEqual(res["gen_time"], "20260901080000Z")

    def test_no_ca_still_detects_signature(self):
        """无 CA → 数学验签仍过（fallback 定位签名者证书）。"""
        tsr, ca, tsa = load()
        res = cms.verify_cms(tsr, ca_certs=None)
        self.assertTrue(res["signature_math_ok"], res["problems"])
        self.assertFalse(res["verified"])  # 未信任锚定，不能算通过

    def test_wrong_ca_rejected(self):
        """给错 CA（随机 DER 当 CA）→ 信任链不成立。"""
        tsr, ca, tsa = load()
        # 用另一个自签 RSA 证书冒充 CA：链验不过
        res = cms.verify_cms(tsr, ca_certs=[tsa])  # TSA 不是 CA，签不了 TSA
        # TSA 自签失败（CA 签的）→ 无 trusted 路径
        self.assertFalse(res["verified"])

    def test_tampered_signature_detected(self):
        """篡改签名值一位 → 数学验签失败。"""
        tsr, ca, tsa = load()
        # 找 encryptedDigest：在文件里替换签名值一个字节（fixture 尾部附近）
        bad = bytearray(tsr)
        # 翻转倒数第 130 字节（落在 RSA 签名区间）
        bad[-130] ^= 0xFF
        res = cms.verify_cms(bytes(bad), ca_certs=[ca])
        self.assertFalse(res["verified"])
        self.assertTrue(any("签名" in p or "异常" in p
                            for p in res["problems"]), res["problems"])

    def test_tampered_content_detected(self):
        """篡改 TSTInfo（eContent 内一字节）→ messageDigest 不符检出。"""
        tsr, ca, tsa = load()
        # 定位 message hash 区域：TSTInfo 里 fixture 特定哈希前缀
        needle = hashlib.sha256(b"anchor-sha256-digest-fixture").digest()
        i = tsr.find(needle)
        self.assertGreater(i, 0)
        bad = bytearray(tsr)
        bad[i] ^= 0xFF
        res = cms.verify_cms(bytes(bad), ca_certs=[ca])
        self.assertFalse(res["verified"])
        self.assertTrue(any("messageDigest" in p or "签名" in p
                            for p in res["problems"]), res["problems"])

    def test_forged_unsigned_tsr_still_caught(self):
        """v1.0 的 P0 场景：自造无签名伪造 TSR → CMS 验签必须拒绝。"""
        tsr, ca, tsa = load()
        # 用 mock TSA 的无签名假 TSR（test_tsa.make_fake_tsr）
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from test_tsa import make_fake_tsr
        forged = make_fake_tsr(hashlib.sha256(b"x").digest())
        res = cms.verify_cms(forged, ca_certs=[ca])
        self.assertFalse(res["verified"])


class TestDERPrimitives(unittest.TestCase):
    def test_roundtrip_short(self):
        e = cms.der_tlv(0x04, b"abc")
        t, v, raw, nxt = cms.parse_tlv(e, 0)
        self.assertEqual((t, v, raw, nxt), (0x04, b"abc", e, len(e)))

    def test_roundtrip_long(self):
        payload = b"\x7f" * 300
        e = cms.der_tlv(0x04, payload)
        t, v, raw, nxt = cms.parse_tlv(e, 0)
        self.assertEqual(v, payload)
        self.assertEqual(raw, e)

    def test_int_encoding(self):
        for n in (0, 1, 127, 128, 255, 256, 65537):
            b = cms.der_int(n)
            _, v, _, _ = cms.parse_tlv(b, 0)
            self.assertEqual(int.from_bytes(v, "big"), n)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestCliCafileIntegration(unittest.TestCase):
    """CLI 集成：tsa verify --cafile 完整链路（fixture 绑定真实锚定哈希）。

    需要 cryptography 动态生成绑定 fixture；缺失时 skip（已提交的静态
    fixture 覆盖纯验签部分，CI 上装有 cryptography 全量跑）。
    """

    def setUp(self):
        try:
            import make_fixture
            make_fixture._crypto()  # 探测 cryptography 可用性
        except ImportError:
            self.skipTest("cryptography 未装（测试专用依赖，CI 已装）")
        import subprocess
        import tempfile
        self.tmp = tempfile.mkdtemp()
        self.root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        # 建带 HMAC 锚定的库
        import sys as _s
        _s.path.insert(0, self.root)
        from agenttrace.anchor import AnchorKey
        from agenttrace.recorder import Recorder, make_session_start
        from agenttrace.store import EvidenceStore
        self.db = os.path.join(self.tmp, "ev.db")
        s = EvidenceStore(self.db, anchor_key=AnchorKey.generate())
        Recorder(s).ingest(make_session_start(agent="cms-cli"))
        s.close()
        # 用真实锚定文件哈希重新生成 fixture（TSR 签名绑定它）
        with open(self.db + ".anchor.json", "rb") as f:
            anchor_bytes = f.read()
        import make_fixture
        self.fx_dir = os.path.join(self.tmp, "fx")
        make_fixture.build_fixture(self.fx_dir, message=anchor_bytes)
        # 手工放 tsq/tsr/tsa.json（等效 stamp，但离线 fixture）
        from agenttrace import tsa
        h = tsa._anchor_hash(self.db)
        with open(self.db + ".anchor.tsq", "wb") as f:
            f.write(tsa.build_tsq(h))
        import shutil
        shutil.copy(os.path.join(self.fx_dir, "fixture_tsr.der"),
                    self.db + ".anchor.tsr")
        with open(self.db + ".anchor.tsa.json", "w") as f:
            f.write("{}")

    def run_cli(self, args):
        import subprocess
        env = {**os.environ, "PYTHONPATH": self.root,
               "AGENTTRACE_ANCHOR_KEY_PATH": self.fx_dir + os.sep + "no.key"}
        return subprocess.run([sys.executable, "-m", "agenttrace"] + args,
                              capture_output=True, text=True,
                              encoding="utf-8", errors="replace",
                              cwd=self.tmp,
                              env=env, timeout=180)

    def test_cafile_verify_passes_with_trusted_chain(self):
        r = self.run_cli(["tsa", "verify", "--db", self.db,
                          "--cafile", os.path.join(self.fx_dir, "fixture_ca.pem")])
        out = r.stdout + r.stderr
        self.assertEqual(r.returncode, 0, out)
        self.assertIn("CMS 签名验证通过", out)
        self.assertIn("ca-trusted", out)

    def test_cafile_verify_detects_tampered_anchor(self):
        # 篡改锚定 → 绑定层就失败（imprint 不符）
        with open(self.db + ".anchor.json", "rb") as f:
            data = bytearray(f.read())
        data[20] ^= 0xFF
        with open(self.db + ".anchor.json", "wb") as f:
            f.write(bytes(data))
        r = self.run_cli(["tsa", "verify", "--db", self.db,
                          "--cafile", os.path.join(self.fx_dir, "fixture_ca.pem")])
        out = r.stdout + r.stderr
        self.assertEqual(r.returncode, 2, out)
        self.assertIn("不符", out)

    def test_untrusted_cafile_rejected(self):
        # 用错误 CA（fixture 里 tsa 证书冒充 CA）→ 信任链不成立
        r = self.run_cli(["tsa", "verify", "--db", self.db,
                          "--cafile", os.path.join(self.fx_dir, "fixture_tsa.der")])
        # der 非 pem → load_ca_pem 报错
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
