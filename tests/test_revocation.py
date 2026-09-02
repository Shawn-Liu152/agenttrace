"""v1.2 证书吊销检查测试：CRL 本地校验 + OCSP 解析/验签（真实密码学 fixture）。

fixture 由 tests/make_fixture.py 用 cryptography 生成（EC CA 真签 CRL/OCSP），
产品代码 revocation.py 零依赖独立解析/验签；CLI 集成用例动态生成绑定锚定
哈希的 RSA fixture + 现场 CRL，走完整 `tsa verify --cafile --crl-file` 链路。
"""
from __future__ import annotations

import base64
import datetime
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agenttrace import cms, revocation as rv

FIXDIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
NOW = datetime.datetime(2026, 9, 2)


def setUpModule():
    if not os.path.exists(os.path.join(FIXDIR, "fixture_crl_good.der")):
        from make_fixture import build_revocation_fixtures
        build_revocation_fixtures(FIXDIR)


def _read(name):
    with open(os.path.join(FIXDIR, name), "rb") as f:
        return f.read()


class TestCRL(unittest.TestCase):
    def setUp(self):
        self.ca = _read("fixture_ec_ca.der")
        self.tsa = _read("fixture_ec_tsa.der")

    def test_good_crl_passes(self):
        r = rv.check_crl(self.tsa, _read("fixture_crl_good.der"),
                         [self.ca], now=NOW)
        self.assertFalse(r["revoked"])
        self.assertTrue(r["crl_signature_ok"])
        self.assertFalse(r["stale"])
        self.assertEqual(r["problems"], [])

    def test_revoked_crl_detected(self):
        r = rv.check_crl(self.tsa, _read("fixture_crl_revoked.der"),
                         [self.ca], now=NOW)
        self.assertTrue(r["revoked"])
        self.assertTrue(r["crl_signature_ok"])
        self.assertIsNotNone(r["revoked_at"])

    def test_other_serial_not_revoked(self):
        """吊销清单不含本证书序列号 → 签名有效但不吊销（现场生成 EC 链）。"""
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.x509.oid import NameOID
            import datetime as _dt
            import make_fixture
        except ImportError:
            self.skipTest("cryptography 未装")
        utc = _dt.timezone.utc
        now = _dt.datetime(2026, 1, 1, tzinfo=utc)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "t")])
        ca_key = ec.generate_private_key(ec.SECP256R1())
        ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
              .public_key(ca_key.public_key()).serial_number(1)
              .not_valid_before(now).not_valid_after(now + _dt.timedelta(days=365))
              .sign(ca_key, hashes.SHA256()))
        leaf_key = ec.generate_private_key(ec.SECP256R1())
        leaf = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(leaf_key.public_key()).serial_number(555)
                .not_valid_before(now).not_valid_after(now + _dt.timedelta(days=365))
                .sign(ca_key, hashes.SHA256()))
        # CRL 吊销的是 999，leaf 是 555
        crl = make_fixture.build_crl_der(
            ca_key, name, [999], _dt.datetime(2036, 1, 1, tzinfo=utc))
        r = rv.check_crl(leaf.public_bytes(serialization.Encoding.DER), crl,
                         [ca.public_bytes(serialization.Encoding.DER)], now=NOW)
        self.assertTrue(r["crl_signature_ok"])
        self.assertFalse(r["revoked"])

    def test_stale_crl_warns(self):
        r = rv.check_crl(self.tsa, _read("fixture_crl_stale.der"),
                         [self.ca], now=NOW)
        self.assertTrue(r["stale"])
        self.assertTrue(any("nextUpdate" in p for p in r["problems"]))

    def test_wrong_ca_rejected(self):
        rsa_ca = _read("fixture_ca.der")
        r = rv.check_crl(self.tsa, _read("fixture_crl_good.der"),
                         [rsa_ca], now=NOW)
        self.assertFalse(r["crl_signature_ok"])
        self.assertTrue(any("无法用任何受信 CA 验证" in p for p in r["problems"]))

    def test_no_ca_explicit_degradation(self):
        r = rv.check_crl(self.tsa, _read("fixture_crl_good.der"),
                         ca_certs=None, now=NOW)
        self.assertIsNone(r["crl_signature_ok"])
        self.assertTrue(any("未提供受信 CA" in p for p in r["problems"]))

    def test_pem_crl(self):
        der = _read("fixture_crl_good.der")
        pem = (b"-----BEGIN X509 CRL-----\n" + base64.encodebytes(der)
               + b"-----END X509 CRL-----\n")
        r = rv.check_crl(self.tsa, pem, [self.ca], now=NOW)
        self.assertTrue(r["crl_signature_ok"])

    def test_tampered_crl_caught(self):
        """翻转 TBS / 外层算法 OID / 签名区任一字节 → 签名验证必须失败。"""
        good = _read("fixture_crl_good.der")
        for idx in (10, len(good) // 2, len(good) - 10):
            bad = bytearray(good)
            bad[idx] ^= 0xFF
            r = rv.check_crl(self.tsa, bytes(bad), [self.ca], now=NOW)
            self.assertFalse(r["crl_signature_ok"], f"idx={idx} 未检出")
            self.assertTrue(r["problems"], f"idx={idx} 无问题输出")


class TestOCSP(unittest.TestCase):
    def setUp(self):
        self.ca = _read("fixture_ec_ca.der")
        self.tsa = _read("fixture_ec_tsa.der")

    def _parsed(self, name):
        return rv.parse_ocsp_response(_read(name))

    def test_good_response_verified(self):
        p = self._parsed("fixture_ocsp_good.der")
        self.assertEqual(p["status"], "successful")
        self.assertEqual(p["cert_status"], "good")
        ok, problems = rv.verify_ocsp_response(
            p, self.tsa, self.ca, request_nonce=b"fixednonce1234567", now=NOW)
        self.assertTrue(ok, problems)

    def test_revoked_response(self):
        p = self._parsed("fixture_ocsp_revoked.der")
        self.assertEqual(p["cert_status"], "revoked")
        self.assertIn("20260601", p.get("revoked_at", ""))
        ok, _ = rv.verify_ocsp_response(
            p, self.tsa, self.ca, request_nonce=b"fixednonce1234567", now=NOW)
        self.assertTrue(ok)  # 响应本身真实有效（状态是 revoked）

    def test_wrong_nonce_rejected(self):
        p = self._parsed("fixture_ocsp_good.der")
        ok, problems = rv.verify_ocsp_response(
            p, self.tsa, self.ca, request_nonce=b"x" * 15, now=NOW)
        self.assertFalse(ok)
        self.assertTrue(any("nonce" in x for x in problems))

    def test_wrong_issuer_rejected(self):
        p = self._parsed("fixture_ocsp_good.der")
        ok, _ = rv.verify_ocsp_response(
            p, self.tsa, _read("fixture_ca.der"),
            request_nonce=b"fixednonce1234567", now=NOW)
        self.assertFalse(ok)

    def test_wrong_cert_rejected(self):
        p = self._parsed("fixture_ocsp_good.der")
        ok, _ = rv.verify_ocsp_response(
            p, _read("fixture_tsa.der"), self.ca,
            request_nonce=b"fixednonce1234567", now=NOW)
        self.assertFalse(ok)

    def test_request_byte_identical_with_cryptography(self):
        """无 nonce 的 CertID/请求结构必须与 cryptography 逐字节一致。"""
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.x509 import ocsp
        except ImportError:
            self.skipTest("cryptography 未装")
        ref = (ocsp.OCSPRequestBuilder()
               .add_certificate(x509.load_der_x509_certificate(self.tsa),
                                 x509.load_der_x509_certificate(self.ca),
                                 hashes.SHA1())
               .build().public_bytes(serialization.Encoding.DER))
        self.assertEqual(ref, rv.build_ocsp_request(self.tsa, self.ca))

    def test_request_with_nonce_roundtrip(self):
        req = rv.build_ocsp_request(self.tsa, self.ca, nonce=b"n" * 16)
        # 外层 OCSPRequest → tbsRequest 末字段为 [2] nonce
        top = cms.seq_items(req)
        tbs = cms.children(top[0][1])
        self.assertEqual(tbs[-1][0], 0xA2)

    def test_unsuccessful_status(self):
        try:
            from cryptography.x509 import ocsp
            from cryptography.hazmat.primitives import serialization
        except ImportError:
            self.skipTest("cryptography 未装")
        raw = (ocsp.OCSPResponseBuilder()
               .build_unsuccessful(ocsp.OCSPResponseStatus.MALFORMED_REQUEST)
               .public_bytes(serialization.Encoding.DER))
        p = rv.parse_ocsp_response(raw)
        self.assertNotEqual(p["status_code"], 0)
        ok, problems = rv.verify_ocsp_response(p, self.tsa, self.ca, now=NOW)
        self.assertFalse(ok)

    def test_future_this_update_flagged(self):
        """thisUpdate 在未来（时钟/伪造）→ 验证失败。签名 tbs_raw 保持不变，
        只改解析层的时间字段，隔离出时间窗判定分支。"""
        p = self._parsed("fixture_ocsp_good.der")
        p["this_update"] = "20990101000000Z"
        p["cert_id_der"] = rv.cert_id(self.tsa, self.ca)
        ok, problems = rv.verify_ocsp_response(
            p, self.tsa, self.ca, request_nonce=b"fixednonce1234567", now=NOW)
        self.assertFalse(ok)
        self.assertTrue(any("未来" in x for x in problems))


class TestCliRevocation(unittest.TestCase):
    """CLI 端到端：tsa verify --cafile --crl-file（动态绑定锚定哈希）。"""

    def setUp(self):
        try:
            import make_fixture
            make_fixture._crypto()
        except ImportError:
            self.skipTest("cryptography 未装（测试专用依赖，CI 已装）")
        import make_fixture
        from agenttrace.anchor import AnchorKey
        from agenttrace.recorder import Recorder, make_session_start
        from agenttrace.store import EvidenceStore
        from agenttrace import tsa
        import datetime
        self.tmp = tempfile.mkdtemp()
        self.root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.db = os.path.join(self.tmp, "ev.db")
        s = EvidenceStore(self.db, anchor_key=AnchorKey.generate())
        Recorder(s).ingest(make_session_start(agent="rev-cli"))
        s.close()
        with open(self.db + ".anchor.json", "rb") as f:
            anchor_bytes = f.read()
        self.fx = os.path.join(self.tmp, "fx")
        tsr, ca_der, tsa_der, ca_key, tsa_cert = make_fixture.build_fixture(
            self.fx, message=anchor_bytes)
        with open(self.db + ".anchor.tsq", "wb") as f:
            f.write(tsa.build_tsq(tsa._anchor_hash(self.db)))
        shutil.copy(os.path.join(self.fx, "fixture_tsr.der"),
                    self.db + ".anchor.tsr")
        with open(self.db + ".anchor.tsa.json", "w") as f:
            f.write("{}")
        self.ca_pem = os.path.join(self.fx, "fixture_ca.pem")
        utc = datetime.timezone.utc
        # RSA TSA 证书序列号 22（见 build_fixture）
        self.good_crl = os.path.join(self.fx, "crl-good.der")
        self.bad_crl = os.path.join(self.fx, "crl-revoked.der")
        with open(self.good_crl, "wb") as f:
            f.write(make_fixture.build_crl_der(
                ca_key, tsa_cert.issuer, [],
                datetime.datetime(2036, 1, 1, tzinfo=utc)))
        with open(self.bad_crl, "wb") as f:
            f.write(make_fixture.build_crl_der(
                ca_key, tsa_cert.issuer, [22],
                datetime.datetime(2036, 1, 1, tzinfo=utc)))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, extra):
        env = {**os.environ, "PYTHONPATH": self.root}
        return subprocess.run(
            [sys.executable, "-m", "agenttrace", "tsa", "verify",
             "--db", self.db, "--cafile", self.ca_pem] + extra,
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", cwd=self.tmp, env=env, timeout=180)

    def test_good_crl_cli_pass(self):
        r = self._run(["--crl-file", self.good_crl])
        out = r.stdout + r.stderr
        self.assertEqual(r.returncode, 0, out)
        self.assertIn("CRL 吊销检查通过", out)

    def test_revoked_crl_cli_exit2(self):
        r = self._run(["--crl-file", self.bad_crl])
        out = r.stdout + r.stderr
        self.assertEqual(r.returncode, 2, out)
        self.assertIn("已被 CRL 吊销", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
