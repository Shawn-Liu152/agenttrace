"""RFC3161 时间戳锚定（tsa v0.9）测试：mock TSA + TSQ/TSR 编解码 + 绑定校验。"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agenttrace import tsa
from agenttrace.anchor import AnchorKey
from agenttrace.recorder import Recorder, make_session_start, make_tool_call, make_tool_result
from agenttrace.store import EvidenceStore


def make_tst_info(data_hash: bytes, gen_time: str = "20260831120000Z") -> bytes:
    """构造最小 TSTInfo（SEQUENCE: version, policy, imprint, serial, genTime）。"""
    body = tsa.der_integer(1)                      # version
    body += tsa.der_sequence(tsa.OID_SHA256)       # policy (用任意 OID 顶位)
    imprint = tsa.der_sequence(tsa.OID_SHA256 + tsa.der_tlv(0x04, data_hash))
    body += imprint
    body += tsa.der_integer(12345)                 # serialNumber
    body += tsa.der_tlv(tsa.TAG_GENERALIZED_TIME, gen_time.encode())
    return tsa.der_sequence(body)


def make_fake_tsr(data_hash: bytes, status: int = 0, gen_time: str = "20260831120000Z") -> bytes:
    """构造结构完整的 TSR（CMS SignedData 外壳，mock 用，无真实签名）。

    结构（与真实 TSA 一致）：
      TimeStampResp ::= SEQUENCE {
        status        PKIStatusInfo,
        token         ContentInfo { contentType=signedData,
                                    [0]{ SignedData {
                                      version, digestAlgorithms,
                                      encapContentInfo { eContentType=id-ct-TSTInfo,
                                                          [0]{ OCTET STRING { TSTInfo } } },
                                      certificates?, signerInfos } } } }
    """
    tst_info = make_tst_info(data_hash, gen_time)
    status_info = tsa.der_sequence(tsa.der_integer(status))
    # SignedData 必要字段（version=3 + digestAlgorithms 空 SET +
    # encapContentInfo + signerInfos 空 SET）
    signed_data = (
        tsa.der_integer(3)
        + tsa.der_tlv(tsa.TAG_SET, b"")                       # digestAlgorithms
        + tsa.der_sequence(                                    # encapContentInfo
            bytes([0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x01, 0x04])
            + tsa.der_tlv(0xA0, tsa.der_tlv(tsa.TAG_OCTET_STRING, tst_info))
        )
        + tsa.der_tlv(tsa.TAG_SET, b"")                       # signerInfos（空，mock）
    )
    content_info = (
        bytes([0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02])
        + tsa.der_tlv(0xA0, tsa.der_sequence(signed_data))    # contentType=signedData
    )
    token = tsa.der_sequence(content_info)
    return tsa.der_sequence(status_info + token)


class MockTSAHandler(BaseHTTPRequestHandler):
    """本地 mock TSA：回显请求中的 messageImprint，返回 granted TSR。"""
    mode = "grant"

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        tsq = self.rfile.read(length)
        # 从 TSQ 提取 32 字节 hashedMessage（OCTET STRING 紧随 OID）
        data_hash = None
        try:
            t, val, _ = tsa._parse_tlv(tsq, 0)
            for tag, cval in tsa.der_parse_children(val):
                if tag == 0x30:  # messageImprint SEQUENCE
                    for sub_tag, sub_val in tsa.der_parse_children(cval):
                        if sub_tag == 0x04:
                            data_hash = sub_val
        except ValueError:
            pass
        if data_hash is None:
            data_hash = b"\x00" * 32
        if self.mode == "reject":
            tsr = make_fake_tsr(data_hash, status=2)
        else:
            tsr = make_fake_tsr(data_hash)
        self.send_response(200)
        self.send_header("Content-Type", "application/timestamp-reply")
        self.send_header("Content-Length", str(len(tsr)))
        self.end_headers()
        self.wfile.write(tsr)

    def log_message(self, *args):
        pass


class TSAHttpServer:
    """启动/关闭 mock TSA（上下文管理器）。"""

    def __enter__(self):
        self.server = HTTPServer(("127.0.0.1", 0), MockTSAHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}/tsa"
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()


def build_anchored_db(path: str) -> None:
    s = EvidenceStore(path, anchor_key=AnchorKey.generate())
    r = Recorder(s)
    s.set_meta("agent", "hermes")
    s.set_meta("model", "m")
    for ev in (make_session_start(agent="hermes", model="m", tools=["terminal"]),
               make_tool_call("terminal", {"command": "ls"}),
               make_tool_result("terminal", "ok")):
        r.ingest(ev)
    s.close()


class TestDER(unittest.TestCase):
    def test_der_integer_roundtrip(self):
        for n in (0, 1, 127, 128, 255, 256, 65536):
            b = tsa.der_integer(n)
            self.assertEqual(b[0], 0x02)
            t, val, _ = tsa._parse_tlv(b, 0)
            self.assertEqual(int.from_bytes(val, "big"), n)

    def test_der_len_long_form(self):
        payload = b"\x00" * 300
        b = tsa.der_tlv(0x04, payload)
        t, val, _ = tsa._parse_tlv(b, 0)
        self.assertEqual(val, payload)
        self.assertEqual(b[1], 0x82)  # 长形式标志 + 2 字节长度

    def test_build_tsq_structure(self):
        h = b"\x11" * 32
        tsq = tsa.build_tsq(h, nonce=99)
        t, val, _ = tsa._parse_tlv(tsq, 0)
        self.assertEqual(t, 0x30)  # SEQUENCE
        fields = tsa.der_parse_children(val)
        self.assertEqual(fields[0][0], 0x02)  # version
        self.assertEqual(int.from_bytes(fields[0][1], "big"), 1)
        self.assertEqual(fields[1][0], 0x30)  # messageImprint
        # nonce
        self.assertEqual(int.from_bytes(fields[2][1], "big"), 99)


class TestStampVerify(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, "ev.db")
        build_anchored_db(self.db)

    def test_stamp_and_verify_ok(self):
        with TSAHttpServer() as ts:
            res = tsa.stamp(self.db, ts.url)
            self.assertEqual(res["status_name"], "granted")
            self.assertEqual(res["status_code"], 0)
            self.assertTrue(os.path.exists(self.db + ".anchor.tsq"))
            self.assertTrue(os.path.exists(self.db + ".anchor.tsr"))
            self.assertTrue(os.path.exists(self.db + ".anchor.tsa.json"))
            ok, problems = tsa.verify(self.db)
            self.assertTrue(ok, problems)

    def test_verify_detects_tampered_anchor(self):
        # stamp 后修改锚定内容 → 哈希变化 → messageImprint 不匹配
        with TSAHttpServer() as ts:
            tsa.stamp(self.db, ts.url)
        with open(self.db + ".anchor.json", encoding="utf-8") as f:
            rec = json.load(f)
        rec["tip_hash"] = "0" * 64
        with open(self.db + ".anchor.json", "w", encoding="utf-8") as f:
            json.dump(rec, f)
        ok, problems = tsa.verify(self.db)
        self.assertFalse(ok)
        self.assertTrue(any("不符" in p for p in problems), problems)

    def test_verify_detects_replaced_tsr(self):
        # 攻击者替换 TSR 为另一个哈希的时间戳
        with TSAHttpServer() as ts:
            tsa.stamp(self.db, ts.url)
        other = make_fake_tsr(b"\x99" * 32)
        with open(self.db + ".anchor.tsr", "wb") as f:
            f.write(other)
        ok, problems = tsa.verify(self.db)
        self.assertFalse(ok)
        self.assertTrue(any("不符" in p for p in problems), problems)

    def test_tsa_rejection_reported(self):
        MockTSAHandler.mode = "reject"
        try:
            with TSAHttpServer() as ts:
                res = tsa.stamp(self.db, ts.url)
                self.assertEqual(res["status_name"], "rejection")
                ok, problems = tsa.verify(self.db)
                self.assertFalse(ok)
                self.assertTrue(any("未授予" in p for p in problems), problems)
        finally:
            MockTSAHandler.mode = "grant"

    def test_missing_files_reported(self):
        ok, problems = tsa.verify(self.db)
        self.assertFalse(ok)
        self.assertTrue(any("缺失" in p for p in problems), problems)

    def test_parse_gen_time(self):
        info = make_tst_info(b"\x11" * 32, gen_time="20260831120000Z")
        rec = json.load(open(self.db + ".anchor.json", encoding="utf-8")) if False else None
        # 直接测内部解析
        t, val, _ = tsa._parse_tlv(info, 0)
        children = tsa.der_parse_children(val)
        self.assertEqual(children[4][0], tsa.TAG_GENERALIZED_TIME)
        self.assertEqual(children[4][1], b"20260831120000Z")


if __name__ == "__main__":
    unittest.main(verbosity=2)

class TestForgedTsrFlagged(unittest.TestCase):
    """复评 P0：无签名的伪造 TSR 必须被显式标记（不能只报"绑定有效"）。"""

    def test_forged_tsr_verify_ok_but_cli_flags_cms(self):
        """验证 CLI 输出：伪造 TSR（自造 DER 无签名）verify 通过但带 CMS 警告。"""
        import subprocess
        import tempfile
        tmp = tempfile.mkdtemp()
        db = os.path.join(tmp, "ev.db")
        build_anchored_db(db)
        h = tsa._anchor_hash(db)
        # 攻击者自造 TSR：正确 DER + granted + imprint 填对 + 无签名
        forged = make_fake_tsr(h, gen_time="19980101000000Z")
        with open(db + ".anchor.tsq", "wb") as f:
            f.write(tsa.build_tsq(h))
        with open(db + ".anchor.tsr", "wb") as f:
            f.write(forged)
        with open(db + ".anchor.tsa.json", "w", encoding="utf-8") as f:
            json.dump({"forged": True}, f)
        # module verify：绑定本身通过（这是设计边界）
        ok, problems = tsa.verify(db)
        self.assertTrue(ok, problems)
        # CLI 输出必须显式声明 CMs 签名未验证
        from agenttrace import __main__ as _m  # noqa
        env = {**os.environ, "PYTHONPATH": __import__("os").path.dirname(
            os.path.dirname(os.path.abspath(__file__)))}
        r = subprocess.run([sys.executable, "-m", "agenttrace", "tsa", "verify",
                            "--db", db], capture_output=True, text=True,
                           encoding="utf-8", errors="replace",
                           env=env, cwd=tmp, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("未验证 TSA 的 CMS 签名", r.stdout)
        self.assertIn("openssl ts -verify", r.stdout)
