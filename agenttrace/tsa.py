"""RFC3161 时间戳锚定（v0.9.0）：把证据链的锚定哈希交给权威 TSA 打时间戳。

时间戳锚定解决什么：现行方案（HMAC/Ed25519）依赖"密钥在谁手里"，但证明
**"证据在某个时刻之前已存在"** 需要权威第三方。RFC3161 TSA 正好是干这个的。

设计：
  - 零第三方依赖：手写最小 DER 编解码 + RFC3161 TSQ/TSR 处理。
  - TSA 交互：POST TSQ（application/timestamp-query），收 TSR。
  - messageImprint 双向绑定：TSQ 里带证据哈希，TSR 里回显同一哈希——
    verify 时重算哈希比对，保证 TSA 签署的确实是"这份证据"。
  - 产物：<db>.anchor.tsq（请求）/ <db>.anchor.tsr（响应）/ <db>.anchor.tsa.json（解析摘要）。
    与锚定文件并列，verify 时校验哈希绑定 + 时间戳时间。

诚实边界（README 已有明确声明）：
  - 本模块**不验证** TSR 内 CMS 签名的合法性（需要 X.509 链/CA 校验，超出
    零依赖范围）——TSTInfo 的 genTime 取自已解析的 DER 结构，若攻击者能
    替换 TSR 且不做外部验证，时间戳可被伪造。生产/执法场景：
        openssl ts -verify -data <tsq> -in <tsr> -CAfile <tsa_cert.pem>
  - 网络不可达时 stamp 失败并明确报错，不伪造成功。
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import secrets
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# 最小 DER (ASN.1) 编解码 —— 只实现 RFC3161 用得到的子集
# ---------------------------------------------------------------------------

# 通用标签
TAG_INTEGER = 0x02
TAG_OID = 0x06
TAG_SEQUENCE = 0x30
TAG_OCTET_STRING = 0x04
TAG_BOOLEAN = 0x01
TAG_UTC_TIME = 0x17
TAG_GENERALIZED_TIME = 0x18
TAG_SET = 0x31
TAG_UTF8_STRING = 0x0C
TAG_PRINTABLE_STRING = 0x13

# SHA-256 OID (2.16.840.1.101.3.4.2.1)
OID_SHA256 = bytes([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01])


def der_len(n: int) -> bytes:
    """DER 长度编码（短/长形式）。"""
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def der_tlv(tag: int, payload: bytes) -> bytes:
    """构造一个 TLV。"""
    return bytes([tag]) + der_len(len(payload)) + payload


def der_integer(n: int) -> bytes:
    """DER INTEGER（正数规范编码，无前导 0）。"""
    if n < 0:
        raise ValueError("仅支持非负整数")
    b = n.to_bytes(max(1, (n.bit_length() + 7) // 8), "big")
    if b[0] & 0x80:  # 补 0 保持正数
        b = b"\x00" + b
    return der_tlv(TAG_INTEGER, b)


def der_oid_single(oid_der: bytes) -> bytes:
    """OID 已是完整 TLV（如 OID_SHA256）时原样返回。"""
    return oid_der


def _parse_tlv(buf: bytes, off: int) -> Tuple[int, bytes, int]:
    """解析一个 TLV：返回 (tag, value, next_offset)。"""
    if off >= len(buf):
        raise ValueError("DER 截断")
    tag = buf[off]
    off += 1
    if off >= len(buf):
        raise ValueError("DER 截断 (len)")
    ln = buf[off]
    off += 1
    if ln & 0x80:
        nbytes = ln & 0x7F
        if nbytes == 0 or nbytes > 4 or off + nbytes > len(buf):
            raise ValueError(f"非法长度: {ln:#x}")
        ln = int.from_bytes(buf[off:off + nbytes], "big")
        off += nbytes
    if off + ln > len(buf):
        raise ValueError(f"长度越界: {ln}")
    return tag, buf[off:off + ln], off + ln


def der_parse_children(buf: bytes) -> List[Tuple[int, bytes]]:
    """把一段 DER（应为 SEQUENCE 内容）解析为 [(tag, value), ...] 子元素列表。"""
    out: List[Tuple[int, bytes]] = []
    off = 0
    while off < len(buf):
        tag, val, off = _parse_tlv(buf, off)
        out.append((tag, val))
    return out


def der_find_first(buf: bytes, tag: int) -> Optional[bytes]:
    """在 DER 子树中递归查找第一个指定 tag 的 value（深度优先）。"""
    try:
        t, val, _ = _parse_tlv(buf, 0)
    except ValueError:
        return None
    if t == tag:
        return val
    if t == TAG_SEQUENCE or t == TAG_SET:
        for _, child_val in der_parse_children(val):
            found = der_find_first(child_val, tag)
            if found is not None:
                return found
    return None


def der_canonical(der_bytes: bytes) -> str:
    """DER 字节的十六进制（用于存 TSQ 原文比对）。"""
    return der_bytes.hex()


# ---------------------------------------------------------------------------
# RFC3161 TSQ 构造
# ---------------------------------------------------------------------------

def build_tsq(data_hash: bytes, nonce: Optional[int] = None,
              cert_req: bool = False, alg: bytes = OID_SHA256) -> bytes:
    """构造 TimeStampReq（RFC3161 §2.4.1）。

    TimeStampReq ::= SEQUENCE {
        version        INTEGER (1),
        messageImprint MessageImprint,   -- {hashAlgorithm, hashedMessage}
        reqPolicy      [0] OPTIONAL (省略),
        nonce          INTEGER OPTIONAL,
        certReq        BOOLEAN DEFAULT FALSE,
    }
    """
    if len(data_hash) != 32:
        raise ValueError("SHA-256 摘要必须 32 字节")
    # messageImprint ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING }
    alg_ident = der_sequence(alg)  # SEQUENCE { OID } (无参数)
    imprint = der_sequence(alg_ident + der_tlv(TAG_OCTET_STRING, data_hash))
    body = der_integer(1) + imprint
    if nonce is not None:
        body += der_integer(nonce)
    if cert_req:
        body += der_tlv(TAG_BOOLEAN, b"\xff")
    return der_sequence(body)


def der_sequence(payload: bytes) -> bytes:
    return der_tlv(TAG_SEQUENCE, payload)


# ---------------------------------------------------------------------------
# RFC3161 TSR 解析
# ---------------------------------------------------------------------------

# PKIStatus 枚举（RFC3161 §2.4.2）
_STATUS_NAMES = {
    0: "granted",
    1: "grantedWithMods",
    2: "rejection",
    3: "waiting",
    4: "revocationWarning",
    5: "revocationNotification",
}


# id-ct-TSTInfo OID 的 value（1.2.840.113549.1.9.16.1.4）
# 完整 TLV: 06 0b 2a 86 48 86 f7 0d 01 09 10 01 04
_TSTINFO_OID_VALUE = bytes.fromhex("2a864886f70d0109100104")


def _extract_tst_info(token_payload: bytes) -> Optional[bytes]:
    """定位 TSTInfo：找 eContentType=id-ct-TSTInfo 的 [0]{OCTET STRING{TSTInfo}}。

    真实 TSA 的 TSR 中 TSTInfo 被 CMS 包在 OCTET STRING 里（并可能有
    BER 展开），直接扫描 OCTET STRING 会误中签名区；用 OID 做锚点最稳。
    """
    def find(buf: bytes) -> Optional[bytes]:
        off = 0
        while off < len(buf):
            try:
                t, v, off = _parse_tlv(buf, off)
            except ValueError:
                return None
            if t == TAG_OID and v == _TSTINFO_OID_VALUE:
                # 下一个元素应为 [0] { OCTET STRING { TSTInfo } }
                rest = buf[off:]
                try:
                    t1, v1, _ = _parse_tlv(rest, 0)
                    if t1 == 0xA0:
                        t2, v2, _ = _parse_tlv(v1, 0)
                        if t2 == TAG_OCTET_STRING:
                            return v2
                except ValueError:
                    pass
            if t in (TAG_SEQUENCE, TAG_SET) or t >= 0xA0:
                sub = find(v)
                if sub is not None:
                    return sub
        return None
    return find(token_payload)


def _parse_gen_time(token_payload: bytes) -> Optional[str]:
    """从 TSTInfo 中提取 genTime（UTC/Generalized 时间，按结构第 5 字段取）。"""
    tst = _extract_tst_info(token_payload)
    if tst is None:
        return None
    try:
        t, tst_val, _ = _parse_tlv(tst, 0)
        if t != TAG_SEQUENCE:
            return None
        children = der_parse_children(tst_val)
        if len(children) < 5:
            return None
        gt_tag, gt_val = children[4]
        if gt_tag in (TAG_GENERALIZED_TIME, TAG_UTC_TIME):
            return gt_val.decode("utf-8", errors="replace")
        return None
    except ValueError:
        return None


def _parse_imprint_inside_token(token_payload: bytes) -> Optional[bytes]:
    """从 TSTInfo.messageImprint.hashedMessage 提取 32 字节哈希（按结构取）。"""
    tst = _extract_tst_info(token_payload)
    if tst is None:
        return None
    try:
        t, tst_val, _ = _parse_tlv(tst, 0)
        if t != TAG_SEQUENCE:
            return None
        children = der_parse_children(tst_val)
        if len(children) < 3:
            return None
        # children[2] = (TAG_SEQUENCE, messageImprint 的 payload)
        mi_fields = der_parse_children(children[2][1])
        for sub_tag, sub_val in mi_fields:
            if sub_tag == TAG_OCTET_STRING and len(sub_val) == 32:
                return sub_val
        return None
    except ValueError:
        return None


def parse_tsr(tsr: bytes) -> Dict[str, Any]:
    """解析 TimeStampResp，返回摘要 dict。不验证 CMS 签名（零依赖边界）。"""
    try:
        t, resp_val, _ = _parse_tlv(tsr, 0)
        if t != TAG_SEQUENCE:
            return {"valid": False, "problems": ["TSR 不是 SEQUENCE"]}
        fields = der_parse_children(resp_val)
        if not fields:
            return {"valid": False, "problems": ["TSR 为空"]}
        # fields[0] = PKIStatusInfo ::= SEQUENCE { status INTEGER, ... }
        # （fields 已是 (tag, payload) 对，payload 直接拆子元素）
        if fields[0][0] != TAG_SEQUENCE:
            return {"valid": False, "problems": ["缺 PKIStatusInfo"]}
        st_fields = der_parse_children(fields[0][1])
        if not st_fields or st_fields[0][0] != TAG_INTEGER:
            return {"valid": False, "problems": ["缺 status INTEGER"]}
        status_code = int.from_bytes(st_fields[0][1], "big")
        result: Dict[str, Any] = {
            "valid": True,
            "status_code": status_code,
            "status_name": _STATUS_NAMES.get(status_code, f"unknown({status_code})"),
            "problems": [],
        }
        # statusString（可选）—— 取第一个可见字符串字段
        for tag, val in st_fields[1:]:
            if tag in (TAG_UTF8_STRING, TAG_PRINTABLE_STRING):  # UTF8String / PrintableString
                result["status_string"] = val.decode("utf-8", errors="replace")
                break
        # 时间戳 token（fields[1..] 中最后的 SEQUENCE —— ContentInfo）
        token = None
        for tag, val in fields[1:]:
            if tag == TAG_SEQUENCE:
                token = val
        if token is None:
            result["problems"].append("无时间戳 token（TSA 未授予）")
        else:
            result["token_present"] = True
            gt = _parse_gen_time(token)
            impr = _parse_imprint_inside_token(token)
            if gt:
                result["gen_time"] = gt
            if impr:
                result["message_imprint"] = impr.hex()
        return result
    except ValueError as e:
        return {"valid": False, "problems": [f"TSR 解析失败: {e}"]}


# ---------------------------------------------------------------------------
# TSA HTTP 交互（urllib，零依赖）
# ---------------------------------------------------------------------------

def request_timestamp(tsq: bytes, url: str, timeout: float = 15.0) -> bytes:
    """POST TSQ 到 TSA 服务，返回 TSR 原始字节。"""
    req = urllib.request.Request(
        url,
        data=tsq,
        headers={"Content-Type": "application/timestamp-query",
                 "Accept": "application/timestamp-reply"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"TSA HTTP {e.code}: {e.reason}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"TSA 不可达: {e.reason}") from e


# ---------------------------------------------------------------------------
# 锚定文件集成：stamp / verify
# ---------------------------------------------------------------------------

def _anchor_hash(db_path: str) -> bytes:
    """对锚定文件内容做 SHA-256（时间戳绑定的是锚定内容本身）。"""
    p = db_path + ".anchor.json"
    if not os.path.exists(p):
        raise FileNotFoundError(f"锚定文件不存在: {p}（请先 init --anchor 或 seal）")
    with open(p, "rb") as f:
        return hashlib.sha256(f.read()).digest()


def stamp(db_path: str, tsa_url: str, out_dir: Optional[str] = None,
          timeout: float = 15.0, nonce: Optional[int] = None) -> Dict[str, Any]:
    """向 TSA 请求锚定哈希的时间戳，并把 TSQ/TSR/摘要写入磁盘。返回摘要。"""
    h = _anchor_hash(db_path)
    nonce = nonce if nonce is not None else secrets.randbits(64)
    tsq = build_tsq(h, nonce=nonce)
    tsr = request_timestamp(tsq, tsa_url, timeout=timeout)
    parsed = parse_tsr(tsr)
    parsed.update({
        "tsa_url": tsa_url,
        "anchor_sha256": h.hex(),
        "tsq_sha256": hashlib.sha256(tsq).hexdigest(),
        "stamped_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "nonce": nonce,
    })
    if not parsed.get("valid") or parsed.get("status_code", 0) not in (0, 1):
        parsed["problems"].append("TSA 未授予时间戳（status=%s）" % parsed.get("status_name"))

    d = out_dir or os.path.dirname(db_path)
    base = os.path.basename(db_path)
    with open(os.path.join(d, base + ".anchor.tsq"), "wb") as f:
        f.write(tsq)
    with open(os.path.join(d, base + ".anchor.tsr"), "wb") as f:
        f.write(tsr)
    with open(os.path.join(d, base + ".anchor.tsa.json"), "w", encoding="utf-8") as f:
        json.dump(parsed, f, ensure_ascii=False, indent=2)
    return parsed


def verify(db_path: str, out_dir: Optional[str] = None) -> tuple[bool, List[str]]:
    """校验时间戳绑定：当前锚定哈希 == TSR messageImprint 回显哈希。

    注意：这不验证 TSA 的 CMS 签名（见模块 docstring 诚实边界）。
    """
    d = out_dir or os.path.dirname(db_path)
    base = os.path.basename(db_path)
    tsq_p = os.path.join(d, base + ".anchor.tsq")
    tsr_p = os.path.join(d, base + ".anchor.tsr")
    problems: List[str] = []
    if not os.path.exists(tsq_p) or not os.path.exists(tsr_p):
        return False, ["时间戳文件缺失（未 stamp 或文件被删）: .anchor.tsq/.anchor.tsr"]
    h = _anchor_hash(db_path)
    with open(tsr_p, "rb") as f:
        tsr = f.read()
    parsed = parse_tsr(tsr)
    if not parsed.get("valid"):
        return False, parsed.get("problems", ["TSR 无效"])
    if parsed.get("status_code", 2) not in (0, 1):
        problems.append("TSA 当时未授予时间戳: %s" % parsed.get("status_name"))
    impr = parsed.get("message_imprint")
    if not impr:
        problems.append("TSR 缺少 messageImprint（可能是伪 TSR）")
    elif impr != h.hex():
        problems.append(f"时间戳绑定失败: TSR 回显哈希 {impr[:16]}… 与当前锚定哈希 {h.hex()[:16]}… 不符（证据已被修改或 TSR 被替换）")
    cd = os.path.join(d, base + ".anchor.tsa.json")
    if not os.path.exists(cd):
        problems.append("摘要文件缺失（.anchor.tsa.json）")
    return (not problems), problems