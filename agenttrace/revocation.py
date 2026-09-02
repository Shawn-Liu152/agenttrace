"""证书吊销检查（v1.2.0，零依赖纯 Python）：CRL 本地校验 + OCSP 在线查询。

cms.py 解决"签名是否由该证书持有者做出、证书链是否通向受信 CA"，但**证书
在有效期内也可能被 CA 吊销**（私钥泄露、误签发）。本模块补上 RFC 5280 的
两条吊销通道：

  - CRL（Certificate Revocation List，RFC 5280 §5）：CA 签名的吊销序列号
    清单，离线文件。解析 + 验签（复用 cms 的 RSA/ECDSA 分派）+ nextUpdate
    新鲜度 + 序列号命中。
  - OCSP（RFC 6960）：实时查询单张证书状态。构造 CertID（issuer 名/公钥
    SHA-1）请求，解析 BasicOCSPResponse，验证响应者签名（直接由 CA 签或
    嵌入式委派证书链到 CA）、nonce 防重放、thisUpdate/nextUpdate 时间窗。

诚实边界（SECURITY.md 同步）：
  - CRL 无受信 CA 验签时只能给"自洽"级结论，输出显式警告（不冒充可信）；
    nextUpdate 已过 = 陈旧 CRL，警告而非静默放行。
  - OCSP 必须验证响应签名与 nonce；网络不可达/响应非 successful 明确报错，
    绝不把"查不到"当成"没吊销"。
  - 委派 OCSP 响应者只接受能链到受信 CA 的嵌入式证书（不做 EKU 深度校验，
    属已知边界）。
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import re
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from . import cms

# ---------------------------------------------------------------------------
# OID（值编码）
# ---------------------------------------------------------------------------

OID_SHA1 = bytes.fromhex("2b0e03021a")                    # 1.3.14.3.2.26
OID_OCSP_NONCE = bytes.fromhex("2b0601050507300102")      # 1.3.6.1.5.5.7.48.1.2
OID_OCSP_BASIC = bytes.fromhex("2b0601050507300101")      # 1.3.6.1.5.5.7.48.1.1

# OCSPResponseStatus（RFC 6960 §4.2.1）
_OCSP_STATUS = {
    0: "successful", 1: "malformedRequest", 2: "internalError",
    3: "tryLater", 5: "sigRequired", 6: "unauthorized",
}


# ---------------------------------------------------------------------------
# PEM/DER 载入
# ---------------------------------------------------------------------------

def _pem_extract(data: bytes, label: str) -> Optional[bytes]:
    """从 PEM 文本提取首个指定 label 块的 DER；非 PEM 返回 None。"""
    try:
        text = data.decode("utf-8", errors="ignore")
    except Exception:
        return None
    m = re.search(rf"-----BEGIN {label}-----(.+?)-----END {label}-----",
                  text, re.S)
    if not m:
        return None
    return base64.b64decode("".join(m.group(1).split()))


def load_der_or_pem(data: bytes, pem_label: str) -> bytes:
    """PEM（指定 label）→ DER；已经是 DER（0x30 开头）原样返回。"""
    if data[:1] == b"\x30":
        return data
    der = _pem_extract(data, pem_label)
    if der is None:
        raise ValueError(f"既不是 DER（应以 0x30 开头），也找不到 {pem_label} PEM 块")
    return der


# ---------------------------------------------------------------------------
# CRL（RFC 5280）
# ---------------------------------------------------------------------------

def parse_crl(crl_der: bytes) -> Dict[str, Any]:
    """CertificateList → 结构 dict（保留 tbs 原始字节供验签）。"""
    top = cms.seq_items(crl_der)
    if len(top) < 3:
        raise ValueError("CRL 字段不足")
    _, tbs_v, tbs_raw = top[0]
    sig_alg_oid = cms._algid_oid(top[1][1])
    sig = top[2][1][1:]  # BIT STRING 去 unused-bits
    fields = cms.children(tbs_v)
    off = 0
    if fields and fields[off][0] == 0x02:  # 可选 version INTEGER
        off += 1
    off += 1  # tbs signature AlgorithmIdentifier
    issuer_raw = fields[off][2]; off += 1  # issuer Name 完整 TLV
    # thisUpdate / nextUpdate（UTC=0x17 / Generalized=0x18）
    def _time_at(i: int) -> Optional[datetime.datetime]:
        if i < len(fields) and fields[i][0] in (0x17, 0x18):
            return cms._asn1_time(fields[i][0], fields[i][1])
        return None
    this_update = _time_at(off); off += 1
    next_update = _time_at(off)
    if off < len(fields) and fields[off][0] in (0x17, 0x18):
        off += 1
    revoked: Dict[int, datetime.datetime] = {}
    if off < len(fields) and fields[off][0] == 0x30:
        for _, entry_v, _ in cms.children(fields[off][1]):
            ef = cms.children(entry_v)
            if len(ef) >= 2 and ef[0][0] == 0x02:
                serial = int.from_bytes(ef[0][1], "big")
                revoked[serial] = cms._asn1_time(ef[1][0], ef[1][1])
        off += 1
    return {"tbs_raw": tbs_raw, "sig_alg_oid": sig_alg_oid, "sig": sig,
            "issuer_raw": issuer_raw, "this_update": this_update,
            "next_update": next_update, "revoked": revoked}


def verify_crl_signature(crl: Dict[str, Any],
                         ca_certs: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """用受信 CA 验证 CRL 签名（含 issuer 名匹配）。返回命中的 CA，否则 None。"""
    for ca in ca_certs:
        if cms._cert_subject_raw(ca["der"]) != crl["issuer_raw"]:
            continue
        ok, _ = cms.verify_with_cert_key(ca, crl["tbs_raw"], crl["sig"],
                                         crl["sig_alg_oid"])
        if ok:
            return ca
    return None


def check_crl(cert_der: bytes, crl_bytes: bytes,
              ca_certs: Optional[List[bytes]] = None,
              now: Optional[datetime.datetime] = None) -> Dict[str, Any]:
    """检查证书序列号是否在 CRL 吊销清单中。

    返回 {revoked, revoked_at, stale, crl_signature_ok, problems[]}。
    无 ca_certs 时 crl_signature_ok=None（无法验签，调用方必须显式降级提示）。
    """
    res: Dict[str, Any] = {"revoked": False, "stale": False,
                           "crl_signature_ok": None, "problems": []}
    crl_der = load_der_or_pem(crl_bytes, "X509 CRL")
    cert = cms.parse_cert(cert_der)
    serial = int.from_bytes(cert["serial"], "big")
    try:
        crl = parse_crl(crl_der)
    except (ValueError, IndexError) as e:
        res["problems"].append(f"CRL 解析失败: {e}")
        return res
    res["this_update"] = crl["this_update"]
    res["next_update"] = crl["next_update"]
    # ① CRL 签名必须由受信 CA 签发
    if ca_certs:
        cas = [cms.parse_cert(d) for d in ca_certs]
        hit = verify_crl_signature(crl, cas)
        res["crl_signature_ok"] = hit is not None
        if hit is None:
            res["problems"].append("CRL 签名无法用任何受信 CA 验证（CRL 可能被伪造）")
    else:
        res["problems"].append("未提供受信 CA：CRL 签名未验证，吊销结论仅自洽级")
    # ② 新鲜度
    now = now or datetime.datetime.utcnow()
    if crl["next_update"] and now > crl["next_update"]:
        res["stale"] = True
        res["problems"].append(
            f"CRL 已过 nextUpdate（{crl['next_update']}），吊销清单可能陈旧")
    # ③ 序列号命中
    if serial in crl["revoked"]:
        res["revoked"] = True
        res["revoked_at"] = crl["revoked"][serial]
    return res


# ---------------------------------------------------------------------------
# OCSP 请求构造（RFC 6960 §4.1.1）
# ---------------------------------------------------------------------------

def _issuer_name_hash(issuer_cert_der: bytes) -> bytes:
    """issuerNameHash = SHA-1(issuer 的 subject Name 完整 TLV)。"""
    return hashlib.sha1(cms._cert_subject_raw(issuer_cert_der)).digest()


def _issuer_key_hash(issuer_cert_der: bytes) -> bytes:
    """issuerKeyHash = SHA-1(issuer SubjectPublicKey BIT STRING 内容字节)。"""
    parsed = cms.parse_cert(issuer_cert_der)
    spki = cms.children(cms.seq_items(issuer_cert_der)[0][1])
    # TBS 字段定位 SPKI（version 可选 → 固定第 6/7 个字段，直接扫 BIT STRING 不稳，
    # 用 parse_cert 已解析的公钥字节重拼不如直接定位：subject 后一个字段）
    off = 0
    if spki[off][0] == 0xA0:
        off += 1
    off += 5  # serial/sigAlg/issuer/validity/subject → SPKI
    _, spki_v, _ = spki[off]
    bit = cms.children(spki_v)[1]      # BIT STRING TLV
    return hashlib.sha1(bit[1][1:]).digest()  # 去 unused-bits 字节


def cert_id(cert_der: bytes, issuer_cert_der: bytes,
            hash_oid: bytes = OID_SHA1) -> bytes:
    """构造 CertID DER（默认 SHA-1，RFC 6960 强制实现项）。"""
    if hash_oid != OID_SHA1:
        raise ValueError("当前仅支持 SHA-1 CertID（RFC 6960 强制项）")
    cert = cms.parse_cert(cert_der)
    name_hash = _issuer_name_hash(issuer_cert_der)
    key_hash = _issuer_key_hash(issuer_cert_der)
    # SHA-1 AlgorithmIdentifier 带 NULL 参数（与主流实现逐字节一致）
    algid = cms.der_tlv(0x30, cms.der_tlv(0x06, hash_oid) + cms.der_tlv(0x05, b""))
    body = (algid + cms.der_tlv(0x04, name_hash)
            + cms.der_tlv(0x04, key_hash) + cms.der_int(int.from_bytes(cert["serial"], "big")))
    return cms.der_tlv(0x30, body)


def _nonce_ext(nonce: bytes) -> bytes:
    """requestExtensions [2] EXPLICIT Extensions { Extension(nonce) }。"""
    ext = cms.der_tlv(
        0x30,
        cms.der_tlv(0x06, OID_OCSP_NONCE)
        + cms.der_tlv(0x04, cms.der_tlv(0x04, nonce)))  # extnValue OCTET STRING 内嵌值
    return cms.der_tlv(0xA2, cms.der_tlv(0x30, ext))


def build_ocsp_request(cert_der: bytes, issuer_cert_der: bytes,
                       nonce: Optional[bytes] = None) -> bytes:
    """OCSPRequest DER（单证书查询，可选 nonce）。"""
    cid = cert_id(cert_der, issuer_cert_der)
    request = cms.der_tlv(0x30, cid)
    request_list = cms.der_tlv(0x30, request)
    tbs = request_list
    if nonce:
        tbs += _nonce_ext(nonce)
    tbs_request = cms.der_tlv(0x30, tbs)
    return cms.der_tlv(0x30, tbs_request)


def ocsp_http_post(url: str, req_der: bytes, timeout: float = 10.0) -> bytes:
    """POST OCSP 请求（application/ocsp-request），返回响应原始字节。"""
    req = urllib.request.Request(
        url, data=req_der,
        headers={"Content-Type": "application/ocsp-request",
                 "Accept": "application/ocsp-response"},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"OCSP HTTP {e.code}: {e.reason}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"OCSP 不可达: {e.reason}") from e


# ---------------------------------------------------------------------------
# OCSP 响应解析与验证（RFC 6960 §4.2）
# ---------------------------------------------------------------------------

def _extension_value(ext_container_payload: bytes,
                     want_oid: bytes) -> Optional[bytes]:
    """从 Extensions（SEQUENCE OF Extension 的 payload）找指定 OID 的 extnValue。"""
    try:
        for _, ext_v, _ in cms.children(ext_container_payload):
            ef = cms.children(ext_v)
            if ef and ef[0][1] == want_oid:
                # Extension { OID, [critical], OCTET STRING extnValue }
                ov = ef[-1][1]
                inner = cms.children(ov)
                # nonce 的 extnValue 里再包一层 OCTET STRING
                return inner[0][1] if inner else ov
    except (ValueError, IndexError):
        return None
    return None


def parse_ocsp_response(resp_der: bytes) -> Dict[str, Any]:
    """OCSPResponse → 状态/证书状态/时间窗/签名原文（保留验签所需字节）。"""
    out: Dict[str, Any] = {"problems": []}
    top = cms.seq_items(resp_der)
    if not top or top[0][0] != 0x0A:  # ENUMERATED tag
        raise ValueError("OCSPResponse 缺 responseStatus ENUMERATED")
    status_code = int.from_bytes(top[0][1], "big")
    out["status_code"] = status_code
    out["status"] = _OCSP_STATUS.get(status_code, f"unknown({status_code})")
    if status_code != 0:
        return out
    # responseBytes [0] EXPLICIT SEQUENCE { responseType OID, response OCTET STRING }
    if len(top) < 2 or top[1][0] != 0xA0:
        out["problems"].append("successful 但缺 responseBytes")
        return out
    rb = cms.children(top[1][1])
    rbf = cms.children(rb[0][1])
    if rbf[0][1] != OID_OCSP_BASIC:
        out["problems"].append("仅支持 id-pkix-ocsp-basic 响应类型")
        return out
    basic_der = rbf[1][1]
    basic = cms.seq_items(basic_der)
    _, tbs_v, tbs_raw = basic[0]
    out["sig_alg_oid"] = cms._algid_oid(basic[1][1])
    out["sig"] = basic[2][1][1:]
    out["embedded_certs"] = []
    if len(basic) > 3 and basic[3][0] == 0xA0:
        for _, cv, craw in cms.children(basic[3][1]):
            out["embedded_certs"].append(craw)
    # ResponseData
    rd = cms.children(tbs_v)
    off = 0
    if rd and rd[off][0] == 0xA0:  # version [0]
        off += 1
    off += 1  # responderID
    _, produced_v, _ = rd[off]; off += 1
    out["produced_at"] = produced_v.decode("ascii", errors="replace")
    _, responses_v, _ = rd[off]; off += 1
    # responseExtensions [1] EXPLICIT Extensions（nonce 回显）
    out["nonce"] = None
    for t, v, _ in rd[off:]:
        if t == 0xA1:
            ext_seq = cms.children(v)  # EXPLICIT 包一层 Extensions SEQUENCE
            if ext_seq:
                out["nonce"] = _extension_value(ext_seq[0][1], OID_OCSP_NONCE)
    # SingleResponse（取第一个；本工具一次只查一张证书）
    singles = cms.children(responses_v)
    if not singles:
        out["problems"].append("响应无 SingleResponse")
        return out
    sf = cms.children(singles[0][1])
    out["cert_id_der"] = sf[0][2]
    # good [0] IMPLICIT NULL → 0x80；revoked [1] IMPLICIT SEQUENCE → 0xA1；
    # unknown [2] IMPLICIT NULL → 0x82（IMPLICIT primitive 位为 0）
    status_tag = sf[1][0]
    out["cert_status"] = {0x80: "good", 0xA1: "revoked", 0x82: "unknown"}.get(
        status_tag, "unknown")
    if status_tag == 0xA1 and sf[1][1]:
        rv = cms.children(sf[1][1])
        if rv:
            out["revoked_at"] = rv[0][1].decode("ascii", errors="replace")
    # thisUpdate / nextUpdate
    times: List[Tuple[int, bytes]] = [(sf[i][0], sf[i][1])
                                      for i in range(2, len(sf))]
    for tag, val in times:
        if tag == 0x18 and "this_update" not in out:
            out["this_update"] = val.decode("ascii", errors="replace")
        elif tag == 0xA0:
            inner = cms.children(val)
            if inner:
                out["next_update"] = inner[0][1].decode("ascii", errors="replace")
    out["tbs_raw"] = tbs_raw
    return out


def _parse_gen_time(s: str) -> Optional[datetime.datetime]:
    for fmt in ("%Y%m%d%H%M%SZ", "%Y%m%d%H%M%S%z"):
        try:
            return datetime.datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def verify_ocsp_response(parsed: Dict[str, Any], cert_der: bytes,
                         issuer_cert_der: bytes,
                         request_nonce: Optional[bytes] = None,
                         now: Optional[datetime.datetime] = None
                         ) -> Tuple[bool, List[str]]:
    """验证 OCSP 响应：签名（CA 直签或委派证书链到 CA）+ CertID 匹配 +
    nonce 回显 + 时间窗。返回 (是否通过验证, problems)。"""
    problems: List[str] = []
    if parsed.get("status_code") != 0:
        return False, [f"OCSP 响应状态非 successful: {parsed.get('status')}"]
    if parsed.get("cert_status") is None:
        problems.extend(parsed.get("problems", ["响应缺证书状态"]))
        return False, problems
    issuer = cms.parse_cert(issuer_cert_der)
    # ① 签名：先试 CA 直签；再试嵌入式委派证书（必须能链到 CA）
    tbs, sig, alg = parsed.get("tbs_raw"), parsed.get("sig"), parsed.get("sig_alg_oid")
    sig_ok = False
    ok, _ = cms.verify_with_cert_key(issuer, tbs, sig, alg)
    if ok:
        sig_ok = True
    else:
        for d in parsed.get("embedded_certs", []):
            try:
                deleg = cms.parse_cert(d)
                chain_ok = cms.cert_signed_by(deleg, issuer)
                own_ok, _ = cms.verify_with_cert_key(deleg, tbs, sig, alg)
                if chain_ok and own_ok:
                    sig_ok = True
                    break
            except (ValueError, IndexError):
                continue
    if not sig_ok:
        problems.append("OCSP 响应签名无法用受信 CA（或其委派证书）验证")
    # ② CertID 必须与请求一致（防响应张冠李戴）
    expect_cid = cert_id(cert_der, issuer_cert_der)
    if parsed.get("cert_id_der") != expect_cid:
        problems.append("OCSP 响应 CertID 与请求不匹配（被查询证书不一致）")
    # ③ nonce
    if request_nonce is not None and parsed.get("nonce") != request_nonce:
        problems.append("OCSP nonce 不匹配或未回显（重放/伪造风险）")
    # ④ 时间窗：now 应落在 [thisUpdate, nextUpdate]
    now = now or datetime.datetime.utcnow()
    tu = _parse_gen_time(parsed.get("this_update", ""))
    nu = _parse_gen_time(parsed.get("next_update", "")) if parsed.get("next_update") else None
    if tu and now < tu:
        problems.append(f"OCSP thisUpdate 在未来（{parsed['this_update']}），时钟或伪造问题")
    if nu and now > nu:
        problems.append(f"OCSP 响应已过 nextUpdate（{parsed['next_update']}），结论过期")
    return (not problems), problems


def check_ocsp(cert_der: bytes, issuer_cert_der: bytes, url: str,
               use_nonce: bool = True, timeout: float = 10.0,
               now: Optional[datetime.datetime] = None) -> Dict[str, Any]:
    """端到端 OCSP 查询：构造请求 → POST → 解析 → 验证。网络失败显式报错。"""
    import secrets
    nonce = secrets.token_bytes(16) if use_nonce else None
    req = build_ocsp_request(cert_der, issuer_cert_der, nonce=nonce)
    resp = ocsp_http_post(url, req, timeout=timeout)
    parsed = parse_ocsp_response(resp)
    ok, problems = verify_ocsp_response(parsed, cert_der, issuer_cert_der,
                                        request_nonce=nonce, now=now)
    parsed["response_verified"] = ok
    parsed["verify_problems"] = problems
    return parsed
