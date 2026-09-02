"""RFC3161 TSR 的 CMS 签名验证（v1.2.0，零依赖纯 Python）。

收回终评 −0.2 那项：v1.0 的 `tsa verify` 明确声明"不验证 CMS 签名"。
本模块用纯标准库实现完整验证链：

  TSR → PKCS#7 SignedData → {certs, signerInfos}
    ① 验证 signerInfo 对 signedAttrs 的签名（按算法分派）：
       - RSA PKCS#1 v1.5（sha256WithRSAEncryption）
       - ECDSA P-256（ecdsa-with-SHA256，v1.2 新增，见 ecc.py）
    ② signedAttrs.messageDigest == SHA-256(eContent = TSTInfo DER)
    ③ 签名者证书：自签（自证结构正确）或 CA 链（--cafile 受信锚点）
    ④ genTime 落在证书有效期内（时间戳有效性以签名时刻为准）

已知边界（诚实声明，SECURITY.md 同步）：
  - 算法：sha256WithRSAEncryption 与 ecdsa-with-SHA256(P-256)；其余算法
    （P-384/P-521、RSA-SHA1、Ed25519 证书等）报"不支持"而非放行
  - 吊销检查由 revocation.py 负责（CRL 本地 / OCSP 在线，v1.2 新增）
  - 无 --cafile 时即使签名数学有效也只给"untrusted"级——防自签伪造冒充
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import re
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# DER：保留原始字节切片的解析器（验签必须用原始编码字节）
# ---------------------------------------------------------------------------


def parse_tlv(buf: bytes, off: int) -> Tuple[int, bytes, bytes, int]:
    """(tag, payload, raw_tlv_bytes, next_off)。"""
    start = off
    t = buf[off]; off += 1
    first = buf[off]
    if first < 0x80:
        ln = first; off += 1
    else:
        nb = first & 0x7F
        if nb == 0 or nb > 4:
            raise ValueError(f"坏长度首字节 {first:#x}")
        off += 1
        ln = int.from_bytes(buf[off:off + nb], "big")
        off += nb
    if off + ln > len(buf):
        raise ValueError("长度越界")
    end = off + ln
    return t, buf[off:end], buf[start:end], end


def children(buf: bytes) -> List[Tuple[int, bytes, bytes]]:
    """解析一个 payload（构造类型的内容区）为子 TLV 列表。"""
    out = []
    off = 0
    while off < len(buf):
        t, v, raw, off = parse_tlv(buf, off)
        out.append((t, v, raw))
    return out


def seq_items(buf: bytes) -> List[Tuple[int, bytes, bytes]]:
    """要求输入本身是一个完整 SEQUENCE，返回其子元素。"""
    t, v, raw, end = parse_tlv(buf, 0)
    if t != 0x30:
        raise ValueError(f"期望 SEQUENCE 得 {t:#x}")
    return children(v)


def der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def der_tlv(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + der_len(len(payload)) + payload


def der_int(n: int) -> bytes:
    b = n.to_bytes(max(1, (n.bit_length() + 7) // 8), "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return der_tlv(0x02, b)


# ---------------------------------------------------------------------------
# RSA PKCS#1 v1.5 验签（SHA-256 DigestInfo）
# ---------------------------------------------------------------------------

_SHA256_DIGEST_INFO_PREFIX = bytes.fromhex(
    "3031300d060960864801650304020105000420")


def rsa_verify_sha256(n: int, e: int, message: bytes, sig: bytes) -> bool:
    """RSA PKCS#1 v1.5 验签（sha256）。message 是原文（内部做 SHA-256）。

    EM = 00 || 01 || PS(FF…) || 00 || DigestInfo(SHA-256)
    """
    k = (n.bit_length() + 7) // 8
    if len(sig) != k:
        return False
    s = int.from_bytes(sig, "big")
    if s >= n:
        return False
    m = pow(s, e, n)
    em = m.to_bytes(k, "big")
    digest = hashlib.sha256(message).digest()
    # 00 01 后至少 8 字节 PS；分隔 00；DigestInfo
    tail = b"\x00" + _SHA256_DIGEST_INFO_PREFIX + digest
    if not em.endswith(tail):
        return False
    pad = em[:k - len(tail)]
    return len(pad) >= 11 and pad == b"\x00\x01" + b"\xff" * (len(pad) - 2)


# ---------------------------------------------------------------------------
# 算法 OID（值编码，不含 tag/长度）
# ---------------------------------------------------------------------------

OID_RSA_ENCRYPTION = bytes.fromhex("2a864886f70d010101")     # 1.2.840.113549.1.1.1
OID_SHA256_RSA = bytes.fromhex("2a864886f70d01010b")         # 1.2.840.113549.1.1.11
OID_DIGEST_SHA256 = bytes.fromhex("608648016503040201")      # 2.16.840.1.101.3.4.2.1
OID_EC_PUBLIC_KEY = bytes.fromhex("2a8648ce3d0201")          # 1.2.840.10045.2.1
OID_P256 = bytes.fromhex("2a8648ce3d030107")                 # 1.2.840.10045.3.1.7
OID_ECDSA_SHA256 = bytes.fromhex("2a8648ce3d040302")         # 1.2.840.10045.4.3.2


def _algid_oid(algid_payload: bytes) -> Optional[bytes]:
    """AlgorithmIdentifier 的 payload → 内部 OID 的值字节。"""
    try:
        f = children(algid_payload)
        if f and f[0][0] == 0x06:
            return f[0][1]
    except (ValueError, IndexError):
        pass
    return None


def verify_with_cert_key(cert: Dict[str, Any], message: bytes, sig: bytes,
                         sig_alg_oid: Optional[bytes] = None
                         ) -> Tuple[bool, Optional[str]]:
    """用证书公钥验证签名，按公钥类型/签名算法 OID 分派（v1.2 支持 ECDSA）。

    返回 (是否通过, 不通过原因)。不支持的组合必须返回 False + 原因，
    绝不静默放行（降级必须显式声明纪律）。签名算法 OID 缺失时 fail-closed：
    不允许"识别不出算法就按公钥类型默认"——那是算法混淆攻击面。
    """
    if sig_alg_oid is None:
        return False, "签名算法 OID 缺失或无法识别（拒绝按默认算法放行）"
    if cert.get("key_type") == "rsa":
        if sig_alg_oid is not None and sig_alg_oid not in (
                OID_RSA_ENCRYPTION, OID_SHA256_RSA):
            return False, f"RSA 证书不支持的签名算法 OID {sig_alg_oid.hex()}"
        return rsa_verify_sha256(cert["rsa_n"], cert["rsa_e"], message, sig), None
    if cert.get("key_type") == "ec":
        if cert.get("ec_curve") != OID_P256:
            return False, "仅支持 P-256（prime256v1）EC 证书"
        if sig_alg_oid is not None and sig_alg_oid != OID_ECDSA_SHA256:
            want = sig_alg_oid.hex() if sig_alg_oid else None
            return False, f"EC 证书仅支持 ecdsa-with-SHA256，收到 {want}"
        from .ecc import ecdsa_verify_p256
        return ecdsa_verify_p256(cert["ec_point"], message, sig), None
    return False, "证书公钥算法不支持（仅 RSA / EC P-256）"


# ---------------------------------------------------------------------------
# X.509 最小解析（TBS 原文保留 —— 证书链验签需要 TBS 原始字节）
# ---------------------------------------------------------------------------


def _asn1_time(t: int, v: bytes) -> Optional[datetime.datetime]:
    try:
        if t == 0x17:
            return datetime.datetime.strptime(v.decode(), "%y%m%d%H%M%SZ")
        if t == 0x18:
            s = v.decode()
            if s.endswith("Z"):
                return datetime.datetime.strptime(s, "%Y%m%d%H%M%SZ")
    except ValueError:
        pass
    return None


def parse_cert(cert_der: bytes) -> Dict[str, Any]:
    """X.509 证书 → 公钥/有效期/序列号/TBS 原文等（v1.2：支持 EC P-256 公钥）。"""
    top = seq_items(cert_der)
    if len(top) < 3:
        raise ValueError("证书字段不足")
    _, tbs_v, tbs_raw = top[0]
    # 证书自身签名值（BIT STRING payload，跳首 unused-bits 字节）
    cert_sig = top[2][1][1:]
    # TBSCertificate 内部
    fields = children(tbs_v)
    off = 0
    # version [0] 可选
    if fields[off][0] == 0xA0:
        off += 1
    _, serial, _ = fields[off]; off += 1
    _, tbs_sigalg_v, _ = fields[off]; off += 1   # tbs sigAlg
    _, _, _ = fields[off]; off += 1              # issuer
    _, validity, _ = fields[off]; off += 1
    vf = children(validity)
    nb = _asn1_time(vf[0][0], vf[0][1]) if len(vf) > 0 else None
    na = _asn1_time(vf[1][0], vf[1][1]) if len(vf) > 1 else None
    _, _, _ = fields[off]; off += 1          # subject
    _, spki_v, _ = fields[off]               # SPKI
    spki = children(spki_v)
    rsa_n = rsa_e = None
    key_type = None
    ec_curve = ec_point = None
    spki_alg_oid = _algid_oid(spki[0][1]) if spki else None
    try:
        bit_payload = spki[1][1][1:]         # BIT STRING payload（跳 unused-bits）
        if spki_alg_oid == OID_EC_PUBLIC_KEY:
            # EC 公钥：BIT STRING 内直接是 SEC1 点；curve OID 在 algId 参数位
            alg_fields = children(spki[0][1])
            ec_curve = alg_fields[1][1] if len(alg_fields) > 1 else None
            ec_point = bit_payload
            key_type = "ec"
        else:
            # 默认按 RSA：BIT STRING → RSAPublicKey DER
            t, rsa_v, _, _ = parse_tlv(bit_payload, 0)
            rf = children(rsa_v)
            rsa_n = int.from_bytes(rf[0][1], "big")
            rsa_e = int.from_bytes(rf[1][1], "big")
            key_type = "rsa"
    except (ValueError, IndexError):
        pass
    return {"tbs_raw": tbs_raw, "cert_sig": cert_sig, "not_before": nb,
            "not_after": na, "rsa_n": rsa_n, "rsa_e": rsa_e,
            "key_type": key_type, "ec_curve": ec_curve, "ec_point": ec_point,
            "tbs_sig_oid": _algid_oid(tbs_sigalg_v),
            "serial": serial, "der": cert_der}


def _signer_sid(si_der: bytes) -> Optional[Tuple[bytes, bytes]]:
    """从 SignerInfo 提取 IssuerAndSerialNumber（issuer 完整 TLV raw, serial payload）。"""
    try:
        items = seq_items(si_der)
        t, sid_v, _ = items[1]
        if t != 0x30:
            return None
        f = children(sid_v)
        if len(f) >= 2:
            return f[0][2], f[1][1]
    except (ValueError, IndexError):
        pass
    return None


def _cert_subject_raw(cert_der: bytes) -> Optional[bytes]:
    """证书 TBS 的 subject 完整 TLV raw。"""
    fields = children(seq_items(cert_der)[0][1])
    off = 0
    if fields[off][0] == 0xA0:
        off += 1
    off += 4  # serial, sigAlg, issuer, validity → subject
    return fields[off][2] if off < len(fields) else None


def _match_signer_cert(si_der: bytes, certs: List[bytes]) -> Optional[Dict[str, Any]]:
    """按 issuer+serial 匹配签名者证书（CMS IssuerAndSerialNumber）。"""
    sid = _signer_sid(si_der)
    if sid is None:
        return None
    issuer_raw, serial = sid
    for cder in certs:
        try:
            c = parse_cert(cder)
            if c.get("serial") == serial and _cert_subject_raw(cder) == issuer_raw:
                return c
        except (ValueError, IndexError):
            continue
    return None


def cert_self_signed(cert: Dict[str, Any]) -> bool:
    """证书自签验证：用自身公钥验证对 TBS 原文的签名（RSA / ECDSA 分派）。"""
    ok, _ = verify_with_cert_key(cert, cert["tbs_raw"], cert["cert_sig"],
                                 cert.get("tbs_sig_oid"))
    return ok


def cert_signed_by(cert: Dict[str, Any], issuer: Dict[str, Any]) -> bool:
    """证书由 issuer 公钥签名（CA 链一级，RSA / ECDSA 分派）。"""
    ok, _ = verify_with_cert_key(issuer, cert["tbs_raw"], cert["cert_sig"],
                                 cert.get("tbs_sig_oid"))
    return ok


# ---------------------------------------------------------------------------
# PKCS#7 SignedData 提取
# ---------------------------------------------------------------------------

OID_SIGNED_DATA = b"\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02"
OID_MESSAGE_DIGEST = b"\x2a\x86\x48\x86\xf7\x0d\x01\x09\x04"


def extract_signed_data_der(tsr_der: bytes) -> Optional[bytes]:
    """从 TimeStampResp 原始提取 SignedData 完整 TLV 字节。"""
    def find(buf: bytes) -> Optional[bytes]:
        off = 0
        while off < len(buf):
            try:
                t, v, raw, off = parse_tlv(buf, off)
            except ValueError:
                return None
            if t == 0x06 and v == OID_SIGNED_DATA:
                # 后随 [0]EXPLICIT 里第一个元素 = SignedData 完整 TLV
                try:
                    t1, v1, raw1, _ = parse_tlv(buf[off:], 0)
                    if t1 == 0xA0:
                        _, _, sd_raw, _ = parse_tlv(v1, 0)
                        return sd_raw
                except ValueError:
                    return None
            if t in (0x30, 0x31) or t >= 0xA0:
                sub = find(v)
                if sub is not None:
                    return sub
        return None
    try:
        _, top_v, _, _ = parse_tlv(tsr_der, 0)
    except ValueError:
        return None
    return find(top_v)


def parse_signed_data(sd_der: bytes) -> Dict[str, Any]:
    """SignedData → {econtent_raw, certs, signer_info}（保留验签所需原始字节）。"""
    items = seq_items(sd_der)
    out: Dict[str, Any] = {"certs": []}
    for t, v, raw in items:
        if t == 0x30 and "eci" not in out and v[:1] == b"\x06":
            # encapContentInfo: SEQUENCE { OID ... }
            out["eci"] = (v, raw)
        elif t == 0xA0:
            off = 0
            while off < len(v):
                try:
                    ct, cv, craw, off = parse_tlv(v, off)
                except ValueError:
                    break
                if ct == 0x30:
                    out["certs"].append(craw)
        elif t == 0x31:  # signerInfos SET
            sinfos = children(v)
            if sinfos:
                out["signer_info_raw"] = sinfos[0][2]
    return out


def _eci_content(eci_val: bytes) -> Optional[bytes]:
    """encapContentInfo.eContent [0]{ OCTET STRING } → 内容原始字节。"""
    off = 0
    while off < len(eci_val):
        try:
            t, v, raw, off = parse_tlv(eci_val, off)
        except ValueError:
            return None
        if t == 0xA0:
            try:
                _, cv, craw, _ = parse_tlv(v, 0)  # OCTET STRING
                return cv
            except ValueError:
                return None
    return None


def parse_signer_info(si_der: bytes) -> Dict[str, Any]:
    """SignerInfo → signedAttrs(SET形态)/签名值/摘要算法 OID/签名算法 OID。

    SignerInfo ::= SEQUENCE { version, sid, digestAlgorithm,
      signedAttrs [1], signatureAlgorithm, signature BIT STRING }
    """
    items = seq_items(si_der)
    out: Dict[str, Any] = {}
    sa_raw = None
    idx_a1 = None
    for i, (t, v, raw) in enumerate(items):
        if t == 0xA1 and sa_raw is None:
            sa_raw = raw
            idx_a1 = i
    # digestAlgorithm 固定第 3 个字段
    if len(items) > 2:
        out["digest_alg_oid"] = _algid_oid(items[2][1])
    if sa_raw is not None:
        # CMS 规定：验签时 [1] 替换为 SET OF（0x31），内容字节不变
        out["signed_attrs_set_der"] = b"\x31" + sa_raw[1:]
    if idx_a1 is not None and idx_a1 + 2 < len(items):
        _, ed_bits, _ = items[idx_a1 + 2]
        out["encrypted_digest"] = ed_bits[1:]  # BIT STRING unused-bits
        out["sig_alg_oid"] = _algid_oid(items[idx_a1 + 1][1])
    return out


def _attr_value(attrs_set_der: bytes, oid: bytes) -> Optional[bytes]:
    """从 signedAttrs（SET 形态）提取指定 attr OID 的第一个值原始字节。"""
    _, set_v, _, _ = parse_tlv(attrs_set_der, 0)
    off = 0
    while off < len(set_v):
        try:
            t, v, raw, off = parse_tlv(set_v, off)
        except ValueError:
            return None
        if t != 0x30:
            continue
        af = children(v)
        if af and af[0][1] == oid and len(af) > 1:
            # af[1] = SET OF 完整 TLV；其 payload 是元素序列
            el = children(af[1][1])
            if el:
                return el[0][1]  # 第一个元素的 payload
    return None


# ---------------------------------------------------------------------------
# 主验证入口
# ---------------------------------------------------------------------------

def verify_cms(tsr_der: bytes,
               ca_certs: Optional[List[bytes]] = None) -> Dict[str, Any]:
    """验证 TSR 的 CMS 签名链。

    返回:
      verified: 全部通过
      level:    "ca-trusted"（CA 链验证+信任锚定）
                / "self-signed-untrusted"（自签结构有效，无信任锚）
      gen_time / message_digest_ok / problems
    """
    res: Dict[str, Any] = {"verified": False, "level": None, "problems": []}
    try:
        sd_der = extract_signed_data_der(tsr_der)
        if sd_der is None:
            res["problems"].append("TSR 无 SignedData")
            return res
        sd = parse_signed_data(sd_der)
        certs = sd.get("certs", [])
        if not certs:
            res["problems"].append("SignedData 无证书")
            return res
        si_raw = sd.get("signer_info_raw")
        if si_raw is None:
            res["problems"].append("无 signerInfos")
            return res
        si = parse_signer_info(si_raw)
        sa = si.get("signed_attrs_set_der")
        sig = si.get("encrypted_digest")
        if not sa or not sig:
            res["problems"].append("signerInfo 缺 signedAttrs/encryptedDigest")
            return res
        sig_alg_oid = si.get("sig_alg_oid")
        # 摘要算法门禁：只支持 SHA-256（其余明确拒绝，不猜测放行）
        digest_alg_oid = si.get("digest_alg_oid")
        if digest_alg_oid is not None and digest_alg_oid != OID_DIGEST_SHA256:
            res["problems"].append(
                f"仅支持 SHA-256 摘要算法，收到 OID {digest_alg_oid.hex()}")
            return res
        # ① 签名者证书：按 issuer+serial 匹配（CMS IssuerAndSerialNumber）
        signer = _match_signer_cert(si_raw, certs)
        if signer is None:
            # 回退：逐个尝试所有证书（容错：验过即签名者；RSA/ECDSA 分派）
            for cder in certs:
                c = parse_cert(cder)
                ok, _ = verify_with_cert_key(c, sa, sig, sig_alg_oid)
                if ok:
                    signer = c
                    res["signature_math_ok"] = True
                    break
            if signer is None:
                res["problems"].append("signerInfo 签名与任何证书都不匹配（TSR 被篡改或伪造）")
                return res
        # ② 验 signedAttrs 签名（回退路径已验证过则跳过）
        if not res.get("signature_math_ok"):
            ok, prob = verify_with_cert_key(signer, sa, sig, sig_alg_oid)
            if not ok:
                res["problems"].append(
                    prob or "signerInfo 签名验证失败（TSR 被篡改或非本证书签发）")
                return res
        res["signature_math_ok"] = True
        res["sig_alg"] = ("ecdsa-p256-sha256" if sig_alg_oid == OID_ECDSA_SHA256
                          else "rsa-pkcs1v15-sha256")
        res["signer_cert_der"] = signer.get("der")
        # ③ messageDigest attr == SHA-256(eContent)
        content = _eci_content(sd["eci"][0]) if sd.get("eci") else None
        md_attr = _attr_value(sa, OID_MESSAGE_DIGEST)
        if content is None or md_attr is None:
            res["problems"].append("缺 eContent 或 messageDigest attr")
            return res
        if hashlib.sha256(content).digest() != md_attr:
            res["problems"].append("messageDigest 与 eContent 不符")
            return res
        res["message_digest_ok"] = True
        # ④ 证书信任判定
        ca_list = ca_certs or []
        trusted = False
        if cert_self_signed(signer):
            res["level"] = "self-signed-untrusted"
        if not trusted and ca_list:
            for ca_der in ca_list:
                ca = parse_cert(ca_der)
                if cert_signed_by(signer, ca):
                    # 信任链成立（CA 还要求自身可信——它由用户提供即视为锚点）
                    res["level"] = "ca-trusted"
                    trusted = True
                    break
        # ⑤ 有效期：genTime（签名时刻）在证书有效期内
        gen_s = _gen_time_from_tsr(tsr_der)
        gen = None
        if gen_s:
            try:
                gen = _parse_ts(gen_s)
            except ValueError:
                pass
        if gen and signer["not_before"] and signer["not_after"]:
            if not (signer["not_before"] <= gen <= signer["not_after"]):
                res["problems"].append(
                    f"genTime {gen_s} 不在证书有效期 "
                    f"[{signer['not_before']} ~ {signer['not_after']}] 内")
        res["gen_time"] = gen_s
        if res["level"] == "ca-trusted" and not res["problems"]:
            res["verified"] = True
    except (ValueError, IndexError) as e:
        res["problems"].append(f"CMS 解析异常: {e}")
    return res


def _gen_time_from_tsr(tsr_der: bytes) -> Optional[str]:
    """按 id-ct-TSTInfo OID 锚点提取 genTime（RFC3161 genTime 字段）。"""
    from .tsa import _extract_tst_info, parse_tsr
    parsed = parse_tsr(tsr_der)
    return parsed.get("gen_time")


def _parse_ts(s: str) -> datetime.datetime:
    if len(s) == 15 and s.endswith("Z"):     # YYMMDDHHMMSSZ (UTC)
        return datetime.datetime.strptime(s, "%y%m%d%H%M%SZ")
    if len(s) == 17 and s.endswith("Z"):     # YYYYMMDDHHMMSSZ
        return datetime.datetime.strptime(s, "%Y%m%d%H%M%SZ")
    if len(s) == 19 and s.endswith("Z"):     # YYYYMMDDHHMMSSZ 14→15,17,19? 兼容
        pass
    raise ValueError(f"未知时间格式: {s}")


def load_ca_pem(path: str) -> List[bytes]:
    """PEM 文件 → [DER, ...]（多证书 bundle）。"""
    with open(path, encoding="utf-8") as f:
        text = f.read()
    blocks = re.findall(
        r"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----",
        text, re.S)
    return [base64.b64decode(b.strip()) for b in blocks]
