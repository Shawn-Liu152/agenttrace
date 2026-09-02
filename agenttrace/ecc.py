"""零依赖 NIST P-256（secp256r1 / prime256v1）ECDSA 验签（v1.2.0）。

只做**验签**（不做签名、不做密钥生成）——AgentTrace 是审计工具，只需要
用证书里的公钥验证别人的签名，不需要持有 EC 私钥。验签不需要随机源，
也不需要 RFC 6979，数学上只涉及有限域上的点运算。

覆盖范围（诚实边界，与 SECURITY.md 同步）：
  - 曲线：仅 NIST P-256；压缩点格式 / P-384、P-521 报"不支持"而非放行
  - 哈希：仅 SHA-256（ecdsa-with-SHA256，CMS/CRL/OCSP 的主流组合）
  - 签名编码：ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }（DER）
  - 非常数时间实现：与 ed25519.py 同一声明，威胁模型是事后离线验签，
    不面对时序侧信道对手

交叉验证：tests/make_fixture.py 用 cryptography 生成 P-256 真实签名链，
本模块的判定必须与 cryptography 一致（有效通过、翻转即拒）。
"""

from __future__ import annotations

import hashlib
from typing import Optional, Tuple

# ---------------------------------------------------------------------------
# P-256 域参数（FIPS 186-4 / SEC2）
# ---------------------------------------------------------------------------

_P = int.from_bytes(bytes.fromhex(
    "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"), "big")
_A = _P - 3
_B = int.from_bytes(bytes.fromhex(
    "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"), "big")
_N = int.from_bytes(bytes.fromhex(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"), "big")
_GX = int.from_bytes(bytes.fromhex(
    "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"), "big")
_GY = int.from_bytes(bytes.fromhex(
    "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"), "big")
_G = (_GX, _GY)

Point = Optional[Tuple[int, int]]  # None = 无穷远点 O


class UnsupportedEllipticCurve(ValueError):
    """非 P-256 / 压缩点 / 不支持的组合——调用方必须显式降级，禁止放行。"""


# ---------------------------------------------------------------------------
# 椭圆曲线点运算（仿射坐标，P-256 素域）
# ---------------------------------------------------------------------------


def _point_add(p1: Point, p2: Point) -> Point:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % _P == 0:
        return None  # P + (-P) = O
    if p1 == p2:
        # 倍点：λ = (3x²+a)/(2y)
        m = (3 * x1 * x1 + _A) * pow(2 * y1 % _P, -1, _P) % _P
    else:
        m = (y2 - y1) * pow((x2 - x1) % _P, -1, _P) % _P
    x3 = (m * m - x1 - x2) % _P
    y3 = (m * (x1 - x3) - y1) % _P
    return x3, y3


def scalar_mult(k: int, point: Point) -> Point:
    """double-and-add 标量乘法。k 对阶 n 取模。"""
    if point is None or k % _N == 0:
        return None
    k = k % _N
    result: Point = None
    addend: Point = point
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


def _on_curve(point: Point) -> bool:
    if point is None:
        return False
    x, y = point
    return (y * y - x * x * x - _A * x - _B) % _P == 0


def decode_uncompressed_point(raw: bytes) -> Tuple[int, int]:
    """SEC1 未压缩点 0x04 || X(32) || Y(32) → (x, y)。其余格式明确拒绝。"""
    if len(raw) != 65:
        raise UnsupportedEllipticCurve(
            f"P-256 未压缩点应为 65 字节，实际 {len(raw)}")
    if raw[0] == 0x02 or raw[0] == 0x03:
        raise UnsupportedEllipticCurve("暂不支持压缩点格式（仅未压缩 0x04 点）")
    if raw[0] != 0x04:
        raise UnsupportedEllipticCurve(f"无法识别的 EC 点前缀 {raw[0]:#x}")
    x = int.from_bytes(raw[1:33], "big")
    y = int.from_bytes(raw[33:65], "big")
    point = (x, y)
    if not (0 < x < _P and 0 < y < _P) or not _on_curve(point):
        raise UnsupportedEllipticCurve("公钥点不在 P-256 曲线上（非法公钥）")
    return point


# ---------------------------------------------------------------------------
# ECDSA-Sig-Value DER 解析（本模块自包含，避免与 cms 循环导入）
# ---------------------------------------------------------------------------


def _der_int_at(buf: bytes, off: int) -> Tuple[int, int]:
    """读一个 DER INTEGER，返回 (值, 下一偏移)。"""
    if buf[off] != 0x02:
        raise ValueError("ECDSA 签名期望 INTEGER")
    off += 1
    first = buf[off]
    if first < 0x80:
        ln = first
        off += 1
    else:
        nb = first & 0x7F
        off += 1
        ln = int.from_bytes(buf[off:off + nb], "big")
        off += nb
    return int.from_bytes(buf[off:off + ln], "big"), off + ln


def parse_ecdsa_signature(sig_der: bytes) -> Tuple[int, int]:
    """SEQUENCE { r INTEGER, s INTEGER } → (r, s)。"""
    if sig_der[0] != 0x30:
        raise ValueError("ECDSA 签名期望 SEQUENCE")
    # 外层长度（短/长形式）
    off = 1
    first = sig_der[off]
    off += 1
    if first >= 0x80:
        nb = first & 0x7F
        off += nb
    r, off = _der_int_at(sig_der, off)
    s, _ = _der_int_at(sig_der, off)
    return r, s


# ---------------------------------------------------------------------------
# ECDSA 验签（FIPS 186-4 验证算法）
# ---------------------------------------------------------------------------


def _truncate_to_order(digest: bytes) -> int:
    """e = 最左 n.bit_length() 位（SHA-256 与 n 同为 256 位时原样）。"""
    e = int.from_bytes(digest, "big")
    excess = len(digest) * 8 - _N.bit_length()
    if excess > 0:
        e >>= excess
    return e


def ecdsa_verify_p256(public_point: bytes, message: bytes,
                      signature_der: bytes, hash_name: str = "sha256") -> bool:
    """验证 P-256 ECDSA 签名。

    public_point: SEC1 未压缩点（65 字节，来自 X.509 SubjectPublicKeyInfo）
    message:      被签名原文（内部做哈希；CMS 场景是 signedAttrs 的 SET 形态）
    signature_der: ECDSA-Sig-Value DER（r, s）
    """
    if hash_name != "sha256":
        raise UnsupportedEllipticCurve(f"仅支持 SHA-256，收到 {hash_name}")
    try:
        q = decode_uncompressed_point(public_point)
        r, s = parse_ecdsa_signature(signature_der)
    except (ValueError, IndexError, UnsupportedEllipticCurve):
        return False
    # 1) 区间检查
    if not (1 <= r < _N and 1 <= s < _N):
        return False
    # 2) e = H(m)；w = s^-1 mod n；u1=ew, u2=rw；(x1,y1)=u1G+u2Q
    digest = hashlib.sha256(message).digest()
    e = _truncate_to_order(digest)
    w = pow(s, -1, _N)
    u1 = e * w % _N
    u2 = r * w % _N
    point = _point_add(scalar_mult(u1, _G), scalar_mult(u2, q))
    if point is None:
        return False
    # 3) r == x1 mod n
    return r == point[0] % _N
