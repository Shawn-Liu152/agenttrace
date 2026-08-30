"""纯 Python Ed25519（RFC 8032）— 零依赖数字签名，用于外部锚定的非对称升级。

为什么升级到 Ed25519（复评 4.1 的根本解法）：
  HMAC 是对称签名——验证者必须持有签名密钥，密钥放哪里都两难：
    放 Agent 侧 → Agent 被攻破即可重签（自我作证）
    放验证端   → 验证端被攻破即可重签（防伪失效）
  Ed25519 是非对称签名——**私钥只在签名端（Agent 侧），公钥可自由分发
  给任何验证者**。验证端没有私钥，被攻破也只能"验证"，无法伪造。
  信任根从"共享秘密"升级为"单向能力"。

实现说明：
  - RFC 8032 完整实现（SHA-512 + Edwards25519 曲线运算）
  - 纯 Python 标准库，约 200 行，签名/验证各 ~1ms（事件链验证场景足够）
  - 公钥/签名均为 32/64 字节，hex 存储
"""

from __future__ import annotations

import hashlib
import os
import secrets

# ---------------------------------------------------------------------------
# RFC 8032 基础参数
# ---------------------------------------------------------------------------

P = 2**255 - 19  # 域素数
L = 2**252 + 27742317777372353535851937790883648493  # 群阶
D = -121665 * pow(121666, P - 2, P) % P  # 曲线常数 d

# 基点（RFC 8032 官方坐标，避免恢复公式的分支选择问题）
G_X = 15112221349535400772501151409588531511454012693041857206046113283949847762202
G_Y = 46316835694926478169428394003475163141307993866256225615783033603165251855960
G = (G_X, G_Y, 1, G_X * G_Y % P)  # 扩展坐标 (X, Y, Z, T)
IDENTITY = (0, 1, 1, 0)


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _point_add(p: tuple, q: tuple) -> tuple:
    """扩展坐标 Edwards 曲线点加。"""
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = 2 * t1 * t2 * D % P
    d = 2 * z1 * z2 % P
    e = b - a
    f = d - c
    g = d + c
    h = b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _point_mul(s: int, p: tuple) -> tuple:
    """标量乘（double-and-add）。"""
    q = IDENTITY
    while s > 0:
        if s & 1:
            q = _point_add(q, p)
        p = _point_add(p, p)
        s >>= 1
    return q


def _point_equal(p: tuple, q: tuple) -> bool:
    """Z 归一后比较。"""
    x1, y1, z1, _ = p
    x2, y2, z2, _ = q
    if (x1 * z2 - x2 * z1) % P != 0:
        return False
    if (y1 * z2 - y2 * z1) % P != 0:
        return False
    return True


def _point_compress(p: tuple) -> bytes:
    """点 → 32 字节编码（y | x 符号位）。"""
    x, y, z, _ = p
    zinv = pow(z, P - 2, P)
    x = x * zinv % P
    y = y * zinv % P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _point_decompress(s: bytes) -> tuple | None:
    """32 字节解码 → 点；无效返回 None。

    RFC 8032 5.1.3: 给定 y，x = sqrt(u/v)，u = y²-1，v = d·y²+1。
    恢复公式（p ≡ 5 mod 8）: x = u·v³ · (u·v⁷)^((p-5)/8)
    """
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= P:
        return None
    y2 = y * y % P
    u = (y2 - 1) % P
    v = (D * y2 + 1) % P
    if u == 0 and v == 0:
        return None
    # x = u·v³ · (u·v⁷)^((P-5)/8)
    v3 = v * v % P * v % P
    v7 = v3 * v3 % P * v % P
    x = u * v3 % P * pow(u * v7 % P, (P - 5) // 8, P) % P
    # 校验 x²·v == u（即 x² == u/v）；不成立则乘 √-1 再试
    if (x * x % P * v - u) % P != 0:
        if (x * x % P * v + u) % P != 0:
            return None
        x = x * pow(2, (P - 1) // 4, P) % P  # × √-1
    if x == 0 and sign:
        return None
    if x & 1 != sign:
        x = P - x
    return (x, y, 1, x * y % P)


def _secret_expand(secret: bytes) -> tuple:
    h = _sha512(secret)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


# ---------------------------------------------------------------------------
# 公开 API
# ---------------------------------------------------------------------------


def generate_secret() -> bytes:
    """生成 32 字节私钥（密码学随机）。"""
    return secrets.token_bytes(32)


def public_key(secret: bytes) -> bytes:
    """私钥 → 公钥（32 字节）。"""
    a, _ = _secret_expand(secret)
    return _point_compress(_point_mul(a, G))


def sign(secret: bytes, msg: bytes) -> bytes:
    """Ed25519 签名（64 字节：R || S）。"""
    a, prefix = _secret_expand(secret)
    A = _point_compress(_point_mul(a, G))
    r = int.from_bytes(_sha512(prefix + msg), "little") % L
    R = _point_compress(_point_mul(r, G))
    h = int.from_bytes(_sha512(R + A + msg), "little") % L
    s = (r + h * a) % L
    return R + int.to_bytes(s, 32, "little")


def verify(public: bytes, msg: bytes, signature: bytes) -> bool:
    """验证签名。无效签名/公钥返回 False（不抛异常）。"""
    if len(public) != 32 or len(signature) != 64:
        return False
    A = _point_decompress(public)
    if A is None:
        return False
    Rs = signature[:32]
    R = _point_decompress(Rs)
    if R is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= L:  # 防malleability：s 必须小于群阶
        return False
    h = int.from_bytes(_sha512(Rs + public + msg), "little") % L
    # 校验 sB = R + hA（左侧 vs 右侧同时乘基点/公钥）
    left = _point_mul(s, G)
    right = _point_add(R, _point_mul(h, A))
    return _point_equal(left, right)


# ---------------------------------------------------------------------------
# 密钥文件管理
# ---------------------------------------------------------------------------


class Ed25519KeyPair:
    """Ed25519 密钥对（私钥文件 + 公钥分发）。"""

    def __init__(self, secret: bytes):
        self.secret = secret
        self.public = public_key(secret)

    @classmethod
    def generate(cls) -> "Ed25519KeyPair":
        return cls(generate_secret())

    @classmethod
    def load(cls, path: str) -> "Ed25519KeyPair":
        return cls(open(path, "rb").read())

    @classmethod
    def from_hex(cls, hex_str: str) -> "Ed25519KeyPair":
        return cls(bytes.fromhex(hex_str.strip()))

    def secret_hex(self) -> str:
        return self.secret.hex()

    def public_hex(self) -> str:
        return self.public.hex()

    def save_secret(self, path: str) -> str:
        """写私钥（0600；生产建议放 Agent 侧/离线保管，绝不与证据库同目录）。"""
        with open(path, "wb") as f:
            f.write(self.secret)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return path

    def save_public(self, path: str) -> str:
        """写公钥（可自由分发，无保密性）。"""
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.public_hex() + "\n")
        return path