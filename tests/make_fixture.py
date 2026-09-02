"""构造密码学有效的真实签名 TSR fixture（测试专用）。

用 cryptography 库做真实 RSA-SHA256 签名，结构严格按 RFC3161/CMS 手工构造。
产品代码 cms.py（零依赖）独立验签它；CA 链/自签判定交叉验证。

注意：cryptography 只是 **测试专用** 依赖（fixture 生成器用）。
仓库已提交预生成 fixture（tests/fixtures/），无 cryptography 时测试直接
读取，不重新生成。
"""
import hashlib
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from agenttrace import cms  # 产品 DER 原语（构造 fixture 也用它，结构绝对一致）

der_tlv = cms.der_tlv
der_int = cms.der_int


def _crypto():
    """惰性 import——无 cryptography 时未调用 build_fixture 就不失败。"""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    return x509, hashes, serialization, rsa, ExtendedKeyUsageOID, NameOID


def build_fixture(out_dir, message: bytes = b"anchor-sha256-digest-fixture",
                  gen_time: bytes = b"20260901080000Z"):
    x509, hashes, serialization, rsa, ExtendedKeyUsageOID, NameOID = _crypto()
    # ---- CA + TSA 证书（真实签名链）----
    import datetime
    now = datetime.datetime(2026, 1, 1)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    tsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Fixture Root CA")])
    ca_cert = (x509.CertificateBuilder()
               .subject_name(ca_name).issuer_name(ca_name)
               .public_key(ca_key.public_key())
               .serial_number(11)
               .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=3650))
               .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
               .sign(ca_key, hashes.SHA256()))
    tsa_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Fixture TSA")])
    tsa_cert = (x509.CertificateBuilder()
                .subject_name(tsa_name).issuer_name(ca_name)
                .public_key(tsa_key.public_key())
                .serial_number(22)
                .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=3650))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.ExtendedKeyUsage(
                    [ExtendedKeyUsageOID.TIME_STAMPING]), critical=False)
                .sign(ca_key, hashes.SHA256()))

    ca_der = ca_cert.public_bytes(serialization.Encoding.DER)
    tsa_der = tsa_cert.public_bytes(serialization.Encoding.DER)

    # ---- TSTInfo（真实哈希绑定）----
    msg_hash = hashlib.sha256(message).digest()

    oid_sha256 = der_tlv(0x06, bytes.fromhex("6086480165030402010500"[0:0] or "608648016503040201"))
    # messageImprint = SEQUENCE { SEQUENCE{OID sha256}, OCTET STRING hash }
    imprint = der_tlv(0x30,
                      der_tlv(0x30, oid_sha256) + der_tlv(0x04, msg_hash))
    oid_tstpolicy = der_tlv(0x06, bytes.fromhex("2b0601040182cabbf007"))  # 随便一个策略 OID
    tstinfo_body = (der_int(1) + oid_tstpolicy + imprint + der_int(99)
                    + der_tlv(0x18, gen_time))
    tstinfo = der_tlv(0x30, tstinfo_body)

    # ---- signedAttrs（contentType + messageDigest）----
    OID_CT = der_tlv(0x06, bytes.fromhex("2a864886f70d010903"))      # contentType
    OID_MD = der_tlv(0x06, bytes.fromhex("2a864886f70d010904"))      # messageDigest
    OID_SD = bytes.fromhex("2a864886f70d010702")                    # signedData
    attrs_content = der_tlv(0x30, OID_CT + der_tlv(0x31, der_tlv(0x06, OID_SD)))
    attrs_md = der_tlv(0x30, OID_MD + der_tlv(0x31, der_tlv(0x04, hashlib.sha256(tstinfo).digest())))
    attrs = attrs_content + attrs_md
    sa_for_verify = der_tlv(0x31, attrs)   # SET OF 形态

    # ---- RSA PKCS#1 v1.5 签名（对 sa_for_verify 的 SHA-256 DigestInfo）----
    prefix = bytes.fromhex("3031300d060960864801650304020105000420")
    di = prefix + hashlib.sha256(sa_for_verify).digest()
    k = 256
    em = b"\x00\x01" + b"\xff" * (k - 3 - len(di)) + b"\x00" + di
    d = tsa_key.private_numbers().d
    n = tsa_key.private_numbers().public_numbers.n
    sig = pow(int.from_bytes(em, "big"), d, n).to_bytes(k, "big")

    # ---- SignerInfo ----
    ca_parsed = cms.parse_cert(ca_der)
    # IssuerAndSerialNumber = SEQUENCE{ issuer Name DER, serial INTEGER DER }
    # issuer 是 tsa_cert 的 issuer（= CA subject）→ 从 tsa cert TBS 取
    tbs_fields = cms.children(cms.seq_items(tsa_der)[0][1])
    idx = 0
    if tbs_fields[idx][0] == 0xA0:
        idx += 1
    serial_item = tbs_fields[idx]
    idx += 1                 # serial
    idx += 1                 # sigAlg
    issuer_item = tbs_fields[idx]
    sid = der_tlv(0x30, issuer_item[2] + serial_item[2])

    oid_sha256_alg = der_tlv(0x30, der_tlv(0x06, bytes.fromhex("608648016503040201"))
                             + der_tlv(0x05, b""))
    oid_rsa = der_tlv(0x30, der_tlv(0x06, bytes.fromhex("2a864886f70d010101"))
                      + der_tlv(0x05, b""))
    si_body = (der_int(1) + sid + oid_sha256_alg
               + der_tlv(0xA1, attrs) + oid_rsa + der_tlv(0x03, b"\x00" + sig))
    signer_info = der_tlv(0x30, si_body)

    # ---- encapContentInfo（id-ct-TSTInfo + [0] OCTET TSTInfo）----
    OID_TSTINFO = der_tlv(0x06, bytes.fromhex("2a864886f70d0109100104"))
    eci = der_tlv(0x30, OID_TSTINFO + der_tlv(0xA0, der_tlv(0x04, tstinfo)))

    # ---- SignedData / ContentInfo / TimeStampResp ----
    dig_algs = der_tlv(0x31, oid_sha256_alg)
    certs = der_tlv(0xA0, ca_der + tsa_der)
    signed_data = der_tlv(0x30, der_int(3) + dig_algs + eci + certs
                          + der_tlv(0x31, signer_info))
    OID_SIGNED_DATA = der_tlv(0x06, bytes.fromhex("2a864886f70d010702"))
    content_info = der_tlv(0x30, OID_SIGNED_DATA + der_tlv(0xA0, signed_data))
    tsr = der_tlv(0x30, der_tlv(0x30, der_int(0)) + content_info)

    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "fixture_tsr.der"), "wb") as f:
        f.write(tsr)
    with open(os.path.join(out_dir, "fixture_ca.der"), "wb") as f:
        f.write(ca_der)
    with open(os.path.join(out_dir, "fixture_tsa.der"), "wb") as f:
        f.write(tsa_der)
    with open(os.path.join(out_dir, "fixture_ca.pem"), "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    with open(os.path.join(out_dir, "fixture_message.bin"), "wb") as f:
        f.write(message)
    return tsr, ca_der, tsa_der


if __name__ == "__main__":
    out = os.path.join(ROOT, "tests", "fixtures")
    tsr, ca, tsa = build_fixture(out)
    print(f"fixture 生成 {len(tsr)} bytes → {out}")
    # 即时自测：产品代码验签
    res = cms.verify_cms(tsr, ca_certs=[ca])
    print("verify_cms(ca-trusted):", res["level"], res["problems"])
