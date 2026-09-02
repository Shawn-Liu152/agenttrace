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
    return tsr, ca_der, tsa_der, ca_key, tsa_cert


def build_ec_fixture(out_dir, message: bytes = b"anchor-sha256-digest-fixture-ec",
                     gen_time: bytes = b"20260901080000Z",
                     revoked_serial: int = 0):
    """构造 ECDSA P-256 真实签名链 fixture（v1.2）：EC CA → EC TSA → ECDSA CMS TSR。

    revoked_serial 非 0 时供 CRL fixture 复用同一 CA/TSA 序列（保持序列号稳定）。
    返回 (tsr, ca_der, tsa_der, ca_key, tsa_cert)——后两者供 CRL/OCSP fixture 复用。
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    import datetime
    now = datetime.datetime(2026, 1, 1)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    tsa_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Fixture EC Root CA")])
    ca_cert = (x509.CertificateBuilder()
               .subject_name(ca_name).issuer_name(ca_name)
               .public_key(ca_key.public_key())
               .serial_number(101)
               .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=3650))
               .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
               .sign(ca_key, hashes.SHA256()))
    tsa_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Fixture EC TSA")])
    serial = revoked_serial or 202
    tsa_cert = (x509.CertificateBuilder()
                .subject_name(tsa_name).issuer_name(ca_name)
                .public_key(tsa_key.public_key())
                .serial_number(serial)
                .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=3650))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.ExtendedKeyUsage(
                    [ExtendedKeyUsageOID.TIME_STAMPING]), critical=False)
                .sign(ca_key, hashes.SHA256()))
    ca_der = ca_cert.public_bytes(serialization.Encoding.DER)
    tsa_der = tsa_cert.public_bytes(serialization.Encoding.DER)

    # ---- TSTInfo ----
    msg_hash = hashlib.sha256(message).digest()
    oid_sha256 = der_tlv(0x06, bytes.fromhex("608648016503040201"))
    imprint = der_tlv(0x30, der_tlv(0x30, oid_sha256) + der_tlv(0x04, msg_hash))
    oid_tstpolicy = der_tlv(0x06, bytes.fromhex("2b0601040182cabbf007"))
    tstinfo_body = (der_int(1) + oid_tstpolicy + imprint + der_int(98)
                    + der_tlv(0x18, gen_time))
    tstinfo = der_tlv(0x30, tstinfo_body)

    # ---- signedAttrs ----
    OID_CT = der_tlv(0x06, bytes.fromhex("2a864886f70d010903"))
    OID_MD = der_tlv(0x06, bytes.fromhex("2a864886f70d010904"))
    OID_SD = bytes.fromhex("2a864886f70d010702")
    attrs_content = der_tlv(0x30, OID_CT + der_tlv(0x31, der_tlv(0x06, OID_SD)))
    attrs_md = der_tlv(0x30, OID_MD + der_tlv(0x31, der_tlv(0x04, hashlib.sha256(tstinfo).digest())))
    attrs = attrs_content + attrs_md
    sa_for_verify = der_tlv(0x31, attrs)

    # ---- ECDSA P-256 签名（cryptography 默认输出 DER Ecdsa-Sig-Value）----
    sig = tsa_key.sign(sa_for_verify, ec.ECDSA(hashes.SHA256()))

    # ---- SignerInfo ----
    tbs_fields = cms.children(cms.seq_items(tsa_der)[0][1])
    idx = 0
    if tbs_fields[idx][0] == 0xA0:
        idx += 1
    serial_item = tbs_fields[idx]
    idx += 1                 # serial
    idx += 1                 # sigAlg
    issuer_item = tbs_fields[idx]
    sid = der_tlv(0x30, issuer_item[2] + serial_item[2])

    oid_sha256_alg = der_tlv(0x30, der_tlv(0x06, bytes.fromhex("608648016503040201")))
    # ecdsa-with-SHA256（1.2.840.10045.4.3.2），AlgorithmIdentifier 无参数
    oid_ecdsa = der_tlv(0x30, der_tlv(0x06, bytes.fromhex("2a8648ce3d040302")))
    si_body = (der_int(1) + sid + oid_sha256_alg
               + der_tlv(0xA1, attrs) + oid_ecdsa + der_tlv(0x03, b"\x00" + sig))
    signer_info = der_tlv(0x30, si_body)

    # ---- encapContentInfo / SignedData / TimeStampResp ----
    OID_TSTINFO = der_tlv(0x06, bytes.fromhex("2a864886f70d0109100104"))
    eci = der_tlv(0x30, OID_TSTINFO + der_tlv(0xA0, der_tlv(0x04, tstinfo)))
    dig_algs = der_tlv(0x31, oid_sha256_alg)
    certs = der_tlv(0xA0, ca_der + tsa_der)
    signed_data = der_tlv(0x30, der_int(3) + dig_algs + eci + certs
                          + der_tlv(0x31, signer_info))
    OID_SIGNED_DATA = der_tlv(0x06, bytes.fromhex("2a864886f70d010702"))
    content_info = der_tlv(0x30, OID_SIGNED_DATA + der_tlv(0xA0, signed_data))
    tsr = der_tlv(0x30, der_tlv(0x30, der_int(0)) + content_info)

    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "fixture_ec_tsr.der"), "wb") as f:
        f.write(tsr)
    with open(os.path.join(out_dir, "fixture_ec_ca.der"), "wb") as f:
        f.write(ca_der)
    with open(os.path.join(out_dir, "fixture_ec_tsa.der"), "wb") as f:
        f.write(tsa_der)
    with open(os.path.join(out_dir, "fixture_ec_message.bin"), "wb") as f:
        f.write(message)
    return tsr, ca_der, tsa_der, ca_key, tsa_cert


def build_crl_der(ca_key, issuer_name, serials, next_update,
                  last_update=None, revoked_at=None):
    """通用 CRL 构造（RSA/EC CA 均可），serials 为空=干净清单。"""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    import datetime
    utc = datetime.timezone.utc
    last_update = last_update or datetime.datetime(2026, 1, 1, tzinfo=utc)
    revoked_at = revoked_at or datetime.datetime(2026, 6, 1, tzinfo=utc)
    b = (x509.CertificateRevocationListBuilder()
         .issuer_name(issuer_name).last_update(last_update)
         .next_update(next_update))
    for s in serials:
        b = b.add_revoked_certificate(
            x509.RevokedCertificateBuilder().serial_number(s)
            .revocation_date(revoked_at).build())
    return b.sign(ca_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def build_ocsp_resp_der(ca_key, ca_cert, leaf_cert, status,
                        nonce=b"fixednonce1234567", revocation_time=None,
                        this_update=None, next_update=None):
    """通用 OCSP 响应构造（CA 直签，NAME responder，默认带固定 nonce）。"""
    from cryptography.x509 import ocsp
    from cryptography.hazmat.primitives import hashes, serialization
    import datetime
    utc = datetime.timezone.utc
    this_update = this_update or datetime.datetime(2026, 1, 1, tzinfo=utc)
    next_update = next_update or datetime.datetime(2036, 1, 1, tzinfo=utc)
    b = (ocsp.OCSPResponseBuilder()
         .add_response(cert=leaf_cert, issuer=ca_cert, algorithm=hashes.SHA1(),
                       cert_status=status, this_update=this_update,
                       next_update=next_update, revocation_time=revocation_time,
                       revocation_reason=None)
         .responder_id(ocsp.OCSPResponderEncoding.NAME, ca_cert))
    if nonce:
        from cryptography import x509
        b = b.add_extension(x509.OCSPNonce(nonce), critical=False)
    return b.sign(ca_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def build_revocation_fixtures(out_dir):
    """CRL（good/revoked/stale）+ OCSP 响应（good/revoked），全部 EC CA 真签。"""
    from cryptography import x509
    from cryptography.x509 import ocsp
    import datetime
    # 复用 EC fixture 的 CA/TSA（序列号固定 202）
    _, ca_der, _, ca_key, tsa_cert = build_ec_fixture(out_dir)
    ca_cert = x509.load_der_x509_certificate(ca_der)
    utc = datetime.timezone.utc
    far = datetime.datetime(2036, 1, 1, tzinfo=utc)
    past = datetime.datetime(2026, 2, 1, tzinfo=utc)

    good_crl = build_crl_der(ca_key, ca_cert.subject, [], far)
    revoked_crl = build_crl_der(ca_key, ca_cert.subject, [202], far)
    stale_crl = build_crl_der(ca_key, ca_cert.subject, [], past)
    good_ocsp = build_ocsp_resp_der(ca_key, ca_cert, tsa_cert, ocsp.OCSPCertStatus.GOOD)
    revoked_ocsp = build_ocsp_resp_der(
        ca_key, ca_cert, tsa_cert, ocsp.OCSPCertStatus.REVOKED,
        revocation_time=datetime.datetime(2026, 6, 1, tzinfo=utc))

    os.makedirs(out_dir, exist_ok=True)
    for name, data in [("fixture_crl_good.der", good_crl),
                       ("fixture_crl_revoked.der", revoked_crl),
                       ("fixture_crl_stale.der", stale_crl),
                       ("fixture_ocsp_good.der", good_ocsp),
                       ("fixture_ocsp_revoked.der", revoked_ocsp)]:
        with open(os.path.join(out_dir, name), "wb") as f:
            f.write(data)
    return good_crl, revoked_crl, stale_crl, good_ocsp, revoked_ocsp


if __name__ == "__main__":
    out = os.path.join(ROOT, "tests", "fixtures")
    tsr, ca, tsa, _, _ = build_fixture(out)
    print(f"RSA fixture 生成 {len(tsr)} bytes → {out}")
    # 即时自测：产品代码验签
    res = cms.verify_cms(tsr, ca_certs=[ca])
    print("verify_cms(rsa, ca-trusted):", res["level"], res["problems"])
    tsr2, ca2, tsa2, _, _ = build_ec_fixture(out)
    res2 = cms.verify_cms(tsr2, ca_certs=[ca2])
    print("verify_cms(ecdsa, ca-trusted):", res2["level"], res2.get("sig_alg"),
          res2["problems"])
    build_revocation_fixtures(out)
    print("revocation fixtures (CRL good/revoked/stale + OCSP good/revoked) →", out)
