# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

"""What a verifier reports about a signature timestamp, for PDF and detached CMS.

XAdES has said something about its timestamp since XAdES-T support landed (see test_xades_t).
PAdES and CAdES said nothing at all: pyHanko hands back a ``timestamp_validity`` with the token's
integrity, validity and trust, and both verifiers dropped it on the floor. A file whose timestamp
was broken in every one of those ways still came back VALID with no row mentioning a timestamp,
which is the worst shape for this to fail in: silence reads as "fine".

Signed here with software keys and pyHanko's DummyTimeStamper, so no card, no network and no real
TSA are involved.
"""

import datetime
import io
from pathlib import Path

from asn1crypto import keys as asn1keys
from asn1crypto import x509 as asn1x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.writer import PageObject, PdfFileWriter
from pyhanko.sign.signers import PdfSignatureMetadata, SimpleSigner, sign_pdf
from pyhanko.sign.timestamps import DummyTimeStamper
from pyhanko_certvalidator.registry import SimpleCertificateStore

from firmauy.cms_sign import sign_cms_detached
from firmauy.cms_verify import verify_cms
from firmauy.pdf_verify import verify_pdf
from firmauy.verify_common import extract_timestamp_token
from firmauy.xml_verify import verify_xml

DATA = b"contenido a firmar"


def _self_signed(cn: str, *, timestamping: bool = False):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    builder = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
    )
    if timestamping:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=False)
    else:
        builder = builder.add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=True, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
    return key, builder.sign(key, hashes.SHA256())


def _asn1(key, cert):
    return (
        asn1x509.Certificate.load(cert.public_bytes(serialization.Encoding.DER)),
        asn1keys.PrivateKeyInfo.load(key.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption())),
    )


def _simple_signer(key, cert) -> SimpleSigner:
    a_cert, a_key = _asn1(key, cert)
    return SimpleSigner(signing_cert=a_cert, signing_key=a_key,
                        cert_registry=SimpleCertificateStore())


def _timestamper():
    key, cert = _self_signed("Test TSA", timestamping=True)
    a_cert, a_key = _asn1(key, cert)
    return cert, DummyTimeStamper(a_cert, a_key, certs_to_embed=SimpleCertificateStore())


def _blank_pdf() -> io.BytesIO:
    writer = PdfFileWriter()
    box = generic.ArrayObject([generic.NumberObject(n) for n in (0, 0, 200, 200)])
    contents = writer.add_object(generic.StreamObject(stream_data=b""))
    writer.insert_page(PageObject(contents=contents, media_box=box))
    base = io.BytesIO()
    writer.write(base)
    base.seek(0)
    return base


def _signed_pdf(tmp_path, timestamper=None):
    key, cert = _self_signed("PEREZ JUAN")
    out = io.BytesIO()
    sign_pdf(IncrementalPdfFileWriter(_blank_pdf()), PdfSignatureMetadata(field_name="Sig1"),
             signer=_simple_signer(key, cert), output=out, timestamper=timestamper)
    path = tmp_path / "firmado.pdf"
    path.write_bytes(out.getvalue())
    return path, cert


def _signed_p7s(timestamper=None):
    key, cert = _self_signed("PEREZ JUAN")
    p7s = sign_cms_detached(io.BytesIO(DATA), signer=_simple_signer(key, cert),
                            timestamper=timestamper)
    return p7s, cert


def _timestamp_checks(result):
    return [c for c in result.checks if "timestamp" in c.name.lower()]


# --- a timestamp that is there must be reported ------------------------------

def test_a_timestamped_pdf_says_it_has_one(tmp_path):
    _tsa_cert, timestamper = _timestamper()
    path, _cert = _signed_pdf(tmp_path, timestamper)

    result = verify_pdf(path)[0]

    assert _timestamp_checks(result), "a stamped PDF reported nothing about its timestamp"
    assert result.timestamp is not None
    assert result.timestamp.present is True
    assert result.timestamp.gen_time is not None


def test_a_timestamped_p7s_says_it_has_one():
    _tsa_cert, timestamper = _timestamper()
    p7s, _cert = _signed_p7s(timestamper)

    result = verify_cms(io.BytesIO(DATA), p7s)

    assert _timestamp_checks(result), "a stamped .p7s reported nothing about its timestamp"
    assert result.timestamp is not None
    assert result.timestamp.present is True


# --- and one that is not there must not be invented ---------------------------

def test_a_pdf_without_a_timestamp_reports_none(tmp_path):
    path, _cert = _signed_pdf(tmp_path)

    result = verify_pdf(path)[0]

    assert _timestamp_checks(result) == []
    assert result.timestamp is None or result.timestamp.present is False


def test_a_p7s_without_a_timestamp_reports_none():
    p7s, _cert = _signed_p7s()

    result = verify_cms(io.BytesIO(DATA), p7s)

    assert _timestamp_checks(result) == []
    assert result.timestamp is None or result.timestamp.present is False


# --- an untrusted TSA is said, not hidden -------------------------------------

def test_an_unvalidated_tsa_is_reported_as_not_trusted(tmp_path):
    """No TSA anchors given, so the token's chain was never evaluated. That is not the same as
    trusted, and it is not the same as broken either."""
    _tsa_cert, timestamper = _timestamper()
    path, _cert = _signed_pdf(tmp_path, timestamper)

    result = verify_pdf(path)[0]

    assert result.timestamp.trusted is not True


# --- with anchors, the TSA chain is actually validated -------------------------

def _pem(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def test_tsa_ca_lets_a_pdf_timestamp_be_trusted(tmp_path):
    """--tsa-ca used to apply to XML only. The option was accepted for a PDF and did nothing."""
    tsa_cert, timestamper = _timestamper()
    path, _cert = _signed_pdf(tmp_path, timestamper)
    anchors = [x509.load_pem_x509_certificate(_pem(tsa_cert))]

    result = verify_pdf(path, tsa_trust_roots=anchors)[0]

    assert result.timestamp.trusted is True
    assert result.timestamp.tsa_common_name == "Test TSA"


def test_tsa_ca_lets_a_p7s_timestamp_be_trusted():
    tsa_cert, timestamper = _timestamper()
    p7s, _cert = _signed_p7s(timestamper)
    anchors = [x509.load_pem_x509_certificate(_pem(tsa_cert))]

    result = verify_cms(io.BytesIO(DATA), p7s, tsa_trust_roots=anchors)

    assert result.timestamp.trusted is True


def test_the_wrong_anchor_does_not_trust_the_timestamp(tmp_path):
    """Evaluated and not trusted, which is a different claim from not evaluated."""
    _tsa_cert, timestamper = _timestamper()
    _key, other = _self_signed("Otra TSA", timestamping=True)
    path, _cert = _signed_pdf(tmp_path, timestamper)
    anchors = [x509.load_pem_x509_certificate(_pem(other))]

    result = verify_pdf(path, tsa_trust_roots=anchors)[0]

    assert result.timestamp.trusted is False       # False, not None
    assert result.timestamp.intact is True         # the token itself is fine


def test_the_signer_anchors_do_not_decide_the_timestamp(tmp_path):
    """The security point of a separate context. Trusting a TSA must not widen who is accepted
    as having signed the document, and trusting a signer must not vouch for a TSA."""
    tsa_cert, timestamper = _timestamper()
    path, signer_cert = _signed_pdf(tmp_path, timestamper)

    signer_anchors = [x509.load_pem_x509_certificate(_pem(signer_cert))]
    result = verify_pdf(path, trust_roots=signer_anchors)[0]

    assert result.trusted is True                  # the signature is trusted
    assert result.timestamp.trusted is None        # and that says nothing about the TSA


# --- through the public API, which is where the option is actually spelled -----

def test_tsa_ca_reaches_a_pdf_through_the_api(tmp_path):
    """The wiring, not the verifier. --tsa-ca was resolved inside the XML branch, so passing it
    for a PDF was accepted and silently did nothing, and no test noticed because every timestamp
    test called the XML verifier directly.
    """
    from firmauy import api

    tsa_cert, timestamper = _timestamper()
    path, _cert = _signed_pdf(tmp_path, timestamper)
    anchors = tmp_path / "tsa.pem"
    anchors.write_bytes(_pem(tsa_cert))

    report = api.verify(path, tsa_ca=anchors)

    assert report.signatures[0].timestamp.trusted is True


def test_tsa_ca_reaches_a_p7s_through_the_api(tmp_path):
    from firmauy import api

    tsa_cert, timestamper = _timestamper()
    p7s, _cert = _signed_p7s(timestamper)
    original = tmp_path / "documento.bin"
    original.write_bytes(DATA)
    signature = tmp_path / "documento.bin.p7s"
    signature.write_bytes(p7s)
    anchors = tmp_path / "tsa.pem"
    anchors.write_bytes(_pem(tsa_cert))

    report = api.verify(signature, tsa_ca=anchors)

    assert report.signatures[0].timestamp.trusted is True


def test_without_tsa_ca_the_api_reports_the_stamp_as_unevaluated(tmp_path):
    from firmauy import api

    _tsa_cert, timestamper = _timestamper()
    path, _cert = _signed_pdf(tmp_path, timestamper)

    report = api.verify(path)

    assert report.signatures[0].timestamp.present is True
    assert report.signatures[0].timestamp.trusted is None


# --- and out through --json, which is what a tool reads ------------------------

def test_the_json_carries_the_timestamp_as_data(tmp_path):
    """A consumer should never have to read a check's wording to find out whether the stamp held,
    and the wording differs per format."""
    from firmauy.cli import _result_to_json_obj

    tsa_cert, timestamper = _timestamper()
    path, _cert = _signed_pdf(tmp_path, timestamper)
    anchors = [x509.load_pem_x509_certificate(_pem(tsa_cert))]

    obj = _result_to_json_obj(verify_pdf(path, tsa_trust_roots=anchors)[0], redact=False)

    assert obj["timestamp"]["trusted"] is True
    assert obj["timestamp"]["tsa_common_name"] == "Test TSA"
    assert obj["timestamp"]["gen_time"] is not None


def test_the_json_says_null_for_a_chain_that_was_not_looked_at(tmp_path):
    from firmauy.cli import _result_to_json_obj

    _tsa_cert, timestamper = _timestamper()
    path, _cert = _signed_pdf(tmp_path, timestamper)

    obj = _result_to_json_obj(verify_pdf(path)[0], redact=False)

    assert obj["timestamp"]["present"] is True
    assert obj["timestamp"]["trusted"] is None      # not false: nothing was validated


def test_the_json_says_null_when_there_is_no_timestamp(tmp_path):
    from firmauy.cli import _result_to_json_obj

    path, _cert = _signed_pdf(tmp_path)
    assert _result_to_json_obj(verify_pdf(path)[0], redact=False)["timestamp"] is None


def test_redacting_leaves_the_timestamp_alone(tmp_path):
    """None of it is about the cardholder: it names the timestamping authority, not the signer."""
    from firmauy.cli import _result_to_json_obj

    _tsa_cert, timestamper = _timestamper()
    path, _cert = _signed_pdf(tmp_path, timestamper)

    plain = _result_to_json_obj(verify_pdf(path)[0], redact=False)["timestamp"]
    hidden = _result_to_json_obj(verify_pdf(path)[0], redact=True)["timestamp"]

    assert plain == hidden


# --- a broken timestamp, which is the case the whole thing started from --------
#
# Produced by editing the file, in both formats. This used to be done with a hand-built pyHanko
# status, on the belief that a corrupted timestamp could not be produced by editing a PDF or a
# .p7s because tampering would break the signature first. That belief was wrong, and the reason
# is the whole point of the attribute: a signature timestamp lives in the SignerInfo's
# **unsigned** attributes, which by construction are not covered by the signature. So the token
# can be rewritten while the signature over the document stays perfectly intact, which is exactly
# the case a verifier has to survive, and the one an attacker gets for free.

def _tamper_with_the_token(p7s: bytes) -> bytes:
    """Corrupt the timestamp token inside a .p7s, leaving everything else byte-identical."""
    from asn1crypto import cms as asn1cms
    from asn1crypto import core as asn1core

    content_info = asn1cms.ContentInfo.load(p7s)
    signer_info = content_info["content"]["signer_infos"][0]
    for attr in signer_info["unsigned_attrs"]:
        if attr["type"].native != "signature_time_stamp_token":
            continue
        token = attr["values"][0]
        tst_signer = token["content"]["signer_infos"][0]
        # Flip one byte of the token's own signature. Nothing else moves: the imprint still
        # matches, the TSA certificate is still there, and only the token's signature is a lie.
        broken = bytearray(tst_signer["signature"].native)
        broken[0] ^= 0xFF
        tst_signer["signature"] = asn1core.OctetString(bytes(broken))
        return content_info.dump(force=True)
    raise AssertionError("the .p7s carries no timestamp token to tamper with")


def test_tampering_with_the_unsigned_timestamp_attribute_leaves_the_signature_intact():
    """The premise of the test below, checked rather than assumed. If tampering broke the
    signature, the interesting branch would be unreachable and a hand-built status would be the
    only way to test it, which is what this file used to believe."""
    _tsa_cert, timestamper = _timestamper()
    p7s, _cert = _signed_p7s(timestamper)

    result = verify_cms(io.BytesIO(DATA), _tamper_with_the_token(p7s))

    assert [c for c in result.checks if c.name == "signature intact (signed bytes unmodified)"][0].ok
    assert [c for c in result.checks if c.name == "signature cryptographically valid"][0].ok


def test_a_tampered_timestamp_token_is_reported_as_broken():
    tsa_cert, timestamper = _timestamper()
    p7s, _cert = _signed_p7s(timestamper)
    anchors = [x509.load_pem_x509_certificate(_pem(tsa_cert))]

    result = verify_cms(io.BytesIO(DATA), _tamper_with_the_token(p7s), tsa_trust_roots=anchors)

    assert result.timestamp.present is True
    assert result.timestamp.valid is False
    rows = _timestamp_checks(result)
    assert rows and rows[0].ok is False


def test_a_tampered_timestamp_holds_the_verdict_at_indeterminate():
    """Not INVALID: the signature over the document is untouched and saying otherwise would
    accuse the wrong thing. Not VALID either, which is what this returned before 1.12.0."""
    tsa_cert, timestamper = _timestamper()
    p7s, signer_cert = _signed_p7s(timestamper)
    anchors = [x509.load_pem_x509_certificate(_pem(tsa_cert))]

    result = verify_cms(io.BytesIO(DATA), _tamper_with_the_token(p7s),
                        trust_roots=[x509.load_pem_x509_certificate(_pem(signer_cert))],
                        tsa_trust_roots=anchors)

    assert result.indication == "INDETERMINATE"


def _tamper_with_the_pdf_token(path) -> bytes:
    """The same edit, inside a PDF.

    The token's signature bytes sit hex-encoded in the signature's ``/Contents``, which the
    ByteRange deliberately skips, so flipping one hex digit changes nothing the document digest
    covers. The length is unchanged, so every offset in the file still points where it did.
    """
    raw = Path(path).read_bytes()
    with open(path, "rb") as f:
        emb = list(PdfFileReader(f).embedded_signatures)[0]
        token, _gen_time = extract_timestamp_token(emb.signer_info)
    hexed = token["signer_infos"][0]["signature"].native.hex().upper().encode()
    at = raw.find(hexed)
    assert at >= 0, "could not find the token's signature inside the PDF"
    data = bytearray(raw)
    data[at] = ord("B") if data[at] != ord("B") else ord("C")
    return bytes(data)


def test_a_tampered_pdf_timestamp_is_caught_and_the_signature_is_not_accused(tmp_path):
    tsa_cert, timestamper = _timestamper()
    path, _cert = _signed_pdf(tmp_path, timestamper)
    tampered = tmp_path / "tampered.pdf"
    tampered.write_bytes(_tamper_with_the_pdf_token(path))
    anchors = [x509.load_pem_x509_certificate(_pem(tsa_cert))]

    result = verify_pdf(tampered, tsa_trust_roots=anchors)[0]

    assert result.timestamp.valid is False
    rows = _timestamp_checks(result)
    assert rows and rows[0].ok is False
    # The signature over the document is untouched, and every row about it still says so.
    assert all(c.ok for c in result.checks if "timestamp" not in c.name)


def test_a_tampered_pdf_timestamp_holds_the_verdict_at_indeterminate(tmp_path):
    """Never INVALID: a timestamp is an unsigned attribute and cannot break the signature. Never
    VALID either, which is what PAdES and CAdES used to say while a row underneath admitted the
    token was broken. XAdES has held at INDETERMINATE since XAdES-T landed; now all three agree.
    """
    tsa_cert, timestamper = _timestamper()
    path, signer_cert = _signed_pdf(tmp_path, timestamper)
    tampered = tmp_path / "tampered.pdf"
    tampered.write_bytes(_tamper_with_the_pdf_token(path))

    result = verify_pdf(tampered,
                        trust_roots=[x509.load_pem_x509_certificate(_pem(signer_cert))],
                        tsa_trust_roots=[x509.load_pem_x509_certificate(_pem(tsa_cert))])[0]

    assert result.indication == "INDETERMINATE"


def test_a_sound_timestamp_does_not_hold_anything_back(tmp_path):
    tsa_cert, timestamper = _timestamper()
    path, signer_cert = _signed_pdf(tmp_path, timestamper)

    result = verify_pdf(path,
                        trust_roots=[x509.load_pem_x509_certificate(_pem(signer_cert))],
                        tsa_trust_roots=[x509.load_pem_x509_certificate(_pem(tsa_cert))])[0]

    assert result.indication == "VALID"


# --- the TSA is judged when it signed, not when we happen to look --------------

def _tsa_chain(leaf_days: int):
    """A long-lived TSA root and a responder certificate that expires in ``leaf_days``.

    Two levels on purpose. A self-signed TSA used as its own anchor proves nothing here: a trust
    anchor's own validity period is not checked during path validation, so the certificate could
    be expired for a century and still validate. Real TSAs look like this anyway, and the
    responder certificate is the short-lived part.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TSA Root CA")])
    root = (x509.CertificateBuilder().subject_name(root_name).issuer_name(root_name)
            .public_key(root_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
            .sign(root_key, hashes.SHA256()))

    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TSA Responder")])
    leaf = (x509.CertificateBuilder().subject_name(leaf_name).issuer_name(root_name)
            .public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=leaf_days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .sign(root_key, hashes.SHA256()))

    a_cert, a_key = _asn1(leaf_key, leaf)
    return root, DummyTimeStamper(a_cert, a_key, certs_to_embed=SimpleCertificateStore())


def test_a_pdf_timestamp_is_judged_at_gentime_and_not_at_verification_time(tmp_path):
    """The stamp does not decay. A TSA responder certificate is short-lived by design and the
    documents it stamps are not, so judging it at verification time means every timestamp turns
    untrusted on a schedule, which is the one thing a timestamp exists to prevent.

    Until 1.12.1 this is what PAdES and CAdES did, while their own docstrings claimed otherwise
    and XAdES did it right."""
    root, timestamper = _tsa_chain(leaf_days=1)      # the responder expires tomorrow
    path, _cert = _signed_pdf(tmp_path, timestamper)
    long_after = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30)

    now = verify_pdf(path, tsa_trust_roots=[root])[0]
    later = verify_pdf(path, tsa_trust_roots=[root], at_time=long_after)[0]

    assert now.timestamp.trusted is True
    assert later.timestamp.trusted is True, "the same token stopped being trusted with time"
    assert later.timestamp.gen_time == now.timestamp.gen_time


def test_a_p7s_timestamp_is_judged_at_gentime_and_not_at_verification_time():
    root, timestamper = _tsa_chain(leaf_days=1)
    p7s, _cert = _signed_p7s(timestamper)
    long_after = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30)

    now = verify_cms(io.BytesIO(DATA), p7s, tsa_trust_roots=[root])
    later = verify_cms(io.BytesIO(DATA), p7s, tsa_trust_roots=[root], at_time=long_after)

    assert now.timestamp.trusted is True
    assert later.timestamp.trusted is True, "the same token stopped being trusted with time"


# --- and the signer is judged when they signed, once the stamp is trusted ------
#
# The point of a timestamp, one level up. A certificate expires and the signature it made does
# not: the stamp proves the signature already existed while the certificate was still valid, so
# that is the moment to judge the certificate at. XAdES has done this since XAdES-T landed and
# PDF and CMS did not, so the same situation gave VALID in one format and INDETERMINATE in the
# other two.

def _chain(cn: str, *, leaf_days: int, timestamping: bool = False):
    """``(ca, leaf, leaf_key)``: a CA and a leaf it issues, expiring in ``leaf_days``.

    Built here rather than borrowed from test_xades_t, which omits KeyUsage on its leaves. XAdES
    validates the chain itself and does not mind, but pyHanko enforces key usage on a CMS signer,
    so a leaf without ``digital_signature`` never gets a trusted chain in a PDF or a .p7s no
    matter what moment it is judged at. That cost an hour of blaming the wrong code.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{cn} CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - datetime.timedelta(days=3650))
          .not_valid_after(now + datetime.timedelta(days=3650))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .add_extension(x509.KeyUsage(
              digital_signature=False, content_commitment=False, key_encipherment=False,
              data_encipherment=False, key_agreement=False, key_cert_sign=True,
              crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
          .sign(ca_key, hashes.SHA256()))

    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    builder = (x509.CertificateBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
               .issuer_name(ca_name).public_key(leaf_key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(days=1))
               .not_valid_after(now + datetime.timedelta(days=leaf_days))
               .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
               .add_extension(x509.KeyUsage(
                   digital_signature=True, content_commitment=not timestamping,
                   key_encipherment=False, data_encipherment=False, key_agreement=False,
                   key_cert_sign=False, crl_sign=False, encipher_only=False,
                   decipher_only=False), critical=True))
    if timestamping:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
    return ca, builder.sign(ca_key, hashes.SHA256()), leaf_key


def _signer_and_tsa(signer_days: int):
    """A signer whose certificate expires in ``signer_days``, and a TSA good for a year."""
    signer_ca, signer_leaf, signer_key = _chain("PEREZ JUAN", leaf_days=signer_days)
    tsa_ca, tsa_leaf, tsa_key = _chain("MY TSA", leaf_days=365, timestamping=True)
    a_cert, a_key = _asn1(tsa_key, tsa_leaf)
    stamper = DummyTimeStamper(a_cert, a_key, certs_to_embed=SimpleCertificateStore())
    return signer_ca, signer_leaf, signer_key, tsa_ca, tsa_leaf, tsa_key, stamper


def test_a_trusted_stamp_lets_an_expired_signing_certificate_still_verify_a_pdf(tmp_path):
    signer_ca, signer_leaf, signer_key, tsa_ca, _l, _k, stamper = _signer_and_tsa(1)
    out = io.BytesIO()
    sign_pdf(IncrementalPdfFileWriter(_blank_pdf()), PdfSignatureMetadata(field_name="Sig1"),
             signer=_simple_signer(signer_key, signer_leaf), output=out, timestamper=stamper)
    path = tmp_path / "firmado.pdf"
    path.write_bytes(out.getvalue())
    later = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=2)

    without = verify_pdf(path, trust_roots=[signer_ca], at_time=later)[0]
    with_stamp = verify_pdf(path, trust_roots=[signer_ca], at_time=later,
                            tsa_trust_roots=[tsa_ca])[0]

    # No anchors for the TSA: nothing vouches for the date, so the expired certificate stands.
    assert without.indication == "INDETERMINATE"
    assert with_stamp.indication == "VALID"
    chain = [c for c in with_stamp.checks if c.name == "certificate chain to trusted root"][0]
    assert "trusted genTime" in chain.detail, "a VALID expired certificate must say why"


def test_a_trusted_stamp_lets_an_expired_signing_certificate_still_verify_a_p7s():
    signer_ca, signer_leaf, signer_key, tsa_ca, _l, _k, stamper = _signer_and_tsa(1)
    p7s = sign_cms_detached(io.BytesIO(DATA), signer=_simple_signer(signer_key, signer_leaf),
                            timestamper=stamper)
    later = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=2)

    without = verify_cms(io.BytesIO(DATA), p7s, trust_roots=[signer_ca], at_time=later)
    with_stamp = verify_cms(io.BytesIO(DATA), p7s, trust_roots=[signer_ca], at_time=later,
                            tsa_trust_roots=[tsa_ca])

    assert without.indication == "INDETERMINATE"
    assert with_stamp.indication == "VALID"


def test_the_three_formats_agree_about_an_expired_signer_with_a_trusted_stamp(tmp_path):
    """The asymmetry this release exists to remove. Same situation, same answer, whatever the
    file happens to be."""
    from test_xades_t import _signed_with_tsa

    now = datetime.datetime.now(datetime.timezone.utc)
    later = now + datetime.timedelta(days=2)
    signer_ca, signer_leaf, signer_key, tsa_ca, tsa_leaf, tsa_key, stamper = _signer_and_tsa(1)

    out = io.BytesIO()
    sign_pdf(IncrementalPdfFileWriter(_blank_pdf()), PdfSignatureMetadata(field_name="Sig1"),
             signer=_simple_signer(signer_key, signer_leaf), output=out, timestamper=stamper)
    pdf_path = tmp_path / "firmado.pdf"
    pdf_path.write_bytes(out.getvalue())
    p7s = sign_cms_detached(io.BytesIO(DATA), signer=_simple_signer(signer_key, signer_leaf),
                            timestamper=stamper)
    xml = _signed_with_tsa(signer_leaf, signer_key, tsa_leaf, tsa_key, tsa_ca, now)

    kw = dict(trust_roots=[signer_ca], at_time=later, tsa_trust_roots=[tsa_ca])
    said = {
        "pdf": verify_pdf(pdf_path, **kw)[0].indication,
        "cms": verify_cms(io.BytesIO(DATA), p7s, **kw).indication,
        "xml": verify_xml(xml, **kw)[0].indication,
    }
    assert set(said.values()) == {"VALID"}, said


def test_an_untrusted_stamp_does_not_move_the_moment(tmp_path):
    """Only a *trusted* token counts. An unvalidated genTime is a claim by a stranger, and letting
    it choose the day the signing certificate is checked on would hand that choice to whoever
    could alter the file."""
    signer_ca, signer_leaf, signer_key, _tsa_ca, _l, _k, stamper = _signer_and_tsa(1)
    _other_ca, _ol, _ok = _chain("OTHER", leaf_days=365, timestamping=True)
    p7s = sign_cms_detached(io.BytesIO(DATA), signer=_simple_signer(signer_key, signer_leaf),
                            timestamper=stamper)
    later = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=2)

    result = verify_cms(io.BytesIO(DATA), p7s, trust_roots=[signer_ca], at_time=later,
                        tsa_trust_roots=[_other_ca])

    assert result.timestamp.trusted is False
    # The chain row, not the overall indication: a token that does not validate already holds the
    # verdict at INDETERMINATE by itself, so asserting on the word would pass whether or not the
    # moment moved. What has to stay false is the certificate, which expired before `later`.
    chain = [c for c in result.checks if c.name == "certificate chain to trusted root"][0]
    assert chain.ok is False, "an untrusted genTime was allowed to rescue an expired certificate"
    assert "trusted genTime" not in chain.detail


def test_a_stamp_from_an_expired_responder_is_still_not_trusted_under_the_wrong_root(tmp_path):
    """Judging at genTime is not the same as trusting anything that claims an old date. The
    anchors still decide; the moment only decides when they are applied."""
    root, timestamper = _tsa_chain(leaf_days=1)
    _other_root, _other_ts = _tsa_chain(leaf_days=1)
    path, _cert = _signed_pdf(tmp_path, timestamper)
    long_after = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30)

    result = verify_pdf(path, tsa_trust_roots=[_other_root], at_time=long_after)[0]

    assert result.timestamp.trusted is False
    assert root is not _other_root
