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

from asn1crypto import keys as asn1keys
from asn1crypto import x509 as asn1x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.writer import PageObject, PdfFileWriter
from pyhanko.sign.signers import PdfSignatureMetadata, SimpleSigner, sign_pdf
from pyhanko.sign.timestamps import DummyTimeStamper
from pyhanko_certvalidator.registry import SimpleCertificateStore

from firmauy.cms_sign import sign_cms_detached
from firmauy.cms_verify import verify_cms
from firmauy.pdf_verify import verify_pdf

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
