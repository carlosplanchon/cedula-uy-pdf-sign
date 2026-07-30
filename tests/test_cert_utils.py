import datetime

from asn1crypto import x509 as asn1x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from firmauy.cert_utils import (
    _cert_digital_signature,
    _cert_record,
    _redact_cert_record,
    cert_not_after,
    get_common_name,
    name_fields,
    normalize_issuer_name,
)


class TestNameFields:
    def test_cryptography_and_asn1crypto_produce_same_dict(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "PEREZ JUAN"),
            x509.NameAttribute(NameOID.SERIAL_NUMBER, "DNI123"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Org"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "UY"),
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256())
        )
        expected = {"common_name": "PEREZ JUAN", "serial_number": "DNI123",
                    "organization": "Org", "country": "UY"}
        # cryptography Name (used by the XML verifier)
        assert name_fields(cert.subject) == expected
        # asn1crypto Name (used by the PDF/CMS verifiers) -> identical structure
        asn1_cert = asn1x509.Certificate.load(cert.public_bytes(serialization.Encoding.DER))
        assert name_fields(asn1_cert.subject) == expected

    def test_missing_attributes_are_none(self):
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Only CN")])
        assert name_fields(name) == {
            "common_name": "Only CN", "serial_number": None,
            "organization": None, "country": None,
        }


class TestGetCommonName:
    def test_returns_cn_when_present(self, cert_valid):
        assert get_common_name(cert_valid.subject) == "Juan Test"

    def test_fallback_to_rfc4514_when_no_cn(self):
        name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Acme")])
        result = get_common_name(name)
        assert "Acme" in result

    def test_issuer_cn(self, cert_valid):
        cn = get_common_name(cert_valid.issuer)
        assert "Ministerio del Interior" in cn


class TestNormalizeIssuerName:
    def test_known_alias(self):
        raw = "AUTORIDAD CERTIFICADORA DEL MINISTERIO DEL INTERIOR"
        assert normalize_issuer_name(raw) == (
            "Autoridad Certificadora del Ministerio del Interior"
        )

    def test_alias_case_insensitive(self):
        raw = "  autoridad certificadora del ministerio del interior  "
        assert normalize_issuer_name(raw) == (
            "Autoridad Certificadora del Ministerio del Interior"
        )

    def test_extra_whitespace_normalized(self):
        assert normalize_issuer_name("Foo   Bar") == "Foo Bar"

    def test_leading_trailing_whitespace(self):
        assert normalize_issuer_name("  Foo Bar  ") == "Foo Bar"

    def test_unknown_name_returned_as_is(self):
        assert normalize_issuer_name("Otra Entidad") == "Otra Entidad"


class TestCertNotAfter:
    def test_format_is_yyyy_mm_dd(self, cert_valid):
        result = cert_not_after(cert_valid)
        assert len(result) == 10
        parts = result.split("-")
        assert len(parts) == 3
        assert len(parts[0]) == 4  # year

    def test_expired_cert_date_in_past(self, cert_expired):
        import datetime
        result = cert_not_after(cert_expired)
        date = datetime.date.fromisoformat(result)
        assert date < datetime.date.today()


def _build_cert(*, cn="PEREZ JUAN", serial_number="DNI123", digital_signature=True,
                with_key_usage=True):
    """A self-signed cert for the record helpers, optionally with a KeyUsage extension."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.SERIAL_NUMBER, serial_number),
    ])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CA MI")])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
        .public_key(key.public_key()).serial_number(0xABCDEF)
        .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
    )
    if with_key_usage:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=digital_signature, content_commitment=True,
                key_encipherment=False, data_encipherment=False, key_agreement=False,
                key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
    return builder.sign(key, hashes.SHA256())


class TestCertRecord:
    def test_record_has_all_fields(self):
        cert = _build_cert()
        rec = _cert_record("01", cert, include_pem=True)
        assert rec["id"] == "01"
        assert rec["subject"] == {
            "common_name": "PEREZ JUAN", "serial_number": "DNI123",
            "organization": None, "country": None,
        }
        assert rec["issuer"]["common_name"] == "CA MI"
        assert rec["certificate_serial"] == format(cert.serial_number, "X")
        assert rec["not_after"] == cert_not_after(cert)
        assert rec["digital_signature"] is True
        assert rec["pem"].startswith("-----BEGIN CERTIFICATE-----")

    def test_record_omits_pem_by_default(self):
        assert "pem" not in _cert_record("02", _build_cert(), include_pem=False)

    def test_digital_signature_true_false_and_absent(self):
        assert _cert_digital_signature(_build_cert(digital_signature=True)) is True
        assert _cert_digital_signature(_build_cert(digital_signature=False)) is False
        assert _cert_digital_signature(_build_cert(with_key_usage=False)) is None

    def test_redact_hides_holder_and_keeps_issuer(self):
        rec = _cert_record("01", _build_cert(), include_pem=True)
        red = _redact_cert_record(rec)
        assert red["subject"]["common_name"] == "[REDACTED]"
        assert red["subject"]["serial_number"] == "[REDACTED]"
        assert red["certificate_serial"] == "[REDACTED]"
        assert red["pem"] == "[REDACTED]"
        assert red["issuer"]["common_name"] == "CA MI"  # a public CA, kept
        # The original record is not mutated.
        assert rec["subject"]["common_name"] == "PEREZ JUAN"
