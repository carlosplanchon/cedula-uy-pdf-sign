from cryptography import x509
from cryptography.x509.oid import NameOID

from cedula_uy_pdf_sign.cert_utils import cert_not_after, get_common_name, normalize_issuer_name


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
