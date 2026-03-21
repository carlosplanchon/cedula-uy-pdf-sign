import pytest
import typer

from cedula_uy_pdf_sign.pkcs11_utils import cert_is_expired, normalize_cert_id_hex


class TestNormalizeCertIdHex:
    def test_clean_hex_uppercased(self):
        assert normalize_cert_id_hex("abcdef") == "ABCDEF"

    def test_already_uppercase(self):
        assert normalize_cert_id_hex("ABCDEF") == "ABCDEF"

    def test_strips_colons(self):
        assert normalize_cert_id_hex("ab:cd:ef") == "ABCDEF"

    def test_strips_spaces(self):
        assert normalize_cert_id_hex("ab cd ef") == "ABCDEF"

    def test_strips_colons_and_spaces(self):
        assert normalize_cert_id_hex("ab: cd :ef") == "ABCDEF"

    def test_digits_only(self):
        assert normalize_cert_id_hex("0123456789") == "0123456789"

    def test_invalid_raises_bad_parameter(self):
        with pytest.raises(typer.BadParameter):
            normalize_cert_id_hex("zz")

    def test_empty_raises_bad_parameter(self):
        with pytest.raises(typer.BadParameter):
            normalize_cert_id_hex("")


class TestCertIsExpired:
    def test_valid_cert_not_expired(self, cert_valid):
        assert cert_is_expired(cert_valid) is False

    def test_expired_cert_is_expired(self, cert_expired):
        assert cert_is_expired(cert_expired) is True
