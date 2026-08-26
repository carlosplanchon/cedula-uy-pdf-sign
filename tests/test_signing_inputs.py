"""Security checks for signing input file boundaries."""

import pytest

from firmauy import signing
from firmauy.signing import _open_regular_input, _read_input_bounded
from firmauy.xml_sign import sign_xml


def test_signing_input_does_not_follow_a_symlink(tmp_path):
    target = tmp_path / "target.txt"
    target.write_text("secret")
    link = tmp_path / "input.txt"
    link.symlink_to(target)

    with pytest.raises(OSError):
        with _open_regular_input(link):
            pass


def test_signing_input_reader_enforces_limit(tmp_path):
    source = tmp_path / "input.txt"
    source.write_bytes(b"12345")

    with pytest.raises(ValueError, match="exceeds the 4 byte limit"):
        _read_input_bounded(source, 4, "input")


def test_xml_signing_parser_enforces_limit(monkeypatch):
    monkeypatch.setattr("firmauy.xml_sign.MAX_XML_BYTES", 4)

    with pytest.raises(ValueError, match="XML input exceeds the 4 byte limit"):
        sign_xml(b"<root>", cert=None, signer=None, signing_time=None)


def test_pdf_signing_parser_enforces_limit(tmp_path, monkeypatch):
    source = tmp_path / "input.pdf"
    source.write_bytes(b"12345")
    monkeypatch.setattr(signing, "MAX_PDF_BYTES", 4)

    with pytest.raises(ValueError, match="PDF exceeds the 4 byte limit"):
        signing._sign_one_pdf(
            input_pdf=source,
            output_pdf=tmp_path / "output.pdf",
            pkcs11_signer=None,
            signer_name="signer",
            issuer_name="issuer",
            cert_serial="1",
            timestamper=None,
            meta=None,
            page=0,
            x1=0,
            y1=0,
            x2=1,
            y2=1,
            timezone="UTC",
            field_name="Signature",
            force=False,
            overwrite=False,
        )
