"""Security checks for the XML signing input parser."""

import datetime

import pytest
from lxml import etree

from firmauy.xml_sign import MAX_XML_BYTES, sign_xml


def test_external_entity_is_not_resolved_when_signing(tmp_path, cert_valid):
    payload = tmp_path / "secret.txt"
    payload.write_text("TOPSECRET")
    xml = (
        f"<!DOCTYPE root [<!ENTITY xxe SYSTEM 'file://{payload}'>]>"
        "<root>&xxe;</root>"
    ).encode()

    with pytest.raises(etree.C14NError):
        sign_xml(
            xml,
            cert=cert_valid,
            signer=lambda data: b"signature",
            signing_time=datetime.datetime.now(datetime.timezone.utc),
        )


def test_oversized_xml_is_rejected_before_parsing(cert_valid):
    xml = b"<root>" + b"x" * MAX_XML_BYTES + b"</root>"

    with pytest.raises(ValueError, match="exceeds the .* byte limit"):
        sign_xml(
            xml,
            cert=cert_valid,
            signer=lambda data: b"signature",
            signing_time=datetime.datetime.now(datetime.timezone.utc),
        )
