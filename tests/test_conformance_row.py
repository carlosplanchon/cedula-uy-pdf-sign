# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

"""The conformance row keeps its redaction promise, or it prints nothing.

The row is designed to be pasted into a public GitHub issue by people reporting how firmauy and
firma.gub.uy judged the same document. The one way that can go wrong is the row carrying who
signed: a name, a document number, a serial. These tests hold the promise mechanically, with a
fixture that contains a fake document number precisely so its absence from the output means the
redaction ran, rather than that there was nothing to redact.
"""

from __future__ import annotations

import datetime
import importlib.util
import re
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "conformance_row.py"


def _load_script():
    spec = importlib.util.spec_from_file_location("conformance_row", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _chained_p7s(data: bytes) -> bytes:
    """A detached CMS signed by a leaf under a distinct CA, shaped like a real cédula signature.

    Distinct on purpose: with a self-signed certificate the issuer column would carry the
    signer's own name and the guard would fire on legitimate output. The leaf also carries a
    fake document number and a CRL distribution point, so the test can tell redaction from
    absence and the crl column has something real to show.
    """
    from asn1crypto import keys as asn1keys
    from asn1crypto import x509 as asn1x509
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from pyhanko.sign.signers import SimpleSigner
    from pyhanko_certvalidator.registry import SimpleCertificateStore

    from firmauy.cms_sign import sign_cms_detached

    now = datetime.datetime.now(datetime.timezone.utc)

    def _cert(builder, key, issuer_key):
        return (builder.public_key(key.public_key())
                .not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=365))
                .sign(issuer_key, hashes.SHA256()))

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TEST CONFORMANCE CA")])
    ca = _cert(
        x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).serial_number(1000)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True),
        ca_key, ca_key)

    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "PERSONA DE PRUEBA PEREZ"),
        x509.NameAttribute(NameOID.SERIAL_NUMBER, "DNI99999999"),
    ])
    leaf = _cert(
        x509.CertificateBuilder().subject_name(leaf_name).issuer_name(ca_name)
        .serial_number(0x781910B3462611FA)
        .add_extension(x509.CRLDistributionPoints([x509.DistributionPoint(
            full_name=[x509.UniformResourceIdentifier("http://example.invalid/test.crl")],
            relative_name=None, reasons=None, crl_issuer=None)]), critical=False),
        leaf_key, ca_key)

    registry = SimpleCertificateStore()
    registry.register(asn1x509.Certificate.load(ca.public_bytes(serialization.Encoding.DER)))
    signer = SimpleSigner(
        signing_cert=asn1x509.Certificate.load(leaf.public_bytes(serialization.Encoding.DER)),
        signing_key=asn1keys.PrivateKeyInfo.load(leaf_key.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption())),
        cert_registry=registry,
    )
    return sign_cms_detached(data, signer=signer)


def _run(*args) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(SCRIPT), *map(str, args)],
                          capture_output=True, text=True, timeout=120)


def test_the_row_describes_the_infrastructure_and_never_the_person(tmp_path):
    data = tmp_path / "contrato-confidencial-perez.bin"
    data.write_bytes(b"contenido\n")
    p7s = tmp_path / "contrato-confidencial-perez.bin.p7s"
    p7s.write_bytes(_chained_p7s(b"contenido\n"))

    result = _run(p7s, "--original", data,
                  "--firma-gub-uy", "La firma del documento es correcta.")

    assert result.returncode == 0, result.stderr
    out = result.stdout
    # what the row must carry: the infrastructure
    assert "cades" in out
    assert "TEST CONFORMANCE CA" in out, "the issuing CA is public and belongs on the row"
    assert "http://example.invalid/test.crl" in out, "which CRL the cert points at is the point"
    assert "sha256_rsa" in out
    assert "correcta" in out
    assert "| ? |" not in out.split("agree")[0]  # chip column carries ? by default, fine
    # what it must never carry: the person and the document
    assert "PERSONA DE PRUEBA" not in out, "the signer's name reached the row"
    assert "PEREZ" not in out.upper(), "part of the signer's name reached the output"
    assert "DNI99999999" not in out, "the document number reached the row"
    assert "781910" not in out, "the certificate serial reached the row"
    assert "contrato-confidencial" not in out, "the file name reached the output"


def test_a_self_signed_certificate_trips_the_guard_rather_than_leaking(tmp_path):
    """With a self-signed certificate the issuer column IS the signer's name. The right answer
    is refusing loudly, not printing a row that carries a person."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import test_cli

    data = tmp_path / "d.bin"
    data.write_bytes(b"x\n")
    p7s = tmp_path / "d.bin.p7s"
    p7s.write_bytes(test_cli._software_p7s(b"x\n"))

    result = _run(p7s, "--original", data)

    assert result.returncode == 3
    assert "refusing" in result.stderr
    assert "TEST SIGNER" not in result.stdout, "it refused and printed the row anyway"


def test_the_portal_vocabulary_maps_to_agreement():
    """The portal answers with one of three phrases. Pasting any of them, in any casing, has to
    land on the right side of the agree column, because that column is the whole point."""
    mod = _load_script()

    assert mod._portal("La firma del documento es correcta.") == "correcta"
    assert mod._portal("CORRECTA") == "correcta"
    assert mod._portal("La firma del documento no es correcta") == "no correcta"
    assert mod._portal("Se encontró un problema al analizar el documento.") == "problema"
    assert mod._portal("") == "pending"

    assert mod._agree("VALID", "correcta") == "yes"
    assert mod._agree("INVALID", "no correcta") == "yes"
    assert mod._agree("VALID", "no correcta") == "NO"
    assert mod._agree("INVALID", "correcta") == "NO"
    assert mod._agree("INDETERMINATE", "correcta") == "?"
    assert mod._agree("VALID", "pending") == "?"


def test_the_guard_ignores_degenerate_values_and_catches_real_ones():
    """A test certificate's serial of "1" substring-matches every date on the row. A guard that
    cries wolf on that gets deleted, which is worse than one that skips values too short to
    identify anybody."""
    mod = _load_script()

    row = "| 2026-08 | 1.14.1 | cades | 1 | ? | 2026 | SOME CA | none | sha256_rsa | ..."
    assert mod._leaks(row, {"certificate serial": "1"}) == []
    assert mod._leaks(row, {"signer name": "SOME CA"}) == ["signer name"]
    assert mod._leaks(row, {"document number": ""}) == []


@pytest.mark.parametrize("verdict,expected", [("VALID", "yes"), ("INDETERMINATE", "?")])
def test_agree_never_invents_agreement(verdict, expected):
    mod = _load_script()
    assert mod._agree(verdict, "correcta") == expected


def test_a_hostile_phrase_cannot_break_the_table(tmp_path):
    """Every cell is either pasted text or a field read out of a hostile file, and one pipe or
    newline in either shifts every later column of the issue's table into the wrong place."""
    data = tmp_path / "d.bin"
    data.write_bytes(b"x\n")
    p7s = tmp_path / "d.bin.p7s"
    p7s.write_bytes(_chained_p7s(b"x\n"))

    result = _run(p7s, "--original", data,
                  "--firma-gub-uy", "raro | columna inyectada\nsegunda línea")

    assert result.returncode == 0, result.stderr
    lines = result.stdout.splitlines()
    header, row = lines[0], lines[2]
    # What markdown actually splits on is an unescaped pipe. An escaped one renders as a literal
    # character inside its cell, which is exactly where the injected text should have ended up.
    unescaped = re.findall(r"(?<!\\)\|", row)
    assert len(unescaped) == header.count("|"), "an injected pipe shifted the columns"
    assert "raro \\| columna" in row, "the phrase should survive, sanitized, inside its cell"
    assert "segunda línea" in row, "the newline should collapse, not truncate the phrase"


def test_cells_collapse_whitespace_and_escape_pipes():
    mod = _load_script()
    assert mod._cell("a | b\nc") == "a \\| b c"
    assert mod._cell("  spaced   out  ") == "spaced out"
