# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

from typing import Optional

from asn1crypto import x509 as asn1x509
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID


def to_asn1_cert(cert: x509.Certificate) -> asn1x509.Certificate:
    """Bridge a ``cryptography`` certificate to ``asn1crypto`` (the type pyhanko and
    pyhanko-certvalidator consume)."""
    return asn1x509.Certificate.load(cert.public_bytes(Encoding.DER))


def to_asn1_certs(certs) -> list:
    """List form of ``to_asn1_cert``; tolerates ``None``."""
    return [to_asn1_cert(c) for c in (certs or [])]


def name_fields(name) -> dict:
    """Extract a uniform ``{common_name, serial_number, organization, country}`` dict from an
    X.509 Name, accepting either a ``cryptography`` or an ``asn1crypto`` Name. Missing
    attributes are ``None``. Used to build a consistent, structured signer/issuer across the
    XML (cryptography) and PDF/CMS (asn1crypto) verifiers."""
    if isinstance(name, asn1x509.Name):
        native = name.native or {}
        return {
            "common_name": native.get("common_name"),
            "serial_number": native.get("serial_number"),
            "organization": native.get("organization_name"),
            "country": native.get("country_name"),
        }

    def _first(oid):
        attrs = name.get_attributes_for_oid(oid)
        return attrs[0].value if attrs else None

    return {
        "common_name": _first(NameOID.COMMON_NAME),
        "serial_number": _first(NameOID.SERIAL_NUMBER),
        "organization": _first(NameOID.ORGANIZATION_NAME),
        "country": _first(NameOID.COUNTRY_NAME),
    }


def get_common_name(name: x509.Name) -> str:
    """Return the CN from an x509.Name, falling back to the RFC 4514 string."""
    try:
        return name.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except IndexError:
        return name.rfc4514_string()


def normalize_issuer_name(name: str) -> str:
    """Normalize whitespace and apply known display aliases."""
    normalized = " ".join(name.split()).strip()
    if normalized.upper() == "AUTORIDAD CERTIFICADORA DEL MINISTERIO DEL INTERIOR":
        return "Autoridad Certificadora del Ministerio del Interior"
    return normalized


def cert_not_after(cert: x509.Certificate) -> str:
    try:
        return cert.not_valid_after_utc.strftime("%Y-%m-%d")
    except AttributeError:
        return cert.not_valid_after.strftime("%Y-%m-%d")  # type: ignore[attr-defined]


def cert_not_before(cert: x509.Certificate) -> str:
    try:
        return cert.not_valid_before_utc.strftime("%Y-%m-%d")
    except AttributeError:
        return cert.not_valid_before.strftime("%Y-%m-%d")  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# PKCS#11 certificate records (shared by the list-certs command and firmauy.api)
# ---------------------------------------------------------------------------


def _cert_digital_signature(cert) -> Optional[bool]:
    try:
        return bool(cert.extensions.get_extension_for_class(x509.KeyUsage).value.digital_signature)
    except x509.ExtensionNotFound:
        return None


def _cert_record(obj_id_hex: str, cert, include_pem: bool) -> dict:
    rec = {
        "id": obj_id_hex,
        "subject": name_fields(cert.subject),
        "issuer": name_fields(cert.issuer),
        "certificate_serial": format(cert.serial_number, "X"),
        "not_after": cert_not_after(cert),
        "digital_signature": _cert_digital_signature(cert),
    }
    if include_pem:
        rec["pem"] = cert.public_bytes(Encoding.PEM).decode().strip()
    return rec


def _redact_cert_record(rec: dict) -> dict:
    """Hide the cardholder's personal data for a shareable listing. The issuer (a public CA) is
    kept; the certificate serial and the PEM identify the holder, so they are hidden too."""
    out = dict(rec)
    out["subject"] = dict(rec["subject"])
    for k in ("common_name", "serial_number"):
        if out["subject"].get(k):
            out["subject"][k] = "[REDACTED]"
    out["certificate_serial"] = "[REDACTED]"
    if "pem" in out:
        out["pem"] = "[REDACTED]"
    return out
