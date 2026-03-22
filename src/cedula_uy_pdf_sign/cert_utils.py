# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

from cryptography import x509
from cryptography.x509.oid import NameOID


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
