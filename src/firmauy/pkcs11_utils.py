# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Optional

import pkcs11
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

from firmauy.cert_utils import cert_not_after, cert_not_before, get_common_name


def load_pkcs11_lib(pkcs11_lib: str) -> pkcs11.lib:
    try:
        return pkcs11.lib(pkcs11_lib)
    except pkcs11.exceptions.GeneralError as exc:
        raise RuntimeError(
            f"Could not load PKCS#11 module '{pkcs11_lib}': {exc}"
        ) from exc
    except Exception as exc:
        if not Path(pkcs11_lib).exists():
            raise RuntimeError(
                f"PKCS#11 module not found: '{pkcs11_lib}'"
            ) from exc
        raise RuntimeError(
            f"Error loading PKCS#11 module '{pkcs11_lib}': {exc}"
        ) from exc


def find_token(lib: pkcs11.lib, token_label: Optional[str]) -> pkcs11.Token:
    """Return a PKCS#11 token by label, or auto-detect if exactly one is present."""
    if token_label:
        return lib.get_token(token_label=token_label)

    tokens = list(lib.get_tokens())
    if not tokens:
        raise RuntimeError("No PKCS#11 tokens available.")

    if len(tokens) == 1:
        return tokens[0]

    labels = [
        (getattr(t, "label", "") or "").strip() or "<no label>"
        for t in tokens
    ]
    raise RuntimeError(
        "Multiple tokens found and --token-label was not specified. "
        f"Available tokens: {labels}"
    )


def iter_cert_objects(session: pkcs11.Session) -> Iterable[pkcs11.Object]:
    return session.get_objects(
        {pkcs11.Attribute.CLASS: pkcs11.ObjectClass.CERTIFICATE}
    )


def normalize_cert_id_hex(cert_id_hex: str) -> str:
    """Strip colons/spaces and validate that the result is valid, even-length hex.

    A PKCS#11 object ID is a byte string, so its hex form always has an even number of digits.
    Rejecting an odd length here (with a clear message) keeps the promise of "a valid hexadecimal
    value": otherwise it would pass this check and then blow up later in ``bytes.fromhex`` with a
    cryptic ``ValueError``."""
    normalized = cert_id_hex.replace(":", "").replace(" ", "").upper()
    if not re.fullmatch(r"[0-9A-F]+", normalized):
        raise ValueError(
            f"--cert-id '{cert_id_hex}' is not a valid hexadecimal value."
        )
    if len(normalized) % 2 != 0:
        raise ValueError(
            f"--cert-id '{cert_id_hex}' has an odd number of hex digits; "
            "a byte ID is an even-length hex string."
        )
    return normalized


def cert_is_expired(cert: x509.Certificate) -> bool:
    try:
        not_after = cert.not_valid_after_utc
    except AttributeError:
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)  # type: ignore[attr-defined]
    return datetime.now(timezone.utc) > not_after


def cert_not_yet_valid(cert: x509.Certificate) -> bool:
    try:
        not_before = cert.not_valid_before_utc
    except AttributeError:
        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)  # type: ignore[attr-defined]
    return datetime.now(timezone.utc) < not_before


def get_private_key(session: pkcs11.Session, key_id: bytes) -> pkcs11.Object:
    """Return the private-key object on the token matching the given ID."""
    keys = list(session.get_objects({
        pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PRIVATE_KEY,
        pkcs11.Attribute.ID: key_id,
    }))
    if not keys:
        raise RuntimeError(
            "No private key found on the token for the selected certificate."
        )
    return keys[0]


def has_private_key(session: pkcs11.Session, key_id: bytes) -> bool:
    """Return True if a private key with the given ID exists on the token.

    "No key" is simply an empty result, not an error. A genuine PKCS#11 error (e.g. the device is
    pulled mid-query) is allowed to propagate rather than being swallowed as "no key": hiding it
    could wrongly drop the only usable certificate and surface a misleading "no key" message."""
    keys = list(session.get_objects({
        pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PRIVATE_KEY,
        pkcs11.Attribute.ID: key_id,
    }))
    return len(keys) > 0


def select_certificate(
    session: pkcs11.Session, cert_id_hex: Optional[str],
    notify: Optional[Callable[[str], None]] = None,
) -> tuple[bytes, x509.Certificate]:
    """Select the best signing certificate from the token.

    If cert_id_hex is given, filters to that specific certificate ID.
    Otherwise, scores all available certificates and returns the one most
    likely to be a cédula identity certificate. Expired certificates are
    excluded; if all candidates are expired an error is raised.

    ``notify``, when given, receives the skipped-candidate warning lines (certificates without a
    private key, expired ones); without it they are dropped.
    """
    wanted_id = bytes.fromhex(normalize_cert_id_hex(cert_id_hex)) if cert_id_hex else None
    cert_candidates: list[tuple[bytes, x509.Certificate]] = []
    unusable_candidates: list[tuple[bytes, x509.Certificate]] = []   # expired or not yet valid

    for cert_obj in iter_cert_objects(session):
        try:
            obj_id = cert_obj[pkcs11.Attribute.ID]
            cert_der = cert_obj[pkcs11.Attribute.VALUE]
            cert = x509.load_der_x509_certificate(cert_der)
        except Exception:
            continue

        if wanted_id is not None and obj_id != wanted_id:
            continue

        if cert_is_expired(cert) or cert_not_yet_valid(cert):
            unusable_candidates.append((obj_id, cert))
        else:
            cert_candidates.append((obj_id, cert))

    if not cert_candidates and not unusable_candidates:
        if cert_id_hex:
            raise RuntimeError(
                f"No certificate found with ID {cert_id_hex} in the token."
            )
        raise RuntimeError("No usable certificates found in the token.")

    if not cert_candidates:
        cert = unusable_candidates[0][1]
        cn = get_common_name(cert.subject)
        if cert_is_expired(cert):
            reason = f"expired (valid until {cert_not_after(cert)})"
        else:
            reason = f"not yet valid (valid from {cert_not_before(cert)})"
        raise RuntimeError(
            f"Selected certificate is {reason}: {cn}\n"
            "No valid certificates found in the token."
        )

    no_key_candidates: list[tuple[bytes, x509.Certificate]] = []
    valid_candidates: list[tuple[bytes, x509.Certificate]] = []
    for key_id, cert in cert_candidates:
        if has_private_key(session, key_id):
            valid_candidates.append((key_id, cert))
        else:
            no_key_candidates.append((key_id, cert))

    if no_key_candidates and notify:
        notify(
            f"Warning: {len(no_key_candidates)} certificate(s) skipped, no matching private key in token."
        )

    if not valid_candidates:
        cn_list = ", ".join(get_common_name(c.subject) or "?" for _, c in no_key_candidates)
        raise RuntimeError(
            "No valid certificate with available private key found. "
            f"Certificates without key: {cn_list}"
        )

    cert_candidates = valid_candidates

    if unusable_candidates and notify:
        notify(
            f"Warning: {len(unusable_candidates)} certificate(s) skipped (expired or not yet valid)."
        )

    def score(item: tuple[bytes, x509.Certificate]) -> int:
        _, cert = item
        subject = cert.subject.rfc4514_string().upper()
        issuer = cert.issuer.rfc4514_string().upper()

        points = 0
        if "SERIALNUMBER=" in subject or "DNI" in subject:
            points += 5
        if "MINISTERIO DEL INTERIOR" in issuer:
            points += 3
        if get_common_name(cert.subject):
            points += 1
        try:
            ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
            if ku.value.digital_signature:
                points += 4
            if ku.value.content_commitment:
                points += 3
        except x509.ExtensionNotFound:
            pass
        try:
            eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
            signing_oids = {
                ExtendedKeyUsageOID.EMAIL_PROTECTION,
                ExtendedKeyUsageOID.CLIENT_AUTH,
            }
            if any(oid in signing_oids for oid in eku.value):
                points += 2
        except x509.ExtensionNotFound:
            pass
        return points

    cert_candidates.sort(key=score, reverse=True)
    return cert_candidates[0]


def token_to_dict(token) -> dict:
    """Structured view of a PKCS#11 token: ``label``, ``manufacturer``, ``model`` and ``serial``.

    Each value is the trimmed attribute or ``None`` when empty (the display sentinels such as
    ``<no label>`` / ``-`` are a CLI concern, not part of the data). Shared by the ``list-tokens``
    command and :func:`firmauy.api.list_tokens`."""
    def _attr(name: str) -> Optional[str]:
        val = (getattr(token, name, "") or "").strip()
        return val or None

    return {
        "label": _attr("label"),
        "manufacturer": _attr("manufacturer"),
        "model": _attr("model"),
        "serial": _attr("serial"),
    }
