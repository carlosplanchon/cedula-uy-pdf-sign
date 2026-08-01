# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

"""CAdES / detached CMS (.p7s) verification (the verify side of ``cms_sign``).

Tiered like the XML/PDF verifiers:

- **Level 1** (offline, always): signature integrity, the signed bytes hash to the
  embedded ``messageDigest`` and the signature is cryptographically valid.
- **Level 2** (offline, default): certificate chain to a trusted root (RFC 5280).
- **Level 3** (``check_revocation=True``): CRL/OCSP. Needs network.

A detached CMS signature has no PDF-style *coverage* notion: it signs exactly the
bytes it is verified against, so integrity already implies full coverage.
"""

import asyncio
from datetime import datetime, timezone
from typing import IO, Optional, Union

from asn1crypto import cms as asn1cms
from pyhanko.sign.validation import async_validate_detached_cms
from pyhanko_certvalidator import ValidationContext

from firmauy.cert_utils import name_fields, to_asn1_certs
from firmauy.verify_common import (
    TS_PRESENT,
    TS_TRUSTED,
    Check,
    TimestampInfo,
    VerifyResult,
    muted_path_building_warnings,
)


def _load_signed_data(p7s_bytes: bytes) -> asn1cms.SignedData:
    """Parse a DER-encoded ``.p7s`` into its CMS SignedData. Raises ValueError if it
    is not a CMS SignedData structure."""
    try:
        ci = asn1cms.ContentInfo.load(p7s_bytes)
        content_type = ci["content_type"].native
    except Exception as exc:
        raise ValueError(f"not a valid CMS/.p7s structure: {exc}") from exc
    if content_type != "signed_data":
        raise ValueError(f"not a CMS SignedData (.p7s): content type is '{content_type}'")
    return ci["content"]



def _timestamp_of(status, tsa_evaluated: bool):
    """Turn pyHanko's ``timestamp_validity`` into a (TimestampInfo, Check) pair, or (None, None).

    Both verifiers dropped this object entirely, so a file whose timestamp was broken in every
    way pyHanko reports still came back with no row about it at all, and silence reads as fine.

    ``tsa_evaluated`` says whether TSA trust anchors were supplied. pyHanko returns
    ``trusted=False`` when it had nothing to validate against, which is not the same claim as
    "validated and not trusted", so without anchors the trust field stays None.
    """
    validity = getattr(status, "timestamp_validity", None)
    if validity is None:
        return None, None

    intact = bool(getattr(validity, "intact", False))
    valid = bool(getattr(validity, "valid", False))
    trusted = bool(getattr(validity, "trusted", False)) if tsa_evaluated else None
    cert = getattr(validity, "signing_cert", None)
    info = TimestampInfo(
        present=True,
        intact=intact,
        valid=valid,
        trusted=trusted,
        gen_time=getattr(validity, "timestamp", None),
        # pyHanko hands back an asn1crypto certificate here, not a cryptography one, so
        # cert_utils.get_common_name (which takes the latter) does not apply.
        tsa_common_name=dict(cert.subject.native).get("common_name", "") if cert else "",
    )

    if not (intact and valid):
        info.detail = "the timestamp token is broken"
        return info, Check(TS_TRUSTED if tsa_evaluated else TS_PRESENT, False, info.detail)
    when = info.gen_time.isoformat() if info.gen_time else "unknown time"
    if not tsa_evaluated:
        info.detail = f"genTime {when} (asserted by the TSA, not verified)"
        return info, Check(TS_PRESENT, True, info.detail)
    if trusted:
        info.detail = f"genTime {when} (trusted)"
        return info, Check(TS_TRUSTED, True, info.detail)
    info.detail = "TSA chain does not reach a trusted root"
    return info, Check(TS_TRUSTED, False, info.detail)


def _map_status(status, trust_evaluated: bool, tsa_evaluated: bool = False) -> VerifyResult:
    intact = bool(getattr(status, "intact", False))
    valid = bool(getattr(status, "valid", False))
    trusted = bool(getattr(status, "trusted", False))

    checks = [
        Check("signature intact (signed bytes unmodified)", intact),
        Check("signature cryptographically valid", valid),
    ]
    if trust_evaluated:
        checks.append(Check("certificate chain to trusted root", trusted,
                            "" if trusted else "not trusted"))

    cert = getattr(status, "signing_cert", None)
    if cert is not None:
        signer = {**name_fields(cert.subject), "certificate_serial": format(cert.serial_number, "X")}
        issuer = name_fields(cert.issuer)
    else:
        signer, issuer = {}, {}

    if not (intact and valid):
        indication = "INVALID"
    elif trust_evaluated:
        indication = "VALID" if trusted else "INDETERMINATE"
    else:
        indication = "INDETERMINATE"   # integrity OK, trust not evaluated

    info, ts_check = _timestamp_of(status, tsa_evaluated)
    if ts_check is not None:
        checks.append(ts_check)

    return VerifyResult(indication, checks, signer, issuer, trusted, info)



def _tsa_context(tsa_trust_roots, tsa_other_certs, at):
    """A validation context for the timestamp alone, or None when no anchors were given.

    Deliberately separate from the signer's. ``trust_roots`` decides who is accepted as having
    *signed* the document, so folding a TSA's root into it to make a timestamp validate would
    quietly widen that, which is a security change and not a convenience. pyHanko takes the two
    contexts as separate arguments for this reason.

    The moment is the TSA's own genTime rather than now, so a token whose responder certificate
    has since expired still validates as of when it was issued, which is the point of a
    timestamp.
    """
    if not tsa_trust_roots:
        return None
    return ValidationContext(
        trust_roots=to_asn1_certs(tsa_trust_roots),
        other_certs=to_asn1_certs(tsa_other_certs),
        allow_fetching=False,
        revocation_mode="soft-fail",
        moment=at,
    )


def verify_cms(
    input_data: Union[bytes, IO],
    p7s_bytes: bytes,
    *,
    trust_roots: Optional[list] = None,
    intermediates: Optional[list] = None,
    at_time: Optional[datetime] = None,
    check_revocation: bool = False,
    tsa_trust_roots: Optional[list] = None,
    tsa_other_certs: Optional[list] = None,
) -> VerifyResult:
    """Verify a detached CAdES/.p7s signature (``p7s_bytes``) over ``input_data``.

    With ``trust_roots`` it also validates the certificate chain (level 2); with
    ``check_revocation=True`` it also checks CRL/OCSP (level 3, needs network).
    Otherwise only integrity is checked (level 1).

    ``tsa_trust_roots`` validates an RFC 3161 signature timestamp's own chain. Without it the
    timestamp is reported as present and unvalidated rather than as trusted or as broken."""
    signed_data = _load_signed_data(p7s_bytes)
    at = at_time or datetime.now(timezone.utc)

    vc = None
    if trust_roots:
        vc = ValidationContext(
            trust_roots=to_asn1_certs(trust_roots),
            other_certs=to_asn1_certs(intermediates),
            allow_fetching=check_revocation,
            revocation_mode="hard-fail" if check_revocation else "soft-fail",
            moment=at,
        )

    ts_vc = _tsa_context(tsa_trust_roots, tsa_other_certs, at)
    with muted_path_building_warnings():
        status = asyncio.run(
            async_validate_detached_cms(input_data, signed_data, signer_validation_context=vc,
                                        ts_validation_context=ts_vc)
        )
    return _map_status(status, bool(trust_roots), bool(tsa_trust_roots))
