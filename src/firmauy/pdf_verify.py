# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

"""PAdES / PDF signature verification, wrapping pyHanko's validator.

Tiered like the XML verifier:
- Level 1: signature integrity (intact + cryptographically valid).
- Level 2: certificate chain to a trusted root (RFC 5280, via pyhanko_certvalidator).
- Level 3 (`check_revocation=True`): CRL/OCSP. Needs network.

Beyond the XML case, a PDF signature also has a *coverage* level: whether it covers
the whole file or content was added afterwards. That is surfaced and factored in.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext

from firmauy.cert_utils import name_fields, to_asn1_certs
from firmauy.verify_common import (
    TS_PRESENT,
    TS_TRUSTED,
    Check,
    TimestampInfo,
    VerifyResult,
    muted_path_building_warnings,
    timestamp_gen_time,
)



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
    coverage = getattr(status, "coverage", None)
    cov_name = coverage.name if coverage is not None else "UNKNOWN"
    cov_ok = cov_name == "ENTIRE_FILE"

    checks = [
        Check("signature intact (covered bytes unmodified)", intact),
        Check("signature cryptographically valid", valid),
        Check("coverage (whole file)", cov_ok, cov_name),
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

    info, ts_check = _timestamp_of(status, tsa_evaluated)

    if not (intact and valid):
        indication = "INVALID"
    elif not cov_ok:
        indication = "INDETERMINATE"   # valid, but does not cover the whole file
    elif ts_check is not None and not ts_check.ok:
        # A timestamp is an unsigned attribute, so a bad one never makes the signature INVALID.
        # It does hold the result at INDETERMINATE, which is what the XAdES path has always done:
        # saying VALID with a row underneath admitting the token is broken is a mixed message,
        # and the word is the part somebody remembers.
        indication = "INDETERMINATE"
    elif trust_evaluated:
        indication = "VALID" if trusted else "INDETERMINATE"
    else:
        indication = "INDETERMINATE"   # integrity OK, trust not evaluated

    if ts_check is not None:
        checks.append(ts_check)

    return VerifyResult(indication, checks, signer, issuer, trusted, info)



def _tsa_context(tsa_trust_roots, tsa_other_certs, at):
    """A validation context for the timestamp alone, or None when no anchors were given.

    Deliberately separate from the signer's. ``trust_roots`` decides who is accepted as having
    *signed* the document, so folding a TSA's root into it to make a timestamp validate would
    quietly widen that, which is a security change and not a convenience. pyHanko takes the two
    contexts as separate arguments for this reason.

    ``at`` is the token's own genTime, supplied by the caller, and not the verification time. A
    TSA responder certificate is short-lived by design and the documents it stamps are not, so
    judging it now means every timestamp turns untrusted the day that certificate expires, which
    is the one thing a timestamp exists to prevent. This is what XAdES already did; PAdES and
    CAdES judged at ``at_time`` until 1.12.1, so the same token flipped from trusted to untrusted
    with nothing about the file having changed.

    Optimistic without an archive timestamp, and knowingly so: a genTime is self-asserted, so
    strictly this needs proof the token existed before the certificate expired, which only a
    later timestamp can give (the AdES -LTA level, out of scope here). The exposure is a TSA key
    compromised after expiry, which is a smaller problem than every -T signature decaying on a
    schedule.
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


def verify_pdf(
    pdf_path,
    *,
    trust_roots: Optional[list] = None,
    intermediates: Optional[list] = None,
    at_time: Optional[datetime] = None,
    check_revocation: bool = False,
    tsa_trust_roots: Optional[list] = None,
    tsa_other_certs: Optional[list] = None,
) -> list:
    """Verify every signature in a PDF. Returns a list of VerifyResult (one per
    signature). With `trust_roots`, also validates the chain (level 2); with
    `check_revocation=True`, also CRL/OCSP (level 3).

    ``tsa_trust_roots`` validates an RFC 3161 signature timestamp's own chain. Without it the
    timestamp is reported as present and unvalidated rather than as trusted or as broken."""
    at = at_time or datetime.now(timezone.utc)
    if trust_roots:
        vc = ValidationContext(
            trust_roots=to_asn1_certs(trust_roots),
            other_certs=to_asn1_certs(intermediates),
            allow_fetching=check_revocation,
            revocation_mode="hard-fail" if check_revocation else "soft-fail",
            moment=at,
        )
    else:
        vc = ValidationContext(allow_fetching=False, revocation_mode="soft-fail", moment=at)

    results = []
    with open(Path(pdf_path), "rb") as f:
        reader = PdfFileReader(f)
        hybrid = reader.xrefs.hybrid_xrefs_present
        if hybrid:
            # pyHanko refuses to validate hybrid cross-reference PDFs in strict mode, but such a
            # signature can still be valid (these are accepted by the official AGESIC validator, and
            # firmauy can produce them with `sign --allow-hybrid-xref`). Re-open non-strict so we can
            # actually check it; normal (non-hybrid) PDFs stay strict.
            f.seek(0)
            reader = PdfFileReader(f, strict=False)
        sigs = list(reader.embedded_signatures)
        if not sigs:
            return [VerifyResult("INVALID", [Check("signature present", False, "no signatures in PDF")])]
        with muted_path_building_warnings():
            for emb in sigs:
                # Per signature, not once for the file: each carries its own token and its own
                # genTime, and a PDF signed twice months apart would otherwise have the second
                # signature's TSA judged at the first one's moment.
                ts_vc = _tsa_context(tsa_trust_roots, tsa_other_certs,
                                     timestamp_gen_time(emb.signer_info) or at)
                status = validate_pdf_signature(emb, vc, ts_vc)
                result = _map_status(status, bool(trust_roots), bool(tsa_trust_roots))
                if hybrid:
                    result.checks.append(Check(
                        "hybrid cross-reference sections: validated in relaxed mode", True,
                        "pyHanko rejects these in strict mode; the signature itself is unaffected",
                    ))
                results.append(result)
    return results
