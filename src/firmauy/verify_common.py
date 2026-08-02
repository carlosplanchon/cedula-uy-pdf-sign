# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

"""Shared result types and helpers for signature verification (XML, PDF and CMS).

Indication model (mirrors the EU DSS semantics):
- VALID:         integrity holds and the chain is trusted.
- INDETERMINATE: integrity holds but trust could not be established / was not checked.
- INVALID:       the signature is broken or the document was modified.
"""

import logging
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

# Check names for a signature timestamp, shared by the PDF and CMS verifiers. XAdES has its own
# pair carrying "XAdES-T", which is meaningful there and is left alone.
TS_PRESENT = "signature timestamp present (TSA not trust-validated)"
TS_TRUSTED = "signature timestamp (TSA chain validated)"


@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""


@dataclass
class TimestampInfo:
    """What is known about a signature's RFC 3161 timestamp, as data rather than as prose.

    The three-valued fields are the point. ``None`` means *not evaluated*, which is neither a
    pass nor a failure and is the usual case: without TSA trust anchors the token's chain is
    never checked, and a consumer that reads False there would be reporting a problem that was
    never looked for. pyHanko itself returns ``trusted=False`` in that situation, so the
    distinction has to be restored here, where it is known whether anchors were supplied.

    A timestamp says *when* a signature existed. It is separate from whether the signature is
    valid, and worth keeping separate: a document can carry a perfectly good signature and a
    broken timestamp, and saying so needs two verdicts, not one.
    """

    present: bool = False
    intact: Optional[bool] = None       # the token's own signature is unbroken
    valid: Optional[bool] = None        # ...and cryptographically correct
    trusted: Optional[bool] = None      # the TSA chain reached a trusted root
    gen_time: Optional[datetime] = None
    tsa_common_name: str = ""
    detail: str = ""                    # why, when something is not True


@dataclass
class VerifyResult:
    indication: str                 # VALID | INDETERMINATE | INVALID
    checks: list = field(default_factory=list)
    # Structured {common_name, serial_number, organization, country[, certificate_serial]};
    # uniform across the XML/PDF/CMS verifiers (see cert_utils.name_fields).
    signer: dict = field(default_factory=dict)
    issuer: dict = field(default_factory=dict)
    trusted: bool = False
    # None when the format carries no timestamp. A consumer should read this rather than parse
    # the check rows: the rows are display and their wording differs per format.
    timestamp: Optional[TimestampInfo] = None


# The unsigned CMS attribute an RFC 3161 signature timestamp travels in (id-aa-timeStampToken).
_TST_ATTR = "signature_time_stamp_token"


def timestamp_gen_time(signer_info) -> Optional[datetime]:
    """The genTime a signature-timestamp attribute claims, or None when there is no token.

    Read *before* the token is validated, which is the whole reason this exists. A TSA's
    certificate has to be evaluated at the moment it says it signed, otherwise the timestamp
    stops being trusted the day that certificate expires, which is the opposite of what a
    timestamp is for. Building that validation context means knowing the moment first, and the
    moment is inside the token.

    Reading a claim is not believing it. Nothing here is trusted: this only decides *when* to
    evaluate, and whether the token holds up at that moment is decided afterwards, by the
    validation this time is used to set up. A forged genTime buys nothing on its own, because a
    token that does not chain to the supplied anchors fails regardless of which moment it is
    judged at.

    Anything unparseable reads as absent. A token too broken to state a time has nothing to say
    about when the file was signed, and the validation that follows is what reports it as broken.
    """
    try:
        attrs = signer_info["unsigned_attrs"]
        if not attrs:
            return None
        for attr in attrs:
            if attr["type"].native != _TST_ATTR:
                continue
            token = attr["values"][0]
            return token["content"]["encap_content_info"]["content"].parsed["gen_time"].native
    except Exception:
        return None
    return None


# pyHanko logs a full traceback at WARNING when it cannot build a trust path during CMS or
# PDF validation (both go through ``pyhanko.sign.validation.generic_cms``). That is an
# *expected* outcome: no trust anchors (--no-trust / no cached CAs) or a chain that does not
# reach a trusted root, which the verifiers already surface cleanly as INDETERMINATE via the
# per-check breakdown. Keep that traceback out of the user's terminal.
_PYHANKO_PATH_LOGGER = "pyhanko.sign.validation.generic_cms"


@contextmanager
def muted_path_building_warnings():
    """Temporarily raise the pyHanko path-building logger to ERROR, restoring it after."""
    logger = logging.getLogger(_PYHANKO_PATH_LOGGER)
    prev_level = logger.level
    logger.setLevel(logging.ERROR)
    try:
        yield
    finally:
        logger.setLevel(prev_level)
