# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

"""Exhaustive mutation sweep over a signature timestamp, off by default.

Every bit of a real TSTInfo is flipped, one mutation at a time, and every mutation must land
inside the verifier's failure envelope: a verdict, a traceable cause, and no doubt cast on the
document's own signature. This is the procedure that found the two escapes fixed in 1.14.0
(lazy parsing past genTime, and a well-formed OID naming a digest nobody implements), kept
runnable so "no mutation escapes" stays a checkable claim instead of a historical one.

It verifies the same file over a thousand times (about half a minute), so it is not part of the
normal suite. It runs in CI on its own job (`sweep` in ci.yml), on every pull request and every
push to main, and locally with:

    FIRMAUY_SWEEP=1 uv run pytest tests/test_sweep_tstinfo.py -q

Its findings graduate into deterministic regressions in test_timestamp_status.py, which do run
with the normal suite.

The acceptance criteria are the four assertions below, all of them per mutation. Any violation
should become a deterministic regression in test_timestamp_status.py before it is fixed, so the
finding outlives the sweep that made it.

Documented as a procedure, with its acceptance criteria, in docs/security-invariants.md.
"""

import io
import os

import pytest

from firmauy.cms_sign import sign_cms_detached
from firmauy.cms_verify import verify_cms

pytestmark = pytest.mark.skipif(
    not os.environ.get("FIRMAUY_SWEEP"),
    reason="exhaustive sweep, about half a minute: set FIRMAUY_SWEEP=1 to run it",
)


def test_no_tstinfo_mutation_escapes_the_failure_envelope():
    from asn1crypto import cms as a_cms

    from test_timestamp_status import DATA, _chain, _simple_signer, _timestamper

    signer_ca, signer_leaf, signer_key = _chain("PEREZ JUAN", leaf_days=365)
    _tsa, stamper = _timestamper()
    p7s = sign_cms_detached(io.BytesIO(DATA), signer=_simple_signer(signer_key, signer_leaf),
                            timestamper=stamper)

    si = a_cms.ContentInfo.load(p7s)["content"]["signer_infos"][0]
    der = None
    for attr in si["unsigned_attrs"]:
        if attr["type"].native == "signature_time_stamp_token":
            der = attr["values"][0]["content"]["encap_content_info"]["content"].contents
    assert der, "the fixture lost its timestamp"
    at = p7s.find(der)
    assert at >= 0, "could not locate the TSTInfo bytes in the file"

    violations = []
    for i in range(len(der)):
        for mask in (1, 2, 4, 8, 16, 32, 64, 128):
            data = bytearray(p7s)
            data[at + i] ^= mask
            try:
                result = verify_cms(io.BytesIO(DATA), bytes(data), trust_roots=[signer_ca])
            except Exception as exc:
                # The escape itself is the finding: an exception is detection with no verdict
                # and no traceable cause, which is the failure mode 1.13.1 and 1.14.0 closed.
                violations.append((i, mask, f"escaped as {type(exc).__name__}"))
                continue
            ts = result.timestamp
            if result.indication != "INDETERMINATE":
                violations.append((i, mask, f"indication={result.indication}"))
            elif ts is None or not ts.present:
                violations.append((i, mask, "a damaged token reported as absent"))
            elif ts.intact and ts.valid:
                violations.append((i, mask, "a damaged token reported as sound"))
            elif not all(c.ok for c in result.checks if "timestamp" not in c.name):
                violations.append((i, mask, "the document's own signature was accused"))

    assert not violations, f"{len(violations)} of {len(der) * 8} mutations: {violations[:10]}"
