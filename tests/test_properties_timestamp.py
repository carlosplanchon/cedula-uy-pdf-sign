# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

"""Property-based tests over a signature timestamp, where the exhaustive sweep cannot reach.

The sweep in test_sweep_tstinfo.py enumerates every single-bit mutation of a TSTInfo, which is
1096 cases and therefore worth enumerating rather than sampling. These are the spaces that cannot
be feasibly enumerated:

  - **Combined damage.** The unrestricted mutation space of a 137 byte structure is 2^1096.
    This property samples its two-to-twelve-flip subspace, which is still about 6x10^27 sets:
    finite, and not feasibly enumerable. Shrinking earns its keep there, since a failure found
    with twelve flips gets reduced toward a smaller and simpler failing set before anybody has
    to read it.
  - **Time.** A hundred years at microsecond resolution is about 3.15x10^15 instants: finite,
    like the one above, and just as far past walking through. These sample it, measured from the
    genTime the token itself states. A loop would pick a handful of moments and the interesting
    one is always the moment nobody picked.

Every property here was derived from an outcome that was measured first, not from what seemed
likely to hold. The invariant that costs the most is the one that is subtly wrong: it fails
loudly on inputs that are not defects, and the noise is worse than the test it replaced.

Two profiles, registered in conftest.py: 50 examples with the normal suite, 2000 with
FIRMAUY_DEEP=1, which CI runs in the sweep job on every pull request and every push to main.
Keys and signed artifacts are built once for the whole module and reused for every example. Generating a 2048 bit RSA chain per example costs 1.76 seconds, which
at even the shallow profile would be a minute and a half of key generation and no more coverage.

Any counterexample found here is to be reduced to a deterministic regression in
test_timestamp_status.py, so the finding outlives the run that made it. See
docs/security-invariants.md for the procedure and its acceptance criteria.
"""

import datetime
import io
from functools import lru_cache

from asn1crypto import cms as a_cms
from hypothesis import given
from hypothesis import strategies as st
from pyhanko.sign.timestamps import DummyTimeStamper
from pyhanko_certvalidator.registry import SimpleCertificateStore

from firmauy.cms_sign import sign_cms_detached
from firmauy.cms_verify import verify_cms
from firmauy.verify_common import extract_timestamp_token

# The signer's certificate expires tomorrow, which is what makes the temporal properties say
# anything: past that, only a trusted timestamp can keep the signature verifiable.
_SIGNER_DAYS = 1

_BITS = st.sampled_from([1, 2, 4, 8, 16, 32, 64, 128])


@lru_cache(maxsize=1)
def _artifacts():
    """Everything the properties run against, built once. See the module docstring on why."""
    from test_timestamp_status import DATA, _asn1, _chain, _simple_signer

    signer_ca, signer_leaf, signer_key = _chain("PEREZ JUAN", leaf_days=_SIGNER_DAYS)
    tsa_ca, tsa_leaf, tsa_key = _chain("MY TSA", leaf_days=365, timestamping=True)
    other_ca, _leaf, _key = _chain("OTRA TSA", leaf_days=365, timestamping=True)

    a_cert, a_key = _asn1(tsa_key, tsa_leaf)
    stamper = DummyTimeStamper(a_cert, a_key, certs_to_embed=SimpleCertificateStore())
    p7s = sign_cms_detached(io.BytesIO(DATA), signer=_simple_signer(signer_key, signer_leaf),
                            timestamper=stamper)
    signer_info = a_cms.ContentInfo.load(p7s)["content"]["signer_infos"][0]
    _token, gen_time = extract_timestamp_token(signer_info)
    return {
        "data": DATA,
        "p7s": p7s,
        "signer_ca": signer_ca,
        "tsa_ca": tsa_ca,
        "other_ca": other_ca,
        # What the token itself says, not what the clock said when the fixture was built. The
        # properties below are about the moment somebody verifies relative to the stamped moment,
        # so the stamped moment has to come from the stamp.
        "gen_time": gen_time,
        "tstinfo": _tstinfo_span(p7s),
    }


def _tstinfo_span(p7s: bytes) -> tuple:
    """``(offset, length)`` of the TSTInfo inside the file."""
    si = a_cms.ContentInfo.load(p7s)["content"]["signer_infos"][0]
    for attr in si["unsigned_attrs"]:
        if attr["type"].native == "signature_time_stamp_token":
            der = attr["values"][0]["content"]["encap_content_info"]["content"].contents
            at = p7s.find(der)
            assert at >= 0, "could not locate the TSTInfo bytes"
            return at, len(der)
    raise AssertionError("the fixture lost its timestamp")


def _chain_check(result):
    rows = [c for c in result.checks if c.name == "certificate chain to trusted root"]
    assert rows, "no chain row: the fixture stopped exercising trust validation"
    return rows[0]


# --- combined damage ----------------------------------------------------------

@given(data=st.data())
def test_combined_damage_stays_inside_the_failure_envelope(data):
    """Any set of bit flips in the TSTInfo lands in the same envelope as a single one.

    The four acceptance criteria are the sweep's, and they are what makes "detection with
    traceability" a checkable claim rather than a slogan: a verdict comes back, the token is
    named as the problem, and the document's own signature is not accused of anything.

    Two or more flips, because one is the sweep's job and it does it exhaustively.
    """
    art = _artifacts()
    at, length = art["tstinfo"]
    flips = data.draw(st.lists(
        st.tuples(st.integers(min_value=0, max_value=length - 1), _BITS),
        min_size=2, max_size=12, unique=True,
    ))

    mutated = bytearray(art["p7s"])
    for index, mask in flips:
        mutated[at + index] ^= mask
    assert bytes(mutated) != art["p7s"], "the mutation was a no-op"

    result = verify_cms(io.BytesIO(art["data"]), bytes(mutated),
                        trust_roots=[art["signer_ca"]])      # must not raise

    ts = result.timestamp
    assert result.indication == "INDETERMINATE"
    assert ts is not None and ts.present, "a damaged token reported as absent"
    assert not (ts.intact and ts.valid), "a damaged token reported as sound"
    assert all(c.ok for c in result.checks if "timestamp" not in c.name), \
        "the document's own signature was accused"


# --- time ---------------------------------------------------------------------

# A century past the stamp, sampled at whatever resolution timedeltas carry, which is
# microseconds. Not "every moment": a sample of a dense domain, which is the honest description.
# It starts at the genTime because verifying *before* the signature existed is not a question
# anybody asks and not a threat model.
_HORIZON = datetime.timedelta(days=36500)
_AFTER_SIGNING = st.timedeltas(min_value=datetime.timedelta(0), max_value=_HORIZON)
# Past the signer certificate's expiry, which is where the interesting half of the question is.
_AFTER_EXPIRY = st.timedeltas(min_value=datetime.timedelta(days=_SIGNER_DAYS + 1),
                              max_value=_HORIZON)


@given(later=_AFTER_SIGNING)
def test_a_trusted_stamp_makes_the_verdict_independent_of_when_you_look(later):
    """With a trusted timestamp, when you verify stops mattering.

    This is invariant 7 taken past the handful of moments a deterministic test can name: the
    signer's certificate and the TSA's are both judged at the genTime, so a signature does not
    decay. Sampled out to a hundred years past a certificate that expires tomorrow.
    """
    art = _artifacts()
    at_time = art["gen_time"] + later

    result = verify_cms(io.BytesIO(art["data"]), art["p7s"], trust_roots=[art["signer_ca"]],
                        at_time=at_time, tsa_trust_roots=[art["tsa_ca"]])

    assert result.indication == "VALID", f"decayed {later} after the stamp"
    assert _chain_check(result).ok is True
    assert result.timestamp.trusted is True


@given(later=_AFTER_EXPIRY)
def test_an_untrusted_stamp_never_rescues_an_expired_certificate(later):
    """The other half, and the one that matters for security.

    A genTime nobody validated is a claim by a stranger. If it could move the moment the signer's
    certificate is judged at, whoever could rewrite an unsigned attribute would choose the day
    their expired certificate gets checked on.

    Asserted on the chain row and not on the indication. An unvalidated token already holds the
    verdict at INDETERMINATE by itself, so asserting on the word would pass whether or not the
    moment moved. That exact trap was found in this suite by mutation testing.
    """
    art = _artifacts()
    at_time = art["gen_time"] + later

    no_anchors = verify_cms(io.BytesIO(art["data"]), art["p7s"],
                            trust_roots=[art["signer_ca"]], at_time=at_time)
    wrong_anchor = verify_cms(io.BytesIO(art["data"]), art["p7s"],
                              trust_roots=[art["signer_ca"]], at_time=at_time,
                              tsa_trust_roots=[art["other_ca"]])

    for label, result in (("no anchors", no_anchors), ("wrong anchor", wrong_anchor)):
        assert _chain_check(result).ok is False, f"{label}: an unvalidated genTime moved the moment"
        assert "trusted genTime" not in _chain_check(result).detail, label
    assert no_anchors.timestamp.trusted is None       # nobody looked
    assert wrong_anchor.timestamp.trusted is False    # looked, and it did not chain
