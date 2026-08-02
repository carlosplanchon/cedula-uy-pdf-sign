"""XAdES-T (signature timestamp) unit tests.

Sign with a software key + a pyHanko DummyTimeStamper (no real TSA, no smart card), then verify
that the SignatureTimeStamp is present and binds to the SignatureValue. Tampering the timestamp
must fail the dedicated check (and only that check, since it lives in UnsignedProperties)."""

import datetime

from asn1crypto import keys as a_keys
from asn1crypto import x509 as a_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from pyhanko.sign.timestamps import DummyTimeStamper
from pyhanko_certvalidator.registry import SimpleCertificateStore

from firmauy.xml_sign import sign_xml
from firmauy.xml_verify import TS_CHECK_NAME, TS_CHECK_NAME_TRUSTED, verify_xml

XML = b"<?xml version='1.0'?><root><data>hola</data></root>"
TS_CHECK = TS_CHECK_NAME


def _self_signed(cn, *, timestamping=False):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    builder = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(1)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
    )
    if timestamping:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=False)
    return key, builder.sign(key, hashes.SHA256())


def _dummy_timestamper():
    key, cert = _self_signed("Test TSA", timestamping=True)
    a_cert = a_x509.Certificate.load(cert.public_bytes(serialization.Encoding.DER))
    a_key = a_keys.PrivateKeyInfo.load(key.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return DummyTimeStamper(a_cert, a_key, certs_to_embed=SimpleCertificateStore())


def _sign(timestamper=None):
    key, cert = _self_signed("PEREZ JUAN")
    raw_signer = lambda data: key.sign(data, padding.PKCS1v15(), hashes.SHA256())  # noqa: E731
    now = datetime.datetime.now(datetime.timezone.utc)
    return sign_xml(XML, cert=cert, signer=raw_signer, signing_time=now, timestamper=timestamper)


def _check(result, name):
    return next((c for c in result.checks if c.name == name), None)


def test_xades_t_timestamp_present_and_verifies():
    signed = _sign(timestamper=_dummy_timestamper())
    assert b"SignatureTimeStamp" in signed

    result = verify_xml(signed, trust_roots=None)[0]
    ts = _check(result, TS_CHECK)
    assert ts is not None and ts.ok
    assert "genTime" in ts.detail
    # The label must not imply trusted time: the TSA is not validated and the genTime is asserted.
    assert "not trust-validated" in ts.name
    assert "not verified" in ts.detail
    # integrity (incl. the timestamp binding) holds; no trust roots -> INDETERMINATE
    assert result.indication == "INDETERMINATE"


def test_xades_bes_has_no_timestamp_check():
    signed = _sign(timestamper=None)  # plain XAdES-BES
    assert b"SignatureTimeStamp" not in signed

    result = verify_xml(signed, trust_roots=None)[0]
    assert _check(result, TS_CHECK) is None
    assert result.indication == "INDETERMINATE"


def test_tampered_timestamp_fails_only_the_timestamp_check():
    signed = _sign(timestamper=_dummy_timestamper())

    # Flip one base64 char inside the EncapsulatedTimeStamp (not covered by the main signature).
    pos = signed.index(b"EncapsulatedTimeStamp>") + len(b"EncapsulatedTimeStamp>") + 6
    data = bytearray(signed)
    data[pos] = ord("B") if data[pos] != ord("B") else ord("A")
    tampered = bytes(data)

    result = verify_xml(tampered, trust_roots=None)[0]
    ts = _check(result, TS_CHECK)
    assert ts is not None and not ts.ok
    # The timestamp is an unsigned property: a broken timestamp holds the result at INDETERMINATE
    # (not INVALID) and the main signature checks stay intact.
    assert result.indication == "INDETERMINATE"
    assert _check(result, "SignedInfo signature (RSA-SHA256)").ok


# --- --tsa-ca: TSA validation + long-term validation (evaluate at genTime) ---

def _to_a(cert):
    return a_x509.Certificate.load(cert.public_bytes(serialization.Encoding.DER))


def _to_a_key(key):
    return a_keys.PrivateKeyInfo.load(key.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))


def _ca_and_leaf(leaf_cn, *, leaf_not_before, leaf_not_after, timestamping=False):
    """A 2-level chain: a self-signed CA and a leaf it issues (so the leaf is not self-signed and
    validates cleanly against the CA as anchor)."""
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{leaf_cn} CA")])
    ca = (
        x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
        .public_key(ca_key.public_key()).serial_number(1)
        .not_valid_before(now - datetime.timedelta(days=3650))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, leaf_cn)]))
        .issuer_name(ca_name).public_key(leaf_key.public_key()).serial_number(2)
        .not_valid_before(leaf_not_before).not_valid_after(leaf_not_after)
    )
    if timestamping:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
    return ca, builder.sign(ca_key, hashes.SHA256()), leaf_key


def _signed_with_tsa(signer_leaf, signer_key, tsa_leaf, tsa_key, tsa_ca, signing_time):
    stamper = DummyTimeStamper(
        _to_a(tsa_leaf), _to_a_key(tsa_key),
        certs_to_embed=SimpleCertificateStore.from_certs([_to_a(tsa_ca)]))
    return sign_xml(
        XML, cert=signer_leaf,
        signer=lambda d: signer_key.sign(d, padding.PKCS1v15(), hashes.SHA256()),
        signing_time=signing_time, timestamper=stamper)


def test_tsa_ca_enables_ltv_evaluation_at_gentime():
    now = datetime.datetime.now(datetime.timezone.utc)
    # Signer cert valid only [-1d, +1d]; the TSA cert is valid for a year.
    signer_ca, signer_leaf, signer_key = _ca_and_leaf(
        "PEREZ JUAN", leaf_not_before=now - datetime.timedelta(days=1),
        leaf_not_after=now + datetime.timedelta(days=1))
    tsa_ca, tsa_leaf, tsa_key = _ca_and_leaf(
        "MY TSA", leaf_not_before=now - datetime.timedelta(days=1),
        leaf_not_after=now + datetime.timedelta(days=365), timestamping=True)
    signed = _signed_with_tsa(signer_leaf, signer_key, tsa_leaf, tsa_key, tsa_ca, now)

    later = now + datetime.timedelta(days=2)   # the signer cert is expired at this "now"

    # Without --tsa-ca: chain evaluated at `later` -> signer cert expired -> INDETERMINATE.
    r_no = verify_xml(signed, trust_roots=[signer_ca], at_time=later)[0]
    assert r_no.indication == "INDETERMINATE"
    assert TS_CHECK_NAME in {c.name for c in r_no.checks}   # binding-only, TSA not validated

    # With --tsa-ca: the timestamp is trust-validated, so the signer cert is evaluated at the
    # trusted genTime (when it was still valid) -> VALID (long-term validation).
    r_yes = verify_xml(signed, trust_roots=[signer_ca], at_time=later, tsa_trust_roots=[tsa_ca])[0]
    assert r_yes.indication == "VALID", [(c.name, c.detail) for c in r_yes.checks]
    ts = _check(r_yes, TS_CHECK_NAME_TRUSTED)
    assert ts is not None and ts.ok and "trusted" in ts.detail


def test_tsa_ca_wrong_anchor_does_not_trust_timestamp():
    now = datetime.datetime.now(datetime.timezone.utc)
    signer_ca, signer_leaf, signer_key = _ca_and_leaf(
        "PEREZ JUAN", leaf_not_before=now - datetime.timedelta(days=1),
        leaf_not_after=now + datetime.timedelta(days=1))
    tsa_ca, tsa_leaf, tsa_key = _ca_and_leaf(
        "MY TSA", leaf_not_before=now - datetime.timedelta(days=1),
        leaf_not_after=now + datetime.timedelta(days=365), timestamping=True)
    signed = _signed_with_tsa(signer_leaf, signer_key, tsa_leaf, tsa_key, tsa_ca, now)

    # An unrelated CA as --tsa-ca: the timestamp's TSA does not chain to it -> not trusted.
    other_ca, _, _ = _ca_and_leaf(
        "OTHER", leaf_not_before=now - datetime.timedelta(days=1),
        leaf_not_after=now + datetime.timedelta(days=1))
    result = verify_xml(signed, trust_roots=[signer_ca], tsa_trust_roots=[other_ca])[0]
    ts = _check(result, TS_CHECK_NAME_TRUSTED)
    assert ts is not None and not ts.ok          # TSA validation failed
    assert "chain" in ts.detail
    # The core signature is intact and the signer chain is fine, but the unverified timestamp holds
    # the result at INDETERMINATE (an unsigned property never makes it INVALID).
    assert result.indication == "INDETERMINATE"


# --- the same structure the other two formats return ---------------------------

def test_a_xades_timestamp_is_reported_as_data_too():
    """Every format now carries a TimestampInfo, so a consumer reads one field instead of knowing
    which format it holds and which check names that format happens to use."""
    signed = _sign(_dummy_timestamper())
    result = verify_xml(signed)[0]

    assert result.timestamp is not None
    assert result.timestamp.present is True
    assert result.timestamp.gen_time is not None
    # No anchors were given, so the chain was never looked at. That is not the same as untrusted.
    assert result.timestamp.trusted is None


def test_a_xades_bes_signature_carries_no_timestamp_info():
    result = verify_xml(_sign())[0]
    assert result.timestamp is None


# --- three questions, kept apart ----------------------------------------------
#
# Integrity, validity and trust are separate properties and only the third depends on --tsa-ca.
# Until 1.12.1 this path answered all three with the one boolean the check row carried, so a
# sound token under the wrong anchor came back looking destroyed. That reading sends somebody to
# inspect a file when the problem is in the anchors they passed.

def _sound_token_under(anchor_for):
    """A signature whose timestamp is perfectly fine, verified against ``anchor_for(other)``."""
    now = datetime.datetime.now(datetime.timezone.utc)
    signer_ca, signer_leaf, signer_key = _ca_and_leaf(
        "PEREZ JUAN", leaf_not_before=now - datetime.timedelta(days=1),
        leaf_not_after=now + datetime.timedelta(days=365))
    tsa_ca, tsa_leaf, tsa_key = _ca_and_leaf(
        "MY TSA", leaf_not_before=now - datetime.timedelta(days=1),
        leaf_not_after=now + datetime.timedelta(days=365), timestamping=True)
    other_ca, _leaf, _key = _ca_and_leaf(
        "OTHER", leaf_not_before=now - datetime.timedelta(days=1),
        leaf_not_after=now + datetime.timedelta(days=365), timestamping=True)
    signed = _signed_with_tsa(signer_leaf, signer_key, tsa_leaf, tsa_key, tsa_ca, now)
    return verify_xml(signed, trust_roots=[signer_ca],
                      tsa_trust_roots=[anchor_for(tsa_ca, other_ca)])[0]


def test_a_sound_token_under_the_wrong_anchor_is_not_called_broken():
    ts = _sound_token_under(lambda right, wrong: wrong).timestamp

    assert ts.intact is True, "a token that binds correctly was reported as not intact"
    assert ts.valid is True, "a token with a good signature was reported as invalid"
    assert ts.trusted is False, "the anchor is wrong, and that is the one thing that failed"


def test_the_gen_time_survives_a_chain_that_did_not_validate():
    """The date is what the row exists to report, and losing it is losing the answer. It used to
    be recovered by re-reading it out of the check's own wording, which only worked when the
    wording happened to contain it, so any failure erased the time along with the trust."""
    ts = _sound_token_under(lambda right, wrong: wrong).timestamp

    assert ts.gen_time is not None
    assert ts.gen_time.tzinfo is not None


def test_the_right_anchor_still_answers_all_three_yes():
    ts = _sound_token_under(lambda right, wrong: right).timestamp

    assert (ts.intact, ts.valid, ts.trusted) == (True, True, True)


def test_without_anchors_the_token_signature_is_still_checked():
    """Without --tsa-ca the chain cannot be judged, but the token's own signature can, and saying
    ``valid`` about something nobody verified is the same mistake as saying ``trusted``. This path
    used to check only the messageImprint binding and then report the signature as valid on that
    basis, so a token with a corrupt signature and a matching imprint passed."""
    signed = _sign(_dummy_timestamper())
    ts = verify_xml(signed)[0].timestamp

    assert ts.intact is True
    assert ts.valid is True        # actually checked now, not inferred from the binding
    assert ts.trusted is None      # and this one genuinely was not looked at


def _forge_the_token_signature(signed: bytes) -> bytes:
    """Rewrite the token's own signature, leaving its messageImprint binding untouched.

    Different from flipping a base64 character, which corrupts the DER and makes the token
    unparseable. Here the token stays structurally perfect and still points at this signature.
    Only the TSA's signature over it is a forgery, which is the case a binding-only check cannot
    see.
    """
    import base64 as b64
    import re as _re

    from asn1crypto import cms as a_cms
    from asn1crypto import core as a_core

    match = _re.search(rb"<[^>]*EncapsulatedTimeStamp[^>]*>([^<]+)<", signed)
    assert match, "no EncapsulatedTimeStamp to forge"
    token = a_cms.ContentInfo.load(b64.b64decode(_re.sub(rb"\s+", b"", match.group(1))))
    tst_signer = token["content"]["signer_infos"][0]
    forged = bytearray(tst_signer["signature"].native)
    forged[0] ^= 0xFF
    tst_signer["signature"] = a_core.OctetString(bytes(forged))
    return signed.replace(match.group(1), b64.b64encode(token.dump(force=True)))


def test_a_forged_token_signature_is_caught_without_any_anchors():
    ts = verify_xml(_forge_the_token_signature(_sign(_dummy_timestamper())))[0].timestamp

    assert ts.present is True
    assert ts.valid is False, "a forged token signature passed a binding-only check"


def test_a_forged_token_does_not_make_the_signature_invalid():
    """The timestamp is an unsigned property. Forging it must not accuse the document."""
    result = verify_xml(_forge_the_token_signature(_sign(_dummy_timestamper())))[0]

    assert result.indication == "INDETERMINATE"
    assert _check(result, "SignedInfo signature (RSA-SHA256)").ok
