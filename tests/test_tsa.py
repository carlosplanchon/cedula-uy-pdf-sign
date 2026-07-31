"""Unit tests for TSA timestamper construction with auth (signing._build_timestamper).

The builder is presentation-free: inconsistent options raise ValueError, and the
argv-visibility warning for sensitive literal headers goes to the optional ``notify``
callback (which the CLI wires to stderr)."""

import pytest
from pyhanko.sign.timestamps import HTTPTimeStamper

from firmauy.signing import _build_timestamper


def _b(**kw):
    kw.setdefault("tsa_url", None)
    kw.setdefault("tsa_user", None)
    kw.setdefault("tsa_pass_env", None)
    kw.setdefault("tsa_header", None)
    kw.setdefault("tsa_header_env", None)
    return _build_timestamper(**kw)


def test_none_without_url():
    assert _b() is None


def test_auth_options_require_url():
    with pytest.raises(ValueError, match="require --tsa-url"):
        _b(tsa_user="u")
    with pytest.raises(ValueError, match="require --tsa-url"):
        _b(tsa_header=["X: y"])


def test_url_only_no_auth():
    ts = _b(tsa_url="https://tsa.example/tsr")
    assert isinstance(ts, HTTPTimeStamper)
    assert ts.auth is None and ts.headers is None


def test_basic_auth(monkeypatch):
    monkeypatch.setenv("MY_TSA_PW", "s3cret")
    ts = _b(tsa_url="https://t", tsa_user="alice", tsa_pass_env="MY_TSA_PW")
    assert ts.auth == ("alice", "s3cret")


def test_user_without_passenv_raises():
    with pytest.raises(ValueError, match="both --tsa-user and --tsa-pass-env"):
        _b(tsa_url="https://t", tsa_user="alice")


def test_passenv_unset_raises(monkeypatch):
    monkeypatch.delenv("ABSENT_TSA_PW", raising=False)
    with pytest.raises(ValueError, match="is not set"):
        _b(tsa_url="https://t", tsa_user="alice", tsa_pass_env="ABSENT_TSA_PW")


def test_headers_parsed():
    ts = _b(tsa_url="https://t", tsa_header=["Authorization: Bearer abc", "X-Api-Key:k"])
    assert ts.headers == {"Authorization": "Bearer abc", "X-Api-Key": "k"}


def test_bad_header_raises():
    with pytest.raises(ValueError, match="Name: Value"):
        _b(tsa_url="https://t", tsa_header=["no-colon"])


# --- --tsa-header-env (keeps secrets off argv) ------------------------------

def test_header_env_reads_value_from_environment(monkeypatch):
    monkeypatch.setenv("TSA_AUTH", "Bearer s3cret")
    ts = _b(tsa_url="https://t", tsa_header_env=["Authorization: TSA_AUTH"])
    assert ts.headers == {"Authorization": "Bearer s3cret"}   # value came from env, not argv


def test_header_env_requires_url():
    with pytest.raises(ValueError, match="require --tsa-url"):
        _b(tsa_header_env=["Authorization: TSA_AUTH"])


def test_header_env_bad_format_raises():
    with pytest.raises(ValueError, match="Name: ENV_VAR"):
        _b(tsa_url="https://t", tsa_header_env=["no-colon"])


def test_header_env_missing_var_raises(monkeypatch):
    monkeypatch.delenv("ABSENT_HDR", raising=False)
    with pytest.raises(ValueError, match="is not set"):
        _b(tsa_url="https://t", tsa_header_env=["Authorization: ABSENT_HDR"])


def test_literal_and_env_headers_merge(monkeypatch):
    monkeypatch.setenv("TSA_AUTH", "Bearer s3cret")
    ts = _b(tsa_url="https://t", tsa_header=["X-Trace-Id: t1"],
            tsa_header_env=["Authorization: TSA_AUTH"])
    assert ts.headers == {"X-Trace-Id": "t1", "Authorization": "Bearer s3cret"}


def test_sensitive_literal_header_warns():
    # A credential passed literally is visible in argv: warn (via notify) and point at
    # --tsa-header-env.
    notes = []
    _b(tsa_url="https://t", tsa_header=["Authorization: Bearer abc"], notify=notes.append)
    assert any("visible in the process list" in n for n in notes)


def test_nonsensitive_literal_header_is_silent():
    notes = []
    _b(tsa_url="https://t", tsa_header=["X-Trace-Id: abc"], notify=notes.append)
    assert notes == []


def test_warning_dropped_without_notify():
    # The public API passes no notify: a sensitive literal header still builds, silently.
    ts = _b(tsa_url="https://t", tsa_header=["Authorization: Bearer abc"])
    assert ts.headers == {"Authorization": "Bearer abc"}
