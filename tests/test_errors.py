"""Unit tests for the domain exception hierarchy (firmauy.errors).

The contract under test: every domain error is catchable precisely (for a GUI) AND keeps
inheriting the built-in the engine historically raised, so pre-1.7.0 handlers and the CLI's
broad ``except Exception`` formatting keep working unchanged.
"""

from __future__ import annotations

import pytest

from firmauy.errors import (
    CardNotFoundError,
    CertificateError,
    CertificateNotFoundError,
    CertificateNotValidError,
    FirmauyError,
    IncorrectPinError,
    OutputExistsError,
    PinError,
    PinLockedError,
    ReaderNotFoundError,
    SigningKeyNotFoundError,
    TokenNotFoundError,
)


def test_every_domain_error_is_a_firmauy_error_and_a_runtime_error():
    for cls in (
        ReaderNotFoundError, CardNotFoundError, PinError, IncorrectPinError, PinLockedError,
        TokenNotFoundError, CertificateError, CertificateNotFoundError, CertificateNotValidError,
        SigningKeyNotFoundError, OutputExistsError,
    ):
        exc = cls("boom") if cls is not IncorrectPinError else cls("boom")
        assert isinstance(exc, FirmauyError)
        assert isinstance(exc, RuntimeError)   # pre-1.7.0 compatibility: broad handlers still work
        assert str(exc) == "boom"


def test_pin_hierarchy():
    assert issubclass(IncorrectPinError, PinError)
    assert issubclass(PinLockedError, PinError)
    assert IncorrectPinError("x").attempts_remaining is None
    assert IncorrectPinError("x", attempts_remaining=2).attempts_remaining == 2


def test_certificate_hierarchy():
    for cls in (CertificateNotFoundError, CertificateNotValidError, SigningKeyNotFoundError):
        assert issubclass(cls, CertificateError)


def test_output_exists_carries_the_path(tmp_path):
    exc = OutputExistsError("exists", path=tmp_path / "out.p7s")
    assert exc.path == tmp_path / "out.p7s"


# ---------------------------------------------------------------------------
# Cheap end-to-end mappings (no card, no HSM)
# ---------------------------------------------------------------------------


def test_open_reader_without_readers_raises_reader_not_found(monkeypatch):
    import firmauy.card_reader as card_reader

    monkeypatch.setattr(card_reader, "list_readers", lambda: [])
    with pytest.raises(ReaderNotFoundError, match="No PC/SC readers found"):
        card_reader.open_reader()


def test_open_reader_missing_named_reader_raises_reader_not_found(monkeypatch):
    import firmauy.card_reader as card_reader

    monkeypatch.setattr(card_reader, "list_readers", lambda: ["ACS ACR 38U"])
    with pytest.raises(ReaderNotFoundError, match="not found"):
        card_reader.open_reader("otro lector")


def test_sign_one_cms_existing_output_raises_output_exists(tmp_path):
    from firmauy.signing import _sign_one_cms

    src = tmp_path / "doc.bin"
    src.write_bytes(b"data")
    out = tmp_path / "doc.bin.p7s"
    out.write_bytes(b"old")   # pre-existing output, no overwrite

    # The exists-check fires before the signer is ever used, so a dummy signer suffices.
    with pytest.raises(OutputExistsError, match="already exists") as ei:
        _sign_one_cms(input_file=src, output_p7s=out, pkcs11_signer=object(),
                      timestamper=None, overwrite=False)
    assert ei.value.path == out
